"""
Session-based decomposition attack tracker.

Detects multi-turn decomposition attacks where an adversary breaks a dangerous
request into individually-benign chunks across multiple requests.

Architecture:
  - Uses Redis sorted sets to track "threat signals" per session (tenant+agent+source_ip)
  - Each request is analyzed for partial threat indicators (topics that are benign alone
    but dangerous when accumulated)
  - When accumulated score exceeds threshold within the time window, verdict escalates to BLOCK

Redis keys:
  bulwark:session:{session_key}:signals  — Sorted set {signal_id: timestamp}
  bulwark:session:{session_key}:score    — Float score with TTL
  bulwark:session:config                 — HASH {thresholds/windows} (admin runtime override)

The tracker is stateless if Redis is unavailable (graceful degradation to per-request only).
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Optional

import structlog

from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict
from src.redis_bootstrap import connect_redis

logger = structlog.get_logger()

# Admin-managed runtime override (see admin/routes/sessions.py). The proxy honors
# these tuning values without a restart, re-reading at most once per interval to
# keep the request hot path cheap.
RUNTIME_CONFIG_KEY = "bulwark:session:config"
_RUNTIME_REFRESH_INTERVAL = 5.0  # seconds

# Tunable fields exposed to the admin override, mapped to instance attributes.
_TUNABLE_FIELDS: dict[str, str] = {
    "block_threshold": "BLOCK_THRESHOLD",
    "warn_threshold": "WARN_THRESHOLD",
    "window_seconds": "WINDOW_SECONDS",
    "block_threshold_30m": "BLOCK_THRESHOLD_30M",
    "warn_threshold_30m": "WARN_THRESHOLD_30M",
    "window_30m_seconds": "WINDOW_30M_SECONDS",
}
_INT_FIELDS = {"window_seconds", "window_30m_seconds"}

# Decomposition topic indicators — individually benign but dangerous when accumulated
# Each carries a weight; accumulating >threshold within time window triggers BLOCK
_DECOMPOSITION_SIGNALS: list[tuple[re.Pattern, str, float]] = [
    # Offensive security topics (individually could be legitimate learning)
    (re.compile(r"\b(buffer\s+overflow|stack\s+overflow|heap\s+overflow)\b", re.I), "memory_corruption", 2.0),
    (re.compile(r"\b(shellcode|shell\s*code|machine\s+code\s+payload)\b", re.I), "shellcode", 3.0),
    (re.compile(r"\b(reverse\s+shell|bind\s+shell|connect.back\s+shell)\b", re.I), "reverse_shell", 3.5),
    (re.compile(r"\b(privilege\s+escalat|privesc|root\s+exploit)\b", re.I), "privesc", 2.5),
    (re.compile(r"\b(ASLR\s+bypass|DEP\s+bypass|NX\s+bypass|SMEP\s+bypass)\b", re.I), "mitigation_bypass", 2.5),
    (re.compile(r"\b(ROP\s+chain|return.oriented\s+program|gadget\s+chain)\b", re.I), "rop", 2.5),
    (re.compile(r"\b(heap\s+spray|use.after.free|double\s+free|format\s+string\s+vuln)\b", re.I), "heap_exploit", 2.5),
    (re.compile(r"\b(SQL\s+inject|SQLi|UNION\s+SELECT|blind\s+SQL)\b", re.I), "sqli", 2.0),
    (re.compile(r"\b(XSS|cross.site\s+script|script\s+inject)\b", re.I), "xss", 1.5),
    (re.compile(r"\b(SSRF|server.side\s+request\s+forg)\b", re.I), "ssrf", 2.0),
    (re.compile(r"\b(container\s+breakout|container\s+escap|docker\s+escap)\b", re.I), "container_escape", 3.0),
    (re.compile(r"\b(kernel\s+exploit|kernel\s+vuln|ring\s*0)\b", re.I), "kernel_exploit", 3.0),
    (re.compile(r"\b(zero.day|0day|n-day|CVE-\d{4}-\d+)\b", re.I), "zero_day", 2.0),
    (re.compile(r"\b(ransomware|cryptolocker|file\s+encrypt\w+\s+malware)\b", re.I), "ransomware", 3.0),
    (re.compile(r"\b(keylogger|keystroke\s+log|input\s+captur)\b", re.I), "keylogger", 2.5),
    (re.compile(r"\b(rootkit|bootkit|firmware\s+implant)\b", re.I), "rootkit", 3.0),
    (re.compile(r"\b(C2\s+server|command\s+and\s+control|C&C|beacon\s+callback)\b", re.I), "c2", 3.0),
    (re.compile(r"\b(phishing|spear.?phish|credential\s+harvest)\b", re.I), "phishing", 2.0),
    (re.compile(r"\b(lateral\s+movement|pivot|pass.the.hash|pass.the.ticket)\b", re.I), "lateral_movement", 2.5),
    (re.compile(r"\b(exfiltrat|data\s+theft|steal\s+data|dump\s+database)\b", re.I), "exfiltration", 2.5),

    # Weapons/drugs/dangerous synthesis (individually might be chemistry class)
    (re.compile(
        r"\b(synthe\w+|manufacture|produce|formul)\s+.{0,20}(explosive|detonat|bomb|weapon)\b", re.I
    ), "weapon_synth", 4.0),
    (re.compile(
        r"\b(methamphetamine|fentanyl|heroin|cocaine|LSD)\s+.{0,20}(synthe|cook|make|produce|formul)\b", re.I
    ), "drug_synth", 4.0),
    (re.compile(r"\b(nerve\s+agent|sarin|VX|ricin|anthrax|botulinum)\b", re.I), "bioweapon", 4.0),
    (re.compile(r"\b(detonator|primer|initiator|blasting\s+cap)\b", re.I), "detonator", 3.0),
    (re.compile(
        r"\b(ammonium\s+nitrate|ANFO|TATP|RDX|C-4|Semtex|TNT)\s+.{0,20}(make|synthe|mix|produce)\b", re.I
    ), "explosive_compound", 4.0),

    # Social engineering / hacking methodology (each step is fine, combination is an attack)
    (re.compile(r"\b(reconnaissance|recon|footprint|OSINT\s+target)\b", re.I), "recon", 1.5),
    (re.compile(r"\b(initial\s+access|gain\s+access|entry\s+point|attack\s+surface)\b", re.I), "initial_access", 1.5),
    (re.compile(r"\b(persistence|maintain\s+access|backdoor\s+install)\b", re.I), "persistence", 2.0),
    (re.compile(r"\b(defense\s+evasion|evade\s+detection|bypass\s+EDR|AV\s+evasion)\b", re.I), "defense_evasion", 2.5),
    (re.compile(r"\b(credential\s+dump|mimikatz|lsass|SAM\s+extract)\b", re.I), "cred_dump", 3.0),
]

# Combination patterns — specific multi-signal combos that are always malicious
_DANGEROUS_COMBINATIONS: list[tuple[set[str], float, str]] = [
    # Full attack chain (kill chain stages)
    (
        {"recon", "initial_access", "privesc", "lateral_movement", "exfiltration"},
        3.0,
        "Complete attack kill chain detected",
    ),
    ({"recon", "initial_access", "persistence", "defense_evasion"}, 2.5, "Attack chain with persistence and evasion"),
    # Exploit development chain
    ({"memory_corruption", "shellcode", "rop", "mitigation_bypass"}, 3.0, "Exploit development pipeline detected"),
    ({"memory_corruption", "shellcode", "reverse_shell"}, 2.5, "Memory exploit to shell chain"),
    # Malware development
    ({"c2", "persistence", "defense_evasion", "keylogger"}, 3.0, "RAT/Malware development pattern"),
    ({"ransomware", "c2", "lateral_movement"}, 3.0, "Ransomware attack chain"),
    # WMD synthesis
    ({"weapon_synth", "detonator"}, 5.0, "Explosive device construction chain"),
    ({"drug_synth", "explosive_compound"}, 5.0, "Dangerous substance synthesis chain"),
    ({"bioweapon", "weapon_synth"}, 5.0, "Bioweapon development chain"),
]


@dataclass
class SessionState:
    """In-memory fallback when Redis is unavailable."""
    signals: dict[str, float] = field(default_factory=dict)  # signal_id -> timestamp
    total_score: float = 0.0


class SessionDecompositionTracker:
    """Tracks threat signal accumulation across requests within a session.

    Configuration:
      - BLOCK_THRESHOLD: accumulated score that triggers BLOCK (default 8.0)
      - WARN_THRESHOLD: accumulated score that triggers WARN (default 5.0)
      - WINDOW_SECONDS: time window for signal accumulation (default 300 = 5 min)
      - MAX_SESSIONS: max in-memory sessions (LRU eviction if Redis unavailable)

    Multi-tier windows (P7-03 fix):
      - 5-min window: original thresholds (fast decomposition)
      - 30-min window: 60% thresholds (slow decomposition over >5 min)

    Tenant-level tracking (P7-02 fix):
      - Cross-agent aggregation prevents distributing signals across agents.
    """

    BLOCK_THRESHOLD = 8.0
    WARN_THRESHOLD = 5.0
    WINDOW_SECONDS = 300  # 5-minute sliding window

    # P7-03 fix: 30-minute window with lower thresholds to catch slow decomposition
    WINDOW_30M_SECONDS = 1800  # 30-minute sliding window
    BLOCK_THRESHOLD_30M = 4.8  # 60% of 5-min threshold
    WARN_THRESHOLD_30M = 3.0   # 60% of 5-min threshold

    MAX_SESSIONS = 10000

    def __init__(self):
        self._redis = None
        self._local_sessions: dict[str, SessionState] = {}
        self._initialized = False
        # Seed instance-level tunables from class defaults. Instance attributes
        # shadow the class constants, so all existing ``self.BLOCK_THRESHOLD``
        # reads transparently pick up admin runtime overrides.
        cls = type(self)
        for attr in _TUNABLE_FIELDS.values():
            setattr(self, attr, getattr(cls, attr))
        self._runtime_checked_at = 0.0

    def _refresh_runtime_config(self) -> None:
        """Honor admin runtime overrides (thresholds/windows) from Redis.

        Throttled to at most one lookup per ``_RUNTIME_REFRESH_INTERVAL`` so the
        request hot path stays cheap. No-op without Redis (defaults apply).
        Invalid values are ignored; only known tunable fields are applied.
        """
        if not self._redis:
            return
        now = time.time()
        if (now - self._runtime_checked_at) < _RUNTIME_REFRESH_INTERVAL:
            return
        self._runtime_checked_at = now
        try:
            cfg = self._redis.hgetall(RUNTIME_CONFIG_KEY) or {}
        except Exception:
            return
        if not cfg:
            return
        for field_name, attr in _TUNABLE_FIELDS.items():
            if field_name not in cfg:
                continue
            raw = cfg[field_name]
            try:
                value: float | int = int(raw) if field_name in _INT_FIELDS else float(raw)
            except (TypeError, ValueError):
                continue
            if value <= 0:
                continue
            setattr(self, attr, value)

    def initialize(self, redis_url: Optional[str] = None, redis_tls_insecure: bool = False):
        """Initialize Redis connection (call once at startup)."""
        if redis_url:
            try:
                self._redis = connect_redis(
                    redis_url, redis_tls_insecure=redis_tls_insecure
                )
            except Exception as e:
                logger.warning("session_tracker_redis_unavailable", error=str(e))
                self._redis = None
        self._initialized = True

    def _session_key(self, tenant_id: str, agent_id: str, source_ip: str) -> str:
        """Generate session key from request context."""
        # SECURITY FIX (H-02): Session key based on tenant+agent only.
        # IP rotation no longer resets threat scores, preventing multi-IP decomposition attacks.
        session_key = hashlib.sha256(f"{tenant_id}:{agent_id}".encode()).hexdigest()[:16]
        return session_key

    def _tenant_session_key(self, tenant_id: str) -> str:
        """Generate tenant-level session key (cross-agent aggregation).

        SECURITY FIX (P7-02): Tracks signals at tenant level so distributing
        attacks across multiple agents per tenant doesn't bypass thresholds.
        """
        return hashlib.sha256(f"tenant:{tenant_id}".encode()).hexdigest()[:16]

    def check_and_update(
        self,
        content: str,
        tenant_id: str = "",
        agent_id: str = "",
        source_ip: str = "",
    ) -> GuardrailResult:
        """Analyze content for decomposition signals and check accumulated score.

        Checks both per-agent session and tenant-level (cross-agent) session,
        using multiple time windows (5min + 30min) to catch slow decomposition.

        Returns:
          - BLOCK if accumulated score exceeds BLOCK_THRESHOLD
          - WARN if exceeds WARN_THRESHOLD
          - ALLOW otherwise (even if signals detected — they're individually benign)
        """
        if not self._initialized:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Honor any admin runtime tuning (throttled, cheap on the hot path).
        self._refresh_runtime_config()

        # Extract signals from current request
        now = time.time()
        detected_signals: list[tuple[str, float]] = []

        for pattern, signal_id, weight in _DECOMPOSITION_SIGNALS:
            if pattern.search(content):
                detected_signals.append((signal_id, weight))

        if not detected_signals:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Get/update session state — check per-agent key (original)
        session_key = self._session_key(tenant_id, agent_id, source_ip)
        # P7-02 fix: Also check tenant-level key (cross-agent aggregation)
        tenant_key = self._tenant_session_key(tenant_id)

        if self._redis:
            result = self._check_redis(session_key, detected_signals, now, tenant_id, agent_id)
            if result.verdict == Verdict.BLOCK:
                return result
            # P7-02: Check tenant-level (cross-agent) accumulation
            tenant_result = self._check_redis(tenant_key, detected_signals, now, tenant_id, agent_id)
            if tenant_result.verdict == Verdict.BLOCK:
                return tenant_result
            # P7-03: Check 30-min window (slow decomposition) on both keys
            slow_result = self._check_redis_30m(session_key, detected_signals, now, tenant_id, agent_id)
            if slow_result.verdict == Verdict.BLOCK:
                return slow_result
            slow_tenant_result = self._check_redis_30m(tenant_key, detected_signals, now, tenant_id, agent_id)
            if slow_tenant_result.verdict == Verdict.BLOCK:
                return slow_tenant_result
            # Return worst non-BLOCK verdict
            for r in (result, tenant_result, slow_result, slow_tenant_result):
                if r.verdict == Verdict.WARN:
                    return r
            return result
        else:
            result = self._check_local(session_key, detected_signals, now, tenant_id, agent_id)
            if result.verdict == Verdict.BLOCK:
                return result
            # P7-02: Check tenant-level (cross-agent) accumulation
            tenant_result = self._check_local(tenant_key, detected_signals, now, tenant_id, agent_id)
            if tenant_result.verdict == Verdict.BLOCK:
                return tenant_result
            # P7-03: Check 30-min window (slow decomposition) on both keys
            slow_result = self._check_local_30m(session_key, detected_signals, now, tenant_id, agent_id)
            if slow_result.verdict == Verdict.BLOCK:
                return slow_result
            slow_tenant_result = self._check_local_30m(tenant_key, detected_signals, now, tenant_id, agent_id)
            if slow_tenant_result.verdict == Verdict.BLOCK:
                return slow_tenant_result
            # Return worst non-BLOCK verdict
            for r in (result, tenant_result, slow_result, slow_tenant_result):
                if r.verdict == Verdict.WARN:
                    return r
            return result

    def _check_redis(
        self,
        session_key: str,
        detected_signals: list[tuple[str, float]],
        now: float,
        tenant_id: str,
        agent_id: str,
    ) -> GuardrailResult:
        """Redis-backed session tracking."""
        try:
            redis_key = f"bulwark:session:{session_key}:signals"
            pipe = self._redis.pipeline()

            # Remove expired signals
            pipe.zremrangebyscore(redis_key, 0, now - self.WINDOW_SECONDS)

            # Add new signals
            for signal_id, weight in detected_signals:
                # Store as "signal_id:weight" with timestamp as score
                pipe.zadd(redis_key, {f"{signal_id}:{weight}": now})

            # Set TTL on key
            pipe.expire(redis_key, self.WINDOW_SECONDS + 60)

            # Get all active signals
            pipe.zrangebyscore(redis_key, now - self.WINDOW_SECONDS, "+inf")

            results = pipe.execute()
            active_signals_raw = results[-1]

            # Calculate accumulated score and check combinations
            signal_ids = set()
            total_score = 0.0
            for entry in active_signals_raw:
                parts = entry.rsplit(":", 1)
                if len(parts) == 2:
                    signal_ids.add(parts[0])
                    total_score += float(parts[1])

            return self._evaluate(total_score, signal_ids, tenant_id, agent_id, len(active_signals_raw))

        except Exception as e:
            logger.warning("session_tracker_redis_error", error=str(e))
            return GuardrailResult(verdict=Verdict.ALLOW)

    def _check_local(
        self,
        session_key: str,
        detected_signals: list[tuple[str, float]],
        now: float,
        tenant_id: str,
        agent_id: str,
    ) -> GuardrailResult:
        """In-memory fallback session tracking."""
        # Evict oldest sessions if at capacity
        if len(self._local_sessions) >= self.MAX_SESSIONS and session_key not in self._local_sessions:
            oldest_key = next(iter(self._local_sessions))
            del self._local_sessions[oldest_key]

        if session_key not in self._local_sessions:
            self._local_sessions[session_key] = SessionState()

        session = self._local_sessions[session_key]

        # Prune expired signals
        cutoff = now - self.WINDOW_SECONDS
        session.signals = {k: v for k, v in session.signals.items() if v > cutoff}

        # Add new signals
        for signal_id, weight in detected_signals:
            session.signals[f"{signal_id}:{weight}"] = now

        # Calculate score
        signal_ids = set()
        total_score = 0.0
        for entry in session.signals:
            parts = entry.rsplit(":", 1)
            if len(parts) == 2:
                signal_ids.add(parts[0])
                total_score += float(parts[1])

        session.total_score = total_score

        return self._evaluate(total_score, signal_ids, tenant_id, agent_id, len(session.signals))

    def _check_redis_30m(
        self,
        session_key: str,
        detected_signals: list[tuple[str, float]],
        now: float,
        tenant_id: str,
        agent_id: str,
    ) -> GuardrailResult:
        """Redis-backed 30-minute window tracking (P7-03 fix).

        Uses a separate Redis key with longer TTL and lower thresholds
        to catch slow decomposition attacks spread over >5 minutes.
        """
        try:
            redis_key = f"bulwark:session_30m:{session_key}:signals"
            pipe = self._redis.pipeline()

            # Remove signals older than 30-min window
            pipe.zremrangebyscore(redis_key, 0, now - self.WINDOW_30M_SECONDS)

            # Add new signals
            for signal_id, weight in detected_signals:
                pipe.zadd(redis_key, {f"{signal_id}:{weight}": now})

            # Set TTL on key
            pipe.expire(redis_key, self.WINDOW_30M_SECONDS + 60)

            # Get all active signals in 30-min window
            pipe.zrangebyscore(redis_key, now - self.WINDOW_30M_SECONDS, "+inf")

            results = pipe.execute()
            active_signals_raw = results[-1]

            # Calculate accumulated score
            signal_ids = set()
            total_score = 0.0
            for entry in active_signals_raw:
                parts = entry.rsplit(":", 1)
                if len(parts) == 2:
                    signal_ids.add(parts[0])
                    total_score += float(parts[1])

            return self._evaluate_30m(total_score, signal_ids, tenant_id, agent_id, len(active_signals_raw))

        except Exception as e:
            logger.warning("session_tracker_redis_30m_error", error=str(e))
            return GuardrailResult(verdict=Verdict.ALLOW)

    def _check_local_30m(
        self,
        session_key: str,
        detected_signals: list[tuple[str, float]],
        now: float,
        tenant_id: str,
        agent_id: str,
    ) -> GuardrailResult:
        """In-memory fallback 30-minute window tracking (P7-03 fix)."""
        key_30m = f"30m:{session_key}"

        # Evict oldest sessions if at capacity
        if len(self._local_sessions) >= self.MAX_SESSIONS and key_30m not in self._local_sessions:
            oldest_key = next(iter(self._local_sessions))
            del self._local_sessions[oldest_key]

        if key_30m not in self._local_sessions:
            self._local_sessions[key_30m] = SessionState()

        session = self._local_sessions[key_30m]

        # Prune signals older than 30-min window
        cutoff = now - self.WINDOW_30M_SECONDS
        session.signals = {k: v for k, v in session.signals.items() if v > cutoff}

        # Add new signals
        for signal_id, weight in detected_signals:
            session.signals[f"{signal_id}:{weight}"] = now

        # Calculate score
        signal_ids = set()
        total_score = 0.0
        for entry in session.signals:
            parts = entry.rsplit(":", 1)
            if len(parts) == 2:
                signal_ids.add(parts[0])
                total_score += float(parts[1])

        session.total_score = total_score

        return self._evaluate_30m(total_score, signal_ids, tenant_id, agent_id, len(session.signals))

    def _evaluate_30m(
        self,
        total_score: float,
        signal_ids: set[str],
        tenant_id: str,
        agent_id: str,
        signal_count: int,
    ) -> GuardrailResult:
        """Evaluate 30-min window with lower thresholds (P7-03 fix)."""
        events: list[SecurityEvent] = []

        # Check dangerous combinations (bonus score)
        combo_bonus = 0.0
        combo_desc = ""
        for required_signals, bonus, description in _DANGEROUS_COMBINATIONS:
            if required_signals.issubset(signal_ids):
                if bonus > combo_bonus:
                    combo_bonus = bonus
                    combo_desc = description

        effective_score = total_score + combo_bonus

        if effective_score >= self.BLOCK_THRESHOLD_30M:
            events.append(SecurityEvent(
                tenant_id=tenant_id,
                agent_id=agent_id,
                verdict=Verdict.BLOCK,
                category=ThreatCategory.JAILBREAK,
                description=(
                    f"Slow multi-turn decomposition attack detected (30-min window): "
                    f"accumulated {signal_count} threat signals (score={effective_score:.1f}, "
                    f"threshold={self.BLOCK_THRESHOLD_30M}). "
                    f"Signals: {', '.join(sorted(signal_ids)[:8])}"
                    + (f". Combo: {combo_desc}" if combo_desc else "")
                ),
                source="session_decomposition_tracker",
                severity="critical",
            ))
            return GuardrailResult(verdict=Verdict.BLOCK, events=events)

        elif effective_score >= self.WARN_THRESHOLD_30M:
            events.append(SecurityEvent(
                tenant_id=tenant_id,
                agent_id=agent_id,
                verdict=Verdict.WARN,
                category=ThreatCategory.JAILBREAK,
                description=(
                    f"Possible slow multi-turn decomposition (30-min window): "
                    f"{signal_count} threat signals accumulated (score={effective_score:.1f}, "
                    f"warn_threshold={self.WARN_THRESHOLD_30M}). "
                    f"Signals: {', '.join(sorted(signal_ids)[:8])}"
                ),
                source="session_decomposition_tracker",
                severity="high",
            ))
            return GuardrailResult(verdict=Verdict.WARN, events=events)

        return GuardrailResult(verdict=Verdict.ALLOW)

    def _evaluate(
        self,
        total_score: float,
        signal_ids: set[str],
        tenant_id: str,
        agent_id: str,
        signal_count: int,
    ) -> GuardrailResult:
        """Evaluate accumulated score + dangerous combinations."""
        events: list[SecurityEvent] = []

        # Check dangerous combinations (bonus score)
        combo_bonus = 0.0
        combo_desc = ""
        for required_signals, bonus, description in _DANGEROUS_COMBINATIONS:
            if required_signals.issubset(signal_ids):
                if bonus > combo_bonus:
                    combo_bonus = bonus
                    combo_desc = description

        effective_score = total_score + combo_bonus

        if effective_score >= self.BLOCK_THRESHOLD:
            events.append(SecurityEvent(
                tenant_id=tenant_id,
                agent_id=agent_id,
                verdict=Verdict.BLOCK,
                category=ThreatCategory.JAILBREAK,
                description=(
                    f"Multi-turn decomposition attack detected: "
                    f"accumulated {signal_count} threat signals (score={effective_score:.1f}, "
                    f"threshold={self.BLOCK_THRESHOLD}). "
                    f"Signals: {', '.join(sorted(signal_ids)[:8])}"
                    + (f". Combo: {combo_desc}" if combo_desc else "")
                ),
                source="session_decomposition_tracker",
                severity="critical",
            ))
            return GuardrailResult(verdict=Verdict.BLOCK, events=events)

        elif effective_score >= self.WARN_THRESHOLD:
            events.append(SecurityEvent(
                tenant_id=tenant_id,
                agent_id=agent_id,
                verdict=Verdict.WARN,
                category=ThreatCategory.JAILBREAK,
                description=(
                    f"Possible multi-turn decomposition: "
                    f"{signal_count} threat signals accumulated (score={effective_score:.1f}, "
                    f"warn_threshold={self.WARN_THRESHOLD}). "
                    f"Signals: {', '.join(sorted(signal_ids)[:8])}"
                ),
                source="session_decomposition_tracker",
                severity="high",
            ))
            return GuardrailResult(verdict=Verdict.WARN, events=events)

        return GuardrailResult(verdict=Verdict.ALLOW)


# Module-level singleton
_tracker: Optional[SessionDecompositionTracker] = None


def get_session_tracker() -> SessionDecompositionTracker:
    """Get or create the singleton session tracker."""
    global _tracker
    if _tracker is None:
        _tracker = SessionDecompositionTracker()
    return _tracker
