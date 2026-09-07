"""Runtime lethal-trifecta accumulator (Redis-backed, in-memory fallback).

The config-time :class:`~src.discovery.lethal_trifecta.LethalTrifectaAnalyzer`
answers "could this agent's *declared* toolset enable a breach?". This module
answers the complementary *runtime* question: "has this origin, across its recent
requests, actually *exercised* all three trifecta pillars?".

The lethal trifecta (Simon Willison) is breach-enabling only when an agent
simultaneously holds **data access**, **exposure to untrusted content**, and an
**outbound exfiltration channel**. At runtime those pillars are lit up by:

* the **tools the agent actually invokes** (mapped to capabilities → pillars via
  the shared :func:`~src.discovery.lethal_trifecta.pillars_for_tools` SSOT),
* a **suspicious INPUT** in the request (prompt injection / jailbreak / … ⇒ the
  session is being exposed to untrusted, attacker-shaped content), and
* a **sensitive OUTPUT** leaving the gateway (PII / credential / exfiltration ⇒ an
  outbound channel is carrying data off).

Signals are accumulated per **origin** over a sliding window. When an origin's
live pillar set first reaches all three (the ``newly_completed`` transition — not
on every subsequent request, to stay quiet) the tracker emits one
:class:`~src.models.SecurityEvent` (``EXCESSIVE_AGENCY``, WARN — or BLOCK when
``trifecta_runtime_blocking`` is on) and elevates the origin's risk state so the
existing adaptive-enforcement loop hardens the next requests.

Design guarantees (consistent with the rest of the correlation subsystem):

* **Opt-in / inert by default.** Nothing runs unless ``trifecta_runtime_enabled``.
* **Fail-open, never raises.** A Redis error degrades to a per-process in-memory
  map behind a circuit breaker (so a slow/down Redis never amplifies latency); any
  unexpected error yields "no event" rather than breaking the response path.
* **Blast-radius aware (F3).** Accumulation keys on the most-specific origin — the
  authenticated ``subject`` when known, otherwise the ``session`` (tenant+agent) —
  so one actor's trifecta does not complete because of another actor's activity.
* **No tap amplification.** The emitted event carries ``metadata.correlation`` so
  the event tap skips it (its own risk bump is applied directly here).
"""

from __future__ import annotations

import time
from typing import Any, Optional

import structlog

from src.correlation.incident import _SENSITIVE_OUTPUT, _SUSPICIOUS_INPUT
from src.correlation.metrics import record_correlation_metric
from src.correlation.risk_state import RiskStateStore, get_risk_state_store
from src.discovery.lethal_trifecta import (
    TrifectaPillar,
    pillars_for_tools,
)
from src.models import SecurityEvent, ThreatCategory, Verdict
from src.redis_bootstrap import connect_redis

logger = structlog.get_logger()

# Redis key namespace for the per-origin pillar accumulator.
_KEY_PREFIX = "bulwark:trifecta"

# Bounded in-memory fallback capacity (FIFO-ish eviction).
_MAX_LOCAL_ENTRIES = 50_000

# Circuit breaker: the observe path sits inline in the output pipeline. After this
# many consecutive Redis errors the breaker opens and calls short-circuit straight
# to the in-memory fallback (no socket, no timeout) until a cooldown elapses.
_CB_FAIL_THRESHOLD = 5
_CB_COOLDOWN_SECONDS = 5.0

# Risk bumps applied to the origin when a runtime trifecta first completes. Mirrors
# the confirmed-incident weighting in :mod:`src.correlation.incident`: the subject
# (the authenticated actor enforcement BLOCKs on) and the session carry the most
# weight; the tenant gets a smaller bump so one origin escalates faster than a
# whole tenant.
_RISK_BUMP_SUBJECT = 4.0
_RISK_BUMP_SESSION = 4.0
_RISK_BUMP_TENANT = 1.0

# All three pillars — a live set of this size is a completed trifecta.
_TRIFECTA_SIZE = 3


class TrifectaStateStore:
    """Sliding-window per-origin pillar accumulator.

    State is a small hash per origin: ``{pillar_value: last_seen_epoch}``. On each
    :meth:`observe` the stale pillars (older than the window) are pruned, the new
    pillars are stamped with *now*, and the store reports the live pillar set plus
    whether this call is the transition that *first* completed the trifecta.
    """

    def __init__(self) -> None:
        self._redis: Optional[Any] = None
        self._local: dict[str, dict[str, float]] = {}
        self._cb_failures = 0
        self._cb_opened_at = 0.0

    # --- lifecycle ---------------------------------------------------------

    def initialize(
        self,
        redis_url: Optional[str] = None,
        redis_tls_insecure: bool = False,
    ) -> None:
        """Connect to Redis (once, at startup). No-op-safe without a URL."""
        if redis_url:
            try:
                self._redis = connect_redis(
                    redis_url, redis_tls_insecure=redis_tls_insecure
                )
            except Exception as e:  # noqa: BLE001 - degrade to in-memory
                logger.warning("trifecta_state_redis_unavailable", error=str(e))
                self._redis = None

    # --- key derivation ----------------------------------------------------

    @staticmethod
    def _redis_key(scope_type: str, scope_id: str) -> str:
        # Reuse the correlation origin-identity digest so a raw subject_id (PII)
        # never reaches the datastore and the key namespace stays consistent.
        digest = RiskStateStore.scope_digest(scope_type, scope_id)
        return f"{_KEY_PREFIX}:{scope_type}:{digest}"

    # --- circuit breaker ---------------------------------------------------

    def _cb_should_skip(self) -> bool:
        if self._cb_opened_at == 0.0:
            return False
        if time.time() - self._cb_opened_at >= _CB_COOLDOWN_SECONDS:
            return False  # half-open: allow one probe through
        return True

    def _cb_success(self) -> None:
        self._cb_failures = 0
        self._cb_opened_at = 0.0

    def _cb_failure(self) -> None:
        self._cb_failures += 1
        if self._cb_failures >= _CB_FAIL_THRESHOLD:
            self._cb_opened_at = time.time()

    # --- public API --------------------------------------------------------

    def observe(
        self,
        scope_type: str,
        scope_id: str,
        new_pillars: set[str],
        window_seconds: float,
        now: Optional[float] = None,
    ) -> tuple[set[str], bool]:
        """Fold ``new_pillars`` into the origin's live set over the window.

        Returns ``(live_after, newly_completed)`` where ``live_after`` is the set
        of pillars currently live for the origin and ``newly_completed`` is True
        only on the call that transitions the origin *into* a full three-pillar
        trifecta (so callers can act once, not on every subsequent request).

        Never raises — a Redis error degrades to the in-memory fallback.
        """
        if not scope_id or not new_pillars:
            return set(), False
        now = time.time() if now is None else now
        window = max(1.0, float(window_seconds))
        if self._redis is not None and not self._cb_should_skip():
            try:
                out = self._observe_redis(scope_type, scope_id, new_pillars, window, now)
                self._cb_success()
                return out
            except Exception as e:  # noqa: BLE001 - degrade, never break hot path
                logger.warning("trifecta_observe_redis_error", error=str(e))
                self._cb_failure()
        return self._observe_local(scope_type, scope_id, new_pillars, window, now)

    # --- helpers -----------------------------------------------------------

    @staticmethod
    def _split_live(
        current: dict[str, Any], window: float, now: float
    ) -> tuple[set[str], list[str]]:
        """Partition stored pillars into (live set, stale field list)."""
        live: set[str] = set()
        stale: list[str] = []
        for pillar, ts in current.items():
            try:
                seen = float(ts)
            except (TypeError, ValueError):
                stale.append(pillar)
                continue
            if now - seen <= window:
                live.add(pillar)
            else:
                stale.append(pillar)
        return live, stale

    # --- redis backend -----------------------------------------------------

    def _observe_redis(
        self,
        scope_type: str,
        scope_id: str,
        new_pillars: set[str],
        window: float,
        now: float,
    ) -> tuple[set[str], bool]:
        key = self._redis_key(scope_type, scope_id)
        current = self._redis.hgetall(key) or {}  # type: ignore[union-attr]
        live_before, stale = self._split_live(current, window, now)
        live_after = live_before | new_pillars

        pipe = self._redis.pipeline()  # type: ignore[union-attr]
        pipe.hset(key, mapping={p: now for p in new_pillars})
        if stale:
            pipe.hdel(key, *stale)
        # TTL a little past the window so a fully-idle origin's key self-expires.
        pipe.expire(key, int(window) + 60)
        pipe.execute()

        newly = len(live_after) == _TRIFECTA_SIZE and len(live_before) < _TRIFECTA_SIZE
        return live_after, newly

    # --- in-memory fallback ------------------------------------------------

    def _observe_local(
        self,
        scope_type: str,
        scope_id: str,
        new_pillars: set[str],
        window: float,
        now: float,
    ) -> tuple[set[str], bool]:
        if len(self._local) >= _MAX_LOCAL_ENTRIES:
            self._local.pop(next(iter(self._local)), None)
        k = f"{scope_type}:{scope_id}"
        entry = self._local.get(k)
        if entry is None:
            entry = {}
        live_before, stale = self._split_live(entry, window, now)
        for pillar in stale:
            entry.pop(pillar, None)
        for pillar in new_pillars:
            entry[pillar] = now
        self._local[k] = entry
        live_after = live_before | new_pillars
        newly = len(live_after) == _TRIFECTA_SIZE and len(live_before) < _TRIFECTA_SIZE
        return live_after, newly


# Module-level singleton -----------------------------------------------------

_store: Optional[TrifectaStateStore] = None


def get_trifecta_state_store() -> TrifectaStateStore:
    """Return the process-wide runtime-trifecta state store singleton."""
    global _store
    if _store is None:
        _store = TrifectaStateStore()
    return _store


class RuntimeTrifectaTracker:
    """Accumulate runtime trifecta signals and emit on first completion."""

    def __init__(self) -> None:
        self._store = get_trifecta_state_store()
        self._risk = get_risk_state_store()

    def _cfg(self):
        from src.config import settings

        return settings

    def _pillars_from_request(
        self,
        *,
        tool_names: list[str],
        input_categories: list[ThreatCategory],
        output_categories: list[ThreatCategory],
    ) -> set[TrifectaPillar]:
        """Project a single request's signals onto trifecta pillars."""
        pillars = pillars_for_tools(tool_names)
        if any(c in _SUSPICIOUS_INPUT for c in input_categories):
            pillars.add(TrifectaPillar.UNTRUSTED_EXPOSURE)
        if any(c in _SENSITIVE_OUTPUT for c in output_categories):
            pillars.add(TrifectaPillar.EXFILTRATION)
        return pillars

    def observe_request(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        tool_names: list[str],
        input_categories: list[ThreatCategory],
        output_categories: list[ThreatCategory],
        request_id: str | None = None,
        subject_id: str | None = None,
    ) -> Optional[SecurityEvent]:
        """Fold this request's signals into the origin's trifecta accumulator.

        Returns a :class:`SecurityEvent` only when this request is the one that
        *completes* the origin's trifecta (WARN, or BLOCK when
        ``trifecta_runtime_blocking`` is on). Returns ``None`` otherwise. Never
        raises — runtime trifecta tracking must never break the response path.
        """
        settings = self._cfg()
        if not getattr(settings, "trifecta_runtime_enabled", False):
            return None
        try:
            pillars = self._pillars_from_request(
                tool_names=tool_names,
                input_categories=input_categories,
                output_categories=output_categories,
            )
            if not pillars:
                return None

            # F3 (blast-radius): accumulate on the most-specific origin.
            if subject_id:
                scope_type, scope_id = "subject", f"{tenant_id}:{subject_id}"
            else:
                scope_type, scope_id = "session", f"{tenant_id}:{agent_id}"

            window = float(getattr(settings, "trifecta_runtime_window_seconds", 1800.0))
            _live_after, newly_completed = self._store.observe(
                scope_type, scope_id, {p.value for p in pillars}, window
            )
            if not newly_completed:
                return None

            blocking = bool(getattr(settings, "trifecta_runtime_blocking", False))
            verdict = Verdict.BLOCK if blocking else Verdict.WARN

            # Elevate origin risk directly (the emitted event is skipped by the
            # event tap, so no feedback amplification). Subject is the primary
            # target when authenticated; session + tenant accrue less.
            if subject_id:
                self._risk.bump("subject", f"{tenant_id}:{subject_id}", _RISK_BUMP_SUBJECT)
            self._risk.bump("session", f"{tenant_id}:{agent_id}", _RISK_BUMP_SESSION)
            self._risk.bump("tenant", tenant_id, _RISK_BUMP_TENANT)

            record_correlation_metric("trifecta_completed_total")
            if blocking:
                record_correlation_metric("trifecta_blocked")

            minutes = max(1, int(round(window / 60.0)))
            action = "blocked" if blocking else "flagged"
            description = (
                f"Runtime lethal trifecta {action} for {scope_type}: the origin has "
                f"exercised all three capability pillars — data access, "
                f"untrusted-content exposure, and an outbound exfiltration channel — "
                f"within a {minutes}-minute window. A prompt injection in this "
                f"session can now escalate into a data breach."
            )
            return SecurityEvent(
                tenant_id=tenant_id,
                agent_id=agent_id,
                verdict=verdict,
                category=ThreatCategory.EXCESSIVE_AGENCY,
                description=description,
                source="trifecta_runtime",
                severity="critical" if blocking else "high",
                request_id=request_id,
                metadata={
                    "correlation": True,
                    "trifecta_runtime": True,
                    "decision_scope": scope_type,
                    "pillars_present": sorted(p.value for p in TrifectaPillar),
                    "window_seconds": window,
                },
            )
        except Exception as e:  # noqa: BLE001 - tracking must never break responses
            logger.warning("trifecta_runtime_observe_error", error=str(e))
            return None


# Module-level singleton -----------------------------------------------------

_tracker: Optional[RuntimeTrifectaTracker] = None


def get_trifecta_tracker() -> RuntimeTrifectaTracker:
    """Return the process-wide runtime-trifecta tracker singleton."""
    global _tracker
    if _tracker is None:
        _tracker = RuntimeTrifectaTracker()
    return _tracker
