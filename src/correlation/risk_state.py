"""Decaying per-origin risk state (Redis-backed, in-memory fallback).

An *origin* is a stable, server-derived identity that a request can be attributed
to: the specific authenticated subject, the tenant, the (tenant, agent) session,
or the content fingerprint (``input_hash``). When a correlation confirms
suspicious behaviour, we ``bump`` the origin's risk score. Subsequent requests
read the (time-decayed) score via ``get`` and can be hardened — e.g. escalating a
borderline WARN to a BLOCK.

Design notes / lessons carried over from ``session_tracker``:

* **Scope keys are never attacker-manipulable.** They are derived from
  authenticated ``tenant_id`` / ``agent_id`` or a content hash — never from the
  source IP (lesson H-02: IP rotation must not reset accumulated risk).
* **Graceful degradation.** If Redis is unavailable the store falls back to a
  bounded in-memory map; risk simply becomes per-worker instead of distributed.
* **Time decay.** Scores decay with a configurable half-life so a single bad
  request does not permanently penalise an origin. Decay is applied lazily on
  every read/write, so no background sweeper is needed.
* **Cheap hot path.** One Redis round-trip (a short pipeline) per ``bump``/``get``;
  a Redis failure degrades to ALLOW-equivalent (score 0.0), never raises.
"""

from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass
from typing import Any, Optional

import structlog

from src.redis_bootstrap import connect_redis

logger = structlog.get_logger()

# Redis key namespace for origin risk state.
_KEY_PREFIX = "bulwark:risk"

# Score is clamped to a 0..10 scale to stay commensurate with the rest of the
# platform (SkillSpector, session_tracker use 0..10-ish weights).
_MAX_SCORE = 10.0

# Bounded in-memory fallback capacity (LRU-ish eviction).
_MAX_LOCAL_ENTRIES = 50_000

# Circuit breaker (F2): the risk read/write path sits inline in the request
# pipeline. With ``socket_timeout=1s`` and no breaker, a slow/down Redis makes
# *every* request pay up to 1s per call — a latency amplifier precisely when the
# backend is already unhealthy. After this many consecutive Redis errors the
# breaker opens and calls short-circuit straight to the in-memory fallback
# (no socket touch, no timeout) until a cooldown elapses, then one probe re-tests.
_CB_FAIL_THRESHOLD = 5
_CB_COOLDOWN_SECONDS = 5.0

# Atomic decay-and-bump executed server-side (Redis runs Lua scripts atomically,
# so concurrent bumps of the *same* origin cannot lose updates — the exact race a
# burst attack would otherwise exploit to under-count its own risk). Mirrors the
# pure ``_apply_bump`` reference below byte-for-byte so the in-memory fallback and
# the tests share one algorithm.
#   KEYS[1] = risk key (hash: {score, ts})
#   ARGV[1] = now, ARGV[2] = amount, ARGV[3] = half_life,
#   ARGV[4] = max_score, ARGV[5] = ttl_seconds
# Returns the new (decayed + amount, clamped) score as a string (preserves the
# float; Redis would otherwise truncate a Lua number to an integer on return).
_LUA_BUMP = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local amount = tonumber(ARGV[2])
local half_life = tonumber(ARGV[3])
local max_score = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5])
local prev_score = tonumber(redis.call('HGET', key, 'score')) or 0
local prev_ts = tonumber(redis.call('HGET', key, 'ts')) or now
local elapsed = now - prev_ts
local decayed = prev_score
if elapsed > 0 and prev_score > 0 then
  decayed = prev_score * math.pow(0.5, elapsed / half_life)
end
local new_score = decayed + amount
if new_score < 0 then new_score = 0 end
if new_score > max_score then new_score = max_score end
redis.call('HSET', key, 'score', new_score, 'ts', now)
redis.call('EXPIRE', key, ttl)
return tostring(new_score)
"""


def _clamp(score: float) -> float:
    if score < 0.0:
        return 0.0
    if score > _MAX_SCORE:
        return _MAX_SCORE
    return score


def _apply_bump(
    prev_score: float,
    prev_ts: float,
    now: float,
    amount: float,
    half_life: float,
    max_score: float,
) -> float:
    """Pure reference for the decay-then-add-then-clamp bump.

    This is the single source of truth for the risk arithmetic: the Redis Lua
    script (:data:`_LUA_BUMP`) and the in-memory fallback both compute exactly
    this, so all three paths stay observably identical.
    """
    decayed = prev_score
    elapsed = now - prev_ts
    if elapsed > 0 and prev_score > 0:
        decayed = prev_score * math.pow(0.5, elapsed / half_life)
    new_score = decayed + amount
    if new_score < 0.0:
        return 0.0
    if new_score > max_score:
        return max_score
    return new_score


@dataclass
class _LocalEntry:
    """In-memory fallback record: last score + when it was written."""

    score: float
    updated_at: float


class RiskStateStore:
    """Decaying risk score keyed by origin scope.

    Scopes (``scope_type``):

    * ``subject`` — ``scope_id = f"{tenant_id}:{subject_id}"`` where ``subject_id``
      is the authenticated actor (JWT ``sub`` or an API-key digest). This is the
      most-specific origin: hardening a subject bounds the blast radius so one
      abusive actor does not BLOCK every other user sharing the agent (F3).
    * ``tenant``  — ``scope_id = tenant_id``
    * ``session`` — ``scope_id = f"{tenant_id}:{agent_id}"``
    * ``input``   — ``scope_id = input_hash`` (sha256[:16] of the request content)

    ``scope_id`` values are hashed before they become Redis keys, so a raw
    ``subject_id`` (which may be PII) never reaches the datastore.
    """

    def __init__(self, decay_seconds: float = 900.0):
        # Half-life of the exponential decay, in seconds.
        self._decay_seconds = max(1.0, float(decay_seconds))
        self._redis: Optional[Any] = None
        # Registered ``_LUA_BUMP`` handle (redis-py ``Script``). Lazily (re)bound
        # so tests that assign ``store._redis`` directly still take the Lua path.
        self._bump_script: Optional[Any] = None
        self._local: dict[str, _LocalEntry] = {}
        self._initialized = False
        # Circuit breaker state (F2). ``_cb_opened_at == 0.0`` ⇒ closed.
        self._cb_failures = 0
        self._cb_opened_at = 0.0

    # --- lifecycle ---------------------------------------------------------

    def initialize(
        self,
        redis_url: Optional[str] = None,
        redis_tls_insecure: bool = False,
        decay_seconds: Optional[float] = None,
    ) -> None:
        """Connect to Redis (once, at startup). No-op-safe without a URL."""
        if decay_seconds is not None:
            self._decay_seconds = max(1.0, float(decay_seconds))
        if redis_url:
            try:
                self._redis = connect_redis(
                    redis_url, redis_tls_insecure=redis_tls_insecure
                )
                # Pre-register the atomic bump script (EVALSHA on the hot path).
                self._bump_script = self._redis.register_script(_LUA_BUMP)
            except Exception as e:  # noqa: BLE001 - degrade to in-memory
                logger.warning("risk_state_redis_unavailable", error=str(e))
                self._redis = None
                self._bump_script = None
        self._initialized = True

    @property
    def redis(self):
        """The shared Redis client (or ``None`` in in-memory fallback mode).

        Exposed so sibling correlation components (metrics, event tap) can reuse
        the single already-initialised connection instead of opening their own.
        """
        return self._redis

    # --- key derivation ----------------------------------------------------

    @staticmethod
    def scope_digest(scope_type: str, scope_id: str) -> str:
        """Irreversible 16-hex digest identifying an origin (scope_type, scope_id).

        Single source of truth for the origin-identity digest. The admin
        ``/correlation/origins`` view, the ``bulwark:risk:*`` key, and the durable
        event store's ``scope_digests`` pivot column all key off this exact value,
        so an analyst can pivot a decayed risk score straight back to the events
        that produced it. Hashing means a raw ``subject_id`` (potential PII) never
        reaches the datastore.
        """
        return hashlib.sha256(f"{scope_type}:{scope_id}".encode()).hexdigest()[:16]

    @staticmethod
    def _redis_key(scope_type: str, scope_id: str) -> str:
        # Hash the scope id so keys are fixed-length and never carry raw content
        # (input_hash is already a digest, but tenant/agent may be arbitrary).
        digest = RiskStateStore.scope_digest(scope_type, scope_id)
        return f"{_KEY_PREFIX}:{scope_type}:{digest}"

    def _decay(self, score: float, elapsed: float) -> float:
        """Apply exponential decay: score * 0.5 ** (elapsed / half_life)."""
        if elapsed <= 0 or score <= 0:
            return _clamp(score)
        factor = math.pow(0.5, elapsed / self._decay_seconds)
        return _clamp(score * factor)

    # --- circuit breaker (F2) ----------------------------------------------

    def _cb_should_skip(self) -> bool:
        """True when the breaker is open — skip Redis, go straight to fallback.

        Open for :data:`_CB_COOLDOWN_SECONDS` after the failure threshold is hit;
        once the cooldown elapses this returns False so the next call becomes a
        *half-open probe* that re-tests Redis (success closes it, failure re-opens).
        """
        if self._cb_opened_at == 0.0:
            return False
        if time.time() - self._cb_opened_at >= _CB_COOLDOWN_SECONDS:
            return False  # half-open: allow one probe through
        return True

    def _cb_success(self) -> None:
        if self._cb_failures or self._cb_opened_at:
            logger.info("risk_state_circuit_closed")
        self._cb_failures = 0
        self._cb_opened_at = 0.0

    def _cb_failure(self) -> None:
        self._cb_failures += 1
        if self._cb_failures >= _CB_FAIL_THRESHOLD and self._cb_opened_at == 0.0:
            self._cb_opened_at = time.time()
            logger.warning(
                "risk_state_circuit_opened",
                consecutive_failures=self._cb_failures,
                cooldown_seconds=_CB_COOLDOWN_SECONDS,
            )
        elif self._cb_opened_at != 0.0:
            # A failed half-open probe — restart the cooldown window.
            self._cb_opened_at = time.time()

    @property
    def circuit_open(self) -> bool:
        """Best-effort breaker state for observability/tests."""
        return self._cb_opened_at != 0.0 and self._cb_should_skip()

    # --- public API --------------------------------------------------------

    def bump(self, scope_type: str, scope_id: str, amount: float) -> float:
        """Add ``amount`` to the (decayed) risk score for an origin.

        Returns the new (clamped) score. Never raises — a backend error yields a
        best-effort in-memory update or 0.0.
        """
        if not scope_id or amount == 0:
            return self.get(scope_type, scope_id)
        now = time.time()
        if self._redis is not None and not self._cb_should_skip():
            try:
                out = self._bump_redis(scope_type, scope_id, amount, now)
                self._cb_success()
                return out
            except Exception as e:  # noqa: BLE001 - degrade, never break hot path
                logger.warning("risk_state_bump_redis_error", error=str(e))
                self._cb_failure()
        return self._bump_local(scope_type, scope_id, amount, now)

    def get(self, scope_type: str, scope_id: str) -> float:
        """Return the current time-decayed risk score for an origin (>= 0.0)."""
        if not scope_id:
            return 0.0
        now = time.time()
        if self._redis is not None and not self._cb_should_skip():
            try:
                out = self._get_redis(scope_type, scope_id, now)
                self._cb_success()
                return out
            except Exception as e:  # noqa: BLE001
                logger.warning("risk_state_get_redis_error", error=str(e))
                self._cb_failure()
        return self._get_local(scope_type, scope_id, now)

    def get_many(self, scopes: list[tuple[str, str]]) -> list[float]:
        """Decayed scores for several origins in a single round-trip (F2).

        Collapses the per-request enforcement reads (session + tenant) from N
        round-trips to one pipeline. Order-preserving; empty/absent origins read
        as ``0.0``. Never raises — degrades to the in-memory map (and trips the
        breaker) on any Redis error.
        """
        if not scopes:
            return []
        now = time.time()
        if self._redis is not None and not self._cb_should_skip():
            try:
                out = self._get_many_redis(scopes, now)
                self._cb_success()
                return out
            except Exception as e:  # noqa: BLE001
                logger.warning("risk_state_get_many_redis_error", error=str(e))
                self._cb_failure()
        return [self._get_local(st, sid, now) for st, sid in scopes]

    # --- redis backend -----------------------------------------------------

    def _bump_redis(self, scope_type: str, scope_id: str, amount: float, now: float) -> float:
        key = self._redis_key(scope_type, scope_id)
        # TTL a few half-lives out: once fully decayed the key is worthless.
        ttl = int(self._decay_seconds * 8) + 60
        script = self._bump_script
        if script is None:
            # Lazily (re)register — covers direct ``store._redis = fake`` in tests
            # and a reconnect that missed ``initialize``.
            script = self._redis.register_script(_LUA_BUMP)  # type: ignore[union-attr]
            self._bump_script = script
        # Atomic server-side decay+bump: one round-trip, no lost updates under
        # concurrent bumps of the same origin (F1).
        raw = script(
            keys=[key],
            args=[now, amount, self._decay_seconds, _MAX_SCORE, ttl],
        )
        return float(raw)

    def _get_redis(self, scope_type: str, scope_id: str, now: float) -> float:
        key = self._redis_key(scope_type, scope_id)
        cur = self._redis.hgetall(key) or {}  # type: ignore[union-attr]
        if not cur:
            return 0.0
        prev_score = float(cur.get("score", 0.0) or 0.0)
        prev_ts = float(cur.get("ts", now) or now)
        return self._decay(prev_score, now - prev_ts)

    def _get_many_redis(self, scopes: list[tuple[str, str]], now: float) -> list[float]:
        pipe = self._redis.pipeline()  # type: ignore[union-attr]
        for scope_type, scope_id in scopes:
            pipe.hgetall(self._redis_key(scope_type, scope_id))
        rows = pipe.execute()
        out: list[float] = []
        for cur in rows:
            cur = cur or {}
            if not cur:
                out.append(0.0)
                continue
            prev_score = float(cur.get("score", 0.0) or 0.0)
            prev_ts = float(cur.get("ts", now) or now)
            out.append(self._decay(prev_score, now - prev_ts))
        return out

    # --- in-memory fallback ------------------------------------------------

    def _local_key(self, scope_type: str, scope_id: str) -> str:
        return f"{scope_type}:{scope_id}"

    def _bump_local(self, scope_type: str, scope_id: str, amount: float, now: float) -> float:
        # Bounded map with cheap FIFO-ish eviction.
        if len(self._local) >= _MAX_LOCAL_ENTRIES:
            self._local.pop(next(iter(self._local)), None)
        k = self._local_key(scope_type, scope_id)
        entry = self._local.get(k)
        if entry is None:
            new_score = _clamp(amount)
        else:
            new_score = _apply_bump(
                prev_score=entry.score,
                prev_ts=entry.updated_at,
                now=now,
                amount=amount,
                half_life=self._decay_seconds,
                max_score=_MAX_SCORE,
            )
        self._local[k] = _LocalEntry(score=new_score, updated_at=now)
        return new_score

    def _get_local(self, scope_type: str, scope_id: str, now: float) -> float:
        entry = self._local.get(self._local_key(scope_type, scope_id))
        if entry is None:
            return 0.0
        return self._decay(entry.score, now - entry.updated_at)


# Module-level singleton -----------------------------------------------------

_store: Optional[RiskStateStore] = None


def get_risk_state_store() -> RiskStateStore:
    """Return the process-wide risk state store singleton."""
    global _store
    if _store is None:
        _store = RiskStateStore()
    return _store
