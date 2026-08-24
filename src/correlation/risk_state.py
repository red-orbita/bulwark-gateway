"""Decaying per-origin risk state (Redis-backed, in-memory fallback).

An *origin* is a stable, server-derived identity that a request can be attributed
to: the tenant, the (tenant, agent) session, or the content fingerprint
(``input_hash``). When a correlation confirms suspicious behaviour, we ``bump``
the origin's risk score. Subsequent requests read the (time-decayed) score via
``get`` and can be hardened — e.g. escalating a borderline WARN to a BLOCK.

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
from typing import Optional

import structlog

logger = structlog.get_logger()

# Redis key namespace for origin risk state.
_KEY_PREFIX = "bulwark:risk"

# Score is clamped to a 0..10 scale to stay commensurate with the rest of the
# platform (SkillSpector, session_tracker use 0..10-ish weights).
_MAX_SCORE = 10.0

# Bounded in-memory fallback capacity (LRU-ish eviction).
_MAX_LOCAL_ENTRIES = 50_000


def _clamp(score: float) -> float:
    if score < 0.0:
        return 0.0
    if score > _MAX_SCORE:
        return _MAX_SCORE
    return score


@dataclass
class _LocalEntry:
    """In-memory fallback record: last score + when it was written."""

    score: float
    updated_at: float


class RiskStateStore:
    """Decaying risk score keyed by origin scope.

    Scopes (``scope_type``):

    * ``tenant``  — ``scope_id = tenant_id``
    * ``session`` — ``scope_id = f"{tenant_id}:{agent_id}"``
    * ``input``   — ``scope_id = input_hash`` (sha256[:16] of the request content)
    """

    def __init__(self, decay_seconds: float = 900.0):
        # Half-life of the exponential decay, in seconds.
        self._decay_seconds = max(1.0, float(decay_seconds))
        self._redis = None
        self._local: dict[str, _LocalEntry] = {}
        self._initialized = False

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
                import redis

                kwargs: dict = {"decode_responses": True, "socket_timeout": 1}
                if redis_url.startswith("rediss://") and redis_tls_insecure:
                    import ssl

                    kwargs["ssl_cert_reqs"] = ssl.CERT_NONE
                self._redis = redis.from_url(redis_url, **kwargs)
                self._redis.ping()
            except Exception as e:  # noqa: BLE001 - degrade to in-memory
                logger.warning("risk_state_redis_unavailable", error=str(e))
                self._redis = None
        self._initialized = True

    # --- key derivation ----------------------------------------------------

    @staticmethod
    def _redis_key(scope_type: str, scope_id: str) -> str:
        # Hash the scope id so keys are fixed-length and never carry raw content
        # (input_hash is already a digest, but tenant/agent may be arbitrary).
        digest = hashlib.sha256(f"{scope_type}:{scope_id}".encode()).hexdigest()[:16]
        return f"{_KEY_PREFIX}:{scope_type}:{digest}"

    def _decay(self, score: float, elapsed: float) -> float:
        """Apply exponential decay: score * 0.5 ** (elapsed / half_life)."""
        if elapsed <= 0 or score <= 0:
            return _clamp(score)
        factor = math.pow(0.5, elapsed / self._decay_seconds)
        return _clamp(score * factor)

    # --- public API --------------------------------------------------------

    def bump(self, scope_type: str, scope_id: str, amount: float) -> float:
        """Add ``amount`` to the (decayed) risk score for an origin.

        Returns the new (clamped) score. Never raises — a backend error yields a
        best-effort in-memory update or 0.0.
        """
        if not scope_id or amount == 0:
            return self.get(scope_type, scope_id)
        now = time.time()
        if self._redis is not None:
            try:
                return self._bump_redis(scope_type, scope_id, amount, now)
            except Exception as e:  # noqa: BLE001 - degrade, never break hot path
                logger.warning("risk_state_bump_redis_error", error=str(e))
        return self._bump_local(scope_type, scope_id, amount, now)

    def get(self, scope_type: str, scope_id: str) -> float:
        """Return the current time-decayed risk score for an origin (>= 0.0)."""
        if not scope_id:
            return 0.0
        now = time.time()
        if self._redis is not None:
            try:
                return self._get_redis(scope_type, scope_id, now)
            except Exception as e:  # noqa: BLE001
                logger.warning("risk_state_get_redis_error", error=str(e))
        return self._get_local(scope_type, scope_id, now)

    # --- redis backend -----------------------------------------------------

    def _bump_redis(self, scope_type: str, scope_id: str, amount: float, now: float) -> float:
        key = self._redis_key(scope_type, scope_id)
        cur = self._redis.hgetall(key) or {}
        prev_score = float(cur.get("score", 0.0) or 0.0)
        prev_ts = float(cur.get("ts", now) or now)
        decayed = self._decay(prev_score, now - prev_ts)
        new_score = _clamp(decayed + amount)
        # TTL a few half-lives out: once fully decayed the key is worthless.
        ttl = int(self._decay_seconds * 8) + 60
        pipe = self._redis.pipeline()
        pipe.hset(key, mapping={"score": new_score, "ts": now})
        pipe.expire(key, ttl)
        pipe.execute()
        return new_score

    def _get_redis(self, scope_type: str, scope_id: str, now: float) -> float:
        key = self._redis_key(scope_type, scope_id)
        cur = self._redis.hgetall(key) or {}
        if not cur:
            return 0.0
        prev_score = float(cur.get("score", 0.0) or 0.0)
        prev_ts = float(cur.get("ts", now) or now)
        return self._decay(prev_score, now - prev_ts)

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
            decayed = self._decay(entry.score, now - entry.updated_at)
            new_score = _clamp(decayed + amount)
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
