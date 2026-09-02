"""Per-key rate limiting for service-account automation calls (Phase 3.2c).

A leaked or misbehaving SOAR/playbook key must not be able to hammer the admin
automation surface unbounded. Every authenticated service-account request that
passes ``require_permission_automation`` also consumes one token from a per-key,
sliding-window budget; exceeding it yields ``429 Too Many Requests`` (and an audit
record) instead of executing the action.

Design mirrors the proxy's tenant limiter (``src/middleware/rate_limit.py``):

* **Redis first** — a sliding-window sorted set (``bulwark:automation:ratelimit:{key}``,
  60s window) shared across admin replicas via a single MULTI/EXEC pipeline of
  core commands (no server-side Lua, which hardened Redis often disables).
* **In-memory fallback** — when Redis is unavailable OR a Redis op errors, the
  check degrades to a per-process sliding window (the admin service runs a single
  replica, so this stays accurate). This is deliberately fail-*to-local-enforcement*,
  not fail-open-to-allow: a Redis blip must not silently unthrottle the surface,
  yet an infra error must not hard-deny legitimate automation either.

Limit resolution (done by the caller): a per-account ``rate_limit_rpm`` override,
else the ``BULWARK_AUTOMATION_RATE_LIMIT_RPM`` environment default. A resolved
limit ``<= 0`` means *unbounded* — ``consume`` short-circuits to allow — so both a
per-key ``0`` opt-out and a globally-disabled default behave identically.

The Redis client is the shared sync pool from ``redis_sync.get_redis_client``;
calling a sync client from this async-adjacent path follows the accepted proxy
precedent (the ops are sub-millisecond, non-blocking pipeline round-trips).
"""

from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from typing import Optional

from .redis_sync import get_redis_client

logger = logging.getLogger(__name__)

# Sliding-window span. Requests-per-minute ⇒ a 60-second window.
_WINDOW_SECONDS = 60.0
_REDIS_KEY_PREFIX = "bulwark:automation:ratelimit:"

# Default per-key RPM when an account carries no explicit override. Generous
# enough for a busy playbook fan-out, low enough to blunt a runaway/leaked key.
_DEFAULT_RPM = 120


def default_rate_limit_rpm() -> int:
    """Environment default per-key RPM (``BULWARK_AUTOMATION_RATE_LIMIT_RPM``).

    Falls back to ``_DEFAULT_RPM`` when unset or unparseable. A value ``<= 0``
    disables automation rate limiting for keys without an explicit override.
    """
    try:
        return int(os.getenv("BULWARK_AUTOMATION_RATE_LIMIT_RPM", str(_DEFAULT_RPM)))
    except ValueError:
        return _DEFAULT_RPM


class _InMemoryWindow:
    """Per-process sliding-window counter (Redis-unavailable fallback).

    Timestamps per key are held in a TTL cache so an idle key is evicted whole,
    keeping memory bounded without a sweeper. Guarded by a lock so concurrent
    requests can't double-spend the window.
    """

    def __init__(self, window_seconds: float, max_keys: int = 4096):
        self._window = window_seconds
        self._lock = threading.Lock()
        from cachetools import TTLCache

        # ttl > window so a key survives long enough to enforce its own window,
        # then self-evicts once idle.
        self._hits: TTLCache = TTLCache(maxsize=max_keys, ttl=int(window_seconds * 2) + 1)

    def consume(self, key: str, limit: int) -> bool:
        with self._lock:
            now = time.time()
            cutoff = now - self._window
            hits = [t for t in self._hits.get(key, ()) if t > cutoff]
            if len(hits) >= limit:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            return True


class AutomationRateLimiter:
    """Sliding-window per-key limiter with Redis + in-memory fallback."""

    def __init__(self) -> None:
        self._fallback = _InMemoryWindow(_WINDOW_SECONDS)

    def consume(self, key: str, limit: int) -> bool:
        """Record one hit for ``key``; return ``True`` if within ``limit`` RPM.

        A ``limit <= 0`` is treated as unbounded (always allowed). Redis is tried
        first; any Redis-side failure falls through to the in-memory window rather
        than hard-denying, so infra trouble never blocks legitimate automation.
        """
        if limit <= 0:
            return True
        client = get_redis_client(timeout=1.0)
        if client is not None:
            allowed = self._redis_consume(client, key, limit)
            if allowed is not None:
                return allowed
        return self._fallback.consume(key, limit)

    def _redis_consume(self, client, key: str, limit: int) -> Optional[bool]:
        """Redis sliding-window check. Returns allow/deny, or ``None`` to fall back.

        ``None`` signals a Redis error so the caller degrades to in-memory
        enforcement (never a silent allow).
        """
        redis_key = _REDIS_KEY_PREFIX + key
        now = time.time()
        window_start = now - _WINDOW_SECONDS
        try:
            member = f"{now}:{uuid.uuid4().hex[:8]}"
            pipe = client.pipeline(transaction=True)
            pipe.zremrangebyscore(redis_key, 0, window_start)
            pipe.zadd(redis_key, {member: now})
            pipe.zcard(redis_key)
            pipe.expire(redis_key, int(_WINDOW_SECONDS * 2))
            results = pipe.execute()
            count = results[2]  # ZCARD (post-add window size)
            if count > limit:
                # Over budget: roll back our own entry so it doesn't inflate the
                # window for subsequent callers, then reject.
                client.zrem(redis_key, member)
                return False
            return True
        except Exception:  # noqa: BLE001 - degrade to in-memory enforcement, never crash auth
            logger.debug("automation rate-limit Redis op failed; using fallback", exc_info=True)
            return None


_limiter: Optional[AutomationRateLimiter] = None
_limiter_lock = threading.Lock()


def get_automation_rate_limiter() -> AutomationRateLimiter:
    """Return the process-wide limiter singleton (thread-safe lazy init)."""
    global _limiter
    if _limiter is None:
        with _limiter_lock:
            if _limiter is None:
                _limiter = AutomationRateLimiter()
    return _limiter
