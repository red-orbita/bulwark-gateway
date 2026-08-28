"""Redis sync for guardrail state — publishes pattern changes to proxy.

Writes to Redis so the proxy's DynamicPatternRegistry picks up changes.
Keys:
  bulwark:guardrails:disabled  — SET of disabled pattern IDs
  bulwark:guardrails:custom    — HASH { id: JSON(regex, severity, category, description, layer) }
  bulwark:guardrails:version   — INT (incremented on every change)
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any, Optional, cast

import redis

logger = logging.getLogger(__name__)

# Redis keys (must match src/guardrails/dynamic_registry.py)
KEY_DISABLED = "bulwark:guardrails:disabled"
KEY_CUSTOM = "bulwark:guardrails:custom"
KEY_EXCEPTIONS = "bulwark:guardrails:exceptions"
KEY_VERSION = "bulwark:guardrails:version"

# Per-tenant recent-blocks lists. The proxy writes one capped list per tenant
# (bulwark:recent_blocks:<tenant_id>, SGW-XT-002) so block metadata never leaks
# across tenant boundaries. Readers MUST aggregate across these keys — there is
# no single shared list.
RECENT_BLOCKS_PREFIX = "bulwark:recent_blocks:"

# Per-tenant recent-ALLOWED lists (opt-in, BULWARK_LOG_ALLOWED). Kept under a
# separate prefix so high-volume legitimate traffic never evicts block/warn
# events from their list. Same per-entry schema as recent_blocks.
RECENT_ALLOWED_PREFIX = "bulwark:recent_allowed:"


def _iter_keys_by_prefix(r: "redis.Redis", prefix: str) -> list[str]:
    """SCAN (never KEYS) for all per-tenant list keys under ``prefix``."""
    keys: list[str] = []
    try:
        for k in r.scan_iter(match=f"{prefix}*", count=200):
            keys.append(k)
    except Exception as exc:
        logger.warning("recent_keys_scan_failed: %s", exc)
    return keys


def _fetch_recent_by_prefix(
    r: "redis.Redis", prefix: str, max_items: int, tenant: Optional[str]
) -> list[dict]:
    """Merge per-tenant lists under ``prefix`` into one newest-first list."""
    events: list[dict] = []
    try:
        if tenant:
            keys = [f"{prefix}{tenant}"]
        else:
            keys = _iter_keys_by_prefix(r, prefix)
        if not keys:
            return []
        pipe = r.pipeline(transaction=False)
        for k in keys:
            pipe.lrange(k, 0, max_items - 1)
        for raw in pipe.execute():
            for item in raw or []:
                try:
                    events.append(json.loads(item))
                except (json.JSONDecodeError, TypeError):
                    continue
    except Exception:
        return events
    events.sort(key=lambda e: e.get("ts", 0), reverse=True)
    return events[:max_items]


def iter_recent_block_keys(r: "redis.Redis") -> list[str]:
    """Return all per-tenant recent-block list keys.

    Uses SCAN (not KEYS) to avoid blocking Redis on large keyspaces.
    """
    return _iter_keys_by_prefix(r, RECENT_BLOCKS_PREFIX)


def fetch_recent_blocks(
    r: "redis.Redis", max_items: int = 200, tenant: Optional[str] = None
) -> list[dict]:
    """Merge per-tenant recent-block lists into one newest-first list.

    Each stored entry is a JSON object with a numeric ``ts`` field; the merged
    result is sorted by ``ts`` descending and truncated to ``max_items``. When
    ``tenant`` is provided, only that tenant's list is read (fast path).
    """
    return _fetch_recent_by_prefix(r, RECENT_BLOCKS_PREFIX, max_items, tenant)


def iter_recent_allowed_keys(r: "redis.Redis") -> list[str]:
    """Return all per-tenant recent-ALLOWED list keys (SCAN-based)."""
    return _iter_keys_by_prefix(r, RECENT_ALLOWED_PREFIX)


def fetch_recent_allowed(
    r: "redis.Redis", max_items: int = 200, tenant: Optional[str] = None
) -> list[dict]:
    """Merge per-tenant recent-ALLOWED lists into one newest-first list.

    Mirrors :func:`fetch_recent_blocks` but reads the opt-in allowed-event feed
    (``bulwark:recent_allowed:<tenant>``). Empty unless ``BULWARK_LOG_ALLOWED`` is
    enabled on the proxy.
    """
    return _fetch_recent_by_prefix(r, RECENT_ALLOWED_PREFIX, max_items, tenant)

# ─── Connection Pool Singleton ────────────────────────────────────────
# Avoids creating a new TCP connection + PING on every call.
# Thread-safe via lock.

_pool_lock = threading.Lock()
_redis_pool: Optional[redis.ConnectionPool] = None
_redis_url_resolved: str = ""
_pool_created_at: float = 0.0
_POOL_TTL = 300.0  # Recreate pool every 5min (handles DNS changes)


def _get_pool() -> Optional[redis.ConnectionPool]:
    """Get or create the Redis connection pool singleton."""
    global _redis_pool, _redis_url_resolved, _pool_created_at

    url = os.getenv("BULWARK_REDIS_URL", "")
    if not url:
        return None

    now = time.monotonic()

    # Fast path: pool exists and is fresh
    if _redis_pool and (now - _pool_created_at) < _POOL_TTL:
        return _redis_pool

    with _pool_lock:
        # Double-check after lock
        if _redis_pool and (now - _pool_created_at) < _POOL_TTL:
            return _redis_pool

        # Load password from secret file and pass it as a connection kwarg —
        # NEVER interpolate it into the URL string. A raw password containing
        # URL-special characters (e.g. '/', '@', ':' — common in base64 secrets)
        # corrupts netloc parsing ("Port could not be cast to integer") and, in
        # the '@' case, could redirect the connection to an attacker-controlled
        # host (VULN 1.7). redis-py applies the password kwarg safely.
        pw_file = os.getenv("BULWARK_REDIS_PASSWORD_FILE", "")
        password = None
        if pw_file and os.path.isfile(pw_file) and "@" not in url:
            with open(pw_file) as f:
                password = f.read().strip() or None

        try:
            kwargs: dict = {
                "decode_responses": True,
                "socket_timeout": 1.0,
                "socket_connect_timeout": 2.0,
                "max_connections": 4,
                "retry_on_timeout": True,
            }
            if password:
                kwargs["password"] = password
            if url.startswith("rediss://"):
                tls_insecure = os.getenv("BULWARK_REDIS_TLS_INSECURE", "false").lower() in ("1", "true", "yes")
                if tls_insecure:
                    import ssl
                    kwargs["ssl_cert_reqs"] = ssl.CERT_NONE

            _redis_pool = redis.ConnectionPool.from_url(url, **kwargs)
            _redis_url_resolved = url
            _pool_created_at = time.monotonic()
            logger.info("Redis connection pool created (max_connections=4)")
            return _redis_pool
        except Exception as e:
            logger.warning("Failed to create Redis pool: %s", e)
            return None


def _build_redis_kwargs(url: str, timeout: float = 2.0, password: Optional[str] = None) -> dict:
    """Build kwargs for redis.from_url() with TLS support."""
    kwargs: dict = {"decode_responses": True, "socket_timeout": timeout}
    if password:
        kwargs["password"] = password
    if url.startswith("rediss://"):
        tls_insecure = os.getenv("BULWARK_REDIS_TLS_INSECURE", "false").lower() in ("1", "true", "yes")
        if tls_insecure:
            import ssl
            kwargs["ssl_cert_reqs"] = ssl.CERT_NONE
    return kwargs


def get_redis_client(timeout: float = 2.0) -> Optional[redis.Redis]:
    """Get a Redis client using the connection pool.

    Uses a shared connection pool (max 4 connections) to avoid
    creating a new TCP connection on every call. The pool handles
    reconnection transparently via retry_on_timeout.

    NOTE: Does NOT ping on every call — callers should handle
    ConnectionError/TimeoutError on first use.
    """
    pool = _get_pool()
    if pool is None:
        return None
    return redis.Redis(connection_pool=pool, socket_timeout=timeout)


def _get_redis() -> Optional[redis.Redis]:
    """Get Redis connection for the admin service (legacy wrapper)."""
    return get_redis_client(timeout=2.0)


def sync_disabled_patterns(patterns: list[dict]) -> None:
    """Sync the full set of disabled pattern IDs to Redis."""
    r = _get_redis()
    if not r:
        return
    disabled = {p["id"] for p in patterns if not p.get("enabled", True)}
    pipe = r.pipeline()
    pipe.delete(KEY_DISABLED)
    if disabled:
        pipe.sadd(KEY_DISABLED, *disabled)
    pipe.incr(KEY_VERSION)
    pipe.execute()


def sync_custom_patterns(patterns: list[dict]) -> None:
    """Sync all custom patterns to Redis."""
    r = _get_redis()
    if not r:
        return
    custom = {
        p["id"]: json.dumps({
            "regex": p.get("regex", ""),
            "severity": p.get("severity", "high"),
            "category": p.get("category", "custom"),
            "description": p.get("description", ""),
            "layer": p.get("layer", "input"),
        })
        for p in patterns
        if "custom" in p.get("id", "")
    }
    pipe = r.pipeline()
    pipe.delete(KEY_CUSTOM)
    if custom:
        pipe.hset(KEY_CUSTOM, mapping=custom)
    pipe.incr(KEY_VERSION)
    pipe.execute()


def sync_exceptions(exceptions: dict[str, list[str]]) -> None:
    """Sync per-tenant/agent allow-exceptions to Redis.

    ``exceptions`` maps ``pattern_id`` → list of scope strings
    (``"tenant:agent"``, ``"tenant:*"`` or ``"*:*"``). The proxy's
    DynamicPatternRegistry reads this HASH to degrade a would-be BLOCK to WARN
    for the matching tenant/agent while keeping the event auditable.
    """
    r = _get_redis()
    if not r:
        return
    mapping = {
        pid: json.dumps(sorted(set(scopes)))
        for pid, scopes in exceptions.items()
        if scopes
    }
    pipe = r.pipeline()
    pipe.delete(KEY_EXCEPTIONS)
    if mapping:
        # redis-py's hset mapping key type is an invariant Union; a plain
        # dict[str, str] is valid at runtime but not assignable under the stub.
        pipe.hset(KEY_EXCEPTIONS, mapping=cast("dict[Any, Any]", mapping))
    pipe.incr(KEY_VERSION)
    pipe.execute()


def sync_all(patterns: list[dict]) -> None:
    """Full sync: disabled set + custom patterns + bump version."""
    r = _get_redis()
    if not r:
        return
    disabled = {p["id"] for p in patterns if not p.get("enabled", True)}
    custom = {
        p["id"]: json.dumps({
            "regex": p.get("regex", ""),
            "severity": p.get("severity", "high"),
            "category": p.get("category", "custom"),
            "description": p.get("description", ""),
            "layer": p.get("layer", "input"),
        })
        for p in patterns
        if "custom" in p.get("id", "")
    }

    pipe = r.pipeline()
    pipe.delete(KEY_DISABLED)
    if disabled:
        pipe.sadd(KEY_DISABLED, *disabled)
    pipe.delete(KEY_CUSTOM)
    if custom:
        pipe.hset(KEY_CUSTOM, mapping=custom)
    pipe.incr(KEY_VERSION)
    pipe.execute()
