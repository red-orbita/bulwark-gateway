"""Redis sync for guardrail state — publishes pattern changes to proxy.

Writes to Redis so the proxy's DynamicPatternRegistry picks up changes.
Keys:
  sentinel:guardrails:disabled  — SET of disabled pattern IDs
  sentinel:guardrails:custom    — HASH { id: JSON(regex, severity, category, description, layer) }
  sentinel:guardrails:version   — INT (incremented on every change)
"""

from __future__ import annotations

import json
import os
from typing import Optional

import redis

# Redis keys (must match src/guardrails/dynamic_registry.py)
KEY_DISABLED = "sentinel:guardrails:disabled"
KEY_CUSTOM = "sentinel:guardrails:custom"
KEY_VERSION = "sentinel:guardrails:version"


def _build_redis_kwargs(url: str, timeout: float = 2.0, password: Optional[str] = None) -> dict:
    """Build kwargs for redis.from_url() with TLS support."""
    kwargs: dict = {"decode_responses": True, "socket_timeout": timeout}
    if password:
        kwargs["password"] = password
    if url.startswith("rediss://"):
        tls_insecure = os.getenv("SENTINEL_REDIS_TLS_INSECURE", "false").lower() in ("1", "true", "yes")
        if tls_insecure:
            import ssl
            kwargs["ssl_cert_reqs"] = ssl.CERT_NONE
    return kwargs


def get_redis_client(timeout: float = 2.0) -> Optional[redis.Redis]:
    """Get a Redis client from environment configuration.

    Supports both redis:// (plain) and rediss:// (TLS) schemes.
    Used by admin routes that need Redis access.
    """
    url = os.getenv("SENTINEL_REDIS_URL", "")
    if not url:
        return None
    # Inject password from secret file if available
    pw_file = os.getenv("SENTINEL_REDIS_PASSWORD_FILE", "")
    password = None
    if pw_file and os.path.isfile(pw_file):
        with open(pw_file) as f:
            password = f.read().strip()
        if password and "@" not in url:
            url = url.replace("://", f"://:{password}@")
            password = None  # Already in URL
    try:
        kwargs = _build_redis_kwargs(url, timeout=timeout, password=password)
        r = redis.from_url(url, **kwargs)
        r.ping()
        return r
    except Exception:
        return None


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
