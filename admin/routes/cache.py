"""Response cache management routes — observability + runtime kill-switch.

The proxy's ``ResponseCache`` stores cached LLM responses in Redis under
``bulwark:cache:{hash}`` with aggregate counters in ``bulwark:cache:stats``.
This admin surface exposes:

  * live stats (hits / misses / hit-rate / tokens saved / entry count)
  * a **real** runtime override (enable/disable + TTL) written to
    ``bulwark:cache:config`` — the proxy honors it within ~5s without a restart
  * a flush control that drops cached entries (keeping stats/config)
  * a stats-reset control

Reads require ``cache:read`` (all roles); mutations require ``cache:write``
(admin + security). The kill-switch is deliberately a security-role capability:
disabling the cache guarantees fresh policy/IOC evaluation on every request.
"""

from __future__ import annotations

import contextlib

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..models.auth import TokenPayload
from ..services.audit_logger import get_audit_logger
from ..services.auth_service import require_permission

router = APIRouter()

_CONFIG_KEY = "bulwark:cache:config"
_STATS_KEY = "bulwark:cache:stats"
_ENTRY_PREFIX = "bulwark:cache:"
# Keys under the bulwark:cache: namespace that are NOT cached entries.
_RESERVED_SUFFIXES = ("stats", "config")


class CacheConfigUpdate(BaseModel):
    """Runtime override for the proxy response cache."""

    enabled: bool | None = None
    ttl: int | None = Field(default=None, ge=1, le=86400)


def _redis():
    try:
        from ..services.redis_sync import get_redis_client

        return get_redis_client()
    except Exception:
        return None


def _can_write(user: TokenPayload) -> bool:
    """True if the caller's role includes cache:write."""
    try:
        from ..models.auth import ROLE_PERMISSIONS

        return "cache:write" in ROLE_PERMISSIONS.get(user.role, set())
    except Exception:
        return False


def _int(v, default: int = 0) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def _is_entry_key(key: str) -> bool:
    """True if the key is a cached response entry (not stats/config)."""
    if not key.startswith(_ENTRY_PREFIX):
        return False
    suffix = key[len(_ENTRY_PREFIX):]
    return suffix not in _RESERVED_SUFFIXES


def _scan(r, match: str) -> list[str]:
    keys: list[str] = []
    with contextlib.suppress(Exception):
        for k in r.scan_iter(match=match, count=200):
            keys.append(k.decode() if isinstance(k, bytes) else k)
    return keys


def _read_config(r) -> dict:
    """Read the runtime override HASH. Missing = env-config default."""
    try:
        raw = r.hgetall(_CONFIG_KEY) or {}
    except Exception:
        return {"enabled": None, "ttl": None, "overridden": False}
    if not raw:
        return {"enabled": None, "ttl": None, "overridden": False}
    enabled = raw.get("enabled")
    if enabled is not None:
        enabled = str(enabled).strip().lower() in ("1", "true", "yes", "on")
    ttl = _int(raw.get("ttl"), 0) or None
    return {"enabled": enabled, "ttl": ttl, "overridden": True}


@router.get("/status")
async def cache_status(
    user: TokenPayload = Depends(require_permission("cache:read")),
):
    """Cache stats, runtime override state, and entry count."""
    import os

    env_enabled = os.environ.get("BULWARK_CACHE_ENABLED", "false").lower() in ("true", "1")
    env_ttl = _int(os.environ.get("BULWARK_CACHE_TTL", "300"), 300)

    r = _redis()
    connected = False
    stats = {"hits": 0, "misses": 0, "evictions": 0, "savings_tokens": 0}
    override = {"enabled": None, "ttl": None, "overridden": False}
    entries = 0
    if r:
        try:
            r.ping()
            connected = True
            raw = r.hgetall(_STATS_KEY) or {}
            stats = {
                "hits": _int(raw.get("hits")),
                "misses": _int(raw.get("misses")),
                "evictions": _int(raw.get("evictions")),
                "savings_tokens": _int(raw.get("savings_tokens")),
            }
            override = _read_config(r)
            entries = sum(1 for k in _scan(r, "bulwark:cache:*") if _is_entry_key(k))
        except Exception:
            connected = False

    total_lookups = stats["hits"] + stats["misses"]
    hit_rate = round(stats["hits"] / total_lookups, 4) if total_lookups else 0.0

    # Effective state = override wins over env when present.
    effective_enabled = override["enabled"] if override["enabled"] is not None else env_enabled
    effective_ttl = override["ttl"] if override["ttl"] is not None else env_ttl

    return {
        "redis_connected": connected,
        "can_write": _can_write(user),
        "effective": {"enabled": effective_enabled, "ttl_seconds": effective_ttl},
        "env": {"enabled": env_enabled, "ttl_seconds": env_ttl},
        "override": override,
        "stats": {**stats, "hit_rate": hit_rate, "total_lookups": total_lookups},
        "entries": entries,
        "note": None
        if connected
        else "Redis not reachable — runtime override and stats require Redis.",
    }


@router.put("/config")
async def update_cache_config(
    body: CacheConfigUpdate,
    user: TokenPayload = Depends(require_permission("cache:write")),
):
    """Set a runtime override for the proxy cache (enable/disable + TTL).

    Written to ``bulwark:cache:config``; the proxy re-reads within ~5s. Passing
    no fields is rejected to avoid silent no-ops.
    """
    if body.enabled is None and body.ttl is None:
        raise HTTPException(status_code=400, detail="Provide at least one of: enabled, ttl")
    r = _redis()
    if not r:
        raise HTTPException(status_code=503, detail="Redis not reachable — cannot set runtime override")

    mapping: dict[str, str] = {}
    if body.enabled is not None:
        mapping["enabled"] = "true" if body.enabled else "false"
    if body.ttl is not None:
        mapping["ttl"] = str(body.ttl)
    try:
        r.hset(_CONFIG_KEY, mapping=mapping)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Redis write error: {e}") from None

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="cache.config_update",
        resource_type="cache",
        resource_id="config",
        details=str(mapping),
    )
    return {"message": "Cache runtime override updated", "override": _read_config(r)}


@router.delete("/config")
async def clear_cache_config(
    user: TokenPayload = Depends(require_permission("cache:write")),
):
    """Remove the runtime override so the proxy reverts to env configuration."""
    r = _redis()
    if not r:
        raise HTTPException(status_code=503, detail="Redis not reachable")
    try:
        r.delete(_CONFIG_KEY)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Redis delete error: {e}") from None

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="cache.config_clear",
        resource_type="cache",
        resource_id="config",
        details="reverted to env config",
    )
    return {"message": "Runtime override cleared — proxy reverts to env config"}


@router.post("/flush")
async def flush_cache(
    user: TokenPayload = Depends(require_permission("cache:write")),
):
    """Drop all cached response entries (keeps stats + config)."""
    r = _redis()
    if not r:
        raise HTTPException(status_code=503, detail="Redis not reachable")
    entry_keys = [k for k in _scan(r, "bulwark:cache:*") if _is_entry_key(k)]
    deleted = 0
    if entry_keys:
        try:
            deleted = r.delete(*entry_keys)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Redis delete error: {e}") from None

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="cache.flush",
        resource_type="cache",
        resource_id="*",
        details=f"deleted {deleted} entries",
    )
    return {"message": "Cache flushed", "entries_deleted": deleted}


@router.post("/stats/reset")
async def reset_cache_stats(
    user: TokenPayload = Depends(require_permission("cache:write")),
):
    """Reset hit/miss/eviction/savings counters."""
    r = _redis()
    if not r:
        raise HTTPException(status_code=503, detail="Redis not reachable")
    try:
        r.delete(_STATS_KEY)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Redis delete error: {e}") from None

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="cache.stats_reset",
        resource_type="cache",
        resource_id="stats",
        details="counters cleared",
    )
    return {"message": "Cache stats reset"}
