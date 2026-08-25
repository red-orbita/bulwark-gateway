"""Correlation engine routes — observability + runtime tuning.

The proxy's inline correlation engine keeps a decaying, per-origin *risk score* in
Redis (``bulwark:risk:{scope}:{digest}``). Risk accrues two ways:

  * a confirmed input↔output exfiltration (the :class:`InputOutputCorrelator`), and
  * ongoing WARN/BLOCK security events folded in by the correlation event tap.

When an origin's score crosses the configured threshold, the *next* request from
that origin is hardened (WARN, or BLOCK when blocking is on). This admin surface
exposes:

  * the effective enforcement config (defaults merged with any runtime override)
  * the read-only tunable catalog + bounds
  * active origins with their current (decayed) risk score and TTL
  * a **real** runtime override written to ``bulwark:correlation:config`` — the
    proxy re-reads it within ~5s without a restart
  * per-scope and global risk reset controls (incident response / tuning)

Redis keys read/managed here:
  bulwark:risk:{scope_type}:{16-hex}   — per-origin risk HASH {score, ts}
  bulwark:correlation:config           — runtime override HASH

Risk keys are irreversible SHA-256 digests (never a raw subject/tenant/agent/IP),
so they are shown as-is and cannot be mapped back to an identity. The ``subject``
scope keys the specific authenticated actor (the origin BLOCK decisions are taken
on) so hardening bounds the blast radius to that actor, not the shared session.

Reads require ``correlation:read`` (all roles); mutations require
``correlation:write`` (admin + security).
"""

from __future__ import annotations

import contextlib
import math
import re
import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..models.auth import TokenPayload
from ..services.audit_logger import get_audit_logger
from ..services.auth_service import require_permission

router = APIRouter()

_CONFIG_KEY = "bulwark:correlation:config"
_RISK_PREFIX = "bulwark:risk:"

# Risk scope digests are sha256()[:16] hex.
_DIGEST_RE = re.compile(r"^[0-9a-f]{16}$")
_VALID_SCOPES = ("subject", "tenant", "session", "input")

# Boolean tunable handled specially; numeric bounds mirror src.correlation.runtime.
_BOOL_FIELDS = ("blocking",)


class CorrelationConfigUpdate(BaseModel):
    """Runtime override for correlation enforcement. All fields optional.

    Only provided fields are written. Bounds mirror the proxy's runtime config so
    an override can never disable enforcement with a nonsensical value.
    """

    blocking: bool | None = None
    window_seconds: float | None = Field(default=None, ge=1, le=3600)
    risk_block_threshold: float | None = Field(default=None, gt=0, le=10)
    risk_warn_threshold: float | None = Field(default=None, gt=0, le=10)
    risk_decay_seconds: float | None = Field(default=None, ge=10, le=604800)
    event_bump_warn: float | None = Field(default=None, ge=0, le=10)
    event_bump_block: float | None = Field(default=None, ge=0, le=10)
    severity_high_mult: float | None = Field(default=None, gt=0, le=10)
    severity_critical_mult: float | None = Field(default=None, gt=0, le=10)


def _redis():
    try:
        from ..services.redis_sync import get_redis_client

        return get_redis_client()
    except Exception:
        return None


def _can_write(user: TokenPayload) -> bool:
    """True if the caller's role includes correlation:write."""
    try:
        from ..models.auth import ROLE_PERMISSIONS

        return "correlation:write" in ROLE_PERMISSIONS.get(user.role, set())
    except Exception:
        return False


def _decode(k) -> str:
    return k.decode() if isinstance(k, bytes) else k


def _defaults() -> dict:
    """Static default enforcement config (settings + built-in weights)."""
    try:
        from src.correlation.runtime import default_config

        return default_config()
    except Exception:
        # Documented fallbacks if the proxy package is unavailable.
        return {
            "blocking": False,
            "window_seconds": 30.0,
            "risk_block_threshold": 7.0,
            "risk_warn_threshold": 4.0,
            "risk_decay_seconds": 900.0,
            "event_bump_warn": 0.5,
            "event_bump_block": 1.0,
            "severity_high_mult": 1.5,
            "severity_critical_mult": 2.0,
        }


def _numeric_bounds() -> dict:
    try:
        from src.correlation.runtime import numeric_field_bounds

        return numeric_field_bounds()
    except Exception:
        return {}


def _read_override(r) -> dict:
    """Read the runtime override HASH. Missing = no override (defaults apply)."""
    try:
        raw = r.hgetall(_CONFIG_KEY) or {}
    except Exception:
        raw = {}
    bounds = _numeric_bounds()
    override: dict[str, float | bool] = {}
    for field_name, val in raw.items():
        name = _decode(field_name)
        sval = _decode(val)
        if name in _BOOL_FIELDS:
            override[name] = str(sval).strip().lower() in ("1", "true", "yes", "on")
        elif name in bounds:
            lo, hi = bounds[name]
            try:
                num = float(sval)
            except (TypeError, ValueError):
                continue
            if lo <= num <= hi:
                override[name] = num
    return override


def _decay(score: float, elapsed: float, half_life: float) -> float:
    if elapsed <= 0 or score <= 0 or half_life <= 0:
        return max(0.0, score)
    return max(0.0, score * math.pow(0.5, elapsed / half_life))


def _scan(r, match: str) -> list[str]:
    keys: list[str] = []
    with contextlib.suppress(Exception):
        for k in r.scan_iter(match=match, count=200):
            keys.append(_decode(k))
    return keys


def _summarize_origin(r, redis_key: str, half_life: float, now: float) -> dict | None:
    """Compute the current (decayed) risk for one origin key."""
    # Key shape: bulwark:risk:{scope_type}:{digest}
    suffix = redis_key[len(_RISK_PREFIX):]
    parts = suffix.split(":", 1)
    if len(parts) != 2:
        return None
    scope_type, digest = parts
    if scope_type not in _VALID_SCOPES or not _DIGEST_RE.match(digest):
        return None
    try:
        cur = r.hgetall(redis_key) or {}
    except Exception:
        return None
    if not cur:
        return None
    try:
        raw_score = float(_decode(cur.get("score", 0.0)) or 0.0)
        raw_ts = float(_decode(cur.get("ts", now)) or now)
    except (TypeError, ValueError):
        return None
    decayed = _decay(raw_score, now - raw_ts, half_life)

    ttl = None
    with contextlib.suppress(Exception):
        raw_ttl = r.ttl(redis_key)
        if isinstance(raw_ttl, int) and raw_ttl >= 0:
            ttl = raw_ttl

    return {
        "scope_type": scope_type,
        "digest": digest,
        "score": round(decayed, 2),
        "stored_score": round(raw_score, 2),
        "updated_ts": raw_ts,
        "ttl_seconds": ttl,
    }


def _all_risk_keys(r) -> list[str]:
    return _scan(r, f"{_RISK_PREFIX}*")


@router.get("/status")
async def correlation_status(
    user: TokenPayload = Depends(require_permission("correlation:read")),
):
    """Effective enforcement config, override state, and active-origin count."""
    defaults = _defaults()

    r = _redis()
    connected = False
    override: dict = {}
    active = 0
    if r:
        try:
            r.ping()
            connected = True
            override = _read_override(r)
            active = len(_all_risk_keys(r))
        except Exception:
            connected = False

    effective = {**defaults, **override}
    return {
        "redis_connected": connected,
        "can_write": _can_write(user),
        "effective": effective,
        "defaults": defaults,
        "override": override,
        "overridden": bool(override),
        "active_origins": active,
        "note": None
        if connected
        else "Redis not reachable — active origins and runtime override require Redis.",
    }


@router.get("/config/fields")
async def correlation_config_fields(
    user: TokenPayload = Depends(require_permission("correlation:read")),
):
    """Read-only catalog of tunable fields and their numeric bounds."""
    bounds = _numeric_bounds()
    return {
        "boolean_fields": list(_BOOL_FIELDS),
        "numeric_fields": {name: {"min": lo, "max": hi} for name, (lo, hi) in bounds.items()},
    }


@router.get("/origins")
async def correlation_origins(
    user: TokenPayload = Depends(require_permission("correlation:read")),
    limit: int = 200,
):
    """List active origins with their current decayed risk score (highest first)."""
    limit = max(1, min(limit, 1000))
    r = _redis()
    if not r:
        return {"redis_connected": False, "origins": [], "count": 0}
    try:
        r.ping()
    except Exception:
        return {"redis_connected": False, "origins": [], "count": 0}

    effective = {**_defaults(), **_read_override(r)}
    half_life = float(effective.get("risk_decay_seconds", 900.0))
    now = time.time()

    origins: list[dict] = []
    for redis_key in _all_risk_keys(r):
        summary = _summarize_origin(r, redis_key, half_life, now)
        if summary:
            origins.append(summary)
        if len(origins) >= limit:
            break

    origins.sort(key=lambda o: o["score"], reverse=True)
    return {"redis_connected": True, "origins": origins, "count": len(origins)}


@router.put("/config")
async def update_correlation_config(
    body: CorrelationConfigUpdate,
    user: TokenPayload = Depends(require_permission("correlation:write")),
):
    """Set a runtime override for correlation enforcement.

    Written to ``bulwark:correlation:config``; the proxy re-reads within ~5s.
    Passing no fields is rejected to avoid silent no-ops.
    """
    provided = body.model_dump(exclude_none=True)
    if not provided:
        raise HTTPException(
            status_code=400,
            detail="Provide at least one field to override.",
        )
    r = _redis()
    if not r:
        raise HTTPException(status_code=503, detail="Redis not reachable — cannot set runtime override")

    mapping = {}
    for k, v in provided.items():
        if isinstance(v, bool):
            mapping[k] = "1" if v else "0"
        else:
            mapping[k] = str(v)
    try:
        r.hset(_CONFIG_KEY, mapping=mapping)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Redis write error: {e}") from None

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="correlation.config_update",
        resource_type="correlation",
        resource_id="config",
        details=str(mapping),
    )
    return {"message": "Correlation override updated", "override": _read_override(r)}


@router.delete("/config")
async def clear_correlation_config(
    user: TokenPayload = Depends(require_permission("correlation:write")),
):
    """Remove the runtime override so the proxy reverts to built-in defaults."""
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
        action="correlation.config_clear",
        resource_type="correlation",
        resource_id="config",
        details="reverted to built-in defaults",
    )
    return {"message": "Runtime override cleared — proxy reverts to built-in defaults"}


@router.delete("/origin/{scope_type}/{digest}")
async def delete_origin(
    scope_type: str,
    digest: str,
    user: TokenPayload = Depends(require_permission("correlation:write")),
):
    """Clear the accumulated risk for one origin (identified by scope + digest)."""
    if scope_type not in _VALID_SCOPES:
        raise HTTPException(status_code=400, detail=f"Invalid scope (expected one of {_VALID_SCOPES})")
    if not _DIGEST_RE.match(digest):
        raise HTTPException(status_code=400, detail="Invalid digest (expected 16 hex chars)")
    r = _redis()
    if not r:
        raise HTTPException(status_code=503, detail="Redis not reachable")

    key = f"{_RISK_PREFIX}{scope_type}:{digest}"
    try:
        deleted = r.delete(key)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Redis delete error: {e}") from None

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="correlation.origin_delete",
        resource_type="correlation",
        resource_id=f"{scope_type}:{digest}",
        details=f"cleared {deleted} risk key(s)",
    )
    return {"message": "Origin risk cleared", "keys_deleted": deleted}


@router.post("/reset")
async def reset_all_origins(
    user: TokenPayload = Depends(require_permission("correlation:write")),
):
    """Clear ALL accumulated origin risk. Keeps the runtime config override."""
    r = _redis()
    if not r:
        raise HTTPException(status_code=503, detail="Redis not reachable")

    keys = _all_risk_keys(r)
    deleted = 0
    if keys:
        try:
            deleted = r.delete(*keys)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Redis delete error: {e}") from None

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="correlation.reset",
        resource_type="correlation",
        resource_id="*",
        details=f"cleared {deleted} risk key(s)",
    )
    return {"message": "All origin risk cleared", "keys_deleted": deleted}
