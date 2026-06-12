"""Rate Limiting management routes — Per-tenant RPM overrides."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Body, Depends, HTTPException

from ..models.auth import TokenPayload
from ..services.auth_service import require_permission
from ..services.audit_logger import get_audit_logger

router = APIRouter()

# Persistent config (writable /app/data in K8s)
_CONFIG_FILE = Path("data/rate_limits_config.json")

# In-memory state: tenant_id → RPM
_tenant_limits: dict[str, int] = {}
_global_settings: dict = {"enabled": True, "default_rpm": 60}


def _load_config() -> None:
    """Load rate limit config from disk."""
    global _tenant_limits, _global_settings
    if _CONFIG_FILE.exists():
        try:
            data = json.loads(_CONFIG_FILE.read_text())
            _tenant_limits = data.get("tenants", {})
            _global_settings.update(data.get("global", {}))
        except Exception:
            pass


def _save_config() -> None:
    """Persist rate limit config to disk."""
    try:
        _CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        _CONFIG_FILE.write_text(json.dumps({
            "global": _global_settings,
            "tenants": _tenant_limits,
        }, indent=2))
    except Exception:
        pass


def _sync_to_redis() -> None:
    """Push rate limit config to Redis so proxy picks up changes."""
    try:
        from ..services.redis_sync import get_redis_client
        r = get_redis_client()
        if not r:
            return
        r.set("sentinel:rate_limits:config", json.dumps(_tenant_limits))
        r.incr("sentinel:rate_limits:version")
    except Exception:
        pass


# Load on import
_load_config()


@router.get("/status")
async def rate_limit_status(
    _user: TokenPayload = Depends(require_permission("guardrails:read")),
):
    """Get rate limiting status — global settings + per-tenant overrides."""
    import os
    return {
        "global": {
            "enabled": os.environ.get("SENTINEL_RATE_LIMIT_ENABLED", "true").lower() in ("true", "1"),
            "default_rpm": int(os.environ.get("SENTINEL_RATE_LIMIT_RPM", "60")),
            "burst": int(os.environ.get("SENTINEL_RATE_LIMIT_RPM_BURST", "10")),
        },
        "tenants": _tenant_limits,
        "total_overrides": len(_tenant_limits),
    }


@router.post("/tenant")
async def set_tenant_limit(
    data: dict = Body(...),
    user: TokenPayload = Depends(require_permission("guardrails:write")),
):
    """Set or update rate limit for a specific tenant."""
    tenant_id = data.get("tenant_id")
    rpm = data.get("rpm")

    if not tenant_id:
        raise HTTPException(status_code=400, detail="'tenant_id' required")
    if rpm is None:
        raise HTTPException(status_code=400, detail="'rpm' required")

    rpm = int(rpm)
    if rpm < 1 or rpm > 10000:
        raise HTTPException(status_code=400, detail="rpm must be between 1 and 10000")

    _tenant_limits[tenant_id] = rpm
    _save_config()
    _sync_to_redis()

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="rate_limit.set_tenant",
        resource_type="rate_limit",
        resource_id=tenant_id,
        details=json.dumps({"rpm": rpm}),
    )

    return {"message": f"Rate limit for '{tenant_id}' set to {rpm} RPM", "tenant_id": tenant_id, "rpm": rpm}


@router.delete("/tenant/{tenant_id}")
async def remove_tenant_limit(
    tenant_id: str,
    user: TokenPayload = Depends(require_permission("guardrails:write")),
):
    """Remove per-tenant rate limit override (reverts to global default)."""
    if tenant_id not in _tenant_limits:
        raise HTTPException(status_code=404, detail=f"No override for tenant '{tenant_id}'")

    del _tenant_limits[tenant_id]
    _save_config()
    _sync_to_redis()

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="rate_limit.remove_tenant",
        resource_type="rate_limit",
        resource_id=tenant_id,
        details="reverted to global default",
    )

    return {"message": f"Rate limit override removed for '{tenant_id}'"}


@router.post("/bulk")
async def set_bulk_limits(
    data: dict = Body(...),
    user: TokenPayload = Depends(require_permission("guardrails:write")),
):
    """Set rate limits for multiple tenants at once."""
    tenants = data.get("tenants", {})
    if not tenants or not isinstance(tenants, dict):
        raise HTTPException(status_code=400, detail="'tenants' dict required: {tenant_id: rpm}")

    updated = []
    for tenant_id, rpm in tenants.items():
        rpm = int(rpm)
        if rpm < 1 or rpm > 10000:
            raise HTTPException(status_code=400, detail=f"rpm for '{tenant_id}' must be between 1 and 10000")
        _tenant_limits[tenant_id] = rpm
        updated.append(tenant_id)

    _save_config()
    _sync_to_redis()

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="rate_limit.bulk_set",
        resource_type="rate_limit",
        resource_id="bulk",
        details=json.dumps({"tenants": tenants}),
    )

    return {"message": f"Updated {len(updated)} tenant limits", "updated": updated}


@router.post("/reset")
async def reset_limits(
    user: TokenPayload = Depends(require_permission("guardrails:write")),
):
    """Remove all per-tenant overrides."""
    global _tenant_limits
    count = len(_tenant_limits)
    _tenant_limits = {}
    _save_config()
    _sync_to_redis()

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="rate_limit.reset_all",
        resource_type="rate_limit",
        resource_id="*",
        details=f"removed {count} overrides",
    )

    return {"message": f"Cleared {count} tenant overrides"}
