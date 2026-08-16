"""Per-tenant resource quota management routes.

Quotas prevent "noisy neighbour" problems in multi-tenancy. They are enforced
by the proxy's ``QuotaMiddleware`` (src/middleware/quotas.py) and persisted in
``agents.yaml`` under ``tenants.<id>.quotas``. The proxy reloads changes via
file mtime, so edits made here take effect without a restart.

Effective, enforced fields exposed here:
  * max_concurrent_requests  — per-tenant asyncio.Semaphore (0 = unlimited)
  * max_tokens_per_day       — daily token budget tracked in Redis (0 = unlimited)
  * max_request_size_bytes   — max request payload size (0 = unlimited)
  * allowed_models           — model allow-list (null/empty = all allowed)
  * priority_weight          — fair-queue weight hint (default 1.0)

``rate_limit_rpm`` is intentionally NOT managed here — effective RPM limits live
on the dedicated Rate Limits page (Redis-backed) to avoid two sources of truth.

Write operations require ``quotas:write`` (admin + security). Reads are visible
to all authenticated roles.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException

from ..models.auth import TokenPayload
from ..models.tenants import TenantQuotaInfo, TenantQuotaUpdate
from ..services.audit_logger import get_audit_logger
from ..services.auth_service import require_permission
from ..services.tenant_manager import get_tenant_manager

router = APIRouter()

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,62}[a-z0-9]$")


def _tokens_used_today(tenant_id: str) -> int:
    """Read the live daily token counter from Redis (0 if unavailable)."""
    try:
        from ..services.redis_sync import get_redis_client

        r = get_redis_client()
        if not r:
            return 0
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        val = r.get(f"bulwark:quota:tokens:{tenant_id}:{today}")
        return int(val) if val else 0
    except Exception:
        return 0


def _redis_connected() -> bool:
    try:
        from ..services.redis_sync import get_redis_client

        r = get_redis_client()
        if not r:
            return False
        r.ping()
        return True
    except Exception:
        return False


def _with_usage(info: TenantQuotaInfo) -> TenantQuotaInfo:
    """Populate the live token usage counter on a quota info object."""
    info.tokens_used_today = _tokens_used_today(info.tenant_id)
    return info


@router.get("/status")
async def quotas_status(
    _user: TokenPayload = Depends(require_permission("quotas:read")),
):
    """Report quota subsystem status and per-tenant coverage."""
    import os

    mgr = get_tenant_manager()
    tenants = mgr.list_tenants()
    configured = 0
    for t in tenants:
        q = mgr.get_tenant_quotas(t.id)
        if q is not None and q.configured:
            configured += 1
    return {
        "enabled": os.environ.get("BULWARK_QUOTAS_ENABLED", "true").lower()
        in ("true", "1", "yes"),
        "redis_connected": _redis_connected(),
        "total_tenants": len(tenants),
        "tenants_with_quotas": configured,
        "enforced_fields": [
            "max_concurrent_requests",
            "max_tokens_per_day",
            "max_request_size_bytes",
            "allowed_models",
            "priority_weight",
        ],
    }


@router.get("/", response_model=list[TenantQuotaInfo])
async def list_quotas(
    _user: TokenPayload = Depends(require_permission("quotas:read")),
):
    """List quota configuration for every tenant (with live token usage)."""
    mgr = get_tenant_manager()
    out: list[TenantQuotaInfo] = []
    for t in mgr.list_tenants():
        info = mgr.get_tenant_quotas(t.id)
        if info is not None:
            out.append(_with_usage(info))
    return out


@router.get("/{tenant_id}", response_model=TenantQuotaInfo)
async def get_quotas(
    tenant_id: str,
    _user: TokenPayload = Depends(require_permission("quotas:read")),
):
    """Get a single tenant's quota configuration."""
    if not _ID_RE.match(tenant_id):
        raise HTTPException(status_code=400, detail="Invalid tenant_id")
    info = get_tenant_manager().get_tenant_quotas(tenant_id)
    if info is None:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")
    return _with_usage(info)


@router.put("/{tenant_id}", response_model=TenantQuotaInfo)
async def update_quotas(
    tenant_id: str,
    req: TenantQuotaUpdate,
    user: TokenPayload = Depends(require_permission("quotas:write")),
):
    """Create or merge a tenant's quota block. Omitted fields are unchanged."""
    if not _ID_RE.match(tenant_id):
        raise HTTPException(status_code=400, detail="Invalid tenant_id")
    if req.allowed_models is not None:
        if len(req.allowed_models) > 100:
            raise HTTPException(status_code=400, detail="Too many allowed_models (max 100)")
        for m in req.allowed_models:
            if not isinstance(m, str) or len(m) > 128:
                raise HTTPException(status_code=400, detail="Invalid model name")

    info = get_tenant_manager().update_tenant_quotas(tenant_id, req)
    if info is None:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="quotas.update",
        resource_type="tenant_quota",
        resource_id=tenant_id,
        details=json.dumps(req.model_dump(exclude_none=True)),
    )
    return _with_usage(info)


@router.delete("/{tenant_id}")
async def clear_quotas(
    tenant_id: str,
    user: TokenPayload = Depends(require_permission("quotas:write")),
):
    """Remove a tenant's quota block entirely (reverts to unlimited)."""
    if not _ID_RE.match(tenant_id):
        raise HTTPException(status_code=400, detail="Invalid tenant_id")
    mgr = get_tenant_manager()
    if mgr.get_tenant_quotas(tenant_id) is None:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")
    removed = mgr.clear_tenant_quotas(tenant_id)
    if not removed:
        raise HTTPException(
            status_code=404, detail=f"Tenant '{tenant_id}' has no quota overrides"
        )

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="quotas.clear",
        resource_type="tenant_quota",
        resource_id=tenant_id,
        details="reverted to unlimited",
    )
    return {"message": f"Quota overrides cleared for '{tenant_id}'"}
