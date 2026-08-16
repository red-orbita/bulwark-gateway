"""Virtual Keys management routes — centralized backend API key vault.

Virtual keys decouple tenants from raw backend API keys: the actual provider
key is encrypted at rest (Fernet) and referenced by an opaque ``vk_*`` id.
Rotation and revocation happen centrally without tenant reconfiguration.

Write operations require the ``vkeys:write`` permission (admin only) because
they handle plaintext backend secrets. Read/list is available to admin,
security and auditor roles — no secret material is ever returned.
"""

from __future__ import annotations

import json
import re

from fastapi import APIRouter, Body, Depends, HTTPException

from ..models.auth import TokenPayload
from ..services import virtual_keys_store as store
from ..services.audit_logger import get_audit_logger
from ..services.auth_service import require_permission

router = APIRouter()

_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_PROVIDER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_KEY_ID_RE = re.compile(r"^vk_[0-9a-f]{16,64}$")


def _require_available() -> None:
    available, reason = store.is_available()
    if not available:
        raise HTTPException(
            status_code=503,
            detail=(
                "Virtual key subsystem unavailable: "
                f"{reason or 'BULWARK_KEY_ENCRYPTION_KEY not configured'}"
            ),
        )


@router.get("/status")
async def virtual_keys_status(
    _user: TokenPayload = Depends(require_permission("vkeys:read")),
):
    """Report subsystem availability and persistence status."""
    available, reason = store.is_available()
    return {
        "available": available,
        "reason": reason,
        "redis_connected": store.redis_connected() if available else False,
        "known_providers": [
            "openai",
            "anthropic",
            "azure",
            "google",
            "mistral",
            "cohere",
            "ollama",
            "custom",
        ],
    }


@router.get("/{tenant_id}")
async def list_tenant_keys(
    tenant_id: str,
    _user: TokenPayload = Depends(require_permission("vkeys:read")),
):
    """List virtual keys for a tenant (metadata only, never the secret)."""
    if not _ID_RE.match(tenant_id):
        raise HTTPException(status_code=400, detail="Invalid tenant_id")
    _require_available()
    try:
        keys = store.list_keys(tenant_id)
    except store.VirtualKeysUnavailable as e:
        raise HTTPException(status_code=503, detail=str(e)) from None
    return {"tenant_id": tenant_id, "keys": keys, "count": len(keys)}


@router.post("/")
async def create_virtual_key(
    data: dict = Body(...),
    user: TokenPayload = Depends(require_permission("vkeys:write")),
):
    """Create a new virtual key for a tenant/provider."""
    _require_available()
    tenant_id = (data.get("tenant_id") or "").strip()
    provider = (data.get("provider") or "").strip().lower()
    backend_api_key = data.get("backend_api_key") or ""
    description = (data.get("description") or "").strip()[:200]
    expires_in_days = data.get("expires_in_days")

    if not _ID_RE.match(tenant_id):
        raise HTTPException(status_code=400, detail="Invalid or missing 'tenant_id'")
    if not _PROVIDER_RE.match(provider):
        raise HTTPException(status_code=400, detail="Invalid or missing 'provider'")
    if not backend_api_key or len(backend_api_key) < 8:
        raise HTTPException(
            status_code=400, detail="'backend_api_key' required (min 8 chars)"
        )
    if len(backend_api_key) > 8192:
        raise HTTPException(status_code=400, detail="'backend_api_key' too long")
    if expires_in_days is not None:
        try:
            expires_in_days = int(expires_in_days)
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=400, detail="'expires_in_days' must be an integer"
            ) from None
        if expires_in_days < 1 or expires_in_days > 3650:
            raise HTTPException(
                status_code=400,
                detail="'expires_in_days' must be between 1 and 3650",
            )

    try:
        vkey = store.create_key(
            tenant_id=tenant_id,
            provider=provider,
            backend_api_key=backend_api_key,
            description=description,
            expires_in_days=expires_in_days,
        )
    except store.VirtualKeysUnavailable as e:
        raise HTTPException(status_code=503, detail=str(e)) from None

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="vkeys.create",
        resource_type="virtual_key",
        resource_id=vkey["key_id"],
        details=json.dumps({"tenant_id": tenant_id, "provider": provider}),
    )
    return {"message": "Virtual key created", "key": vkey}


@router.post("/{tenant_id}/rotate")
async def rotate_virtual_key(
    tenant_id: str,
    data: dict = Body(...),
    user: TokenPayload = Depends(require_permission("vkeys:write")),
):
    """Rotate the active backend key for a tenant/provider."""
    if not _ID_RE.match(tenant_id):
        raise HTTPException(status_code=400, detail="Invalid tenant_id")
    _require_available()
    provider = (data.get("provider") or "").strip().lower()
    new_backend_key = data.get("new_backend_key") or ""
    if not _PROVIDER_RE.match(provider):
        raise HTTPException(status_code=400, detail="Invalid or missing 'provider'")
    if not new_backend_key or len(new_backend_key) < 8:
        raise HTTPException(
            status_code=400, detail="'new_backend_key' required (min 8 chars)"
        )
    if len(new_backend_key) > 8192:
        raise HTTPException(status_code=400, detail="'new_backend_key' too long")

    try:
        vkey = store.rotate_key(tenant_id, provider, new_backend_key)
    except store.VirtualKeysUnavailable as e:
        raise HTTPException(status_code=503, detail=str(e)) from None
    if vkey is None:
        raise HTTPException(status_code=500, detail="Rotation failed")

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="vkeys.rotate",
        resource_type="virtual_key",
        resource_id=vkey["key_id"],
        details=json.dumps({"tenant_id": tenant_id, "provider": provider}),
    )
    return {"message": "Virtual key rotated", "key": vkey}


@router.delete("/{tenant_id}/{key_id}")
async def revoke_virtual_key(
    tenant_id: str,
    key_id: str,
    user: TokenPayload = Depends(require_permission("vkeys:write")),
):
    """Revoke a specific virtual key."""
    if not _ID_RE.match(tenant_id):
        raise HTTPException(status_code=400, detail="Invalid tenant_id")
    if not _KEY_ID_RE.match(key_id):
        raise HTTPException(status_code=400, detail="Invalid key_id")
    _require_available()

    try:
        revoked = store.revoke_key(tenant_id, key_id)
    except store.VirtualKeysUnavailable as e:
        raise HTTPException(status_code=503, detail=str(e)) from None
    if not revoked:
        raise HTTPException(status_code=404, detail="Key not found")

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="vkeys.revoke",
        resource_type="virtual_key",
        resource_id=key_id,
        details=json.dumps({"tenant_id": tenant_id}),
    )
    return {"message": f"Virtual key '{key_id}' revoked"}


@router.get("/audit/trail")
async def virtual_keys_audit(
    limit: int = 100,
    _user: TokenPayload = Depends(require_permission("vkeys:read")),
):
    """Return recent virtual key operations (newest first)."""
    limit = max(1, min(int(limit), 1000))
    return {"entries": store.audit_trail(limit), "limit": limit}
