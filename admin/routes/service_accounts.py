"""Service-account management routes — mint/list/toggle/revoke automation keys.

Service accounts are the scoped, non-interactive credentials a SOAR/playbook
presents to call the admin automation surface (Phase 3.2a). These *management*
endpoints are the human-operator control plane for them and are gated by the
``automation:manage`` permission — which is deliberately NOT in the
service-account grantable whitelist, so a playbook key can never manage (mint,
toggle, revoke) service accounts, including itself. They use the plain
session-only ``require_permission`` dependency (never the automation resolver),
so only an authenticated operator with a session/JWT can reach them.

The raw key is returned exactly once, in the response to the mint call; it is
never persisted in plaintext and cannot be recovered afterwards. Every other
response exposes metadata only (never the key hash).
"""

from __future__ import annotations

import json
import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..models.auth import AUTOMATION_GRANTABLE_PERMISSIONS, TokenPayload
from ..services import service_account_store as store_mod
from ..services.audit_logger import get_audit_logger
from ..services.auth_service import require_permission
from ..services.service_account_store import ServiceAccountStore

router = APIRouter()

_ACCOUNT_ID_RE = re.compile(r"^sa_[0-9a-f]{16}$")


class ServiceAccountCreate(BaseModel):
    name: str
    permissions: list[str]
    expires_at: Optional[str] = None


class ServiceAccountToggle(BaseModel):
    enabled: bool


@router.get("/grantable-permissions")
async def list_grantable_permissions(
    _user: TokenPayload = Depends(require_permission("automation:manage")),
):
    """Return the whitelist of permissions a service account may be granted."""
    return {"permissions": sorted(AUTOMATION_GRANTABLE_PERMISSIONS)}


@router.get("/")
async def list_service_accounts(
    _user: TokenPayload = Depends(require_permission("automation:manage")),
):
    """List all service accounts (metadata only — never the key)."""
    accounts = await ServiceAccountStore().list_accounts()
    return {"accounts": accounts, "count": len(accounts)}


@router.post("/")
async def create_service_account(
    data: ServiceAccountCreate,
    user: TokenPayload = Depends(require_permission("automation:manage")),
):
    """Mint a new service account. The raw key is returned ONCE in this response."""
    try:
        account = await ServiceAccountStore().mint(
            name=data.name,
            permissions=data.permissions,
            created_by=user.sub,
            expires_at=data.expires_at,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="service_account.create",
        resource_type="service_account",
        resource_id=account["account_id"],
        details=json.dumps({
            "name": account["name"],
            "permissions": account["permissions"],
            "expires_at": account.get("expires_at"),
        }),
    )
    # ``account`` carries the one-time ``key`` field; surface it to the operator.
    return {"message": "Service account created", "account": account}


@router.post("/{account_id}/toggle")
async def toggle_service_account(
    account_id: str,
    data: ServiceAccountToggle,
    user: TokenPayload = Depends(require_permission("automation:manage")),
):
    """Enable or disable a service account (revoke-on-disable)."""
    if not _ACCOUNT_ID_RE.match(account_id):
        raise HTTPException(status_code=400, detail="Invalid account_id")
    updated = await ServiceAccountStore().set_enabled(account_id, data.enabled)
    if not updated:
        raise HTTPException(status_code=404, detail="Service account not found")

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="service_account.toggle",
        resource_type="service_account",
        resource_id=account_id,
        details=json.dumps({"enabled": data.enabled}),
    )
    state = "enabled" if data.enabled else "disabled"
    return {"message": f"Service account {state}"}


@router.delete("/{account_id}")
async def delete_service_account(
    account_id: str,
    user: TokenPayload = Depends(require_permission("automation:manage")),
):
    """Permanently delete a service account."""
    if not _ACCOUNT_ID_RE.match(account_id):
        raise HTTPException(status_code=400, detail="Invalid account_id")
    deleted = await ServiceAccountStore().delete(account_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Service account not found")

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="service_account.delete",
        resource_type="service_account",
        resource_id=account_id,
        details="{}",
    )
    return {"message": f"Service account '{account_id}' deleted"}


# Re-export for tests that monkeypatch ``get_database`` on the store module.
__all__ = ["router", "store_mod"]
