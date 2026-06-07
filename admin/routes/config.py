"""Configuration Management routes — Runtime config access and updates."""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException

from ..models.auth import TokenPayload, UserRole
from ..services.auth_service import require_role
from ..services.config_manager import get_config_manager, SECTIONS, RESTART_REQUIRED_FIELDS
from ..services.audit_logger import get_audit_logger
from ..models.metrics import AuditQuery

router = APIRouter()


@router.get("")
async def get_all_config(user: TokenPayload = Depends(require_role(UserRole.ADMIN))):
    """Dump all current config with sensitive values masked."""
    mgr = get_config_manager()
    return mgr.get_config()


@router.get("/sections")
async def list_sections(user: TokenPayload = Depends(require_role(UserRole.ADMIN))):
    """List available config sections."""
    return {"sections": list(SECTIONS.keys())}


@router.get("/restart-required")
async def restart_required(user: TokenPayload = Depends(require_role(UserRole.ADMIN))):
    """List fields that need restart to take effect."""
    mgr = get_config_manager()
    return {"fields": mgr.get_restart_required_fields()}


@router.get("/audit")
async def config_audit(
    limit: int = 50,
    user: TokenPayload = Depends(require_role(UserRole.ADMIN)),
):
    """Config change history from audit log."""
    audit = get_audit_logger()
    entries = await audit.query(AuditQuery(resource_type="config", limit=limit))
    return [
        {
            "id": e.id,
            "timestamp": e.timestamp.isoformat(),
            "actor": e.actor,
            "action": e.action,
            "resource_id": e.resource_id,
            "details": e.details,
        }
        for e in entries
    ]


@router.post("/validate")
async def validate_config(
    section: str = Body(...),
    data: dict = Body(...),
    user: TokenPayload = Depends(require_role(UserRole.ADMIN)),
):
    """Validate proposed config without applying."""
    mgr = get_config_manager()
    return mgr.validate_config(section, data)


@router.get("/{section}")
async def get_section_config(
    section: str,
    user: TokenPayload = Depends(require_role(UserRole.ADMIN)),
):
    """Get specific config section."""
    mgr = get_config_manager()
    try:
        return mgr.get_config(section)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/{section}")
async def update_section_config(
    section: str,
    data: dict = Body(...),
    user: TokenPayload = Depends(require_role(UserRole.ADMIN)),
):
    """Update runtime config (only hot-reloadable fields)."""
    mgr = get_config_manager()
    try:
        result = await mgr.update_config(section, data, actor=user.sub)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return result


@router.post("/onboarding-complete")
async def mark_onboarding_complete(user: TokenPayload = Depends(require_role(UserRole.ADMIN))):
    """Mark onboarding as completed. Writes a flag file to data/."""
    from pathlib import Path
    flag = Path("data/.onboarding_complete")
    flag.parent.mkdir(parents=True, exist_ok=True)
    flag.write_text(user.sub)
    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="onboarding_complete", resource_type="system", resource_id="setup")
    return {"status": "ok"}


@router.get("/onboarding-status")
async def onboarding_status(user: TokenPayload = Depends(require_role(UserRole.ADMIN))):
    """Check if onboarding has been completed."""
    from pathlib import Path
    return {"completed": Path("data/.onboarding_complete").exists()}
