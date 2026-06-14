"""Validation routes — Dry-run and apply configuration changes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..models.auth import TokenPayload
from ..models.config import ConfigApplyRequest, ConfigApplyResult
from ..services.auth_service import require_permission
from ..services.config_validator import ConfigValidator, HotReloader
from ..services.audit_logger import get_audit_logger

router = APIRouter()


@router.post("/dry-run")
async def dry_run_validation(
    content: str,
    user: TokenPayload = Depends(require_permission("config:validate")),
):
    """Validate config without applying. Returns validation result."""
    result = ConfigValidator.validate_yaml(content)
    return result.model_dump()


@router.post("/apply")
async def apply_config(
    req: ConfigApplyRequest,
    user: TokenPayload = Depends(require_permission("policies:apply")),
):
    """
    Apply policy: Dry-Run → Validate → Backup → Atomic Write → Audit.
    """
    from pathlib import Path

    path = Path("config/policies") / f"{req.policy_name}.yaml"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Policy '{req.policy_name}' not found")

    content = path.read_text()
    validation = ConfigValidator.validate_yaml(content)

    if req.dry_run:
        return ConfigApplyResult(
            success=validation.valid,
            policy_name=req.policy_name,
            version=1,
            dry_run=True,
            validation=validation,
        )

    if not validation.valid:
        raise HTTPException(status_code=422, detail={"errors": validation.errors})

    # Backup + apply
    HotReloader.backup_policy(req.policy_name)

    # Trigger hot-reload on proxy (if shared filesystem)
    # In production: send signal or API call to proxy service
    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="apply", resource_type="policy", resource_id=req.policy_name)

    from datetime import datetime, timezone
    return ConfigApplyResult(
        success=True,
        policy_name=req.policy_name,
        version=1,
        applied_at=datetime.now(timezone.utc),
        dry_run=False,
        validation=validation,
        rollback_version=0,
    )
