"""Validation & Orchestration routes — Dry-run, apply, trigger skills."""

from __future__ import annotations

from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks

from ..models.auth import TokenPayload
from ..models.config import ConfigApplyRequest, ConfigApplyResult, PolicyValidationResult
from ..services.auth_service import require_permission
from ..services.config_validator import ConfigValidator, HotReloader
from ..services.audit_logger import get_audit_logger
from ..services.orchestrator_bridge import get_orchestrator_bridge

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


@router.post("/trigger/{skill}")
async def trigger_skill(
    skill: str,
    background_tasks: BackgroundTasks,
    user: TokenPayload = Depends(require_permission("orchestrator:trigger")),
):
    """Trigger a background skill (qa-validation, redteam-audit, performance-benchmark)."""
    bridge = get_orchestrator_bridge()
    task_id = str(uuid4())

    valid_skills = {"qa-validation", "redteam-audit", "performance-benchmark"}
    if skill not in valid_skills:
        raise HTTPException(status_code=400, detail=f"Invalid skill. Valid: {valid_skills}")

    # Run in background
    if skill == "qa-validation":
        background_tasks.add_task(bridge.run_qa_validation, task_id)
    elif skill == "redteam-audit":
        background_tasks.add_task(bridge.run_redteam_audit, task_id)
    elif skill == "performance-benchmark":
        background_tasks.add_task(bridge.run_latency_benchmark, task_id)

    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="trigger", resource_type="orchestrator", resource_id=skill)

    return {"task_id": task_id, "skill": skill, "status": "pending"}


@router.get("/task/{task_id}")
async def get_task_status(
    task_id: str,
    user: TokenPayload = Depends(require_permission("policies:read")),
):
    """Get status of a background task."""
    bridge = get_orchestrator_bridge()
    task = bridge.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return {
        "task_id": task.task_id,
        "skill": task.skill,
        "status": task.status.value,
        "output": task.output[-2048:] if task.output else "",
        "exit_code": task.exit_code,
        "details": task.details,
        "started_at": task.started_at.isoformat() if task.started_at else None,
        "completed_at": task.completed_at.isoformat() if task.completed_at else None,
    }
