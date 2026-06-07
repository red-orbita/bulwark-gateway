"""Policy management routes — CRUD + validation + hot-reload."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from ..models.auth import TokenPayload, UserRole
from ..models.config import (
    PolicySummary, PolicyDetail, PolicyCreateRequest, PolicyUpdateRequest,
    PolicyValidationResult, ConfigApplyRequest, ConfigApplyResult,
)
from ..services.auth_service import get_current_user, require_permission
from ..services.config_validator import ConfigValidator, HotReloader, POLICIES_DIR
from ..services.audit_logger import get_audit_logger

router = APIRouter()

# H-09: Strict policy name validation to prevent path traversal
_SAFE_POLICY_NAME = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")


def _validate_policy_name(name: str) -> None:
    """Raise 400 if policy name contains path traversal characters."""
    if not _SAFE_POLICY_NAME.match(name):
        raise HTTPException(
            status_code=400,
            detail="Invalid policy name. Only alphanumeric, hyphens, and underscores allowed (max 64 chars).",
        )


@router.get("/", response_model=list[PolicySummary])
async def list_policies(user: TokenPayload = Depends(require_permission("policies:read"))):
    """List all policies."""
    policies = []
    for path in sorted(POLICIES_DIR.glob("*.yaml")):
        if path.name.startswith("."):
            continue
        import yaml
        try:
            content = path.read_text()
            data = yaml.safe_load(content)
            agents_raw = data.get("agents", [])
            if isinstance(agents_raw, dict):
                agent_names = list(agents_raw.keys())
            elif isinstance(agents_raw, list):
                agent_names = [a.get("id", str(i)) for i, a in enumerate(agents_raw) if isinstance(a, dict)]
            else:
                agent_names = []
            policies.append(PolicySummary(
                name=path.stem,
                tenant=data.get("tenant", "unknown"),
                active=data.get("active", True),
                agents=agent_names,
                last_modified=datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc),
            ))
        except Exception:
            policies.append(PolicySummary(name=path.stem, tenant="error"))
    return policies


@router.get("/{name}", response_model=PolicyDetail)
async def get_policy(name: str, user: TokenPayload = Depends(require_permission("policies:read"))):
    """Get full policy detail."""
    _validate_policy_name(name)
    path = POLICIES_DIR / f"{name}.yaml"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Policy '{name}' not found")
    content = path.read_text()
    import yaml
    data = yaml.safe_load(content) or {}
    stat = path.stat()
    return PolicyDetail(
        name=name,
        tenant=data.get("tenant", "unknown"),
        active=data.get("active", True),
        content=content,
        agents=list(data.get("agents", {}).keys()) if isinstance(data.get("agents"), dict) else [],
        created_at=datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc),
        last_modified=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
        modified_by="unknown",
        checksum=hashlib.sha256(content.encode()).hexdigest()[:16],
    )


@router.post("", response_model=PolicyDetail)
async def create_policy(
    req: PolicyCreateRequest,
    user: TokenPayload = Depends(require_permission("policies:write")),
):
    """Create a new policy."""
    _validate_policy_name(req.name)
    path = POLICIES_DIR / f"{req.name}.yaml"
    if path.exists():
        raise HTTPException(status_code=409, detail=f"Policy '{req.name}' already exists")

    # Validate
    result = ConfigValidator.validate_yaml(req.content)
    if not result.valid:
        raise HTTPException(status_code=422, detail={"errors": result.errors})

    # Write
    POLICIES_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(req.content, encoding="utf-8")

    # Audit
    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="create", resource_type="policy", resource_id=req.name, payload=req.content)

    return await get_policy(req.name, user)


@router.put("/{name}")
async def update_policy(
    name: str,
    req: PolicyUpdateRequest,
    user: TokenPayload = Depends(require_permission("policies:write")),
):
    """Update an existing policy with backup."""
    _validate_policy_name(name)
    path = POLICIES_DIR / f"{name}.yaml"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Policy '{name}' not found")

    # Validate new content
    result = ConfigValidator.validate_yaml(req.content)
    if not result.valid:
        raise HTTPException(status_code=422, detail={"errors": result.errors})

    # Backup current version
    HotReloader.backup_policy(name)

    # Atomic write
    success = HotReloader.apply_policy(name, req.content)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to write policy")

    # Audit
    audit = get_audit_logger()
    await audit.log(
        actor=user.sub, action="update", resource_type="policy",
        resource_id=name, payload=req.content, details=req.comment,
    )

    return {"status": "updated", "policy": name, "validation": result.model_dump()}


@router.delete("/{name}")
async def delete_policy(
    name: str,
    user: TokenPayload = Depends(require_permission("policies:delete")),
):
    """Deactivate a policy (backup + remove)."""
    path = POLICIES_DIR / f"{name}.yaml"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Policy '{name}' not found")

    HotReloader.backup_policy(name)
    path.unlink()

    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="delete", resource_type="policy", resource_id=name)
    return {"status": "deleted", "policy": name}


@router.post("/{name}/toggle")
async def toggle_policy(
    name: str,
    user: TokenPayload = Depends(require_permission("policies:write")),
):
    """Toggle a policy active/inactive."""
    import yaml
    path = POLICIES_DIR / f"{name}.yaml"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Policy '{name}' not found")

    content = path.read_text()
    data = yaml.safe_load(content) or {}
    data["active"] = not data.get("active", True)

    HotReloader.backup_policy(name)
    path.write_text(yaml.dump(data, default_flow_style=False), encoding="utf-8")

    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="toggle", resource_type="policy", resource_id=name, details=f"active={data['active']}")
    return {"name": name, "active": data["active"]}


@router.get("/{name}/versions")
async def policy_versions(name: str, user: TokenPayload = Depends(require_permission("policies:read"))):
    """List available versions of a policy."""
    return HotReloader.get_policy_versions(name)


@router.post("/{name}/rollback")
async def rollback_policy(
    name: str,
    version: Optional[str] = None,
    user: TokenPayload = Depends(require_permission("config:rollback")),
):
    """Rollback policy to previous version."""
    success = HotReloader.rollback_policy(name, version)
    if not success:
        raise HTTPException(status_code=404, detail="No backup version available")

    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="rollback", resource_type="policy", resource_id=name, details=f"version={version}")
    return {"status": "rolled_back", "policy": name, "version": version or "latest"}
