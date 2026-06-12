"""RBAC management routes — view and edit roles/permissions."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel

from ..models.auth import ROLE_PERMISSIONS, TokenPayload, UserRole
from ..services.auth_service import require_permission

router = APIRouter()

# Persist custom RBAC overrides and custom roles to disk
_RBAC_FILE = Path(os.getenv("SENTINEL_DATA_DIR", "data")) / "rbac_overrides.json"
_CUSTOM_ROLES_FILE = Path(os.getenv("SENTINEL_DATA_DIR", "data")) / "rbac_custom_roles.json"

# Built-in roles that cannot be deleted
BUILTIN_ROLES = {"admin", "security", "auditor", "viewer"}


class PermissionUpdate(BaseModel):
    role: str
    permissions: list[str]


class RoleCreate(BaseModel):
    name: str
    label: str = ""
    description: str = ""
    permissions: list[str] = []
    clone_from: Optional[str] = None


def _load_overrides() -> dict[str, list[str]]:
    """Load persisted RBAC overrides."""
    if _RBAC_FILE.exists():
        try:
            return json.loads(_RBAC_FILE.read_text())
        except Exception:
            pass
    return {}


def _save_overrides(overrides: dict[str, list[str]]) -> None:
    """Persist RBAC overrides to disk."""
    _RBAC_FILE.parent.mkdir(parents=True, exist_ok=True)
    _RBAC_FILE.write_text(json.dumps(overrides, indent=2))


def _load_custom_roles() -> dict[str, dict]:
    """Load custom roles from disk."""
    if _CUSTOM_ROLES_FILE.exists():
        try:
            return json.loads(_CUSTOM_ROLES_FILE.read_text())
        except Exception:
            pass
    return {}


def _save_custom_roles(roles: dict[str, dict]) -> None:
    """Persist custom roles to disk."""
    _CUSTOM_ROLES_FILE.parent.mkdir(parents=True, exist_ok=True)
    _CUSTOM_ROLES_FILE.write_text(json.dumps(roles, indent=2))


def get_all_role_names() -> list[str]:
    """Get all role names: built-in + custom."""
    builtin = [r.value for r in UserRole]
    custom = list(_load_custom_roles().keys())
    return builtin + [r for r in custom if r not in builtin]


def get_effective_permissions() -> dict[str, list[str]]:
    """Get the effective permission matrix (base + overrides + custom roles)."""
    overrides = _load_overrides()
    custom_roles = _load_custom_roles()
    result = {}
    # Built-in roles
    for role in UserRole:
        if role.value in overrides:
            result[role.value] = sorted(overrides[role.value])
        else:
            result[role.value] = sorted(ROLE_PERMISSIONS.get(role, set()))
    # Custom roles
    for name, data in custom_roles.items():
        if name not in result:
            if name in overrides:
                result[name] = sorted(overrides[name])
            else:
                result[name] = sorted(data.get("permissions", []))
    return result


# All known permissions in the system
ALL_PERMISSIONS = sorted({
    "policies:read", "policies:write", "policies:delete", "policies:apply",
    "guardrails:read", "guardrails:write", "guardrails:test",
    "iocs:read", "iocs:write",
    "siem:read", "siem:write", "siem:test",
    "notifications:read", "notifications:write",
    "audit:read", "audit:export",
    "users:manage",
    "config:validate", "config:rollback",
    "admin:read",
})


@router.get("/matrix")
def get_rbac_matrix(_user: TokenPayload = Depends(require_permission("admin:read"))):
    """Get the full RBAC matrix: roles, permissions, and assignments."""
    effective = get_effective_permissions()
    overrides = _load_overrides()
    custom_roles = _load_custom_roles()

    # Build role metadata
    role_meta = {}
    for r in UserRole:
        role_meta[r.value] = {"builtin": True}
    for name, data in custom_roles.items():
        role_meta[name] = {"builtin": False, "label": data.get("label", name), "description": data.get("description", "")}

    return {
        "roles": list(effective.keys()),
        "permissions": ALL_PERMISSIONS,
        "matrix": effective,
        "has_overrides": list(overrides.keys()),
        "role_meta": role_meta,
    }


@router.post("/role")
def create_role(
    req: RoleCreate,
    _user: TokenPayload = Depends(require_permission("users:manage")),
):
    """Create a new custom role."""
    name = req.name.lower().strip().replace(" ", "_")

    # Validate name
    if not name or not name.isidentifier():
        raise HTTPException(status_code=400, detail="Role name must be alphanumeric with underscores")
    if len(name) > 32:
        raise HTTPException(status_code=400, detail="Role name too long (max 32 chars)")

    # Check not already exists
    all_roles = get_all_role_names()
    if name in all_roles:
        raise HTTPException(status_code=409, detail=f"Role '{name}' already exists")

    # Determine permissions
    permissions = req.permissions
    if req.clone_from:
        effective = get_effective_permissions()
        if req.clone_from in effective:
            permissions = effective[req.clone_from]

    # Validate permissions
    invalid = set(permissions) - set(ALL_PERMISSIONS)
    if invalid:
        raise HTTPException(status_code=400, detail=f"Invalid permissions: {sorted(invalid)}")

    # Save
    custom_roles = _load_custom_roles()
    custom_roles[name] = {
        "label": req.label or name.replace("_", " ").title(),
        "description": req.description or "",
        "permissions": sorted(permissions),
    }
    _save_custom_roles(custom_roles)

    return {"role": name, "permissions": sorted(permissions), "created": True}


@router.delete("/role/{role_name}")
def delete_role(
    role_name: str,
    _user: TokenPayload = Depends(require_permission("users:manage")),
):
    """Delete a custom role. Built-in roles cannot be deleted."""
    if role_name in BUILTIN_ROLES:
        raise HTTPException(status_code=400, detail=f"Cannot delete built-in role '{role_name}'")

    custom_roles = _load_custom_roles()
    if role_name not in custom_roles:
        raise HTTPException(status_code=404, detail=f"Custom role '{role_name}' not found")

    del custom_roles[role_name]
    _save_custom_roles(custom_roles)

    # Also remove any overrides
    overrides = _load_overrides()
    if role_name in overrides:
        del overrides[role_name]
        _save_overrides(overrides)

    return {"role": role_name, "deleted": True}


@router.put("/role/{role_name}")
def update_role_permissions(
    role_name: str,
    update: PermissionUpdate,
    _user: TokenPayload = Depends(require_permission("users:manage")),
):
    """Update permissions for a role."""
    all_roles = get_all_role_names()
    if role_name not in all_roles:
        raise HTTPException(status_code=404, detail=f"Role '{role_name}' not found")

    # Prevent removing admin:read from admin role (self-lockout protection)
    if role_name == "admin" and "admin:read" not in update.permissions:
        raise HTTPException(status_code=400, detail="Cannot remove admin:read from admin role")
    if role_name == "admin" and "users:manage" not in update.permissions:
        raise HTTPException(status_code=400, detail="Cannot remove users:manage from admin role")

    # Validate permissions
    invalid = set(update.permissions) - set(ALL_PERMISSIONS)
    if invalid:
        raise HTTPException(status_code=400, detail=f"Invalid permissions: {sorted(invalid)}")

    # Save override
    overrides = _load_overrides()
    overrides[role_name] = sorted(update.permissions)
    _save_overrides(overrides)

    # Update in-memory ROLE_PERMISSIONS for built-in roles
    try:
        role = UserRole(role_name)
        ROLE_PERMISSIONS[role] = set(update.permissions)
    except ValueError:
        pass  # Custom role, no enum entry

    return {"role": role_name, "permissions": sorted(update.permissions)}


@router.post("/role/{role_name}/reset")
def reset_role_permissions(
    role_name: str,
    _user: TokenPayload = Depends(require_permission("users:manage")),
):
    """Reset a role to its default permissions (remove overrides)."""
    all_roles = get_all_role_names()
    if role_name not in all_roles:
        raise HTTPException(status_code=404, detail=f"Role '{role_name}' not found")

    # For custom roles, reset means restore the original custom definition
    custom_roles = _load_custom_roles()

    overrides = _load_overrides()
    if role_name in overrides:
        del overrides[role_name]
        _save_overrides(overrides)

    # Restore in-memory for built-in roles
    defaults = {
        "admin": {
            "policies:read", "policies:write", "policies:delete", "policies:apply",
            "guardrails:read", "guardrails:write", "guardrails:test",
            "iocs:read", "iocs:write",
            "siem:read", "siem:write", "siem:test",
            "notifications:read", "notifications:write",
            "audit:read", "audit:export",
            "users:manage",
            "config:validate", "config:rollback",
            "admin:read",
        },
        "security": {
            "policies:read", "policies:write", "policies:apply",
            "guardrails:read", "guardrails:write", "guardrails:test",
            "iocs:read", "iocs:write",
            "siem:read", "siem:write", "siem:test",
            "notifications:read", "notifications:write",
            "audit:read",
            "config:validate",
            "admin:read",
        },
        "auditor": {
            "policies:read",
            "guardrails:read",
            "iocs:read",
            "siem:read",
            "notifications:read",
            "audit:read", "audit:export",
            "admin:read",
        },
        "viewer": {
            "policies:read",
            "siem:read",
            "notifications:read",
            "admin:read",
        },
    }

    if role_name in defaults:
        try:
            role = UserRole(role_name)
            ROLE_PERMISSIONS[role] = defaults[role_name]
        except ValueError:
            pass

    effective = get_effective_permissions()
    return {"role": role_name, "permissions": effective.get(role_name, []), "reset": True}

