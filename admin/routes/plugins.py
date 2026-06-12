"""Admin API routes for plugin management."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from admin.models.auth import TokenPayload
from admin.services.auth_service import require_permission
from src.plugins.manager import PluginManager
from src.plugins.spec import PluginSpec

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin/plugins", tags=["plugins"])

_PLUGIN_DIR = Path("plugins")


# --- Request models ---


class InstallRequest(BaseModel):
    """Request to install a plugin."""
    name: str = Field(..., description="Plugin name or path to local plugin directory")
    source: str = Field("hub", description="Installation source: 'hub' or 'local'")


class UninstallRequest(BaseModel):
    """Request to uninstall a plugin."""
    name: str = Field(..., description="Plugin name to uninstall")


class ScaffoldRequest(BaseModel):
    """Request to scaffold a new plugin."""
    name: str = Field(..., description="Plugin name (kebab-case)")


# --- Response models ---


class PluginResponse(BaseModel):
    """Plugin information response."""
    name: str
    version: str
    author: str
    license: str
    description: str
    type: str
    blocking: bool


class SecurityCheckResponse(BaseModel):
    """Security check result."""
    plugin: str
    passed: bool
    warnings: list[str]


# --- Helpers ---


def _get_plugin_manager() -> PluginManager:
    """Create a PluginManager instance with the default plugin directory."""
    return PluginManager(plugin_dir=_PLUGIN_DIR)


def _spec_to_response(spec: PluginSpec) -> PluginResponse:
    """Convert a PluginSpec to a response model."""
    return PluginResponse(
        name=spec.name,
        version=spec.version,
        author=spec.author,
        license=spec.license,
        description=spec.description,
        type=spec.type.value,
        blocking=spec.blocking,
    )


# --- Endpoints ---


@router.get("/", response_model=list[PluginResponse])
def list_plugins(
    user: TokenPayload = Depends(require_permission("admin:read")),
) -> list[PluginResponse]:
    """List all installed plugins."""
    manager = _get_plugin_manager()
    plugins = manager.list_installed()
    logger.info("plugins_listed count=%d user=%s", len(plugins), user.sub)
    return [_spec_to_response(spec) for spec in plugins]


@router.get("/{name}", response_model=PluginResponse)
def get_plugin(
    name: str,
    user: TokenPayload = Depends(require_permission("admin:read")),
) -> PluginResponse:
    """Get a specific plugin spec by name."""
    manager = _get_plugin_manager()
    plugins = manager.list_installed()
    for spec in plugins:
        if spec.name == name:
            return _spec_to_response(spec)
    raise HTTPException(status_code=404, detail=f"Plugin '{name}' not found")


@router.post("/install", response_model=dict)
def install_plugin(
    req: InstallRequest,
    user: TokenPayload = Depends(require_permission("guardrails:write")),
) -> dict:
    """Install a plugin from hub or local path."""
    manager = _get_plugin_manager()

    if req.source not in ("hub", "local"):
        raise HTTPException(status_code=400, detail=f"Invalid source '{req.source}'. Must be 'hub' or 'local'.")

    success = manager.install(name=req.name, source=req.source)
    if not success:
        raise HTTPException(status_code=400, detail=f"Failed to install plugin '{req.name}'")

    logger.info("plugin_installed name=%s source=%s user=%s", req.name, req.source, user.sub)
    return {"status": "installed", "name": req.name, "source": req.source}


@router.post("/uninstall", response_model=dict)
def uninstall_plugin(
    req: UninstallRequest,
    user: TokenPayload = Depends(require_permission("guardrails:write")),
) -> dict:
    """Uninstall a plugin by name."""
    manager = _get_plugin_manager()

    success = manager.uninstall(name=req.name)
    if not success:
        raise HTTPException(status_code=404, detail=f"Plugin '{req.name}' not found")

    logger.info("plugin_uninstalled name=%s user=%s", req.name, user.sub)
    return {"status": "uninstalled", "name": req.name}


@router.post("/{name}/enable", response_model=dict)
def enable_plugin(
    name: str,
    user: TokenPayload = Depends(require_permission("guardrails:write")),
) -> dict:
    """Enable a disabled plugin."""
    manager = _get_plugin_manager()

    success = manager.enable(name=name)
    if not success:
        raise HTTPException(status_code=404, detail=f"Plugin '{name}' not found")

    logger.info("plugin_enabled name=%s user=%s", name, user.sub)
    return {"status": "enabled", "name": name}


@router.post("/{name}/disable", response_model=dict)
def disable_plugin(
    name: str,
    user: TokenPayload = Depends(require_permission("guardrails:write")),
) -> dict:
    """Disable an enabled plugin."""
    manager = _get_plugin_manager()

    success = manager.disable(name=name)
    if not success:
        raise HTTPException(status_code=404, detail=f"Plugin '{name}' not found")

    logger.info("plugin_disabled name=%s user=%s", name, user.sub)
    return {"status": "disabled", "name": name}


@router.post("/scaffold", response_model=dict)
def scaffold_plugin(
    req: ScaffoldRequest,
    user: TokenPayload = Depends(require_permission("guardrails:write")),
) -> dict:
    """Create a new plugin scaffold with boilerplate structure."""
    manager = _get_plugin_manager()

    output_dir = manager.plugin_dir
    plugin_path = output_dir / req.name
    if plugin_path.exists():
        raise HTTPException(status_code=400, detail=f"Plugin '{req.name}' already exists")

    created_path = manager.scaffold(name=req.name, output_dir=output_dir)
    logger.info("plugin_scaffolded name=%s path=%s user=%s", req.name, str(created_path), user.sub)
    return {"status": "scaffolded", "name": req.name, "path": str(created_path)}


@router.post("/{name}/security-check", response_model=SecurityCheckResponse)
def security_check_plugin(
    name: str,
    user: TokenPayload = Depends(require_permission("guardrails:write")),
) -> SecurityCheckResponse:
    """Run a security audit on an installed plugin."""
    manager = _get_plugin_manager()

    plugin_path = manager.plugin_dir / name
    if not plugin_path.is_dir():
        raise HTTPException(status_code=404, detail=f"Plugin '{name}' not found")

    warnings = manager._security_check(plugin_path)
    passed = len(warnings) == 0

    logger.info(
        "plugin_security_check name=%s passed=%s warnings=%d user=%s",
        name, passed, len(warnings), user.sub,
    )

    return SecurityCheckResponse(
        plugin=name,
        passed=passed,
        warnings=warnings,
    )
