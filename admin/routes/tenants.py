"""Admin API routes for tenant and agent management."""
import ipaddress
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException

from admin.models.auth import TokenPayload
from admin.models.tenants import (
    AgentCreate,
    AgentInfo,
    AgentUpdate,
    DefaultsInfo,
    DefaultsUpdate,
    HealthCheckResponse,
    TenantCreate,
    TenantInfo,
    TenantUpdate,
)
from admin.services.auth_service import require_permission
from admin.services.tenant_manager import TenantManager, get_tenant_manager

router = APIRouter(prefix="/admin", tags=["tenants"])

# Blocked hosts for SSRF prevention
_SSRF_BLOCKED_RANGES = [
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / cloud metadata
]
_SSRF_BLOCKED_HOSTNAMES = {"metadata.google.internal", "metadata.internal"}


def _validate_backend_url(url: str) -> None:
    """Validate backend URL is not targeting internal/metadata endpoints."""
    try:
        parsed = urlparse(url)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid backend_url format")

    if not parsed.scheme or parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="backend_url must use http or https scheme")

    hostname = parsed.hostname or ""

    # Block known metadata hostnames
    if hostname.lower() in _SSRF_BLOCKED_HOSTNAMES:
        raise HTTPException(status_code=400, detail="backend_url targets a blocked hostname")

    # Resolve IP and check ranges
    try:
        addr = ipaddress.ip_address(hostname)
        for net in _SSRF_BLOCKED_RANGES:
            if addr in net:
                raise HTTPException(status_code=400, detail="backend_url targets a private/reserved IP range")
    except ValueError:
        # hostname is not an IP literal — check for metadata patterns only
        if hostname.lower() in _SSRF_BLOCKED_HOSTNAMES:
            raise HTTPException(status_code=400, detail="backend_url targets a blocked hostname")


def _mgr() -> TenantManager:
    return get_tenant_manager()


# --- Tenant endpoints ---


@router.get("/tenants", response_model=list[TenantInfo])
def list_tenants(mgr: TenantManager = Depends(_mgr), user: TokenPayload = Depends(require_permission("policies:read"))):
    return mgr.list_tenants()


@router.post("/tenants", response_model=TenantInfo, status_code=201)
def create_tenant(req: TenantCreate, mgr: TenantManager = Depends(_mgr), user: TokenPayload = Depends(require_permission("policies:write"))):
    try:
        return mgr.create_tenant(req)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))


@router.put("/tenants/{tenant_id}", response_model=TenantInfo)
def update_tenant(tenant_id: str, req: TenantUpdate, mgr: TenantManager = Depends(_mgr), user: TokenPayload = Depends(require_permission("policies:write"))):
    result = mgr.update_tenant(tenant_id, req)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")
    return result


@router.delete("/tenants/{tenant_id}", status_code=204)
def delete_tenant(tenant_id: str, mgr: TenantManager = Depends(_mgr), user: TokenPayload = Depends(require_permission("policies:delete"))):
    if not mgr.delete_tenant(tenant_id):
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")


@router.patch("/tenants/{tenant_id}/pause", response_model=TenantInfo)
def pause_tenant(tenant_id: str, mgr: TenantManager = Depends(_mgr), user: TokenPayload = Depends(require_permission("policies:write"))):
    result = mgr.pause_tenant(tenant_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")
    return result


@router.get("/tenants/{tenant_id}/agents", response_model=list[AgentInfo])
def list_tenant_agents(tenant_id: str, mgr: TenantManager = Depends(_mgr), user: TokenPayload = Depends(require_permission("policies:read"))):
    result = mgr.list_agents_for_tenant(tenant_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")
    return result


# --- Agent endpoints ---


@router.get("/agents", response_model=list[AgentInfo])
def list_all_agents(
    tenant_id: str | None = None,
    status: str | None = None,
    mgr: TenantManager = Depends(_mgr),
    user: TokenPayload = Depends(require_permission("policies:read")),
):
    agents = mgr.list_all_agents()
    # Tenant-scoped filtering: non-admin users with tenant_scope see only their tenant
    if user.tenant:
        agents = [a for a in agents if getattr(a, "tenant_id", None) == user.tenant]
    # Query param filters
    if tenant_id:
        agents = [a for a in agents if getattr(a, "tenant_id", None) == tenant_id]
    if status:
        agents = [a for a in agents if getattr(a, "status", None) == status]
    # Redact sensitive fields for non-admin/security roles
    if user.role not in ("admin", "security"):
        for agent in agents:
            if hasattr(agent, "backend_url"):
                agent.backend_url = "***"
            if hasattr(agent, "auth_header"):
                agent.auth_header = "***"
    return agents


@router.post("/agents", response_model=AgentInfo, status_code=201)
def create_agent(req: AgentCreate, mgr: TenantManager = Depends(_mgr), user: TokenPayload = Depends(require_permission("policies:write"))):
    # SSRF prevention: validate backend_url
    if hasattr(req, "backend_url") and req.backend_url:
        _validate_backend_url(str(req.backend_url))
    try:
        return mgr.create_agent(req)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))


@router.put("/agents/{tenant_id}/{agent_id}", response_model=AgentInfo)
def update_agent(tenant_id: str, agent_id: str, req: AgentUpdate, mgr: TenantManager = Depends(_mgr), user: TokenPayload = Depends(require_permission("policies:write"))):
    # SSRF prevention: validate backend_url if being updated
    if hasattr(req, "backend_url") and req.backend_url:
        _validate_backend_url(str(req.backend_url))
    result = mgr.update_agent(tenant_id, agent_id, req)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found in tenant '{tenant_id}'")
    return result


@router.delete("/agents/{tenant_id}/{agent_id}", status_code=204)
def delete_agent(tenant_id: str, agent_id: str, mgr: TenantManager = Depends(_mgr), user: TokenPayload = Depends(require_permission("policies:delete"))):
    try:
        if not mgr.delete_agent(tenant_id, agent_id):
            raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found in tenant '{tenant_id}'")
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/agents/{tenant_id}/{agent_id}/pause", response_model=AgentInfo)
def pause_agent(tenant_id: str, agent_id: str, mgr: TenantManager = Depends(_mgr), user: TokenPayload = Depends(require_permission("policies:write"))):
    result = mgr.pause_agent(tenant_id, agent_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found in tenant '{tenant_id}'")
    return result


@router.post("/agents/{tenant_id}/{agent_id}/health-check", response_model=HealthCheckResponse)
async def health_check_agent(tenant_id: str, agent_id: str, mgr: TenantManager = Depends(_mgr), user: TokenPayload = Depends(require_permission("policies:read"))):
    result = await mgr.health_check(tenant_id, agent_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found in tenant '{tenant_id}'")
    return result


# --- Defaults endpoints ---


@router.get("/defaults", response_model=DefaultsInfo)
def get_defaults(mgr: TenantManager = Depends(_mgr), user: TokenPayload = Depends(require_permission("policies:read"))):
    return mgr.get_defaults()


@router.put("/defaults", response_model=DefaultsInfo)
def update_defaults(req: DefaultsUpdate, mgr: TenantManager = Depends(_mgr), user: TokenPayload = Depends(require_permission("policies:write"))):
    if req.backend_url:
        _validate_backend_url(str(req.backend_url))
    return mgr.update_defaults(req)
