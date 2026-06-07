"""Admin endpoints — policy management, IOC feeds, agent registry, reload, stats.

All endpoints require admin-level authentication (valid JWT with role=admin).
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
import jwt
from jwt import InvalidTokenError as JWTError

from src.config import settings

router = APIRouter()


async def require_admin(request: Request):
    """Dependency: require valid JWT with admin role for all admin endpoints."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    token = auth_header[7:]
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    role = payload.get("role", "")
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")

    request.state.admin_user = payload.get("sub", payload.get("tenant_id", "unknown"))
    return payload


@router.post("/policies/reload")
async def reload_policies(request: Request, _=Depends(require_admin)):
    """Hot-reload policies from disk."""
    loader = request.app.state.policy_loader
    await loader.reload()
    return {"status": "reloaded", "count": loader.count}


@router.get("/policies")
async def list_policies(request: Request, _=Depends(require_admin)):
    """List loaded policies."""
    loader = request.app.state.policy_loader
    policies = []
    for p in loader._policies:
        policies.append(
            {
                "tenant_id": p.tenant_id,
                "agent_id": p.agent_id,
                "allowed_tools": p.allowed_tools,
                "denied_tools": p.denied_tools,
                "sandbox_level": p.sandbox_level,
            }
        )
    return {"count": len(policies), "policies": policies}


@router.get("/iocs/stats")
async def ioc_stats(request: Request, _=Depends(require_admin)):
    """IOC database statistics."""
    mgr = request.app.state.ioc_manager
    return {
        "domains": len(mgr.db.domains),
        "ips": len(mgr.db.ips),
        "urls": len(mgr.db.urls),
        "hashes": len(mgr.db.hashes),
    }


@router.post("/iocs/update")
async def update_iocs(request: Request, _=Depends(require_admin)):
    """Trigger IOC feed update from all configured threat intel sources.

    Requires API keys configured via SENTINEL_* environment variables:
    - SENTINEL_URLHAUS_KEY
    - SENTINEL_THREATFOX_KEY
    - SENTINEL_OTX_KEY
    - SENTINEL_ABUSEIPDB_KEY
    """
    from src.services.ioc_feeds import IOCFeedService

    feed_service = IOCFeedService(settings.ioc_path)
    keys = {
        "urlhaus_key": settings.urlhaus_key,
        "threatfox_key": settings.threatfox_key,
        "otx_key": settings.otx_key,
        "abuseipdb_key": settings.abuseipdb_key,
    }

    result = await feed_service.update_all(keys)

    # Reload IOC manager with new data
    mgr = request.app.state.ioc_manager
    await mgr.load()

    return {
        "status": "updated" if result.success else "partial_failure",
        "timestamp": result.timestamp,
        "total_domains_added": result.total_domains_added,
        "total_ips_added": result.total_ips_added,
        "feeds": [
            {
                "source": r.source,
                "success": r.success,
                "domains_added": r.domains_added,
                "ips_added": r.ips_added,
                "error": r.error,
                "duration_ms": round(r.duration_ms, 1),
            }
            for r in result.results
        ],
    }


@router.post("/iocs/reload")
async def reload_iocs(request: Request, _=Depends(require_admin)):
    """Reload IOC database from disk (after manual edit or external update)."""
    mgr = request.app.state.ioc_manager
    await mgr.load()
    return {
        "status": "reloaded",
        "domains": len(mgr.db.domains),
        "ips": len(mgr.db.ips),
        "urls": len(mgr.db.urls),
    }


# === Agent Registry ===


@router.get("/agents")
async def list_agents(request: Request, _=Depends(require_admin)):
    """List all registered agent backends."""
    registry = request.app.state.agent_registry
    return {"count": registry.count, "agents": registry.list_agents()}


@router.post("/agents/reload")
async def reload_agents(request: Request, _=Depends(require_admin)):
    """Hot-reload agent registry from config/agents.yaml."""
    registry = request.app.state.agent_registry
    await registry.load()
    return {"status": "reloaded", "count": registry.count}


@router.post("/agents/register")
async def register_agent(request: Request, _=Depends(require_admin)):
    """Register a new agent backend at runtime.

    Body: {"tenant_id": "...", "agent_id": "...", "backend_url": "...", "timeout": 60.0}
    """
    from src.services.agent_registry import AgentBackend

    body = await request.json()
    tenant_id = body.get("tenant_id")
    agent_id = body.get("agent_id")
    backend_url = body.get("backend_url")

    if not all([tenant_id, agent_id, backend_url]):
        return JSONResponse(
            status_code=400,
            content={"error": "tenant_id, agent_id, and backend_url are required"},
        )

    # SSRF protection: validate backend_url (C-01/H-01)
    from urllib.parse import urlparse
    import ipaddress
    import socket

    parsed = urlparse(backend_url)
    if parsed.scheme not in ("http", "https"):
        return JSONResponse(
            status_code=400,
            content={"error": "backend_url must use http or https scheme"},
        )

    hostname = parsed.hostname or ""

    # Block known dangerous hostnames
    blocked_hosts = {
        "metadata.google.internal", "metadata.google.internal.",
        "169.254.169.254", "metadata", "localhost", "127.0.0.1",
        "0.0.0.0", "kubernetes.default", "kubernetes.default.svc",
    }
    if hostname.lower().rstrip(".") in blocked_hosts or hostname.endswith(".internal") or hostname.endswith(".local"):
        return JSONResponse(
            status_code=400,
            content={"error": "backend_url hostname is blocked (internal/metadata)"},
        )

    # Resolve hostname and check against blocked CIDR ranges
    blocked_networks = [
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("100.64.0.0/10"),
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fc00::/7"),
        ipaddress.ip_network("fe80::/10"),
    ]
    blocked_ips = {"169.254.169.254", "fd00:ec2::254", "100.100.100.200"}

    try:
        addr_infos = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
        for addr_info in addr_infos:
            ip_str = addr_info[4][0]
            if ip_str in blocked_ips:
                return JSONResponse(
                    status_code=400,
                    content={"error": "backend_url resolves to blocked address"},
                )
            ip = ipaddress.ip_address(ip_str)
            for network in blocked_networks:
                if ip in network:
                    return JSONResponse(
                        status_code=400,
                        content={"error": "backend_url must not point to private/internal addresses"},
                    )
    except (socket.gaierror, OSError):
        return JSONResponse(
            status_code=400,
            content={"error": "backend_url hostname could not be resolved"},
        )

    backend = AgentBackend(
        backend_url=backend_url,
        timeout=body.get("timeout", 120.0),
        description=body.get("description", ""),
        auth_header=body.get("auth_header"),
        health_endpoint=body.get("health_endpoint", "/health"),
        path_prefix=body.get("path_prefix", "/v1"),
    )

    registry = request.app.state.agent_registry
    registry.register(tenant_id, agent_id, backend)

    return {
        "status": "registered",
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "backend_url": backend_url,
    }


@router.delete("/agents/{tenant_id}/{agent_id}")
async def unregister_agent(request: Request, tenant_id: str, agent_id: str, _=Depends(require_admin)):
    """Remove an agent from the registry."""
    registry = request.app.state.agent_registry
    removed = registry.unregister(tenant_id, agent_id)
    if not removed:
        return JSONResponse(status_code=404, content={"error": "Agent not found"})
    return {"status": "unregistered", "tenant_id": tenant_id, "agent_id": agent_id}
