"""Admin endpoints — policy management, reload, stats."""
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter()


@router.post("/policies/reload")
async def reload_policies(request: Request):
    """Hot-reload policies from disk."""
    loader = request.app.state.policy_loader
    loader.reload()
    return {"status": "reloading", "message": "Policies will be reloaded"}


@router.get("/policies")
async def list_policies(request: Request):
    """List loaded policies."""
    loader = request.app.state.policy_loader
    policies = []
    for p in loader._policies:
        policies.append({
            "tenant_id": p.tenant_id,
            "agent_id": p.agent_id,
            "allowed_tools": p.allowed_tools,
            "denied_tools": p.denied_tools,
            "sandbox_level": p.sandbox_level,
        })
    return {"count": len(policies), "policies": policies}


@router.get("/iocs/stats")
async def ioc_stats(request: Request):
    """IOC database statistics."""
    mgr = request.app.state.ioc_manager
    return {
        "domains": len(mgr.db.domains),
        "ips": len(mgr.db.ips),
        "urls": len(mgr.db.urls),
        "hashes": len(mgr.db.hashes),
    }
