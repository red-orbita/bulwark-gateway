"""Health check endpoints."""
from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/health")
async def health():
    return {"status": "ok", "service": "sentinel-gateway"}


@router.get("/ready")
async def ready(request: Request):
    """Readiness check — verifies policies and IOCs are loaded."""
    policy_count = getattr(request.app.state, "policy_loader", None)
    ioc_count = getattr(request.app.state, "ioc_manager", None)
    return {
        "status": "ready",
        "policies_loaded": policy_count.count if policy_count else 0,
        "iocs_loaded": ioc_count.count if ioc_count else 0,
    }
