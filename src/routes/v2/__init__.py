"""V2 API routes — date-versioned API with standalone scanning capabilities."""

from fastapi import APIRouter

from src.routes.v2.scan import router as scan_router

router = APIRouter()
router.include_router(scan_router)
