"""
Sentinel Gateway — Main application entry point.

Architecture:
  User Request → Auth → Input Guardrail → Tool Policy → LLM/Agent Backend
  Agent Response → Output Filter → User

Modes:
  1. Proxy mode: sits between user and agent API (OpenAI-compatible)
  2. Sidecar mode: called by the agent framework before/after tool execution
"""

from contextlib import asynccontextmanager

import uvicorn
import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.config import settings, validate_settings
from src.middleware.auth import AuthMiddleware
from src.middleware.rate_limit import RateLimitMiddleware
from src.routes import admin, health, proxy


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    import structlog

    validate_settings()

    logger = structlog.get_logger()
    await logger.ainfo("sentinel-gateway starting", version="0.2.0", mode=settings.mode)

    # Load policies on startup
    from src.policies.loader import PolicyLoader

    app.state.policy_loader = PolicyLoader(settings.policies_dir)
    await app.state.policy_loader.load_all()

    # Start hot-reload polling (5s interval)
    await app.state.policy_loader.start_hot_reload(interval_seconds=5)

    # Load IOC database
    from src.ioc.manager import IOCManager

    app.state.ioc_manager = IOCManager(settings.ioc_path)
    await app.state.ioc_manager.load()

    # Load agent registry (multi-backend routing)
    from src.services.agent_registry import AgentRegistry

    app.state.agent_registry = AgentRegistry(settings.agents_config)
    await app.state.agent_registry.load()

    # Start telemetry exporter (background, non-blocking)
    from src.telemetry.exporter import get_exporter, load_transports_from_config

    app.state.telemetry_exporter = get_exporter()
    load_transports_from_config(app.state.telemetry_exporter)
    await app.state.telemetry_exporter.start()

    # Register enrichment scanners (async, background only)
    from src.enrichment.manager import get_enrichment_manager, ENRICHMENT_ENABLED

    if ENRICHMENT_ENABLED:
        enrichment_mgr = get_enrichment_manager()
        try:
            from src.enrichment.embedding_scanner import EmbeddingScanner
            enrichment_mgr.register(EmbeddingScanner())
            await logger.ainfo("enrichment_enabled", scanners=len(enrichment_mgr.scanners))
        except Exception as e:
            await logger.awarn("enrichment_init_failed", error=str(e))

    await logger.ainfo(
        "sentinel-gateway ready",
        policies=app.state.policy_loader.count,
        iocs=app.state.ioc_manager.count,
        agents=app.state.agent_registry.count,
    )
    yield
    # Shutdown
    await app.state.telemetry_exporter.stop()
    await app.state.policy_loader.stop_hot_reload()
    await logger.ainfo("sentinel-gateway shutting down")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Sentinel Gateway",
        description="Security guardrail proxy for AI agents",
        version="0.2.0",
        lifespan=lifespan,
        docs_url="/docs" if settings.debug else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.debug else None,
    )

    # Global exception handler — fail-closed: never expose 500 with stack traces
    @app.exception_handler(Exception)
    async def _global_exception_handler(request: Request, exc: Exception):
        logger = structlog.get_logger()
        await logger.aerror(
            "unhandled_exception",
            path=request.url.path,
            error=str(exc)[:200],
            tenant=getattr(request.state, "tenant_id", "unknown"),
        )
        # Fail-closed: return 403 on unexpected errors in security paths
        if request.url.path.startswith("/v1/"):
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "message": "Request blocked: internal validation error",
                        "type": "security_violation",
                        "code": "fail_closed",
                    }
                },
            )
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error"},
        )

    # Middleware (order matters — outermost first)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["POST"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-Tenant-ID",
            "X-Agent-ID",
            "X-Redteam-Mode",
        ],
    )
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(AuthMiddleware)

    # Routes
    app.include_router(health.router, tags=["health"])
    app.include_router(proxy.router, prefix="/v1", tags=["proxy"])
    app.include_router(admin.router, prefix="/admin", tags=["admin"])

    return app


app = create_app()


def main():
    uvicorn.run(
        "src.main:app",
        host=settings.host,
        port=settings.port,
        workers=settings.workers,
        log_level="info",
        access_log=False,
        server_header=False,
    )


if __name__ == "__main__":
    main()
