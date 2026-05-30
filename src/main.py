"""
Sentinel Gateway — Main application entry point.

Architecture:
  User Request → Auth → Input Guardrail → Tool Policy → LLM/Agent Backend
  Agent Response → Output Filter → User

Modes:
  1. Proxy mode: sits between user and agent API (OpenAI-compatible)
  2. Sidecar mode: called by the agent framework before/after tool execution
"""
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from src.config import settings
from src.middleware.auth import AuthMiddleware
from src.middleware.rate_limit import RateLimitMiddleware
from src.routes import proxy, health, admin


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    import structlog
    logger = structlog.get_logger()
    await logger.ainfo("sentinel-gateway starting", version="0.1.0", mode=settings.mode)

    # Load policies on startup
    from src.policies.loader import PolicyLoader
    app.state.policy_loader = PolicyLoader(settings.policies_dir)
    await app.state.policy_loader.load_all()

    # Load IOC database
    from src.ioc.manager import IOCManager
    app.state.ioc_manager = IOCManager(settings.ioc_path)
    await app.state.ioc_manager.load()

    await logger.ainfo(
        "sentinel-gateway ready",
        policies=app.state.policy_loader.count,
        iocs=app.state.ioc_manager.count,
    )
    yield
    await logger.ainfo("sentinel-gateway shutting down")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Sentinel Gateway",
        description="Security guardrail proxy for AI agents",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if settings.debug else None,
        redoc_url=None,
    )

    # Middleware (order matters — outermost first)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["POST"],
        allow_headers=["Authorization", "Content-Type", "X-Tenant-ID", "X-Agent-ID"],
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
    )


if __name__ == "__main__":
    main()
