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
import asyncio

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

    # Initialize session decomposition tracker (multi-turn attack detection)
    from src.guardrails.session_tracker import get_session_tracker

    session_tracker = get_session_tracker()
    session_tracker.initialize(
        redis_url=settings.redis_url,
        redis_tls_insecure=settings.redis_tls_insecure,
    )
    await logger.ainfo("session_decomposition_tracker_initialized", redis=bool(settings.redis_url))

    # Register enrichment scanners (async, background only)
    from src.enrichment.manager import get_enrichment_manager, ENRICHMENT_ENABLED

    if ENRICHMENT_ENABLED:
        enrichment_mgr = get_enrichment_manager()
        try:
            from src.enrichment.embedding_scanner import EmbeddingScanner
            scanner = EmbeddingScanner()
            # Pre-initialize model at startup (avoids timeout on first request)
            scanner._ensure_initialized()
            enrichment_mgr.register(scanner)
            await logger.ainfo("enrichment_enabled", scanners=len(enrichment_mgr.scanners))
        except Exception as e:
            await logger.awarn("enrichment_init_failed", error=str(e))

    # Initialize Scanner Pipeline (pluggable scanner framework)
    from src.scanners.pipeline import get_scanner_pipeline
    from src.scanners.builtin import RegexInputScanner, OutputRedactionScanner, ToolPolicyScanner
    from src.scanners.discovery import discover_all_scanners, instantiate_scanner

    pipeline = get_scanner_pipeline()

    # Register built-in scanners
    pipeline.register(RegexInputScanner())
    pipeline.register(OutputRedactionScanner())

    tool_policy_scanner = ToolPolicyScanner()
    tool_policy_scanner.set_policy_engine(app.state.policy_loader.engine)
    pipeline.register(tool_policy_scanner)

    # Register ML scanners (async by default, no latency impact unless ml_blocking=true)
    if settings.ml_enabled:
        from src.scanners.ml import InjectionClassifier, ToxicityScanner, TopicScanner, IntentScanner
        pipeline.register(InjectionClassifier())
        pipeline.register(ToxicityScanner())
        pipeline.register(TopicScanner())
        pipeline.register(IntentScanner())
        await logger.ainfo("ml_scanners_registered", blocking=settings.ml_blocking)

    # Register RAG Guard scanners (memory manipulation + retrieval poisoning)
    if settings.rag_enabled:
        from src.scanners.rag.memory_guard import MemoryGuard
        from src.scanners.rag.retrieval_scanner import RetrievalScanner
        pipeline.register(MemoryGuard())
        pipeline.register(RetrievalScanner())
        await logger.ainfo("rag_scanners_registered")

    # Register Multilingual scanners (language detection + non-English patterns)
    if settings.multilingual_enabled:
        from src.scanners.multilingual.language_detector import LanguageDetector
        from src.scanners.multilingual.patterns import MultilingualPatterns
        pipeline.register(LanguageDetector())
        pipeline.register(MultilingualPatterns())
        await logger.ainfo("multilingual_scanners_registered")

    # Discover and register third-party plugins
    if settings.scanners_dir.exists():
        discovered = discover_all_scanners(settings.scanners_dir)
        for cls in discovered:
            try:
                scanner = instantiate_scanner(cls)
                pipeline.register(scanner)
            except Exception as e:
                await logger.awarn("plugin_instantiation_failed", cls=cls.__name__, error=str(e))

    # Start all scanners (load models, warm caches)
    await pipeline.startup()
    app.state.scanner_pipeline = pipeline

    await logger.ainfo(
        "scanner_pipeline_ready",
        input_blocking=pipeline.input_blocking_count,
        input_async=pipeline.input_async_count,
        output_blocking=pipeline.output_blocking_count,
        output_async=pipeline.output_async_count,
        total=pipeline.total_count,
    )

    # Background: sync ML scanner config from Redis (admin-pushed)
    async def _ml_config_sync_loop():
        """Periodically check Redis for ML scanner config changes."""
        import json as _json
        import redis as _redis
        last_version = 0
        r = None
        if settings.redis_url:
            try:
                kwargs = {"decode_responses": True, "socket_timeout": 2}
                if settings.redis_url.startswith("rediss://") and settings.redis_tls_insecure:
                    import ssl
                    kwargs["ssl_cert_reqs"] = ssl.CERT_NONE
                r = _redis.from_url(settings.redis_url, **kwargs)
                r.ping()
            except Exception:
                r = None
        while True:
            await asyncio.sleep(5)
            if not r:
                continue
            try:
                ver = r.get("sentinel:ml_scanners:version")
                if ver and int(ver) > last_version:
                    raw = r.get("sentinel:ml_scanners:config")
                    if raw:
                        config = _json.loads(raw)
                        pipeline.apply_ml_config(config)
                        last_version = int(ver)
            except Exception:
                pass

    app.state._ml_sync_task = asyncio.create_task(_ml_config_sync_loop())

    await logger.ainfo(
        "sentinel-gateway ready",
        policies=app.state.policy_loader.count,
        iocs=app.state.ioc_manager.count,
        agents=app.state.agent_registry.count,
    )
    yield
    # Shutdown
    app.state._ml_sync_task.cancel()
    await app.state.scanner_pipeline.shutdown()
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
