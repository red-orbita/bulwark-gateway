"""
Bulwark Gateway — Main application entry point.

Architecture:
  User Request → Auth → Input Guardrail → Tool Policy → LLM/Agent Backend
  Agent Response → Output Filter → User

Modes:
  1. Proxy mode: sits between user and agent API (OpenAI-compatible)
  2. Sidecar mode: called by the agent framework before/after tool execution
"""

import asyncio
from contextlib import asynccontextmanager

import structlog
import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.config import settings, validate_settings
from src.middleware.api_version import APIVersionMiddleware
from src.middleware.auth import AuthMiddleware
from src.middleware.quotas import QuotaMiddleware
from src.middleware.rate_limit import RateLimitMiddleware
from src.middleware.request_id import RequestIDMiddleware
from src.middleware.tenant_router import TenantRouterMiddleware
from src.routes import admin, health, proxy
from src.routes.v2 import router as v2_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    import structlog

    validate_settings()

    # Initialize OpenTelemetry tracing (before other components to capture full lifecycle)
    from src.telemetry.tracing import init_tracing

    init_tracing()

    logger = structlog.get_logger()
    await logger.ainfo("bulwark-gateway starting", version="1.0.0", mode=settings.mode)

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

    # Initialize the correlation risk-state store (input↔output correlation).
    # No-op-cheap when correlation is disabled; the store simply stays empty.
    from src.correlation.risk_state import get_risk_state_store

    risk_store = get_risk_state_store()
    risk_store.initialize(
        redis_url=settings.redis_url,
        redis_tls_insecure=settings.redis_tls_insecure,
        decay_seconds=settings.correlation_risk_decay_seconds,
    )
    await logger.ainfo(
        "correlation_risk_state_initialized",
        enabled=settings.correlation_enabled,
        blocking=settings.correlation_blocking,
        redis=bool(settings.redis_url),
    )

    # Initialize the runtime-tunable correlation config (admin can override
    # thresholds/weights via Redis without a restart). Cheap; degrades to the
    # static settings defaults when Redis is unavailable.
    from src.correlation.runtime import get_correlation_runtime

    get_correlation_runtime().initialize(
        redis_url=settings.redis_url,
        redis_tls_insecure=settings.redis_tls_insecure,
    )

    # Start the correlation event tap (feedback loop) only when correlation is
    # enabled — otherwise it stays fully idle (zero cost).
    app.state.correlation_tap = None
    if settings.correlation_enabled:
        from src.correlation.event_tap import get_event_tap

        _corr_tap = get_event_tap()
        _corr_tap.start()
        app.state.correlation_tap = _corr_tap
        await logger.ainfo("correlation_event_tap_started")

    # Register enrichment scanners (async, background only)
    from src.enrichment.manager import ENRICHMENT_ENABLED, get_enrichment_manager

    if ENRICHMENT_ENABLED:
        enrichment_mgr = get_enrichment_manager()
        # Ensure replay DB directory exists at startup
        from src.enrichment.attack_replay_db import REPLAY_DB_PATH
        REPLAY_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        # Pre-initialize replay DB (creates tables)
        from src.enrichment.attack_replay_db import get_attack_replay_db
        get_attack_replay_db()
        await logger.ainfo("enrichment_replay_db_ready", path=str(REPLAY_DB_PATH))

        # Try to register ML enrichment scanners (optional — graceful degradation)
        try:
            from src.enrichment.embedding_scanner import EmbeddingScanner
            scanner = EmbeddingScanner()
            # Pre-initialize model at startup (avoids timeout on first request)
            if scanner._ensure_initialized():
                enrichment_mgr.register(scanner)
                await logger.ainfo("enrichment_ml_scanner_registered", scanners=len(enrichment_mgr.scanners))
            else:
                await logger.ainfo("enrichment_ml_scanner_unavailable",
                                   reason="sentence-transformers not installed, replay DB still active")
        except Exception as e:
            await logger.awarn("enrichment_ml_init_failed", error=str(e),
                             note="Replay DB recording active without ML enrichment")

    # Initialize Scanner Pipeline (pluggable scanner framework)
    from src.scanners.builtin import register_builtin_scanners
    from src.scanners.discovery import discover_all_scanners, instantiate_scanner
    from src.scanners.pipeline import get_scanner_pipeline

    pipeline = get_scanner_pipeline()

    # Register the always-on GA built-in scanners (SSOT: shared with the
    # evaluation CLI / SDK so scanner coverage never drifts between entrypoints).
    register_builtin_scanners(pipeline, policy_engine=app.state.policy_loader.engine)

    # Register ML scanners (async by default, no latency impact unless ml_blocking=true)
    #
    # P0 landmine fix: only register an ML scanner if its model is actually
    # provisioned on disk. A blocking scanner with no loaded model fails-closed
    # and would BLOCK EVERY request — so registering a scanner whose model has no
    # download path while ml_blocking=True would brick the gateway. Missing-model
    # scanners are skipped (with a loud warning) instead.
    if settings.ml_enabled:
        from src.scanners.ml import InjectionClassifier, ToxicityScanner
        from src.scanners.ml.model_manager import ml_dependencies_available, model_files_present

        # (model subdir, scanner class) — subdir matches each scanner's MODEL_NAME
        ml_specs = [
            ("injection-classifier", InjectionClassifier),
            ("toxicity", ToxicityScanner),
        ]

        if not ml_dependencies_available():
            await logger.awarn(
                "ml_scanners_skipped",
                reason="ML dependencies not installed (numpy/onnxruntime/tokenizers)",
            )
        else:
            registered_ml: list[str] = []
            skipped_ml: list[str] = []
            for subdir, scanner_cls in ml_specs:
                if model_files_present(subdir):
                    pipeline.register(scanner_cls())
                    registered_ml.append(subdir)
                else:
                    skipped_ml.append(subdir)
            if skipped_ml:
                await logger.awarn(
                    "ml_scanners_unavailable",
                    skipped=skipped_ml,
                    reason="model files not provisioned — run scripts/download-models.py",
                )
            if registered_ml:
                await logger.ainfo(
                    "ml_scanners_registered",
                    registered=registered_ml,
                    blocking=settings.ml_blocking,
                )

    # Register GA Guard Lite sidecar scanner (opt-in, default off). Independent of
    # BULWARK_ML_ENABLED — it ships no local weights, delegating classification to
    # an operator-provisioned sidecar over HTTP (httpx, a core dep). INPUT_ASYNC
    # (WARN-only) unless BULWARK_GA_GUARD_BLOCKING=true. A request-time sidecar
    # error fails-OPEN (ALLOW); a blocking scanner whose sidecar is unreachable at
    # boot is caught by the readiness backstop below via health()=False.
    if settings.ga_guard_enabled:
        from src.scanners.ml import GaGuardScanner
        pipeline.register(GaGuardScanner())
        await logger.ainfo(
            "ga_guard_scanner_registered",
            blocking=settings.ga_guard_blocking,
            url=settings.ga_guard_url,
        )

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

    # Register structured-output Schema Validator (opt-in, default off).
    # Model-free OUTPUT_BLOCKING scanner (jsonschema is a core dep). It stays inert
    # (ALLOW) for any agent without an `output_validation` policy block, so the only
    # cost of enabling it is a per-request dict lookup on agents that opt in.
    if settings.schema_validation_enabled:
        from src.scanners.output.schema_validator import SchemaValidator
        pipeline.register(SchemaValidator())
        await logger.ainfo("schema_validator_registered")

    # Register embedding-based Relevance Scanner (opt-in, default off).
    # OUTPUT_ASYNC (fire-and-forget) scanner backed by the provisioned
    # `sentence-embeddings` ONNX model — no LLM call, runs off the response hot
    # path. It stays inert (ALLOW) for any agent without an
    # `output_validation.relevance_check` policy, and no-ops entirely if the
    # model is not provisioned, so enabling the flag alone carries no cost.
    if settings.relevance_scanning_enabled:
        from src.scanners.output.relevance_scanner import RelevanceScanner
        pipeline.register(RelevanceScanner())
        await logger.ainfo("relevance_scanner_registered")

    # Register NLI-based output scanners (opt-in, default off). Both share the
    # provisioned nli-classifier ONNX model and run OUTPUT_ASYNC (fire-and-forget,
    # off the hot path). They stay inert (ALLOW) until the model loads and the
    # agent opts in, so enabling the flag alone carries no behavioural cost.
    if settings.hallucination_scanning_enabled:
        from src.scanners.output.hallucination_scanner import HallucinationScanner
        pipeline.register(HallucinationScanner())
        await logger.ainfo("hallucination_scanner_registered")

    if settings.grounding_scanning_enabled:
        from src.scanners.output.grounding_scanner import GroundingScanner
        pipeline.register(GroundingScanner())
        await logger.ainfo("grounding_scanner_registered")

    # Register deterministic Image Hygiene Scanner (opt-in, default off).
    # INPUT_ASYNC (fire-and-forget), zero-dependency model-free guards over inline
    # data:image URIs in text (allow_images policy gate, DoS size limit, base64 +
    # magic-byte format validation). No OCR/pillow needed — ships BETA. It returns
    # ALLOW immediately when a message carries no image, so the only cost of
    # enabling it is a cheap data-URI scan on requests that contain one.
    if settings.image_hygiene_scanning_enabled:
        from src.scanners.multimodal.image_hygiene_scanner import ImageHygieneScanner
        pipeline.register(ImageHygieneScanner())
        await logger.ainfo("image_hygiene_scanner_registered")

    # Register multimodal Vision Scanner (opt-in, default off). INPUT_ASYNC
    # (fire-and-forget). Its eponymous OCR image-content-analysis layer stays inert
    # unless pillow + an OCR backend are installed, so enabling the flag alone
    # carries no hot-path cost. For deterministic image hygiene without OCR, enable
    # the ImageHygieneScanner via BULWARK_IMAGE_HYGIENE_SCANNING_ENABLED.
    if settings.vision_scanning_enabled:
        from src.scanners.multimodal.vision_scanner import VisionScanner
        pipeline.register(VisionScanner())
        await logger.ainfo("vision_scanner_registered")

    # Register binary Artifact Output Scanner (opt-in, default off). OUTPUT_ASYNC
    # (fire-and-forget, off the response hot path) DETECTIVE control: it decodes
    # inline base64 blobs / data: URIs in the LLM response and runs the shared
    # stdlib pickle-opcode engine (never deserializes) over the bytes, emitting a
    # WARN event when a serialized artifact carries a load-time RCE gadget. It
    # never blocks or rewrites the response — base64 in responses is often benign,
    # so the threat is alerted, not blocked. Zero external deps, so no provisioning.
    if settings.artifact_output_scanning_enabled:
        from src.scanners.output.artifact_scanner import ArtifactOutputScanner
        pipeline.register(ArtifactOutputScanner())
        await logger.ainfo("artifact_output_scanner_registered")

    # Discover and register third-party plugins
    if settings.scanners_dir.exists():
        discovered = discover_all_scanners(settings.scanners_dir)
        for cls in discovered:
            try:
                plugin_scanner = instantiate_scanner(cls)
                pipeline.register(plugin_scanner)  # type: ignore[arg-type]
            except Exception as e:
                await logger.awarn("plugin_instantiation_failed", cls=cls.__name__, error=str(e))

    # Start all scanners (load models, warm caches)
    await pipeline.startup()

    # P0 backstop: after startup, no ENABLED blocking scanner may be unhealthy.
    # A blocking scanner whose model failed to load (e.g. integrity/hash failure
    # on a present-but-untrusted model) fails-closed and would BLOCK ALL traffic.
    # Turn that silent, total outage into an explicit boot decision driven by
    # BULWARK_FAIL_MODE: "closed" refuses to start with an actionable error;
    # "open" disables the degraded scanner(s) and serves on the regex floor.
    from src.scanners.pipeline import resolve_blocking_readiness

    degraded_blocking = await pipeline.unhealthy_blocking_scanners()
    action, message = resolve_blocking_readiness(degraded_blocking, settings.fail_mode)
    if action == "refuse":
        await logger.aerror("blocking_scanner_readiness_failed", degraded=degraded_blocking)
        raise RuntimeError(message)
    if action == "degrade":
        for _name in degraded_blocking:
            pipeline.disable(_name)
        await logger.aerror(
            "blocking_scanner_degraded",
            degraded=degraded_blocking,
            note=message,
        )

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
                ver = r.get("bulwark:ml_scanners:version")
                if ver and int(ver) > last_version:
                    raw = r.get("bulwark:ml_scanners:config")
                    if raw:
                        config = _json.loads(raw)
                        pipeline.apply_ml_config(config)
                        last_version = int(ver)
            except Exception as exc:
                await logger.awarning("ml_config_sync_failed", error=str(exc))

    app.state._ml_sync_task = asyncio.create_task(_ml_config_sync_loop())

    await logger.ainfo(
        "bulwark-gateway ready",
        policies=app.state.policy_loader.count,
        iocs=app.state.ioc_manager.count,
        agents=app.state.agent_registry.count,
    )
    yield
    # Shutdown
    app.state._ml_sync_task.cancel()
    corr_tap_shutdown = getattr(app.state, "correlation_tap", None)
    if corr_tap_shutdown is not None:
        await corr_tap_shutdown.stop()
    await app.state.scanner_pipeline.shutdown()
    await app.state.telemetry_exporter.stop()
    await app.state.policy_loader.stop_hot_reload()
    # Flush pending trace spans before exit
    from src.telemetry.tracing import shutdown_tracing

    shutdown_tracing()
    await logger.ainfo("bulwark-gateway shutting down")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Bulwark Gateway",
        description="Security guardrail proxy for AI agents",
        version="1.0.0",
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
        if request.url.path.startswith("/v1/") or request.url.path.startswith("/v2/"):
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

    # Middleware (order matters — last added = outermost = processes request first)
    # Request flow: RequestID → Auth → TenantRouter → APIVersion → RateLimit → Quota → CORS → Route handler
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
            "X-API-Version",
            "X-Request-ID",
        ],
        # Let browser clients read the correlation id echoed on the response.
        expose_headers=["X-Request-ID"],
    )
    app.add_middleware(QuotaMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(APIVersionMiddleware)
    # Tier 2: Route dedicated tenants to their own proxy pods
    # Only active if BULWARK_DEDICATED_TENANTS is configured
    if settings.dedicated_tenants:
        app.add_middleware(TenantRouterMiddleware)
    app.add_middleware(AuthMiddleware)
    # Outermost: mint/honour the per-request correlation id BEFORE auth so even
    # rejected requests are traceable and get the echoed X-Request-ID header.
    app.add_middleware(RequestIDMiddleware)

    # Routes
    app.include_router(health.router, tags=["health"])
    app.include_router(proxy.router, prefix="/v1", tags=["proxy"])
    app.include_router(v2_router, prefix="/v2", tags=["v2"])
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
