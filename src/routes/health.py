"""Health check endpoints including Red Team testing interface."""

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from src.guardrails.input_guardrail import InputGuardrail
from src.guardrails.output_filter import OutputFilter
from src.models import Verdict

router = APIRouter()

# C-03: Red team endpoint disabled by default in production
REDTEAM_ENABLED = os.getenv("BULWARK_REDTEAM_ENABLED", "false").lower() in ("true", "1")

# Pre-instantiate guardrails for redteam testing (avoids import on each request)
_redteam_input = InputGuardrail()
_redteam_output = OutputFilter()

REPORTS_DIR = Path("reports/redteam")


@router.get("/health")
async def health():
    return {"status": "ok", "service": "bulwark-gateway"}


@router.get("/health/live")
async def health_live():
    """Liveness probe — process is running."""
    return {"status": "alive"}


@router.get("/health/telemetry")
async def telemetry_stats(request: Request):
    """Telemetry pipeline stats: queue depth, export counts, circuit breakers.
    Requires authentication (H-13)."""
    # Auth enforced by AuthMiddleware (removed from PUBLIC_PATHS)
    from src.telemetry.exporter import get_exporter

    exporter = get_exporter()
    return JSONResponse(content=exporter.stats)


@router.get("/health/stats")
async def proxy_stats(request: Request):
    """Live request counters: verdicts, latency percentiles, throughput.
    Requires authentication (C-05/H-13)."""
    # C-05: Explicit auth verification (defense-in-depth)
    if not getattr(request.state, "tenant_id", None):
        raise HTTPException(status_code=401, detail="Authentication required")
    from src.telemetry.counters import get_counters, merge_global_counters

    counters = get_counters()
    snapshot = counters.snapshot()

    # In-process counters are per-worker (uvicorn --workers N). Overlay the
    # authoritative cross-worker/replica totals from Redis global counters so
    # /health/stats reports true cluster-wide numbers, not one worker's slice.
    try:
        from src.guardrails.dynamic_registry import get_pattern_registry
        redis_client = get_pattern_registry()._redis
    except Exception:
        redis_client = None
    snapshot = merge_global_counters(snapshot, redis_client)

    return JSONResponse(content=snapshot)


@router.get("/health/cost")
async def cost_usage(request: Request):
    """Token usage and cost tracking per tenant.
    Requires authentication (H-13)."""
    if not getattr(request.state, "tenant_id", None):
        raise HTTPException(status_code=401, detail="Authentication required")

    from src.services.cost_tracker import get_cost_tracker
    tracker = get_cost_tracker()

    tenant_id = request.state.tenant_id
    tenant_usage = tracker.get_tenant_usage(tenant_id)
    global_usage = tracker.get_global_usage()

    return JSONResponse(content={
        "tenant": {
            "tenant_id": tenant_usage.tenant_id,
            "prompt_tokens": tenant_usage.prompt_tokens,
            "completion_tokens": tenant_usage.completion_tokens,
            "total_tokens": tenant_usage.total_tokens,
            "total_requests": tenant_usage.total_requests,
            "estimated_cost_usd": tenant_usage.estimated_cost_usd,
        },
        "global": global_usage,
    })


@router.get("/ready")
async def ready(request: Request):
    """Readiness check — validates core dependencies are functional.

    RELIABILITY (M-12 fix): Now checks Redis connectivity and IOC database
    in addition to policy loading, providing meaningful readiness signal.
    """
    policy_count = getattr(request.app.state, "policy_loader", None)
    ioc_count = getattr(request.app.state, "ioc_manager", None)
    policies_ok = policy_count and policy_count.count > 0
    iocs_ok = ioc_count and ioc_count.count > 0

    # Check Redis connectivity (if configured)
    redis_ok = True
    try:
        from src.config import settings
        if settings.redis_url:
            import redis as _redis_mod
            r = _redis_mod.from_url(str(settings.redis_url), socket_timeout=2)
            r.ping()
    except Exception:
        redis_ok = False

    is_ready = bool(policies_ok and iocs_ok and redis_ok)
    return {
        "status": "ready" if is_ready else "not_ready",
        "checks": {
            "policies": bool(policies_ok),
            "iocs": bool(iocs_ok),
            "redis": redis_ok,
        },
    }


@router.get("/internal/scanners/status")
async def internal_scanner_status(request: Request):
    """Internal endpoint for admin pod to query scanner pipeline state.

    No auth required — network-level isolation enforced by K8s NetworkPolicies.
    Only admin pods can reach this via ClusterIP service.

    Returns: registered scanners, health, lane counts, ML model status.
    """
    from src.scanners.pipeline import get_scanner_pipeline
    from src.config import settings

    pipeline = get_scanner_pipeline()

    # Get scanner list with metrics
    scanners = pipeline.list_scanners()

    # Run health checks (model loaded, warm, etc.)
    health_results = await pipeline.health_check()

    # Enrich scanner info with health status
    for scanner_info in scanners:
        scanner_info["healthy"] = health_results.get(scanner_info["name"], False)

    return JSONResponse(content={
        "status": "ok",
        "ml_enabled": settings.ml_enabled,
        "ml_blocking": settings.ml_blocking,
        "ml_timeout_ms": settings.ml_timeout_ms,
        "rag_enabled": settings.rag_enabled,
        "multilingual_enabled": settings.multilingual_enabled,
        "lanes": {
            "input_blocking": pipeline.input_blocking_count,
            "input_async": pipeline.input_async_count,
            "output_blocking": pipeline.output_blocking_count,
            "output_async": pipeline.output_async_count,
            "total": pipeline.total_count,
        },
        "scanners": scanners,
    })


@router.post("/internal/evaluation/run")
async def internal_evaluation_run(request: Request):
    """Internal endpoint for the admin pod to run a red-team evaluation against
    the REAL scanner pipeline (with ML/multilingual/RAG models loaded).

    No auth required — network-level isolation enforced by K8s NetworkPolicies,
    identical to /internal/scanners/status. Only admin pods can reach this via
    the ClusterIP service.

    The admin pod has no ML dependencies or models, so evaluating there only ever
    exercises the regex floor. Delegating here lets the benchmark measure the
    defense that actually protects production traffic.

    Body (all optional):
      {
        "categories": ["prompt_injection", ...] | null,   # null = default set
        "count_per_category": 5,
        "include_benign": true
      }

    Returns the serialized EvaluationReport (same shape the admin API returns),
    stamped with pipeline_source="proxy-full-pipeline".
    """
    from src.evaluation.harness import run_evaluation_report
    from src.models import ThreatCategory
    from src.scanners.pipeline import get_scanner_pipeline

    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}

    # Resolve requested categories; unknown names are rejected explicitly so a
    # typo does not silently shrink the tested surface.
    raw_categories = body.get("categories")
    categories: list[ThreatCategory] | None
    if raw_categories is None:
        categories = None
    else:
        if not isinstance(raw_categories, list):
            raise HTTPException(status_code=400, detail="categories must be a list or null")
        categories = []
        for name in raw_categories:
            try:
                categories.append(ThreatCategory(name))
            except ValueError:
                raise HTTPException(
                    status_code=400, detail=f"Unknown category: '{name}'"
                ) from None

    # Bound count so a caller cannot request an unbounded generation workload.
    try:
        count = int(body.get("count_per_category", 5))
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=400, detail="count_per_category must be an integer"
        ) from None
    count = max(1, min(count, 200))
    include_benign = bool(body.get("include_benign", True))

    pipeline = get_scanner_pipeline()
    result = await run_evaluation_report(
        pipeline,
        categories=categories,
        count_per_category=count,
        include_benign=include_benign,
    )
    result["pipeline_source"] = "proxy-full-pipeline"
    return JSONResponse(content=result)


@router.post("/internal/evaluation/corpus")
async def internal_evaluation_corpus(request: Request):
    """Internal endpoint: evaluate the REAL pipeline against the EXTERNAL labeled
    corpora (ground truth), not gateway-authored attacks.

    Same trust model as /internal/evaluation/run — no auth, network-isolated by
    K8s NetworkPolicies. The corpora ship in the image (src/evaluation/data/), so
    the proxy always has a hermetic floor; an operator can widen it with
    $BULWARK_EVAL_DATASET_DIR.

    Body (all optional):
      {
        "sources": ["advbench", ...] | null,   # null = all bundled sources
        "limit_per_source": 50 | null,          # null = no cap
        "include_external_dir": true            # false = bundled floor only
      }

    Returns the serialized corpus report (verdict-scored confusion matrices +
    corpus_stats provenance + per_source recall), stamped with
    pipeline_source="proxy-full-pipeline". Returns 400 if the corpus is empty
    (misconfigured dataset dir) so a caller never sees a benchmark that ran on
    nothing.
    """
    from src.evaluation.harness import run_corpus_report
    from src.scanners.pipeline import get_scanner_pipeline

    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}

    raw_sources = body.get("sources")
    sources: list[str] | None
    if raw_sources is None:
        sources = None
    elif isinstance(raw_sources, list) and all(isinstance(s, str) for s in raw_sources):
        sources = raw_sources
    else:
        raise HTTPException(
            status_code=400, detail="sources must be a list of strings or null"
        )

    raw_limit = body.get("limit_per_source")
    limit_per_source: int | None
    if raw_limit is None:
        limit_per_source = None
    else:
        try:
            limit_per_source = int(raw_limit)
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=400, detail="limit_per_source must be an integer or null"
            ) from None
        if limit_per_source < 1:
            raise HTTPException(
                status_code=400, detail="limit_per_source must be >= 1"
            )

    # include_external_dir=false forces the hermetic bundled floor (external_dir=None);
    # true (default) honors $BULWARK_EVAL_DATASET_DIR via the sentinel default.
    include_external_dir = bool(body.get("include_external_dir", True))
    external_dir = ... if include_external_dir else None

    pipeline = get_scanner_pipeline()
    try:
        result = await run_corpus_report(
            pipeline,
            sources=sources,
            limit_per_source=limit_per_source,
            external_dir=external_dir,  # type: ignore[arg-type]
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None
    result["pipeline_source"] = "proxy-full-pipeline"
    return JSONResponse(content=result)


@router.post("/health/redteam")
async def redteam_test(request: Request):
    """
    Red Team testing endpoint — accepts adversarial payloads for guardrail validation.

    SECURITY: Requires authentication (JWT/API key) AND BULWARK_REDTEAM_ENABLED=true.
    Disabled by default in production (C-03).

    Accepts JSON body:
      {
        "module": "input" | "output" | "both",
        "payloads": ["payload1", "payload2", ...],
        "category": "prompt_injection" (optional, for labeling)
      }

    Returns per-payload results with verdicts and latency.
    Does NOT forward to backend — only tests guardrails locally.
    """
    # C-03: Feature flag check
    if not REDTEAM_ENABLED:
        raise HTTPException(
            status_code=403,
            detail="Red team endpoint is disabled. Set BULWARK_REDTEAM_ENABLED=true to enable.",
        )

    # C-03: Require authenticated request (enforced by AuthMiddleware since not in PUBLIC_PATHS)
    # Additional check: verify request passed auth (has tenant_id in state)
    if not getattr(request.state, "tenant_id", None):
        raise HTTPException(
            status_code=401,
            detail="Red team endpoint requires authentication",
        )

    # Gate: require redteam header
    if request.headers.get("X-Redteam-Mode") != "true":
        raise HTTPException(
            status_code=403,
            detail="Red team endpoint requires X-Redteam-Mode: true header",
        )

    body = await request.json()
    module = body.get("module", "input")
    payloads = body.get("payloads", [])
    # Sanitize category: alphanumeric, hyphens, underscores only (prevent path traversal)
    import re
    raw_category = body.get("category", "unknown")
    category = re.sub(r'[^a-zA-Z0-9_\-]', '', raw_category)[:64] or "unknown"
    tenant_id = request.headers.get("X-Tenant-ID", "redteam-test")
    agent_id = request.headers.get("X-Agent-ID", "redteam-tester")

    if not payloads:
        raise HTTPException(status_code=400, detail="No payloads provided")

    results = []
    for payload in payloads:
        start = time.perf_counter_ns()

        if module in ("input", "both"):
            input_result = _redteam_input.inspect(payload, tenant_id, agent_id)
            verdict = input_result.verdict.value
            events = [e.description for e in input_result.events]
        else:
            input_result = None
            verdict = None
            events = []

        if module in ("output", "both"):
            output_result = _redteam_output.inspect_and_redact(payload, tenant_id, agent_id)
            output_verdict = output_result.verdict.value
            output_events = [e.description for e in output_result.events]
            if module == "both" and output_result.verdict == Verdict.REDACT:
                verdict = "redact"
                events.extend(output_events)
            elif module == "output":
                verdict = output_verdict
                events = output_events
        else:
            output_result = None

        latency_ms = (time.perf_counter_ns() - start) / 1e6

        results.append(
            {
                "payload": payload[:200],
                "verdict": verdict,
                "blocked": verdict == "block",
                "events": events,
                "latency_ms": round(latency_ms, 3),
            }
        )

    # Summary
    total = len(results)
    blocked = sum(1 for r in results if r["blocked"])
    bypassed = total - blocked
    avg_latency = sum(r["latency_ms"] for r in results) / total if total else 0

    summary = {
        "total_payloads": total,
        "blocked": blocked,
        "bypassed": bypassed,
        "block_rate": round(blocked / total, 4) if total else 0,
        "avg_latency_ms": round(avg_latency, 3),
        "category": category,
        "module": module,
    }

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "skill": f"redteam-{category}",
        "target": str(request.url),
        "summary": summary,
        "results": results,
        "bypasses": [r for r in results if not r["blocked"]],
    }

    # Persist report if reports dir exists
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    report_path = REPORTS_DIR / f"{ts}-{category}.json"
    report_path.write_text(json.dumps(report, indent=2))

    return JSONResponse(
        content={
            "summary": summary,
            "results": results,
            "report_path": str(report_path),
        }
    )
