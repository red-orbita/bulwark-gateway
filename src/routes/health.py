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
REDTEAM_ENABLED = os.getenv("SENTINEL_REDTEAM_ENABLED", "false").lower() in ("true", "1")

# Pre-instantiate guardrails for redteam testing (avoids import on each request)
_redteam_input = InputGuardrail()
_redteam_output = OutputFilter()

REPORTS_DIR = Path("reports/redteam")


@router.get("/health")
async def health():
    return {"status": "ok", "service": "sentinel-gateway"}


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
    from src.telemetry.counters import get_counters

    counters = get_counters()
    return JSONResponse(content=counters.snapshot())


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


@router.post("/health/redteam")
async def redteam_test(request: Request):
    """
    Red Team testing endpoint — accepts adversarial payloads for guardrail validation.

    SECURITY: Requires authentication (JWT/API key) AND SENTINEL_REDTEAM_ENABLED=true.
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
            detail="Red team endpoint is disabled. Set SENTINEL_REDTEAM_ENABLED=true to enable.",
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
