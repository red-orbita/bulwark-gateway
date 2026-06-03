"""Health & Metrics routes."""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import StreamingResponse

from ..models.auth import TokenPayload, ROLE_PERMISSIONS
from ..services.auth_service import AuthService, get_current_user, require_permission
from ..services.prometheus_client import get_metrics

router = APIRouter()


@router.get("/sse-token")
async def get_sse_token(user: TokenPayload = Depends(require_permission("admin:read"))):
    """Issue a short-lived (60s) token for SSE connections.

    Clients should call this endpoint and use the returned token as
    ?token=<sse_token> in the EventSource URL, avoiding exposure of
    the long-lived session JWT in URL query params / server logs.
    """
    from ..models.auth import UserRole
    role = UserRole(user.role)
    token = AuthService.create_sse_token(user.sub, role)
    return {"token": token, "expires_in": 60}


# Proxy URL for fetching telemetry (internal network)
PROXY_URL = os.getenv("SENTINEL_PROXY_URL", "http://proxy:8080")

def _load_proxy_api_key() -> str:
    """Load proxy API key from file or env."""
    key_file = os.getenv("SENTINEL_PROXY_API_KEY_FILE", "")
    if key_file and os.path.isfile(key_file):
        with open(key_file) as f:
            # api_keys file may have multiple lines; use first non-empty
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    return line
    return os.getenv("SENTINEL_PROXY_API_KEY", "")


@router.get("")
async def health_check():
    """Admin portal health (minimal info for unauthenticated callers)."""
    return {"status": "healthy"}


@router.get("/detailed")
async def health_detailed(_user: TokenPayload = Depends(require_permission("admin:read"))):
    """Detailed health with metrics — requires authentication."""
    metrics = get_metrics()
    s = metrics.snapshot()
    # Also try to fetch proxy stats
    proxy_stats = await _fetch_proxy_telemetry()
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": s.uptime_seconds,
        "requests_total": proxy_stats.get("requests_total", 0),
        "blocked": proxy_stats.get("blocked", 0),
        "queue_depth": s.queue_depth_memory,
        "circuit_breaker": s.circuit_breaker_state,
        "proxy": proxy_stats,
    }


@router.get("/metrics")
async def prometheus_metrics(_user: TokenPayload = Depends(require_permission("admin:read"))):
    """Prometheus exposition format endpoint — requires auth."""
    metrics = get_metrics()
    return Response(
        content=metrics.to_prometheus_text(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@router.get("/stream")
async def metrics_stream(request: Request, token: Optional[str] = Query(None)):
    """Server-Sent Events (SSE) for real-time dashboard updates.

    Accepts auth via query param ?token=<jwt> since EventSource can't send headers.
    Merges admin metrics with proxy telemetry for unified dashboard.
    """
    # Validate auth: try query param token, then header
    auth_token = token
    if not auth_token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            auth_token = auth_header[7:]

    if not auth_token:
        return Response(status_code=401, content="Unauthorized")

    try:
        user = AuthService.verify_token(auth_token)
        if not user:
            return Response(status_code=401, content="Invalid token")
        perms = ROLE_PERMISSIONS.get(user.role, set())
        if "admin:read" not in perms:
            return Response(status_code=403, content="Forbidden")
    except Exception:
        return Response(status_code=401, content="Invalid token")

    async def event_generator():
        metrics = get_metrics()
        while True:
            if await request.is_disconnected():
                break
            snapshot = metrics.snapshot()
            data = snapshot.model_dump()

            # Merge proxy stats
            proxy_stats = await _fetch_proxy_telemetry()
            if proxy_stats:
                data["requests_total"] = proxy_stats.get("requests_total", 0)
                data["requests_per_second"] = proxy_stats.get("requests_per_second", 0)
                data["queue_depth_memory"] = proxy_stats.get("requests_total", 0)  # reuse for display
                data["events_blocked"] = proxy_stats.get("blocked", 0)
                data["events_warned"] = proxy_stats.get("warned", 0)
                data["events_allowed"] = proxy_stats.get("allowed", 0)
                data["latency_p50_ms"] = proxy_stats.get("latency_p50_ms", 0)
                data["latency_p95_ms"] = proxy_stats.get("latency_p95_ms", 0)
                data["latency_p99_ms"] = proxy_stats.get("latency_p99_ms", 0)
                # Bypass rate: allowed / total (only set if there's real traffic)
                total = proxy_stats.get("requests_total", 0)
                allowed = proxy_stats.get("allowed", 0)
                if total > 0:
                    data["bypass_rate"] = round((allowed / total) * 100, 1)
                else:
                    # Don't override — let frontend use persisted red team value
                    data.pop("bypass_rate", None)
                # False positive rate: approximated as warned / (blocked + warned)
                blocked = proxy_stats.get("blocked", 0)
                warned = proxy_stats.get("warned", 0)
                data["false_positive_rate"] = round((warned / (blocked + warned)) * 100, 1) if (blocked + warned) > 0 else 0.0
            else:
                # No proxy stats — remove bypass_rate so frontend keeps persisted value
                data.pop("bypass_rate", None)

            yield f"data: {json.dumps(data, default=str)}\n\n"
            await asyncio.sleep(2)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


async def _fetch_proxy_telemetry() -> dict:
    """Fetch live request counters from the proxy service."""
    try:
        headers = {}
        api_key = _load_proxy_api_key()
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(f"{PROXY_URL}/health/stats", headers=headers)
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return {}


@router.get("/recent-blocks")
async def recent_blocks(
    limit: int = Query(10, ge=1, le=50),
    user: TokenPayload = Depends(require_permission("guardrails:read")),
):
    """Get recent blocked attacks from Redis."""
    try:
        import redis as _redis
        redis_url = os.getenv("SENTINEL_REDIS_URL", "")
        if not redis_url:
            return []
        pw_file = os.getenv("SENTINEL_REDIS_PASSWORD_FILE", "")
        password = None
        if pw_file:
            try:
                password = open(pw_file).read().strip()
            except Exception:
                pass
        r = _redis.from_url(redis_url, password=password, decode_responses=True, socket_timeout=1.0)
        raw = r.lrange("sentinel:recent_blocks", 0, limit - 1)
        return [json.loads(item) for item in raw]
    except Exception:
        return []


@router.get("/redteam-bypass-rate")
async def redteam_bypass_rate(
    user: TokenPayload = Depends(require_permission("admin:read")),
):
    """Get bypass rate from the latest red team prompt_injection report (persisted)."""
    import glob as _glob
    import pathlib

    reports_dir = pathlib.Path(__file__).resolve().parents[2] / "reports" / "redteam"
    if not reports_dir.exists():
        return {"bypass_rate": 0.0, "total_payloads": 0, "bypassed": 0, "report": None}

    # Find most recent prompt_injection report
    pattern = str(reports_dir / "*-prompt_injection.json")
    files = sorted(_glob.glob(pattern), reverse=True)
    if not files:
        return {"bypass_rate": 0.0, "total_payloads": 0, "bypassed": 0, "report": None}

    try:
        with open(files[0]) as f:
            report = json.load(f)
        summary = report.get("summary", {})
        total = summary.get("total_payloads", 0)
        bypassed = summary.get("bypassed", 0)
        bypass_rate = round((bypassed / total) * 100, 1) if total > 0 else 0.0
        return {
            "bypass_rate": bypass_rate,
            "total_payloads": total,
            "bypassed": bypassed,
            "report": os.path.basename(files[0]),
            "timestamp": report.get("timestamp"),
        }
    except Exception:
        return {"bypass_rate": 0.0, "total_payloads": 0, "bypassed": 0, "report": None}


@router.get("/tenant-usage")
async def tenant_usage(
    user: TokenPayload = Depends(require_permission("guardrails:read")),
):
    """Get per-tenant usage stats from Redis."""
    try:
        import redis as _redis
        redis_url = os.getenv("SENTINEL_REDIS_URL", "")
        if not redis_url:
            return {}
        pw_file = os.getenv("SENTINEL_REDIS_PASSWORD_FILE", "")
        password = None
        if pw_file:
            try:
                password = open(pw_file).read().strip()
            except Exception:
                pass
        r = _redis.from_url(redis_url, password=password, decode_responses=True, socket_timeout=1.0)
        total = r.hgetall("sentinel:usage:total") or {}
        blocked = r.hgetall("sentinel:usage:block") or {}
        allowed = r.hgetall("sentinel:usage:allow") or {}
        result = {}
        for tenant in total:
            result[tenant] = {
                "total": int(total.get(tenant, 0)),
                "blocked": int(blocked.get(tenant, 0)),
                "allowed": int(allowed.get(tenant, 0)),
            }
        return result
    except Exception:
        return {}
