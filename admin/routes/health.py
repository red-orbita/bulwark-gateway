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
from ..services.auth_service import AuthService, require_permission
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
# Use FQDN with trailing dot to bypass ndots search in K8s
_raw_proxy_url = os.getenv("SENTINEL_PROXY_URL", "http://proxy:8080")
PROXY_URL = _raw_proxy_url

# SSE interval — how often to push updates (seconds)
SSE_INTERVAL = float(os.getenv("SENTINEL_SSE_INTERVAL", "5"))

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


_redis_health_cache: dict = {"data": {"status": "unknown"}, "ts": 0.0}
_REDIS_HEALTH_TTL = 10.0  # Cache Redis health for 10s


def _check_redis_health() -> dict:
    """Check Redis connectivity and return status info (uses pooled connection, cached)."""
    import time as _t
    now = _t.monotonic()
    if now - _redis_health_cache["ts"] < _REDIS_HEALTH_TTL:
        return _redis_health_cache["data"]
    try:
        from ..services.redis_sync import get_redis_client
        r = get_redis_client(timeout=1.0)
        if r is None:
            result = {"status": "not_configured"}
        else:
            start = _t.perf_counter()
            r.ping()
            latency = round((_t.perf_counter() - start) * 1000, 1)
            pipe = r.pipeline(transaction=False)
            pipe.info(section="server")
            pipe.info(section="memory")
            info, memory = pipe.execute()
            result = {
                "status": "connected",
                "latency_ms": latency,
                "version": info.get("redis_version", "unknown"),
                "memory": memory.get("used_memory_human", "unknown"),
            }
    except Exception as e:
        result = {"status": "disconnected", "error": str(e)}
    _redis_health_cache["data"] = result
    _redis_health_cache["ts"] = _t.monotonic()
    return result


@router.get("/detailed")
async def health_detailed(_user: TokenPayload = Depends(require_permission("admin:read"))):
    """Detailed health with metrics — requires authentication."""
    _ensure_bg_task()
    metrics = get_metrics()
    s = metrics.snapshot()
    # All data from cache (non-blocking, zero I/O in request path)
    proxy_stats, _ = _get_cached_telemetry()
    redis_info = _get_cached_redis_health()

    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": s.uptime_seconds,
        "requests_total": proxy_stats.get("requests_total", 0),
        "blocked": proxy_stats.get("blocked", 0),
        "queue_depth": s.queue_depth_memory,
        "circuit_breaker": s.circuit_breaker_state,
        "proxy": proxy_stats,
        "redis": redis_info.get("status", "unknown"),
        "redis_latency_ms": redis_info.get("latency_ms"),
        "redis_version": redis_info.get("version"),
        "redis_memory": redis_info.get("memory"),
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
        _ensure_bg_task()  # Start background refresh on first SSE connection
        metrics = get_metrics()
        while True:
            if await request.is_disconnected():
                break
            snapshot = metrics.snapshot()
            data = snapshot.model_dump()

            # Read from cache (instant, no I/O)
            proxy_stats, redis_counters = _get_cached_telemetry()
            if proxy_stats:
                # Rate/latency metrics from in-memory (current pod)
                data["requests_per_second"] = proxy_stats.get("requests_per_second", 0)
                data["latency_p50_ms"] = proxy_stats.get("latency_p50_ms", 0)
                data["latency_p95_ms"] = proxy_stats.get("latency_p95_ms", 0)
                data["latency_p99_ms"] = proxy_stats.get("latency_p99_ms", 0)
                # Cumulative counters: use Redis (persists across restarts),
                # fall back to in-memory if Redis unavailable
                blocked = redis_counters.get("blocked", 0) or proxy_stats.get("blocked", 0)
                warned = redis_counters.get("warned", 0) or proxy_stats.get("warned", 0)
                allowed = redis_counters.get("allowed", 0) or proxy_stats.get("allowed", 0)
                total = redis_counters.get("requests_total", 0) or proxy_stats.get("requests_total", 0)
                data["requests_total"] = total
                data["queue_depth_memory"] = total  # reuse for display
                data["events_blocked"] = blocked
                data["events_warned"] = warned
                data["events_allowed"] = allowed
                # Bypass rate: ONLY from red-team testing (persisted).
                # Live allowed/total is NOT a bypass rate — legit requests are
                # correctly allowed, not "bypasses".  Remove field so frontend
                # keeps the persisted red-team value loaded at init.
                data.pop("bypass_rate", None)
                # Detection rate: (blocked + warned) / total — shows guardrail trigger %
                data["detection_rate"] = round(((blocked + warned) / total) * 100, 1) if total > 0 else 0.0
                # False positive rate: approximated as warned / (blocked + warned)
                data["false_positive_rate"] = round((warned / (blocked + warned)) * 100, 1) if (blocked + warned) > 0 else 0.0
            elif redis_counters:
                # Proxy unreachable but Redis has persistent counters
                blocked = redis_counters.get("blocked", 0)
                warned = redis_counters.get("warned", 0)
                allowed = redis_counters.get("allowed", 0)
                total = redis_counters.get("requests_total", 0)
                data["requests_total"] = total
                data["events_blocked"] = blocked
                data["events_warned"] = warned
                data["events_allowed"] = allowed
                data["detection_rate"] = round(((blocked + warned) / total) * 100, 1) if total > 0 else 0.0
                data["false_positive_rate"] = round((warned / (blocked + warned)) * 100, 1) if (blocked + warned) > 0 else 0.0
                data.pop("bypass_rate", None)
            else:
                # No proxy stats, no Redis — remove bypass_rate so frontend keeps persisted value
                data.pop("bypass_rate", None)

            yield f"data: {json.dumps(data, default=str)}\n\n"
            await asyncio.sleep(SSE_INTERVAL)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ─── Telemetry Cache ─────────────────────────────────────────────────
# A background task refreshes telemetry data independently of SSE/requests.
# All SSE clients and API endpoints read from this cache (zero-latency).

import time as _time

_telemetry_cache: dict = {"proxy": {}, "redis": {}, "redis_health": {"status": "unknown"}, "ts": 0.0}
_CACHE_TTL = 4.0  # seconds between background refreshes
_bg_task_started = False


async def _background_telemetry_refresh():
    """Background loop that refreshes proxy+Redis data every CACHE_TTL seconds.

    Runs independently of request handlers — SSE and other endpoints
    only read from the cache, never make network calls themselves.
    Uses a persistent httpx client to avoid connection setup overhead.
    """
    global _telemetry_cache

    # Persistent client — reuses connections across iterations
    headers = {}
    api_key = _load_proxy_api_key()
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    client = httpx.AsyncClient(timeout=2.0, headers=headers)

    while True:
        try:
            # Fetch proxy stats (reuses persistent connection)
            proxy_stats = {}
            try:
                resp = await client.get(f"{PROXY_URL}/health/stats")
                if resp.status_code == 200:
                    proxy_stats = resp.json()
            except Exception:
                pass

            # Fetch Redis counters + health (in executor)
            redis_counters = {}
            redis_health = {"status": "unknown"}
            try:
                redis_counters, redis_health = await asyncio.get_event_loop().run_in_executor(
                    None, _fetch_redis_all_sync
                )
            except Exception:
                pass

            _telemetry_cache = {
                "proxy": proxy_stats,
                "redis": redis_counters,
                "redis_health": redis_health,
                "ts": _time.monotonic(),
            }
        except Exception:
            pass

        await asyncio.sleep(_CACHE_TTL)


def _ensure_bg_task():
    """Start the background telemetry refresh task if not already running."""
    global _bg_task_started
    if not _bg_task_started:
        _bg_task_started = True
        asyncio.get_event_loop().create_task(_background_telemetry_refresh())


def _get_cached_telemetry() -> tuple[dict, dict]:
    """Return (proxy_stats, redis_counters) from cache. Non-blocking, instant."""
    return _telemetry_cache.get("proxy", {}), _telemetry_cache.get("redis", {})


def _get_cached_redis_health() -> dict:
    """Return Redis health info from cache. Non-blocking, instant."""
    return _telemetry_cache.get("redis_health", {"status": "unknown"})


def _fetch_redis_all_sync() -> tuple[dict, dict]:
    """Fetch Redis counters + health in a single call (for background task)."""
    counters = {}
    health = {"status": "unknown"}
    try:
        from ..services.redis_sync import get_redis_client
        r = get_redis_client(timeout=1.0)
        if r is None:
            return {}, {"status": "not_configured"}

        import time as _t
        start = _t.perf_counter()
        # Pipeline: counters + ping in one round-trip
        pipe = r.pipeline(transaction=False)
        pipe.get("sentinel:global:requests_total")
        pipe.get("sentinel:global:block")
        pipe.get("sentinel:global:warn")
        pipe.get("sentinel:global:allow")
        pipe.ping()
        results = pipe.execute()

        latency = round((_t.perf_counter() - start) * 1000, 1)
        counters = {
            "requests_total": int(results[0] or 0),
            "blocked": int(results[1] or 0),
            "warned": int(results[2] or 0),
            "allowed": int(results[3] or 0),
        }

        # Get Redis version/memory (less frequent, but included since we have the connection)
        info = r.info(section="server")
        memory = r.info(section="memory")
        health = {
            "status": "connected",
            "latency_ms": latency,
            "version": info.get("redis_version", "unknown"),
            "memory": memory.get("used_memory_human", "unknown"),
        }
    except Exception as e:
        health = {"status": "disconnected", "error": str(e)}
    return counters, health


def _fetch_redis_global_counters_sync() -> dict:
    """Fetch persistent global counters from Redis (synchronous, for thread executor)."""
    try:
        from ..services.redis_sync import get_redis_client
        r = get_redis_client(timeout=0.5)
        if r is None:
            return {}
        # Pipeline all gets in a single round-trip
        pipe = r.pipeline(transaction=False)
        pipe.get("sentinel:global:requests_total")
        pipe.get("sentinel:global:block")
        pipe.get("sentinel:global:warn")
        pipe.get("sentinel:global:allow")
        results = pipe.execute()
        return {
            "requests_total": int(results[0] or 0),
            "blocked": int(results[1] or 0),
            "warned": int(results[2] or 0),
            "allowed": int(results[3] or 0),
        }
    except Exception:
        return {}


@router.get("/recent-blocks")
async def recent_blocks(
    limit: int = Query(10, ge=1, le=50),
    user: TokenPayload = Depends(require_permission("guardrails:read")),
):
    """Get recent blocked attacks from Redis."""
    def _fetch(lim: int) -> list:
        try:
            from ..services.redis_sync import get_redis_client
            r = get_redis_client(timeout=1.0)
            if r is None:
                return []
            raw = r.lrange("sentinel:recent_blocks", 0, lim - 1)
            return [json.loads(item) for item in raw]
        except Exception:
            return []

    return await asyncio.get_event_loop().run_in_executor(None, _fetch, limit)


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
    def _fetch() -> dict:
        try:
            from ..services.redis_sync import get_redis_client
            r = get_redis_client(timeout=1.0)
            if r is None:
                return {}
            pipe = r.pipeline(transaction=False)
            pipe.hgetall("sentinel:usage:total")
            pipe.hgetall("sentinel:usage:block")
            pipe.hgetall("sentinel:usage:allow")
            total, blocked, allowed = pipe.execute()
            total = total or {}
            blocked = blocked or {}
            allowed = allowed or {}
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

    return await asyncio.get_event_loop().run_in_executor(None, _fetch)
