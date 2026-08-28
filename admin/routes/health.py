"""Health & Metrics routes."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import time as _time
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import StreamingResponse

from ..models.auth import ROLE_PERMISSIONS, TokenPayload
from ..services.auth_service import AuthService, require_permission, require_permission_or_scrape_token
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
_raw_proxy_url = os.getenv("BULWARK_PROXY_URL", "http://proxy:8080")
PROXY_URL = _raw_proxy_url

# SSE interval — how often to push updates (seconds)
SSE_INTERVAL = float(os.getenv("BULWARK_SSE_INTERVAL", "5"))

def _extract_bare_key(raw: str) -> str:
    """Return the bare API key the proxy will accept.

    The shared ``api-keys`` secret stores entries in the proxy's
    ``BULWARK_API_KEYS`` format — ``key:tenant`` (optionally comma-separated:
    ``key1:tenant1,key2:tenant2``). The proxy binds ``sha256(key)`` where
    ``key = entry[:entry.rfind(":")]`` and expects the client to send only that
    bare ``key`` as the bearer token. Sending the full ``key:tenant`` string
    hashes to a different value and is rejected with 401. Mirror the proxy's
    parsing here so the admin health probe authenticates successfully.
    """
    entry = raw.split(",", 1)[0].strip()
    if ":" in entry:
        entry = entry[: entry.rfind(":")]
    return entry


def _load_proxy_api_key() -> str:
    """Load proxy API key from file or env (bare key, proxy-compatible)."""
    key_file = os.getenv("BULWARK_PROXY_API_KEY_FILE", "")
    if key_file and os.path.isfile(key_file):
        with open(key_file) as f:
            # api_keys file may have multiple lines; use first non-empty
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    return _extract_bare_key(line)
    return _extract_bare_key(os.getenv("BULWARK_PROXY_API_KEY", ""))


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
async def prometheus_metrics(_user: TokenPayload = Depends(require_permission_or_scrape_token("admin:read"))):
    """Prometheus exposition format endpoint — requires auth.

    Emits four metric families:

      * the admin service's own in-process gauges (uptime, queue depth), and
      * the authoritative cluster-wide verdict totals from the shared Redis
        ``bulwark:global:*`` counters (``bulwark_requests_total`` /
        ``bulwark_verdicts_total``) plus per-tenant / per-category / per-severity
        / per-pattern detections, token/cost accounting and SIEM export health,
        and
      * the correlation-engine counters from ``bulwark:correlation:counters``
        (``bulwark_correlation_*``), and
      * real proxy latency / throughput gauges from the cached proxy
        ``/health/stats`` (``bulwark_proxy_latency_*``).

    The Redis- and proxy-sourced blocks are best effort: if the source is
    unreachable they are simply omitted rather than failing the scrape.
    """
    metrics = get_metrics()
    body = metrics.to_prometheus_text()
    _ensure_bg_task()  # populate the proxy-stats cache for real latency gauges
    extra = await asyncio.get_event_loop().run_in_executor(
        None, _render_redis_prometheus
    )
    proxy_extra = _render_proxy_telemetry()
    return Response(
        content=body + extra + proxy_extra,
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


# Correlation counter hash fields → Prometheus counter names. Kept local (no
# import from the proxy's ``src`` package, which is not present in the admin
# image) and emitted as a stable zero when a counter has not fired yet.
_CORRELATION_METRIC_MAP: list[tuple[str, str, str]] = [
    ("incidents_total", "bulwark_correlation_incidents_total",
     "Confirmed input-output exfiltration correlations"),
    ("incidents_blocked", "bulwark_correlation_incidents_blocked_total",
     "Correlated exfiltration incidents hardened to BLOCK"),
    ("origin_risk_total", "bulwark_correlation_origin_risk_assessments_total",
     "Adaptive origin-risk assessments that fired"),
    ("origin_risk_blocked", "bulwark_correlation_origin_risk_blocked_total",
     "Origin-risk assessments hardened to BLOCK"),
    ("origin_risk_warned", "bulwark_correlation_origin_risk_warned_total",
     "Origin-risk assessments flagged WARN"),
    ("tap_published", "bulwark_correlation_tap_events_published_total",
     "Security events accepted into the correlation event tap"),
    ("tap_processed", "bulwark_correlation_tap_events_processed_total",
     "Events folded into origin risk state by the tap consumer"),
    ("tap_dropped", "bulwark_correlation_tap_events_dropped_total",
     "Events dropped on a full tap queue (risk telemetry loss)"),
]

# Inline-evaluation latency histogram. Field names + bucket bounds are duplicated
# from src/correlation/metrics.py rather than imported: the metrics scrape path is
# deliberately decoupled from the proxy's correlation package so a hot, unauth-
# adjacent endpoint never triggers its import side-effects (risk-store/Redis client
# wiring). Keep these in lockstep with LATENCY_BUCKETS_SECONDS there.
_CORRELATION_LATENCY_BUCKETS: tuple[float, ...] = (
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
)
_CORRELATION_LAT_COUNT_FIELD = "eval_lat_count"
_CORRELATION_LAT_SUM_US_FIELD = "eval_lat_sum_us"
_CORRELATION_LAT_INF_FIELD = "eval_lat_bucket_inf"
_CORRELATION_LAT_METRIC = "bulwark_correlation_eval_duration_seconds"


def _render_correlation_latency(corr_raw: dict, _i) -> list[str]:
    """Render the inline-evaluation latency histogram from the counter hash.

    Emits a Prometheus histogram: cumulative ``_bucket{le=...}`` lines (bucket
    counts are stored non-cumulatively, summed here), ``_sum`` (seconds, from
    integer microseconds), and ``_count``. Always emitted so the series exist
    from t=0.
    """
    lines: list[str] = [
        f"# HELP {_CORRELATION_LAT_METRIC} Inline correlation evaluation latency "
        "(origin-risk + input-output), including Redis round-trips",
        f"# TYPE {_CORRELATION_LAT_METRIC} histogram",
    ]
    cumulative = 0
    for le in _CORRELATION_LATENCY_BUCKETS:
        cumulative += _i(corr_raw.get(f"eval_lat_bucket_{le}"))
        lines.append(f'{_CORRELATION_LAT_METRIC}_bucket{{le="{le}"}} {cumulative}')
    total = cumulative + _i(corr_raw.get(_CORRELATION_LAT_INF_FIELD))
    lines.append(f'{_CORRELATION_LAT_METRIC}_bucket{{le="+Inf"}} {total}')
    sum_seconds = _i(corr_raw.get(_CORRELATION_LAT_SUM_US_FIELD)) / 1_000_000.0
    lines.append(f"{_CORRELATION_LAT_METRIC}_sum {sum_seconds}")
    lines.append(f"{_CORRELATION_LAT_METRIC}_count {_i(corr_raw.get(_CORRELATION_LAT_COUNT_FIELD))}")
    return lines


def _esc(value: str) -> str:
    """Escape a Prometheus label value (backslash, double-quote, newline).

    Per the exposition format, only these three characters need escaping in a
    label value. Applied to operator-influenced strings (tenant ids, category /
    pattern names) before they are embedded in a ``{label="..."}`` clause.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


# Max number of per-pattern series emitted. Pattern ids are bounded by the
# registered pattern set, but dynamically-added custom patterns could grow it;
# cap defensively (top-N by count) so a scrape response stays bounded.
_MAX_PATTERN_SERIES = 200

_VERDICT_USAGE_KEYS: tuple[tuple[str, str], ...] = (
    ("bulwark:usage:block", "block"),
    ("bulwark:usage:allow", "allow"),
    ("bulwark:usage:warn", "warn"),
    ("bulwark:usage:redact", "redact"),
)


def _render_labeled_counter(
    metric: str, help_text: str, samples: dict, label: str,
) -> list[str]:
    """Render a single-label counter family from a ``{value: count}`` mapping.

    Values are coerced to int and non-numeric entries skipped. Label values are
    escaped. Returns an empty list (no HELP/TYPE) when there are no samples so an
    absent subsystem contributes nothing rather than a bare header.
    """
    def _i(v) -> int:
        try:
            return int(v or 0)
        except (TypeError, ValueError):
            return 0

    if not samples:
        return []
    lines = [f"# HELP {metric} {help_text}", f"# TYPE {metric} counter"]
    for key, raw in samples.items():
        lines.append(f'{metric}{{{label}="{_esc(str(key))}"}} {_i(raw)}')
    return lines


def _render_redis_prometheus() -> str:
    """Render Redis-sourced global + correlation metrics (best effort, sync).

    Returns an empty string when Redis is unavailable so the scrape still
    succeeds with the admin in-process metrics alone.
    """
    try:
        from ..services.redis_sync import get_redis_client
        r = get_redis_client(timeout=0.5)
        if r is None:
            return ""

        pipe = r.pipeline(transaction=False)
        pipe.mget(
            "bulwark:global:requests_total",
            "bulwark:global:block",
            "bulwark:global:allow",
            "bulwark:global:warn",
            "bulwark:global:redact",
        )
        pipe.hgetall("bulwark:correlation:counters")
        pipe.hgetall("bulwark:usage:total")            # tenant -> request count
        for key, _verdict in _VERDICT_USAGE_KEYS:
            pipe.hgetall(key)                          # tenant -> verdict count
        pipe.hgetall("bulwark:detections:category")    # category -> detections
        pipe.hgetall("bulwark:detections:severity")    # severity -> detections
        pipe.hgetall("bulwark:detections:pattern")     # pattern_id -> matches
        pipe.hgetall("bulwark:cost:global")            # token/cost accounting
        pipe.mget(
            "bulwark:siem:batches_sent",
            "bulwark:siem:events_exported",
            "bulwark:siem:export_errors",
        )
        results = pipe.execute()
    except Exception:
        return ""

    # Positional unpack mirrors the pipeline order above (single forward pass).
    it = iter(results)
    globals_raw = next(it) or [None] * 5
    corr_raw = next(it) or {}
    usage_total = next(it) or {}
    usage_by_verdict: list[dict] = [next(it) or {} for _ in _VERDICT_USAGE_KEYS]
    detections_category = next(it) or {}
    detections_severity = next(it) or {}
    detections_pattern = next(it) or {}
    cost_global = next(it) or {}
    siem_raw = next(it) or [None] * 3

    def _i(v) -> int:
        try:
            return int(v or 0)
        except (TypeError, ValueError):
            return 0

    def _f(v) -> float:
        try:
            return float(v or 0)
        except (TypeError, ValueError):
            return 0.0

    lines: list[str] = [
        "# HELP bulwark_requests_total Total proxy requests (cluster-wide, from Redis)",
        "# TYPE bulwark_requests_total counter",
        f"bulwark_requests_total {_i(globals_raw[0])}",
        "# HELP bulwark_verdicts_total Proxy verdicts by type (cluster-wide, from Redis)",
        "# TYPE bulwark_verdicts_total counter",
        f'bulwark_verdicts_total{{verdict="block"}} {_i(globals_raw[1])}',
        f'bulwark_verdicts_total{{verdict="allow"}} {_i(globals_raw[2])}',
        f'bulwark_verdicts_total{{verdict="warn"}} {_i(globals_raw[3])}',
        f'bulwark_verdicts_total{{verdict="redact"}} {_i(globals_raw[4])}',
    ]

    # ── Per-tenant volume (managers: who drives traffic / gets blocked) ──
    lines.extend(_render_labeled_counter(
        "bulwark_requests_by_tenant_total",
        "Total proxy requests per tenant (cluster-wide, from Redis)",
        usage_total, "tenant",
    ))
    verdict_tenant_samples: list[str] = []
    for (_, verdict), samples in zip(_VERDICT_USAGE_KEYS, usage_by_verdict, strict=True):
        for tenant, raw in (samples or {}).items():
            verdict_tenant_samples.append(
                f'bulwark_verdicts_by_tenant_total{{tenant="{_esc(str(tenant))}",'
                f'verdict="{verdict}"}} {_i(raw)}'
            )
    if verdict_tenant_samples:
        lines.append(
            "# HELP bulwark_verdicts_by_tenant_total Proxy verdicts per tenant "
            "and verdict (cluster-wide, from Redis)"
        )
        lines.append("# TYPE bulwark_verdicts_by_tenant_total counter")
        lines.extend(verdict_tenant_samples)

    # ── Guardrail detections (SOC: what is being caught) ──
    lines.extend(_render_labeled_counter(
        "bulwark_detections_by_category_total",
        "Guardrail detections (block+warn) per threat category, from Redis",
        detections_category, "category",
    ))
    lines.extend(_render_labeled_counter(
        "bulwark_detections_by_severity_total",
        "Guardrail detections (block+warn) per severity, from Redis",
        detections_severity, "severity",
    ))
    # Top-N patterns only (bounded scrape size).
    if detections_pattern:
        try:
            top = sorted(
                detections_pattern.items(),
                key=lambda kv: _i(kv[1]),
                reverse=True,
            )[:_MAX_PATTERN_SERIES]
        except Exception:
            top = list(detections_pattern.items())[:_MAX_PATTERN_SERIES]
        lines.append(
            "# HELP bulwark_pattern_matches_total Guardrail pattern matches per "
            "pattern id (top 200 by count, from Redis)"
        )
        lines.append("# TYPE bulwark_pattern_matches_total counter")
        for pattern_id, raw in top:
            lines.append(
                f'bulwark_pattern_matches_total{{pattern_id="{_esc(str(pattern_id))}"}} {_i(raw)}'
            )

    # ── Cost / token accounting (managers: spend & volume) ──
    if cost_global:
        lines.extend([
            "# HELP bulwark_tokens_total LLM tokens processed by direction (from Redis)",
            "# TYPE bulwark_tokens_total counter",
            f'bulwark_tokens_total{{direction="prompt"}} {_i(cost_global.get("prompt"))}',
            f'bulwark_tokens_total{{direction="completion"}} {_i(cost_global.get("completion"))}',
            "# HELP bulwark_llm_requests_total Backend LLM requests accounted for cost (from Redis)",
            "# TYPE bulwark_llm_requests_total counter",
            f'bulwark_llm_requests_total {_i(cost_global.get("requests"))}',
            "# HELP bulwark_cost_usd_total Estimated LLM spend in USD (from Redis)",
            "# TYPE bulwark_cost_usd_total counter",
            f'bulwark_cost_usd_total {_f(cost_global.get("cost_usd"))}',
        ])

    # ── SIEM export health ──
    lines.extend([
        "# HELP bulwark_siem_batches_sent_total SIEM export batches sent (from Redis)",
        "# TYPE bulwark_siem_batches_sent_total counter",
        f"bulwark_siem_batches_sent_total {_i(siem_raw[0])}",
        "# HELP bulwark_siem_events_exported_total SIEM events exported (from Redis)",
        "# TYPE bulwark_siem_events_exported_total counter",
        f"bulwark_siem_events_exported_total {_i(siem_raw[1])}",
        "# HELP bulwark_siem_export_errors_total SIEM export errors (from Redis)",
        "# TYPE bulwark_siem_export_errors_total counter",
        f"bulwark_siem_export_errors_total {_i(siem_raw[2])}",
    ])

    for field, metric, help_text in _CORRELATION_METRIC_MAP:
        lines.append(f"# HELP {metric} {help_text}")
        lines.append(f"# TYPE {metric} counter")
        lines.append(f"{metric} {_i(corr_raw.get(field))}")

    lines.extend(_render_correlation_latency(corr_raw, _i))

    return "\n".join(lines) + "\n"


def _render_proxy_telemetry() -> str:
    """Render real proxy latency / throughput gauges from cached ``/health/stats``.

    The proxy computes these percentiles in-process (``src/telemetry/counters.py``)
    and serves them on ``/health/stats``; the admin background task already caches
    that payload, so this is zero blocking I/O. Values are per-worker best-effort
    (the proxy runs multiple uvicorn workers/replicas behind a Service, so a scrape
    reflects whichever worker answered the last poll) — labelled as such. Emitted
    only when the cache holds a real payload so an unreachable proxy contributes
    nothing rather than a misleading zero.
    """
    proxy_stats, _ = _get_cached_telemetry()
    if not proxy_stats:
        return ""

    def _f(v) -> float:
        try:
            return float(v or 0)
        except (TypeError, ValueError):
            return 0.0

    def _i(v) -> int:
        try:
            return int(v or 0)
        except (TypeError, ValueError):
            return 0

    lines: list[str] = []
    for pct in ("p50", "p95", "p99"):
        key = f"latency_{pct}_ms"
        if key in proxy_stats:
            metric = f"bulwark_proxy_latency_{pct}_ms"
            lines.append(
                f"# HELP {metric} Proxy request latency {pct} in ms "
                "(per-worker best-effort, from proxy /health/stats)"
            )
            lines.append(f"# TYPE {metric} gauge")
            lines.append(f"{metric} {_f(proxy_stats.get(key)):.2f}")
    if "requests_per_second" in proxy_stats:
        lines.append(
            "# HELP bulwark_proxy_requests_per_second Proxy throughput "
            "(per-worker best-effort, from proxy /health/stats)"
        )
        lines.append("# TYPE bulwark_proxy_requests_per_second gauge")
        lines.append(f"bulwark_proxy_requests_per_second {_f(proxy_stats.get('requests_per_second')):.2f}")
    if "errors" in proxy_stats:
        lines.append(
            "# HELP bulwark_proxy_errors_total Proxy internal errors "
            "(per-worker best-effort, from proxy /health/stats)"
        )
        lines.append("# TYPE bulwark_proxy_errors_total counter")
        lines.append(f"bulwark_proxy_errors_total {_i(proxy_stats.get('errors'))}")
    if not lines:
        return ""
    return "\n".join(lines) + "\n"


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
                data["false_positive_rate"] = (
                    round((warned / (blocked + warned)) * 100, 1) if (blocked + warned) > 0 else 0.0
                )
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
                data["false_positive_rate"] = (
                    round((warned / (blocked + warned)) * 100, 1) if (blocked + warned) > 0 else 0.0
                )
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

_telemetry_cache: dict = {
    "proxy": {},
    "redis": {},
    "redis_health": {"status": "unknown"},
    "scanners": {"available": False},
    "ts": 0.0,
}
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
            except Exception:  # noqa: S110 - best-effort telemetry fetch; dashboard must still render
                pass

            # Fetch Redis counters + health (in executor)
            redis_counters = {}
            redis_health = {"status": "unknown"}
            try:
                redis_counters, redis_health = await asyncio.get_event_loop().run_in_executor(
                    None, _fetch_redis_all_sync
                )
            except Exception:  # noqa: S110 - best-effort Redis fetch; dashboard must still render
                pass

            # Fetch scanner pipeline status from the proxy internal endpoint
            # (network-isolated, requires the proxy API key which the background
            # client already carries). Best-effort — the panel degrades
            # gracefully to "unavailable" if the proxy is unreachable.
            scanners = {"available": False}
            with contextlib.suppress(Exception):
                sresp = await client.get(f"{PROXY_URL}/internal/scanners/status")
                if sresp.status_code == 200:
                    scanners = _summarize_scanners(sresp.json())

            _telemetry_cache = {
                "proxy": proxy_stats,
                "redis": redis_counters,
                "redis_health": redis_health,
                "scanners": scanners,
                "ts": _time.monotonic(),
            }
        except Exception:  # noqa: S110 - best-effort telemetry cache refresh; keep last snapshot
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


def _get_cached_scanners() -> dict:
    """Return scanner pipeline summary from cache. Non-blocking, instant."""
    return _telemetry_cache.get("scanners", {"available": False})


def _summarize_scanners(raw: dict) -> dict:
    """Condense the proxy /internal/scanners/status payload for the infra panel.

    Keeps only real, operator-relevant fields; computes a healthy/total roll-up.
    Never fabricates values — missing fields degrade to None/0.
    """
    raw = raw or {}
    scanners = raw.get("scanners") or []
    healthy = sum(1 for s in scanners if s.get("healthy"))
    lanes = raw.get("lanes") or {}
    # Opt-in capability master flags — read straight from the proxy payload,
    # defaulting to False. Never fabricated: a flag the proxy does not report
    # simply reads False (dormant), matching the "no fabrication" contract.
    capability_flags = {
        flag: bool(raw.get(flag, False))
        for flag in (
            "schema_validation_enabled",
            "relevance_scanning_enabled",
            "hallucination_scanning_enabled",
            "grounding_scanning_enabled",
            "image_hygiene_scanning_enabled",
            "vision_scanning_enabled",
        )
    }
    return {
        "available": True,
        "ml_enabled": bool(raw.get("ml_enabled", False)),
        "ml_blocking": bool(raw.get("ml_blocking", False)),
        "ml_timeout_ms": raw.get("ml_timeout_ms"),
        "rag_enabled": bool(raw.get("rag_enabled", False)),
        "multilingual_enabled": bool(raw.get("multilingual_enabled", False)),
        "capability_flags": capability_flags,
        "lanes": {
            "input_blocking": lanes.get("input_blocking", 0),
            "input_async": lanes.get("input_async", 0),
            "output_blocking": lanes.get("output_blocking", 0),
            "output_async": lanes.get("output_async", 0),
            "total": lanes.get("total", 0),
        },
        "scanner_total": len(scanners),
        "scanner_healthy": healthy,
        "scanners": [
            {
                "name": s.get("name", "unknown"),
                "type": s.get("type"),
                "version": s.get("version"),
                "enabled": bool(s.get("enabled", False)),
                "healthy": bool(s.get("healthy", False)),
            }
            for s in scanners
        ],
    }


@router.get("/infra")
async def health_infra(
    request: Request,
    _user: TokenPayload = Depends(require_permission("admin:read")),
):
    """Read-only infrastructure snapshot for the Status page.

    Aggregates ONLY real, already-cached data (zero blocking I/O in the request
    path), clearly attributed to its source:

      * ``admin``     — this portal's own uptime/version (in-process metrics)
      * ``redis``     — connectivity, version, memory, latency (pooled probe)
      * ``proxy``     — live counters/latency from the proxy /health/stats
      * ``scanners``  — pipeline state from the proxy internal endpoint
      * ``runtime``   — the admin's own operational config (env-derived)

    No Kubernetes/pod introspection is performed — the admin service has no
    cluster API access, so nothing here is fabricated.
    """
    _ensure_bg_task()
    snap = get_metrics().snapshot()
    proxy_stats, _ = _get_cached_telemetry()
    redis_info = _get_cached_redis_health()
    scanners = _get_cached_scanners()

    proxy_reachable = bool(proxy_stats)
    proxy = {
        "reachable": proxy_reachable,
        "uptime_seconds": proxy_stats.get("uptime_seconds"),
        "requests_total": proxy_stats.get("requests_total", 0),
        "requests_per_second": proxy_stats.get("requests_per_second", 0),
        "verdicts": {
            "blocked": proxy_stats.get("blocked", 0),
            "warned": proxy_stats.get("warned", 0),
            "allowed": proxy_stats.get("allowed", 0),
            "redacted": proxy_stats.get("redacted", 0),
            "errors": proxy_stats.get("errors", 0),
        },
        "latency": {
            "p50_ms": proxy_stats.get("latency_p50_ms"),
            "p95_ms": proxy_stats.get("latency_p95_ms"),
            "p99_ms": proxy_stats.get("latency_p99_ms"),
        },
    }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "admin": {
            "version": getattr(request.app, "version", "unknown"),
            "uptime_seconds": snap.uptime_seconds,
        },
        "redis": {
            "status": redis_info.get("status", "unknown"),
            "version": redis_info.get("version"),
            "memory": redis_info.get("memory"),
            "latency_ms": redis_info.get("latency_ms"),
        },
        "proxy": proxy,
        "scanners": scanners,
        "runtime": {
            "proxy_url": PROXY_URL,
            "sse_interval_seconds": SSE_INTERVAL,
        },
    }


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
        pipe.get("bulwark:global:requests_total")
        pipe.get("bulwark:global:block")
        pipe.get("bulwark:global:warn")
        pipe.get("bulwark:global:allow")
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
        pipe.get("bulwark:global:requests_total")
        pipe.get("bulwark:global:block")
        pipe.get("bulwark:global:warn")
        pipe.get("bulwark:global:allow")
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
            from ..services.redis_sync import fetch_recent_blocks, get_redis_client
            r = get_redis_client(timeout=1.0)
            if r is None:
                return []
            # Recent blocks are stored per tenant (bulwark:recent_blocks:<tenant>);
            # aggregate newest-first across all tenants.
            return fetch_recent_blocks(r, max_items=lim)
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
            pipe.hgetall("bulwark:usage:total")
            pipe.hgetall("bulwark:usage:block")
            pipe.hgetall("bulwark:usage:allow")
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
