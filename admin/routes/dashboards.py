"""In-UI dashboards route — serves the four ported Grafana dashboards as JSON.

Each dashboard (``overview`` / ``security`` / ``slo`` / ``correlation``) is
defined server-side in :mod:`admin.services.dashboard_catalog`. This route runs
the catalogue's fixed PromQL against Prometheus (via
:mod:`admin.services.prometheus_query`) and shapes the results into a small,
render-ready JSON contract the dashboard page draws with ApexCharts.

Fail-soft / degraded mode
-------------------------
Prometheus reachability is probed once per request (cached ~30s in the client).
When Prometheus is unreachable — down, or blocked by the zero-trust
NetworkPolicy — panels that map 1:1 onto a cumulative Redis counter are filled
directly from Redis (``source="redis"``) and the response is flagged
``degraded=true``. Panels that require ``rate()``/``increase()``/recording-rules
have no honest instant fallback and are returned empty with
``source="unavailable"`` and an explanatory note, rather than fabricated.

Auth: ``admin:read`` (all authenticated roles have it).
"""

from __future__ import annotations

import asyncio
import time

from fastapi import APIRouter, Depends, HTTPException, Query

from ..models.auth import TokenPayload
from ..services.auth_service import require_permission
from ..services.dashboard_catalog import (
    DASHBOARDS,
    RANGE_PRESETS,
    Panel,
    RangePreset,
    list_dashboards,
    render_expr,
    render_legend,
    resolve_range,
)
from ..services.prometheus_query import Sample, get_prometheus_client

router = APIRouter()


@router.get("/status")
async def dashboards_status(_user: TokenPayload = Depends(require_permission("admin:read"))):
    """Return dashboard metadata + Prometheus reachability for the tab bar."""
    client = get_prometheus_client()
    available = await client.available()
    return {
        "prometheus_available": available,
        "prometheus_url": client.base_url,
        "dashboards": list_dashboards(),
        "ranges": [
            {"key": p.key, "label": p.label} for p in RANGE_PRESETS.values()
        ],
    }


@router.get("/{uid}")
async def dashboard_data(
    uid: str,
    range: str | None = Query(None),
    _user: TokenPayload = Depends(require_permission("admin:read")),
):
    """Return every panel of ``uid`` resolved for the requested time ``range``."""
    dashboard = DASHBOARDS.get(uid)
    if dashboard is None:
        raise HTTPException(status_code=404, detail=f"Unknown dashboard: {uid}")

    preset = resolve_range(range or dashboard.default_range)
    client = get_prometheus_client()
    prom_available = await client.available()

    # Load the Redis fallback datasets once when we may need them (Prometheus
    # down, or a mid-flight query failure on a fallback-eligible panel).
    redis_datasets: dict | None = None
    if not prom_available or any(p.fallback for p in dashboard.panels):
        redis_datasets = await asyncio.get_event_loop().run_in_executor(
            None, _read_redis_datasets
        )

    panels = await asyncio.gather(*[
        _resolve_panel(client, panel, preset, prom_available, redis_datasets)
        for panel in dashboard.panels
    ])

    degraded = any(p["source"] != "prometheus" for p in panels)
    return {
        "uid": dashboard.uid,
        "title": dashboard.title,
        "description": dashboard.description,
        "range": {
            "key": preset.key,
            "label": preset.label,
            "window_seconds": preset.window_seconds,
        },
        "prometheus_available": prom_available,
        "degraded": degraded,
        "panels": panels,
    }


# ── Panel resolution ─────────────────────────────────────────────────────────


def _base_panel(panel: Panel) -> dict:
    """Common metadata block shared by every panel-result shape."""
    return {
        "id": panel.id,
        "title": panel.title,
        "type": panel.type,
        "unit": panel.unit,
        "description": panel.description,
        "grid": panel.grid,
    }


async def _resolve_panel(
    client, panel: Panel, preset: RangePreset, prom_available: bool,
    redis_datasets: dict | None,
) -> dict:
    """Resolve one panel to render-ready JSON (Prometheus, else Redis fallback)."""
    if prom_available:
        try:
            result = await _resolve_from_prometheus(client, panel, preset)
            if result is not None:
                return result
        except Exception:  # noqa: BLE001, S110 — never let one panel 500 the dashboard
            pass
        # Prometheus said available but this panel's queries failed — degrade.

    if panel.fallback and redis_datasets is not None:
        fb = _resolve_from_redis(panel, redis_datasets)
        if fb is not None:
            return fb

    out = _base_panel(panel)
    out["source"] = "unavailable"
    out["note"] = (
        "Requires Prometheus (rate/increase/recording-rule series)"
        if panel.requires_prometheus
        else "Metrics source unavailable"
    )
    out["series"] = []
    out["items"] = []
    out["rows"] = []
    out["value"] = None
    return out


async def _resolve_from_prometheus(
    client, panel: Panel, preset: RangePreset
) -> dict | None:
    """Query Prometheus for every target of ``panel`` and shape by panel type.

    Returns ``None`` when *all* targets failed to return (transport error), so
    the caller can fall back to Redis; a successful-but-empty result (Prometheus
    up, no matching series yet) returns a valid empty-shaped panel.
    """
    now = time.time()
    start = now - preset.window_seconds

    async def run(target) -> list[Sample] | None:
        expr = render_expr(target.expr, preset)
        if target.instant:
            return await client.query_instant(expr)
        return await client.query_range(expr, start, now, preset.step_seconds)

    results = await asyncio.gather(*[run(t) for t in panel.targets])
    if all(r is None for r in results):
        return None
    # Treat failed individual targets as empty series.
    results = [r if r is not None else [] for r in results]

    out = _base_panel(panel)
    out["source"] = "prometheus"

    if panel.type == "timeseries":
        out["series"] = _shape_timeseries(panel, results)
    elif panel.type in ("stat", "gauge"):
        out.update(_shape_stat(panel, results))
    elif panel.type in ("piechart", "barchart"):
        out["items"] = _shape_items(panel, results)
    elif panel.type == "table":
        out.update(_shape_table(panel, results))
    else:  # unknown type — expose nothing rather than guess
        out["series"] = []
    return out


def _shape_timeseries(panel: Panel, results: list[list[Sample]]) -> list[dict]:
    """Build ApexCharts-ready series ([{name, points:[[ts_ms, val]]}])."""
    series: list[dict] = []
    for target, samples in zip(panel.targets, results, strict=True):
        for sample in samples:
            name = render_legend(target.legend, sample.metric)
            points = [[int(ts * 1000), val] for ts, val in sample.values]
            series.append({"name": name, "points": points})
    return series


def _shape_stat(panel: Panel, results: list[list[Sample]]) -> dict:
    """Single- or multi-value stat/gauge.

    ``value`` is the first target's latest value (the big number / gauge fill).
    ``items`` carries one entry per target for multi-metric stat panels.
    """
    items: list[dict] = []
    for target, samples in zip(panel.targets, results, strict=True):
        val = samples[0].last_value if samples else None
        label = render_legend(target.legend, samples[0].metric) if samples else target.legend
        items.append({"label": label or target.legend, "value": val})
    value = items[0]["value"] if items else None
    return {"value": value, "items": items}


def _shape_items(panel: Panel, results: list[list[Sample]]) -> list[dict]:
    """Categorical slices/bars: one item per series' latest value."""
    items: list[dict] = []
    for target, samples in zip(panel.targets, results, strict=True):
        for sample in samples:
            label = render_legend(target.legend, sample.metric)
            items.append({"label": label, "value": sample.last_value})
    return items


def _shape_table(panel: Panel, results: list[list[Sample]]) -> dict:
    """Merge targets by rendered legend into rows (Grafana ``merge`` transform).

    Columns are ``[key_column] + distinct target value-columns``. Each series'
    latest value populates its target's column for the row keyed by its legend.
    """
    columns: list[str] = [panel.key_column]
    for target in panel.targets:
        if target.column not in columns:
            columns.append(target.column)

    rows: dict[str, dict] = {}
    order: list[str] = []
    for target, samples in zip(panel.targets, results, strict=True):
        for sample in samples:
            key = render_legend(target.legend, sample.metric)
            if key not in rows:
                rows[key] = {panel.key_column: key}
                order.append(key)
            rows[key][target.column] = sample.last_value
    return {"columns": columns, "rows": [rows[k] for k in order]}


# ── Redis degraded-mode fallback ─────────────────────────────────────────────


def _read_redis_datasets() -> dict:
    """Read every cumulative counter the fallbacks need in one pipeline.

    Synchronous (runs in a thread executor). Returns ``{}`` when Redis is
    unavailable so callers degrade to ``unavailable`` panels.
    """
    try:
        from ..services.redis_sync import get_redis_client
        r = get_redis_client(timeout=1.0)
        if r is None:
            return {}
        pipe = r.pipeline(transaction=False)
        pipe.mget(
            "bulwark:global:requests_total",
            "bulwark:global:block",
            "bulwark:global:allow",
            "bulwark:global:warn",
            "bulwark:global:redact",
        )
        pipe.hgetall("bulwark:detections:category")
        pipe.hgetall("bulwark:detections:pattern")
        pipe.hgetall("bulwark:usage:total")
        pipe.hgetall("bulwark:usage:block")
        pipe.hgetall("bulwark:usage:allow")
        pipe.hgetall("bulwark:usage:warn")
        pipe.hgetall("bulwark:usage:redact")
        pipe.hgetall("bulwark:correlation:counters")
        res = pipe.execute()
    except Exception:
        return {}

    g = res[0] or [None] * 5
    return {
        "verdicts_global": {
            "block": _i(g[1]), "allow": _i(g[2]), "warn": _i(g[3]), "redact": _i(g[4]),
        },
        "requests_total": _i(g[0]),
        "detections_category": {k: _i(v) for k, v in (res[1] or {}).items()},
        "detections_pattern": {k: _i(v) for k, v in (res[2] or {}).items()},
        "usage_total": {k: _i(v) for k, v in (res[3] or {}).items()},
        "usage_block": {k: _i(v) for k, v in (res[4] or {}).items()},
        "usage_allow": {k: _i(v) for k, v in (res[5] or {}).items()},
        "usage_warn": {k: _i(v) for k, v in (res[6] or {}).items()},
        "usage_redact": {k: _i(v) for k, v in (res[7] or {}).items()},
        "correlation_counters": {k: _i(v) for k, v in (res[8] or {}).items()},
    }


def _i(v) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def _topn(mapping: dict, n: int) -> list[dict]:
    ordered = sorted(mapping.items(), key=lambda kv: kv[1], reverse=True)[:n]
    return [{"label": k, "value": v} for k, v in ordered]


# Correlation table row order (matches the dashboard's target order).
_CORR_ROWS: tuple[tuple[str, str], ...] = (
    ("incidents_total", "Incidents"),
    ("incidents_blocked", "Incidents blocked"),
    ("origin_risk_total", "Origin-risk assessments"),
    ("origin_risk_warned", "Origin-risk WARN"),
    ("origin_risk_blocked", "Origin-risk BLOCK"),
    ("tap_dropped", "Tap drops"),
)


def _resolve_from_redis(panel: Panel, ds: dict) -> dict | None:
    """Shape a fallback-eligible panel from the cumulative Redis datasets."""
    if not ds:
        return None
    out = _base_panel(panel)
    out["source"] = "redis"
    out["note"] = "Prometheus unavailable — showing cumulative totals from Redis"

    fb = panel.fallback
    if fb == "verdicts_global":
        v = ds["verdicts_global"]
        out["items"] = [{"label": k, "value": v[k]} for k in ("allow", "block", "warn", "redact")]
    elif fb == "admin_up":
        out["value"] = 1
        out["items"] = [{"label": "up", "value": 1}]
        out["note"] = "Admin metrics endpoint is serving this request"
    elif fb == "requests_total":
        out["value"] = ds["requests_total"]
        out["items"] = [{"label": "Total Requests", "value": ds["requests_total"]}]
    elif fb == "detections_category":
        out["items"] = _topn(ds["detections_category"], 15)
    elif fb == "detections_pattern":
        out["items"] = _topn(ds["detections_pattern"], 10)
    elif fb == "blocks_by_tenant":
        rows = sorted(ds["usage_block"].items(), key=lambda kv: kv[1], reverse=True)[:20]
        out["columns"] = [panel.key_column, "Count"]
        out["rows"] = [{panel.key_column: t, "Count": c} for t, c in rows]
    elif fb == "blocking_by_tenant":
        total = ds["usage_total"]
        rows = sorted(ds["usage_block"].items(), key=lambda kv: kv[1], reverse=True)[:10]
        out["columns"] = [panel.key_column, "Blocks", "Block Rate"]
        out["rows"] = [
            {
                panel.key_column: t,
                "Blocks": c,
                "Block Rate": round(c / total[t], 4) if total.get(t) else 0.0,
            }
            for t, c in rows
        ]
    elif fb == "verdicts_by_tenant":
        out["columns"] = [panel.key_column, "Verdict", "Count"]
        verdict_maps = (
            ("block", ds["usage_block"]), ("allow", ds["usage_allow"]),
            ("warn", ds["usage_warn"]), ("redact", ds["usage_redact"]),
        )
        rows: list[dict] = []
        for verdict, m in verdict_maps:
            for tenant, count in m.items():
                rows.append({panel.key_column: tenant, "Verdict": verdict, "Count": count})
        rows.sort(key=lambda row: row["Count"], reverse=True)
        out["rows"] = rows
    elif fb == "correlation_counters":
        counters = ds["correlation_counters"]
        out["columns"] = [panel.key_column, "Count"]
        out["rows"] = [
            {panel.key_column: label, "Count": counters.get(field, 0)}
            for field, label in _CORR_ROWS
        ]
    else:
        return None
    return out
