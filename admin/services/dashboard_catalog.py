"""Server-side catalogue of the four ported Grafana dashboards.

This module is **pure data + rendering helpers** (no I/O). It mirrors the panel
definitions and PromQL targets of the canonical Grafana dashboards under
``helm/bulwark-gateway/dashboards/*.json`` (kept byte-identical with
``monitoring/grafana/dashboards/*.json``) so the admin UI renders the same views
from the same metrics.

Why a fixed catalogue instead of proxying the dashboard JSON / arbitrary PromQL:

* **Security** — the dashboards route only ever executes PromQL that ships in
  this file. No operator-supplied query string reaches Prometheus, so the
  in-UI dashboards cannot be turned into an ad-hoc PromQL console.
* **Degraded mode** — each instant panel that maps 1:1 onto a cumulative Redis
  counter carries a ``fallback`` tag, so when Prometheus is unreachable the
  route can still populate it directly from Redis. Panels that need
  ``rate()``/``increase()``/recording-rules have no honest instant fallback and
  are reported as ``requires Prometheus`` rather than faked.

Template variables from the Grafana JSON are resolved server-side:

* ``$timerange`` → the range preset's rate window (e.g. ``5m``)
* ``$__range``   → the range preset's full window duration (e.g. ``6h``)
* ``$tenant`` / ``$category`` → ``.*`` (the dashboards' ``allValue``)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ── Range presets ────────────────────────────────────────────────────────────
# Each preset fixes: the query window (seconds back from now), the range-query
# step (resolution, seconds), the rate/increase window substituted for
# ``$timerange``, and the ``$__range`` duration string. Steps are sized so a
# window never exceeds Prometheus' 11k-point matrix cap.


@dataclass(frozen=True)
class RangePreset:
    key: str
    label: str
    window_seconds: int
    step_seconds: int
    rate_window: str
    range_str: str


RANGE_PRESETS: dict[str, RangePreset] = {
    "1h": RangePreset("1h", "Last 1 hour", 3_600, 15, "5m", "1h"),
    "6h": RangePreset("6h", "Last 6 hours", 21_600, 60, "5m", "6h"),
    "24h": RangePreset("24h", "Last 24 hours", 86_400, 300, "5m", "24h"),
    "7d": RangePreset("7d", "Last 7 days", 604_800, 1_800, "15m", "7d"),
    "30d": RangePreset("30d", "Last 30 days", 2_592_000, 7_200, "1h", "30d"),
}

DEFAULT_RANGE = "6h"


def resolve_range(range_key: str | None) -> RangePreset:
    """Return the preset for ``range_key``, falling back to the default."""
    return RANGE_PRESETS.get(range_key or "", RANGE_PRESETS[DEFAULT_RANGE])


# ── Panel / target model ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class Target:
    """One PromQL series in a panel.

    * ``expr`` — PromQL with ``$timerange``/``$__range``/``$tenant``/``$category``
      placeholders (resolved by :func:`render_expr`).
    * ``legend`` — Grafana ``legendFormat`` (``{{label}}`` templating).
    * ``instant`` — instant query (single value) vs range query (time series).
    * ``column`` — for ``table`` panels, the value column header this target
      contributes after the merge-by-legend.
    """

    expr: str
    legend: str = ""
    instant: bool = False
    column: str = "Value"


@dataclass(frozen=True)
class Panel:
    id: int
    title: str
    type: str  # timeseries | stat | gauge | piechart | barchart | table
    targets: tuple[Target, ...]
    unit: str = "short"
    description: str = ""
    grid: dict = field(default_factory=dict)  # {w,h,x,y} — mirrors Grafana gridPos
    # Degraded-mode Redis dataset key (see dashboards route). Only set on instant
    # panels whose PromQL is a plain cumulative counter with a 1:1 Redis source.
    fallback: str = ""
    # First column header for table panels (the merge key column).
    key_column: str = "Name"
    # Panels that need rate()/increase()/recording-rules and therefore have no
    # honest instant fallback are flagged so the UI can label them clearly.
    requires_prometheus: bool = False


@dataclass(frozen=True)
class Dashboard:
    uid: str
    title: str
    description: str
    default_range: str
    panels: tuple[Panel, ...]


# ── Rendering helpers ────────────────────────────────────────────────────────

_LEGEND_TOKEN = re.compile(r"\{\{\s*(\w+)\s*\}\}")


def render_expr(expr: str, preset: RangePreset) -> str:
    """Substitute Grafana template variables for concrete values."""
    return (
        expr.replace("$timerange", preset.rate_window)
        .replace("$__range", preset.range_str)
        .replace("$tenant", ".*")
        .replace("$category", ".*")
    )


def render_legend(template: str, metric: dict[str, str]) -> str:
    """Render a Grafana ``legendFormat`` against a series' label set.

    ``{{label}}`` tokens are replaced by the label value (empty when absent).
    With no template, falls back to the metric name, then a ``k=v`` join, then
    an empty string — matching Grafana's default labelling behaviour closely
    enough for the ported panels.
    """
    if template:
        rendered = _LEGEND_TOKEN.sub(lambda m: metric.get(m.group(1), ""), template)
        rendered = rendered.strip()
        if rendered:
            return rendered
    name = metric.get("__name__")
    if name:
        labels = {k: v for k, v in metric.items() if k != "__name__"}
        if not labels:
            return name
    labels = {k: v for k, v in metric.items() if k != "__name__"}
    if labels:
        return ", ".join(f"{k}={v}" for k, v in sorted(labels.items()))
    return name or ""


# ── Dashboard definitions (mirror helm/bulwark-gateway/dashboards/*.json) ─────


def _g(w: int, h: int, x: int, y: int) -> dict:
    return {"w": w, "h": h, "x": x, "y": y}


_OVERVIEW = Dashboard(
    uid="bulwark-overview",
    title="Operational Overview",
    description="Real-time proxy health, throughput, and latency.",
    default_range="1h",
    panels=(
        Panel(
            id=1, title="Request Rate (RPS) by Tenant", type="timeseries", unit="reqps",
            grid=_g(12, 8, 0, 0), requires_prometheus=True,
            targets=(Target(
                'sum by (tenant)(rate(bulwark_requests_by_tenant_total{tenant=~"$tenant"}[$timerange]))',
                "{{tenant}}"),),
        ),
        Panel(
            id=2, title="Verdict Distribution", type="piechart", unit="short",
            grid=_g(6, 8, 12, 0), fallback="verdicts_global",
            targets=(Target("sum by (verdict)(bulwark_verdicts_total)", "{{verdict}}", instant=True),),
        ),
        Panel(
            id=3, title="Metrics Pipeline", type="stat", unit="updown",
            description="Admin metrics exposition reachability (the sole source of proxy metrics).",
            grid=_g(3, 4, 18, 0), fallback="admin_up",
            targets=(Target('up{job="bulwark-admin"}', instant=True),),
        ),
        Panel(
            id=4, title="Total Requests", type="stat", unit="short",
            description="Cluster-wide total proxy requests (survives restarts).",
            grid=_g(3, 4, 21, 0), fallback="requests_total",
            targets=(Target("bulwark_requests_total", instant=True),),
        ),
        Panel(
            id=5, title="P50 / P95 / P99 Latency", type="timeseries", unit="ms",
            description="Proxy request latency percentiles (per-worker best-effort).",
            grid=_g(12, 8, 0, 8), requires_prometheus=True,
            targets=(
                Target("bulwark:latency:p50", "P50"),
                Target("bulwark:latency:p95", "P95"),
                Target("bulwark:latency:p99", "P99"),
            ),
        ),
        Panel(
            id=6, title="SIEM Export Error Ratio", type="gauge", unit="percentunit",
            description="Share of SIEM export attempts that errored over 5m.",
            grid=_g(6, 4, 18, 4), requires_prometheus=True,
            targets=(Target("bulwark:siem:error_ratio_5m", instant=True),),
        ),
        Panel(
            id=7, title="Top Detected Categories", type="barchart", unit="short",
            description="Guardrail detections (block+warn) by threat category.",
            grid=_g(12, 8, 12, 8), fallback="detections_category",
            targets=(Target("topk(10, sum by (category)(bulwark_detections_by_category_total))",
                            "{{category}}", instant=True),),
        ),
        Panel(
            id=8, title="Blocks by Tenant", type="table", unit="short",
            description="Cluster-wide blocked requests per tenant.",
            grid=_g(24, 8, 0, 16), fallback="blocks_by_tenant", key_column="Tenant",
            targets=(Target('topk(20, bulwark_verdicts_by_tenant_total{verdict="block", tenant=~"$tenant"})',
                            "{{tenant}}", instant=True, column="Count"),),
        ),
    ),
)


_SECURITY = Dashboard(
    uid="bulwark-security",
    title="Security Operations",
    description="Attack categories, severity, pattern matches, per-tenant blocks, SIEM health.",
    default_range="6h",
    panels=(
        Panel(
            id=1, title="Attack Attempts per Minute (by Category)", type="timeseries", unit="cpm",
            grid=_g(16, 9, 0, 0), requires_prometheus=True,
            targets=(Target(
                'sum by (category)(rate(bulwark_detections_by_category_total{category=~"$category"}[$timerange])) * 60',
                "{{category}}"),),
        ),
        Panel(
            id=2, title="Critical Detections (1h)", type="stat", unit="short",
            description="Critical-severity guardrail detections in the last hour.",
            grid=_g(4, 4, 16, 0), requires_prometheus=True,
            targets=(Target('sum(increase(bulwark_detections_by_severity_total{severity="critical"}[1h]))',
                            instant=True),),
        ),
        Panel(
            id=3, title="Total Blocks (24h)", type="stat", unit="short",
            grid=_g(4, 4, 20, 0), requires_prometheus=True,
            targets=(Target('sum(increase(bulwark_verdicts_total{verdict="block"}[24h]))', instant=True),),
        ),
        Panel(
            id=4, title="SIEM Export Rate", type="timeseries", unit="evt/s",
            grid=_g(8, 5, 16, 4), requires_prometheus=True,
            targets=(
                Target("bulwark:siem:export_rate_5m", "Events/sec exported"),
                Target("sum(rate(bulwark_siem_export_errors_total[5m]))", "Errors/sec"),
            ),
        ),
        Panel(
            id=5, title="Matched Patterns (Top 10)", type="barchart", unit="short",
            description="Guardrail pattern matches by pattern id (top 200 exported).",
            grid=_g(12, 9, 0, 9), fallback="detections_pattern",
            targets=(Target("topk(10, sum by (pattern_id)(bulwark_pattern_matches_total))",
                            "{{pattern_id}}", instant=True),),
        ),
        Panel(
            id=6, title="Detections by Severity", type="timeseries", unit="short",
            grid=_g(12, 9, 12, 9), requires_prometheus=True,
            targets=(Target("sum by (severity)(rate(bulwark_detections_by_severity_total[$timerange]))",
                            "{{severity}}"),),
        ),
        Panel(
            id=7, title="Detections by Category (Totals)", type="barchart", unit="short",
            description="Cumulative guardrail detections per category.",
            grid=_g(12, 8, 0, 18), fallback="detections_category",
            targets=(Target('topk(15, sum by (category)(bulwark_detections_by_category_total{category=~"$category"}))',
                            "{{category}}", instant=True),),
        ),
        Panel(
            id=8, title="Top Blocking by Tenant", type="table", unit="short",
            description="Tenants with highest block counts and block rate.",
            grid=_g(12, 8, 12, 18), fallback="blocking_by_tenant", key_column="Tenant",
            targets=(
                Target('topk(10, sum by (tenant)(bulwark_verdicts_by_tenant_total{verdict="block"}))',
                       "{{tenant}}", instant=True, column="Blocks"),
                Target('topk(10, sum by (tenant)(bulwark_verdicts_by_tenant_total{verdict="block"}) '
                       '/ clamp_min(sum by (tenant)(bulwark_requests_by_tenant_total), 1))',
                       "{{tenant}}", instant=True, column="Block Rate"),
            ),
        ),
        Panel(
            id=9, title="Per-Tenant Verdict Breakdown", type="table", unit="short",
            description="Verdict counts per tenant.",
            grid=_g(24, 8, 0, 26), fallback="verdicts_by_tenant", key_column="Tenant",
            targets=(Target("sum by (tenant, verdict)(bulwark_verdicts_by_tenant_total)",
                            "{{tenant}} — {{verdict}}", instant=True, column="Count"),),
        ),
    ),
)


_SLO = Dashboard(
    uid="bulwark-slo",
    title="SLO / Error Budget",
    description="Availability + latency SLOs and error-budget burn (Prometheus recording rules).",
    default_range="30d",
    panels=(
        Panel(
            id=2, title="Availability Error Budget Remaining", type="gauge", unit="percentunit",
            grid=_g(6, 6, 0, 1), requires_prometheus=True,
            targets=(Target("bulwark:error_budget:availability:remaining", instant=True),),
        ),
        Panel(
            id=3, title="Latency Error Budget Remaining", type="gauge", unit="percentunit",
            grid=_g(6, 6, 6, 1), requires_prometheus=True,
            targets=(Target("bulwark:error_budget:latency:remaining", instant=True),),
        ),
        Panel(
            id=4, title="Availability (30d)", type="gauge", unit="percentunit",
            grid=_g(6, 6, 12, 1), requires_prometheus=True,
            targets=(Target("bulwark:slo:availability:ratio_30d", instant=True),),
        ),
        Panel(
            id=5, title="Latency SLO (30d)", type="gauge", unit="percentunit",
            grid=_g(6, 6, 18, 1), requires_prometheus=True,
            targets=(Target("bulwark:slo:latency:ratio_30d", instant=True),),
        ),
        Panel(
            id=6, title="Error Budget Burn Rate (Availability)", type="timeseries", unit="short",
            grid=_g(12, 8, 0, 7), requires_prometheus=True,
            targets=(
                Target("bulwark:error_budget:availability:burn_rate_1h", "1h burn rate"),
                Target("bulwark:error_budget:availability:burn_rate_6h", "6h burn rate"),
            ),
        ),
        Panel(
            id=7, title="Error Budget Burn Rate (Latency)", type="timeseries", unit="short",
            grid=_g(12, 8, 12, 7), requires_prometheus=True,
            targets=(Target("bulwark:error_budget:latency:burn_rate_1h", "1h burn rate"),),
        ),
        Panel(
            id=8, title="SLO Compliance Timeline (30d)", type="timeseries", unit="percentunit",
            grid=_g(24, 8, 0, 15), requires_prometheus=True,
            targets=(
                Target("bulwark:slo:availability:ratio_30d", "Availability (target: 99.9%)"),
                Target("bulwark:slo:latency:ratio_30d", "Latency (target: 99%)"),
            ),
        ),
        Panel(
            id=9, title="Time Until Budget Exhaustion", type="stat", unit="h",
            grid=_g(8, 5, 0, 23), requires_prometheus=True,
            targets=(Target(
                "clamp_min(bulwark:error_budget:availability:remaining, 0) / "
                "clamp_min(bulwark:error_budget:availability:burn_rate_1h / 720, 0.000001)",
                "Availability", instant=True),),
        ),
        Panel(
            id=10, title="30-Day SLO Performance", type="stat", unit="percentunit",
            grid=_g(16, 5, 8, 23), requires_prometheus=True,
            targets=(
                Target("bulwark:slo:availability:ratio_30d", "Availability SLO", instant=True),
                Target("bulwark:slo:latency:ratio_30d", "Latency SLO", instant=True),
            ),
        ),
        Panel(
            id=11, title="Monthly SLO Report", type="table", unit="percentunit",
            grid=_g(24, 7, 0, 28), requires_prometheus=True, key_column="SLO",
            targets=(
                Target("bulwark:error_budget:availability:remaining",
                       "Availability (99.9%)", instant=True, column="Budget Remaining"),
                Target("bulwark:error_budget:latency:remaining",
                       "Latency (p95 < 100ms, 99%)", instant=True, column="Budget Remaining"),
            ),
        ),
    ),
)


_CORRELATION = Dashboard(
    uid="bulwark-correlation",
    title="Correlation Engine",
    description="Inline exfiltration incidents, adaptive origin-risk enforcement, event-tap health.",
    default_range="6h",
    panels=(
        Panel(
            id=1, title="Correlated Exfiltration Incidents (24h)", type="stat", unit="short",
            grid=_g(6, 4, 0, 0), requires_prometheus=True,
            targets=(Target("sum(increase(bulwark_correlation_incidents_total[24h]))", instant=True),),
        ),
        Panel(
            id=2, title="Incidents Blocked (24h)", type="stat", unit="short",
            grid=_g(6, 4, 6, 0), requires_prometheus=True,
            targets=(Target("sum(increase(bulwark_correlation_incidents_blocked_total[24h]))", instant=True),),
        ),
        Panel(
            id=3, title="Origin-Risk Assessments (24h)", type="stat", unit="short",
            grid=_g(6, 4, 12, 0), requires_prometheus=True,
            targets=(Target("sum(increase(bulwark_correlation_origin_risk_assessments_total[24h]))", instant=True),),
        ),
        Panel(
            id=4, title="Event-Tap Drops (24h)", type="stat", unit="short",
            grid=_g(6, 4, 18, 0), requires_prometheus=True,
            targets=(Target("sum(increase(bulwark_correlation_tap_events_dropped_total[24h]))", instant=True),),
        ),
        Panel(
            id=5, title="Correlation Activity Rate", type="timeseries", unit="cpm",
            grid=_g(12, 9, 0, 4), requires_prometheus=True,
            targets=(
                Target("sum(rate(bulwark_correlation_incidents_total[$timerange])) * 60", "Exfiltration incidents"),
                Target("sum(rate(bulwark_correlation_origin_risk_warned_total[$timerange])) * 60", "Origin-risk WARN"),
                Target(
                    "sum(rate(bulwark_correlation_origin_risk_blocked_total[$timerange])) * 60",
                    "Origin-risk BLOCK",
                ),
            ),
        ),
        Panel(
            id=6, title="Event-Tap Throughput & Loss", type="timeseries", unit="evt/s",
            grid=_g(12, 9, 12, 4), requires_prometheus=True,
            targets=(
                Target("sum(rate(bulwark_correlation_tap_events_published_total[$timerange]))", "Published"),
                Target("sum(rate(bulwark_correlation_tap_events_processed_total[$timerange]))", "Processed"),
                Target("sum(rate(bulwark_correlation_tap_events_dropped_total[$timerange]))", "Dropped"),
            ),
        ),
        Panel(
            id=7, title="Enforcement Mix (selected window)", type="piechart", unit="short",
            grid=_g(12, 8, 0, 13), requires_prometheus=True,
            targets=(
                Target(
                    "sum(increase(bulwark_correlation_origin_risk_warned_total[$__range]))",
                    "Origin-risk WARN", instant=True,
                ),
                Target(
                    "sum(increase(bulwark_correlation_origin_risk_blocked_total[$__range]))",
                    "Origin-risk BLOCK", instant=True,
                ),
                Target(
                    "sum(increase(bulwark_correlation_incidents_blocked_total[$__range]))",
                    "Incident BLOCK", instant=True,
                ),
            ),
        ),
        Panel(
            id=8, title="Correlation Counters (cumulative)", type="table", unit="short",
            description="Raw cumulative counter values (cluster-wide, survive restarts).",
            grid=_g(12, 8, 12, 13), fallback="correlation_counters", key_column="Metric",
            targets=(
                Target("bulwark_correlation_incidents_total", "Incidents", instant=True, column="Count"),
                Target(
                    "bulwark_correlation_incidents_blocked_total",
                    "Incidents blocked", instant=True, column="Count",
                ),
                Target(
                    "bulwark_correlation_origin_risk_assessments_total",
                    "Origin-risk assessments", instant=True, column="Count",
                ),
                Target(
                    "bulwark_correlation_origin_risk_warned_total",
                    "Origin-risk WARN", instant=True, column="Count",
                ),
                Target(
                    "bulwark_correlation_origin_risk_blocked_total",
                    "Origin-risk BLOCK", instant=True, column="Count",
                ),
                Target("bulwark_correlation_tap_events_dropped_total", "Tap drops", instant=True, column="Count"),
            ),
        ),
    ),
)


DASHBOARDS: dict[str, Dashboard] = {
    d.uid: d for d in (_OVERVIEW, _SECURITY, _SLO, _CORRELATION)
}


def list_dashboards() -> list[dict]:
    """Return lightweight metadata for the dashboard tab bar."""
    return [
        {
            "uid": d.uid,
            "title": d.title,
            "description": d.description,
            "default_range": d.default_range,
            "panel_count": len(d.panels),
        }
        for d in DASHBOARDS.values()
    ]
