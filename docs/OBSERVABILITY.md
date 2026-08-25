# Observability — Prometheus & Grafana

> How Bulwark Gateway is monitored end-to-end, what every metric means, where it
> comes from, and how the dashboards are wired. This document is **honest**: it
> describes the scrape topology exactly as it is, including the parts that are
> deliberately *not* scraped and why.

---

## 1. Design Principle: One Honest Scrape Target

Bulwark Gateway exposes **a single Prometheus scrape target — the admin
service** (`/admin/health/metrics`). There is intentionally **no** proxy scrape
job and **no** Redis scrape job. This is a deliberate architecture, not a gap:

| Component | Scraped directly? | Why |
|-----------|-------------------|-----|
| **admin** (`:8090/admin/health/metrics`) | ✅ Yes | The only Prometheus exposition endpoint in the system. Renders `bulwark_*` series server-side. |
| **proxy** (`:8080`) | ❌ No | The proxy exposes **no** `/metrics` endpoint by design (keeps the hot path free of scrape-time work). It writes all counters to Redis instead. Scraping it would 404/401. |
| **Redis** (`:6379`) | ❌ No | The stack ships plain `redis:7-alpine` with **no** `redis_exporter` sidecar. Port 6379 speaks RESP, not the Prometheus text format. Scraping it would only produce scrape errors. |

### How proxy & Redis metrics still reach Prometheus

The proxy writes verdict/detection/correlation counters to Redis on the hot path
(`bulwark:global:*`, `bulwark:detections:*`, `bulwark:correlation:counters`,
`bulwark:usage:*`, …). The **admin exposition endpoint reads Redis and renders
those values as `bulwark_*` Prometheus series** at scrape time
(`admin/routes/health.py` → `_render_redis_prometheus`). Real proxy latency
percentiles are pulled from the proxy's own `/health/stats` (cached by an admin
background task) and rendered as `bulwark_proxy_latency_*` gauges
(`_render_proxy_telemetry`).

**Consequence for infra metrics:** because only `bulwark-admin` is a scrape
target, `up{job="bulwark-admin"}` is the single availability signal. Any panel
or rule that references a *different* `job`/`instance` (e.g. a hypothetical
`bulwark-proxy` target) will be empty — those series do not exist. This is why
the SLO rules aggregate with `max()` (see §5).

---

## 2. Scrape Configuration — Three Stacks in Sync

The exact same monitoring is expressed in three deployment stacks. They must
stay consistent.

| Stack | Prometheus config | Grafana dashboards | Notes |
|-------|-------------------|--------------------|-------|
| **Kubernetes (Helm)** — source of truth | `helm/bulwark-gateway/templates/monitoring.yaml` (ConfigMap `prometheus-config`) | `helm/bulwark-gateway/dashboards/*.json` → ConfigMap `grafana-dashboards` | Prod. Target FQDN with trailing dot. Token from `bulwark-admin-secrets`. |
| **Standalone / docker-compose** | `prometheus/prometheus.yml` + `prometheus/rules.yml` + `prometheus/recording-rules.yml` | Grafana `grafana_data` volume (imported) | `docker compose --profile monitoring up`. Target `admin:8090`. Token from `./secrets/metrics_scrape_token.txt`. |
| **`monitoring/` provisioning** | `monitoring/prometheus/recording-rules.yml` | `monitoring/grafana/dashboards/*.json` + `monitoring/grafana/provisioning/` | Grafana file-provisioning variant. |

> **Dashboard sync invariant:** the four dashboards under
> `helm/bulwark-gateway/dashboards/` and `monitoring/grafana/dashboards/` are
> kept **byte-identical**. When you edit one, edit the other identically and
> verify:
> ```bash
> diff helm/bulwark-gateway/dashboards/bulwark-overview.json \
>      monitoring/grafana/dashboards/bulwark-overview.json
> ```

### Scrape auth (least-privilege bearer)

`/admin/health/metrics` is gated by `require_permission_or_scrape_token("admin:read")`:

- **Dedicated scrape token** — `BULWARK_METRICS_SCRAPE_TOKEN` (admin-side, `*_FILE`
  supported), compared with `hmac.compare_digest`. Prometheus sends it as a
  `Bearer` credential (`credentials_file`). This lets Prometheus scrape without
  holding an admin session.
- **Fallback** — if the token is empty, the endpoint requires a normal
  `admin:read` JWT, and an unauthenticated Prometheus scrape would get **401**.
  Populate the token secret in every stack that scrapes.

| Stack | Token location |
|-------|----------------|
| Helm | Secret `bulwark-admin-secrets` key `metrics-scrape-token` → mounted at `/etc/prometheus-token/metrics-scrape-token` |
| docker-compose | `./secrets/metrics_scrape_token.txt` → `/run/secrets/metrics_scrape_token` |

### DNS trailing dot (K8s)

The Helm scrape target is
`admin.<namespace>.svc.cluster.local.:8090` — note the **trailing dot**. The pod
resolver uses `ndots:5`; this name has fewer than 5 dots, so without the trailing
dot the resolver walks the search domains first (slow → scrape timeout /
"context deadline exceeded"). The dot forces an absolute lookup.

> **Grafana → Prometheus datasource:** inside the Grafana pod, Prometheus is
> reachable **only** as the short service name `http://prometheus:9090` (the
> `.svc.cluster.local` FQDN does not resolve in that pod's context). The
> datasource is provisioned with that URL and `uid: prometheus`.

---

## 3. Metrics Catalog

All series below are rendered by `admin/routes/health.py`. The authoritative
source is that module — this table is a readable index. "Source" indicates where
the value originates.

### Cluster-wide verdicts & requests (Redis `bulwark:global:*`)

| Metric | Type | Labels | Source |
|--------|------|--------|--------|
| `bulwark_requests_total` | counter | — | `bulwark:global:requests_total` |
| `bulwark_verdicts_total` | counter | `verdict` (block/allow/warn/redact) | `bulwark:global:{block,allow,warn,redact}` |

### Per-tenant volume (Redis `bulwark:usage:*`)

| Metric | Type | Labels | Source |
|--------|------|--------|--------|
| `bulwark_requests_by_tenant_total` | counter | `tenant` | `bulwark:usage:total` |
| `bulwark_verdicts_by_tenant_total` | counter | `tenant`, `verdict` | `bulwark:usage:{block,allow,warn,redact}` |

### Guardrail detections (Redis `bulwark:detections:*`)

| Metric | Type | Labels | Source |
|--------|------|--------|--------|
| `bulwark_detections_by_category_total` | counter | `category` | `bulwark:detections:category` |
| `bulwark_detections_by_severity_total` | counter | `severity` | `bulwark:detections:severity` |
| `bulwark_pattern_matches_total` | counter | `pattern_id` | `bulwark:detections:pattern` (top-200 by count, capped for bounded scrape) |

### Cost / token accounting (Redis `bulwark:cost:global`)

| Metric | Type | Labels | Source |
|--------|------|--------|--------|
| `bulwark_tokens_total` | counter | `direction` (prompt/completion) | `bulwark:cost:global` |
| `bulwark_llm_requests_total` | counter | — | `bulwark:cost:global` |
| `bulwark_cost_usd_total` | counter | — | `bulwark:cost:global` |

### SIEM export health (Redis `bulwark:siem:*`)

| Metric | Type | Source |
|--------|------|--------|
| `bulwark_siem_batches_sent_total` | counter | `bulwark:siem:batches_sent` |
| `bulwark_siem_events_exported_total` | counter | `bulwark:siem:events_exported` |
| `bulwark_siem_export_errors_total` | counter | `bulwark:siem:export_errors` |

### Correlation engine (Redis `bulwark:correlation:counters`) — opt-in

Emitted always (stable zero until first fire) so the series exist from t=0. Only
non-trivial when `BULWARK_CORRELATION_ENABLED=true`.

| Metric | Type | Meaning |
|--------|------|---------|
| `bulwark_correlation_incidents_total` | counter | Confirmed input↔output exfiltration correlations |
| `bulwark_correlation_incidents_blocked_total` | counter | Correlated incidents hardened to BLOCK |
| `bulwark_correlation_origin_risk_assessments_total` | counter | Adaptive origin-risk assessments that fired |
| `bulwark_correlation_origin_risk_blocked_total` | counter | Origin-risk assessments hardened to BLOCK |
| `bulwark_correlation_origin_risk_warned_total` | counter | Origin-risk assessments flagged WARN |
| `bulwark_correlation_tap_events_published_total` | counter | Events accepted into the correlation event tap |
| `bulwark_correlation_tap_events_processed_total` | counter | Events folded into origin-risk state |
| `bulwark_correlation_tap_events_dropped_total` | counter | Events dropped on a full tap queue (risk-telemetry loss) |
| `bulwark_correlation_eval_duration_seconds` | histogram | Inline-evaluation latency (origin-risk + input/output correlation, incl. Redis round-trips). Buckets: 0.5ms…1s + `+Inf`; `_sum` derived from integer microseconds. |

### Real proxy latency / throughput (proxy `/health/stats`, cached)

Per-worker best-effort (the proxy runs multiple workers/replicas behind a
Service — a scrape reflects whichever worker last answered the admin poll).
Emitted only when the cache holds a real payload (absent proxy contributes
nothing, not a misleading zero).

| Metric | Type |
|--------|------|
| `bulwark_proxy_latency_p50_ms` / `_p95_ms` / `_p99_ms` | gauge |
| `bulwark_proxy_requests_per_second` | gauge |
| `bulwark_proxy_errors_total` | counter |

### Admin in-process gauges

`bulwark_*` uptime / queue-depth gauges rendered from
`prometheus_client.get_metrics().to_prometheus_text()` (the admin's own metrics
registry — no external dependency added).

---

## 4. Recording Rules

Defined in `monitoring.yaml` (`recording-rules.yml`) and mirrored in
`prometheus/recording-rules.yml`.

### Operational (`bulwark_operational_recording`, 30s)

| Rule | Expression |
|------|-----------|
| `bulwark:requests:rate5m:by_tenant` | `sum by (tenant)(rate(bulwark_requests_by_tenant_total[5m]))` |
| `bulwark:verdicts:rate5m:by_verdict` | `sum by (verdict)(rate(bulwark_verdicts_total[5m]))` |
| `bulwark:blocks:rate5m:by_category` | `sum by (category)(rate(bulwark_detections_by_category_total[5m]))` |
| `bulwark:latency:p50` / `p95` / `p99` | `max(bulwark_proxy_latency_pXX_ms)` |
| `bulwark:siem:export_rate_5m` | `sum(rate(bulwark_siem_events_exported_total[5m]))` |
| `bulwark:siem:error_ratio_5m` | errors / (errors + batches), `clamp_min` guarded |

### SLO (`bulwark_slo_recording`, 30s)

See §5 for the `max()` rationale.

| Rule | Expression |
|------|-----------|
| `bulwark:slo:availability:ratio_{1h,7d,30d}` | `max(avg_over_time(up{job="bulwark-admin"}[W]))` |
| `bulwark:slo:latency:ratio_{1h,7d,30d}` | `avg_over_time((max(bulwark_proxy_latency_p95_ms) <= bool 100)[W:1m])` |
| `bulwark:error_budget:availability:remaining` | `1 - (1 - ratio_30d)/(1 - 0.999)` |
| `bulwark:error_budget:latency:remaining` | `1 - (1 - latency_ratio_30d)/(1 - 0.99)` |
| `bulwark:error_budget:availability:burn_rate_{1h,6h}` | `(1 - ratio_W)/(1 - 0.999)` |
| `bulwark:error_budget:latency:burn_rate_1h` | `(1 - latency_ratio_1h)/(1 - 0.99)` |

**Objectives:** availability **99.9%**, latency (proxy p95 ≤ **100 ms**) **99%**.
The latency SLO is an *availability-of-latency* ratio (fraction of time p95 held
under objective), not a per-request bucket ratio — the proxy exports percentile
gauges, not a per-request histogram.

---

## 5. Why SLO Rules Aggregate with `max()`

The SLO recording rules wrap the availability query in `max(...)`:

```promql
bulwark:slo:availability:ratio_30d = max(avg_over_time(up{job="bulwark-admin"}[30d]))
```

Reasons:

1. **Collapse to a single series.** Single-value SLO gauges break if the query
   returns multiple series (one per `instance`). `max()` collapses per-target
   `instance`/`job` labels into one cluster-wide value.
2. **Correct availability semantics.** `max()` answers "was **at least one**
   target up" — which matches load-balanced routing. That is the right
   service-availability aggregation.
3. **Robust to ghost series.** A scrape-config or FQDN change can leave a stale
   `instance` series behind. An `avg()` would be dragged down by that dead
   series and understate availability; `max()` ignores it.

---

## 6. Dashboards

Four dashboards, provisioned with fixed UIDs.

### `bulwark-overview` — Operational Overview

| Panel | Type | Query |
|-------|------|-------|
| Request Rate (RPS) by Tenant | timeseries | `sum by (tenant)(rate(bulwark_requests_by_tenant_total{tenant=~"$tenant"}[$timerange]))` |
| Verdict Distribution | piechart | `sum by (verdict)(bulwark_verdicts_total)` |
| Metrics Pipeline | stat | `up{job="bulwark-admin"}` |
| Total Requests | stat | `bulwark_requests_total` |
| P50/P95/P99 Latency | timeseries | `bulwark:latency:{p50,p95,p99}` |
| SIEM Export Error Ratio | gauge | `bulwark:siem:error_ratio_5m` |
| **Top Detected Categories** | barchart | `topk(10, sum by (category)(bulwark_detections_by_category_total))` — see §7 |
| Blocks by Tenant | table | `topk(20, bulwark_verdicts_by_tenant_total{verdict="block", tenant=~"$tenant"})` |

### `bulwark-security` — Security Operations

| Panel | Type | Query |
|-------|------|-------|
| Attack Attempts per Minute (by Category) | timeseries | `sum by (category)(rate(bulwark_detections_by_category_total{category=~"$category"}[$timerange])) * 60` |
| Critical Detections (1h) | stat | `sum(increase(bulwark_detections_by_severity_total{severity="critical"}[1h]))` |
| Total Blocks (24h) | stat | `sum(increase(bulwark_verdicts_total{verdict="block"}[24h]))` |
| SIEM Export Rate | timeseries | `bulwark:siem:export_rate_5m`, `sum(rate(bulwark_siem_export_errors_total[5m]))` |
| **Matched Patterns (Top 10)** | barchart | `topk(10, sum by (pattern_id)(bulwark_pattern_matches_total))` — see §7 |
| Detections by Severity | timeseries | `sum by (severity)(rate(bulwark_detections_by_severity_total[$timerange]))` |
| **Detections by Category (Totals)** | barchart | `topk(15, sum by (category)(bulwark_detections_by_category_total{category=~"$category"}))` — see §7 |
| Top Blocking by Tenant | table | `topk(10, sum by (tenant)(bulwark_verdicts_by_tenant_total{verdict="block"}))` (+ block ratio) |
| Per-Tenant Verdict Breakdown | table | `sum by (tenant, verdict)(bulwark_verdicts_by_tenant_total)` |

Templating vars: `$tenant`, `$category`, `$timerange`.

### `bulwark-slo` — SLO / Error Budget

Gauges + timeseries over the `bulwark:slo:*` / `bulwark:error_budget:*`
recording rules (see §4). Panel 11 "Monthly SLO Report" is a table over instant
vectors and uses the `merge`+`organize` transform pattern (the reference
implementation for §7).

### `bulwark-correlation` — Correlation Engine (opt-in)

Stats, rates, enforcement mix and cumulative table over `bulwark_correlation_*`.
Effectively flat until `BULWARK_CORRELATION_ENABLED=true`. The
`bulwark_correlation_eval_duration_seconds` histogram powers latency alerting
(`histogram_quantile(0.95, …) > 0.025` for 10m → warning).

---

## 7. Categorical Barcharts from Instant Vectors (the `merge` pattern)

**This is the single most common dashboard gotcha in this repo — read before
editing any barchart/table fed by an instant vector.**

A query like `topk(10, sum by (category)(bulwark_detections_by_category_total))`
returns, in table/instant mode, **one frame per series** — each frame has a
`Time` column and a `Value` field, and the `category` dimension is carried as a
**label on the `Value` field**, never as its own column. Therefore:

- `xField: "category"` → **empty panel** (no such column exists).
- `labelsToFields` + `merge` → **broken** (each frame's `Value` keeps a distinct
  label, so `merge` produces separate columns, not one categorical axis).

**Correct approach** (used by the working "Verdict Distribution" piechart and the
"Monthly SLO Report" table):

```json
"targets": [{ "expr": "topk(10, sum by (category)(bulwark_detections_by_category_total))",
              "format": "table", "instant": true, "legendFormat": "{{category}}" }],
"transformations": [
  { "id": "merge", "options": {} },
  { "id": "organize", "options": {
      "excludeByName": { "Time": true, "__name__": true, "job": true, "instance": true } } }
]
```

- `merge` collapses the per-series frames into one wide frame (one field per
  series).
- `legendFormat: "{{category}}"` (or `{{pattern_id}}`) names each field.
- `organize` drops the noise columns.

Applies to the three barcharts: overview "Top Detected Categories", security
"Detections by Category (Totals)" and "Matched Patterns (Top 10)".

> See the empty-panel runbook in
> [TROUBLESHOOTING.md](TROUBLESHOOTING.md#grafana-panel-shows-no-data) for the
> full diagnosis workflow.

---

## 8. Operating Notes

- **Live dashboard update (Helm/K8s):** patch the ConfigMap, then wait for the
  kubelet to sync it into the Grafana pod (~60–75 s) and Grafana's file provider
  to reload:
  ```bash
  kubectl patch cm grafana-dashboards -n bulwark-gateway --type merge \
    --patch-file <(python3 -c 'import json,sys;print(json.dumps({"data":{"bulwark-overview.json":open("helm/bulwark-gateway/dashboards/bulwark-overview.json").read()}}))')
  ```
  A hard browser refresh (Ctrl+Shift+R) clears Grafana's client-side panel cache.
- **Distroless images:** the admin/proxy containers have **no shell**. Use
  `kubectl exec … -- python3 -c '…'` for in-pod inspection. The Grafana image
  (`grafana/grafana:10.4.0`) has BusyBox `wget`/`grafana-cli` but no `python3`;
  the Redis pod has BusyBox `sh`.
- **Redis inspection:** `KEYS` is disabled — use `SCAN`. AUTH via secret
  `bulwark-redis-secrets` key `redis-password`.
- **Verify a metric exists** before wiring a panel:
  ```bash
  curl -s -H "Authorization: Bearer $TOKEN" \
    http://admin:8090/admin/health/metrics | grep '^bulwark_'
  ```
