# Runbook: Correlation Engine Alerts

Covers the four alerts in the `bulwark_correlation` group
(`prometheus/rules.yml` and the Helm `monitoring.yaml` ConfigMap):

| Alert | Severity | Signal |
|-------|----------|--------|
| `BulwarkCorrelatedExfiltration` | Warning | Suspicious input paired with a sensitive output in the *same* request |
| `BulwarkOriginRiskBlocking` | Warning | Requests hardened to BLOCK from *accumulated* origin risk, not the current input |
| `BulwarkCorrelationTapDropping` | Warning | Event tap dropping WARN/BLOCK events → origin-risk under-counting |
| `BulwarkCorrelationEvaluationSlow` | Warning | Inline-evaluation P95 latency above 25 ms |

- **Team**: Security (exfiltration / origin-risk), Platform (tap drops / latency)
- **Compliance**: SOC 2 CC7.2

> **Opt-in feature.** These alerts only fire when `BULWARK_CORRELATION_ENABLED`
> is set on the proxy. When the engine is disabled the counters stay flat and
> none of these rules trigger. The metrics are sourced from the shared Redis
> hash `bulwark:correlation:counters` and surfaced via the admin exposition
> (`GET /admin/health/metrics`); the proxy itself exposes no `/metrics`.

> **Distroless note.** The proxy and admin images are Google Distroless — **no
> shell, no `curl`, no `redis-cli`**. Inspect the proxy/admin with `python3 -c`,
> inspect Redis on the Redis pod (which *does* have `redis-cli` and `sh`), and
> prefer the admin API/UI for correlation state.

---

## Shared Triage (all four alerts)

```bash
# 1. Confirm the engine is actually enabled (else the alert is stale config)
kubectl exec deploy/proxy -n bulwark-gateway -- \
  python3 -c "from src.config import settings; print('enabled=', settings.correlation_enabled, 'blocking=', settings.correlation_blocking)"

# 2. Read the live counter hash directly from Redis (source of truth)
kubectl exec deploy/redis -n bulwark-gateway -- \
  redis-cli HGETALL bulwark:correlation:counters

# 3. Read the correlation engine status via the admin API (effective config,
#    Redis health, enabled/blocking) — requires a correlation:read session/JWT
kubectl exec deploy/admin -n bulwark-gateway -- \
  python3 -c "import urllib.request as u; print(u.urlopen('http://localhost:8090/admin/health').read().decode())"
```

The counter hash contains, among others: `incidents_total`, `incidents_blocked`,
`origin_risk_total`, `origin_risk_blocked`, `origin_risk_warned`,
`tap_published`, `tap_processed`, `tap_dropped`, and the latency histogram fields
(`eval_lat_count`, `eval_lat_sum_us`, `eval_lat_bucket_*`).

---

## `BulwarkCorrelatedExfiltration`

- **Expression**: `sum(increase(bulwark_correlation_incidents_total[15m])) > 0`
- **Fires when**: ≥1 confirmed input↔output correlation in 15 minutes
- **MITRE ATT&CK**: T1041, T1048

### What it means

The engine paired a *suspicious input* (a WARN/BLOCK input verdict) with a
*sensitive output* (secret/PII/credential in the response) inside the **same
request and time window**. This is a high-confidence data-exfiltration signal —
an attacker may have coaxed the model into emitting sensitive data that the
per-request guardrails alone let through.

### Response

1. Open the admin **Security Events** viewer and filter `source = correlation_engine`.
2. For each incident inspect the `metadata` (paired input category, output
   category, `confidence` score, request_id). A high `confidence` (≥ the
   configured `confidence_block_threshold`) means strong lexical corroboration
   between the input ask and the leaked output.
3. Identify the tenant/agent/session. Pull the offending request from
   `bulwark:recent_blocks`:
   ```bash
   kubectl exec deploy/redis -n bulwark-gateway -- \
     redis-cli LRANGE bulwark:recent_blocks 0 20
   ```
4. If confirmed malicious: rotate any credential that appeared in the output,
   and consider hardening enforcement (see below). Follow
   [`incident-guardrail-bypass.md`](incident-guardrail-bypass.md) for the full
   bypass playbook.
5. If false positive: the output filter should have redacted the secret anyway —
   verify redaction fired, and tune the paired output pattern if it is benign.

### Hardening (make it BLOCK, not just WARN)

```bash
# Turn on blocking for correlated exfiltration + origin risk at runtime
# (no restart) — requires a correlation:write session/JWT.
# Prefer the admin UI (Correlation page) or:
kubectl exec deploy/admin -n bulwark-gateway -- python3 - <<'PY'
import json, urllib.request
# PUT /admin/correlation/config {"blocking": true}
# (send with a valid admin session cookie / bearer in your environment)
print("Use the admin Correlation page → 'Blocking' toggle, or PUT /admin/correlation/config")
PY
```

---

## `BulwarkOriginRiskBlocking`

- **Expression**: `sum(increase(bulwark_correlation_origin_risk_blocked_total[15m])) > 0`
- **Fires when**: ≥1 request hardened to BLOCK from accumulated origin risk
- **MITRE ATT&CK**: T1190

### What it means

A session/tenant accrued enough **decayed** risk from repeated WARN/BLOCK signals
that the engine hardened a *subsequent* request — even though that request's input
looked clean on its own. This is the signal for a **slow, multi-request probing or
decomposition attack** that any single-request guardrail would miss.

### Response

1. List the active high-risk origins:
   ```bash
   # Admin API: GET /admin/correlation/origins (decayed score, scope, digest, TTL)
   kubectl exec deploy/admin -n bulwark-gateway -- \
     python3 -c "import urllib.request as u; print(u.urlopen('http://localhost:8090/admin/correlation/origins').read().decode())"
   ```
2. The `scope` is `session` or `tenant` (never client IP — origins are not
   attacker-manipulable). Correlate the digest with your access logs to identify
   the caller.
3. Decide: legitimate bursty user vs. adversary.
   - **Adversary** → escalate per [`incident-guardrail-bypass.md`](incident-guardrail-bypass.md);
     consider revoking the API key / session.
   - **False positive** → clear that origin's accrued risk (below) and consider
     raising `correlation_risk_block_threshold` or shortening
     `correlation_risk_decay_seconds` at runtime.
4. Clear a single origin's risk (after handling the caller):
   ```bash
   # DELETE /admin/correlation/origin/{scope_type}/{digest}  (correlation:write)
   # or clear ALL accrued risk: POST /admin/correlation/reset
   ```

---

## `BulwarkCorrelationTapDropping`

- **Expression**: `sum(rate(bulwark_correlation_tap_events_dropped_total[5m])) > 0`
- **Fires when**: the event tap has dropped events for 5 minutes
- **Team**: Platform

### What it means

The async event tap folds WARN/BLOCK events into origin-risk state on a bounded
queue. Drops mean **risk is under-counted** and adaptive enforcement silently
weakens — a security-relevant availability problem, not just a perf blip.

### Response

1. Confirm the drop rate and queue pressure:
   ```bash
   kubectl exec deploy/redis -n bulwark-gateway -- \
     redis-cli HMGET bulwark:correlation:counters tap_published tap_processed tap_dropped
   ```
   A growing gap between `tap_published` and `tap_processed` confirms a saturated
   consumer.
2. Check proxy CPU / throttling and Redis latency:
   ```bash
   kubectl top pod -l app.kubernetes.io/name=proxy -n bulwark-gateway
   kubectl exec deploy/redis -n bulwark-gateway -- redis-cli --latency-history -i 5
   ```
3. Remediate the saturation:
   - Scale the proxy out (more replicas share the load; counters are HINCRBY
     deltas so they sum correctly across replicas).
   - If Redis is the bottleneck, address Redis latency (see
     [`alert-redis-down.md`](alert-redis-down.md)).
4. The tap degrades safe: enforcement still runs on every request; only the
   *accrual* of cross-request risk is affected while drops persist.

---

## `BulwarkCorrelationEvaluationSlow`

- **Expression**:
  `histogram_quantile(0.95, sum(rate(bulwark_correlation_eval_duration_seconds_bucket[5m])) by (le)) > 0.025`
- **Fires when**: inline-evaluation P95 latency exceeds 25 ms for 10 minutes
- **Team**: Platform

### What it means

This histogram measures the hot-path cost the opt-in correlation engine adds:
the origin-risk read (PHASE 1r) and the input↔output correlation (PHASE 5c),
**including their Redis round-trips**. A rising P95 means the feature is taxing
the request path — almost always Redis latency, occasionally regex/entropy cost
on very large payloads — before it surfaces as end-to-end latency.

### Response

1. Confirm the histogram and compute the mean:
   ```bash
   kubectl exec deploy/redis -n bulwark-gateway -- \
     redis-cli HMGET bulwark:correlation:counters eval_lat_count eval_lat_sum_us
   # mean_seconds = eval_lat_sum_us / eval_lat_count / 1e6
   ```
2. Check Redis latency first — it dominates this path:
   ```bash
   kubectl exec deploy/redis -n bulwark-gateway -- redis-cli --latency-history -i 5
   ```
   If Redis is slow, treat as [`alert-redis-down.md`](alert-redis-down.md)-adjacent
   (network, CPU, memory pressure on the Redis pod).
3. Check proxy CPU throttling:
   ```bash
   kubectl top pod -l app.kubernetes.io/name=proxy -n bulwark-gateway
   ```
4. If the cause cannot be fixed quickly and latency is user-impacting, the engine
   is **safe to disable** — it fails safe OFF:
   ```bash
   # Set BULWARK_CORRELATION_ENABLED=false and roll the proxy.
   helm upgrade bulwark ./helm/bulwark-gateway \
     --reuse-values --set proxy.correlation.enabled=false
   ```
   Disabling removes all inline cost; per-request guardrails are unaffected.

---

## Escalation

- Confirmed exfiltration or origin-risk block with a real attacker → P1, page
  security on-call, follow [`incident-guardrail-bypass.md`](incident-guardrail-bypass.md).
- Tap drops or eval latency sustained > 30 min → page platform on-call.

## Related Alerts

- [`BulwarkExfiltrationAttempts`](alert-high-block-rate.md) — per-request exfiltration blocks (the input-only signal this engine correlates).
- [`BulwarkRedisDown`](alert-redis-down.md) — Redis is the dependency behind tap drops and eval latency.
- [`BulwarkGuardrailLatencyHigh`](alert-guardrail-latency.md) — the per-request guardrail latency counterpart.

## Post-Incident

- [ ] Record the tenant/agent/session and whether it was true/false positive.
- [ ] If false positive, capture the tuning change (threshold/decay/window) and why.
- [ ] If tap drops recurred, right-size proxy replicas / Redis before re-enabling blocking.
- [ ] Confirm no credential that appeared in a correlated output remains valid.
- [ ] Update this runbook with lessons learned.
