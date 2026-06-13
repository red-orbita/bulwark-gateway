# Runbook: SentinelGuardrailLatencyHigh

## Alert Details

- **Severity**: Critical
- **Alert rule**: `SentinelGuardrailLatencyHigh`
- **Prometheus expression**:
  ```promql
  histogram_quantile(0.99,
    sum(rate(sentinel_request_duration_seconds_bucket{phase="input_guardrail"}[5m])) by (le)
  ) > 0.100
  ```
- **Fires when**: Input guardrail P99 latency exceeds 100ms for more than 3 minutes
- **Team**: Platform
- **Compliance**: SOC 2 CC7.2

## Impact Assessment

- **Who is affected**: All tenants — guardrail processing is in the hot path for every request
- **What degrades**: End-to-end request latency increases, user experience suffers, possible timeouts
- **What still works**: Security enforcement continues (slower but still blocking)
- **Business impact**: SLA latency targets at risk, user-perceived slowness, possible client-side timeouts

## Immediate Actions (First 5 Minutes)

1. **Acknowledge the alert** in PagerDuty
2. **Confirm latency is actually elevated** (not a metric artifact):
   ```bash
   # Check current P99 from Prometheus
   # histogram_quantile(0.99, sum(rate(sentinel_request_duration_seconds_bucket{phase="input_guardrail"}[5m])) by (le))

   # Check proxy health stats
   kubectl exec deploy/proxy -n sentinel-gateway -- \
     curl -s http://localhost:8080/health/stats | jq '.latency'
   ```
3. **Check CPU pressure** (regex processing is CPU-bound):
   ```bash
   kubectl top pods -l app.kubernetes.io/name=sentinel-proxy -n sentinel-gateway
   ```
4. **Check for recent pattern changes** that may have introduced backtracking:
   ```bash
   kubectl exec deploy/redis -n sentinel-gateway -- redis-cli GET sentinel:guardrails:version
   ```
5. **Decision point**: Is this CPU saturation, regex backtracking, or a large payload issue?

## Investigation Steps

```bash
# 1. CPU utilization of proxy pods
kubectl top pods -l app.kubernetes.io/name=sentinel-proxy -n sentinel-gateway

# 2. Check if specific phase is slow (compare guardrail vs total)
# Prometheus:
# histogram_quantile(0.99, sum(rate(sentinel_request_duration_seconds_bucket{phase="input_guardrail"}[5m])) by (le))
# histogram_quantile(0.99, sum(rate(sentinel_request_duration_seconds_bucket{phase="total"}[5m])) by (le))

# 3. Look for large payloads (long messages trigger more regex work)
kubectl logs deploy/proxy -n sentinel-gateway --since=5m | \
  jq 'select(.event=="request_processed") | {duration_ms: .guardrail_duration_ms, message_length: .message_length}' | \
  sort -t: -k2 -rn | head -10

# 4. Check if entropy detection is triggering excessive decoding
kubectl logs deploy/proxy -n sentinel-gateway --since=5m | \
  grep -i "entropy\|decode\|base64"

# 5. Check request rate (more requests = more CPU contention)
# Prometheus: sum(rate(sentinel_requests_total[5m]))

# 6. Check if HPA is scaling (are we at max replicas?)
kubectl get hpa -n sentinel-gateway
kubectl describe hpa proxy -n sentinel-gateway

# 7. Pod resource limits
kubectl get deploy/proxy -n sentinel-gateway -o jsonpath='{.spec.template.spec.containers[0].resources}'

# 8. Check for regex backtracking (patterns with catastrophic backtracking)
# Look for requests taking >1s in guardrail phase
kubectl logs deploy/proxy -n sentinel-gateway --since=10m | \
  jq 'select(.guardrail_duration_ms > 1000)'
```

### Common Causes

| Cause | Indicator | Fix |
|-------|-----------|-----|
| CPU saturation | `kubectl top` shows >90% CPU | Scale HPA, increase CPU limits |
| Large payloads | Logs show high `message_length` correlated with high latency | Add message size limit |
| Regex backtracking | Single requests with >1s guardrail time, specific pattern | Fix or disable the pattern |
| New custom pattern | Latency spike correlates with `guardrails:version` change | Revert the pattern |
| High request rate | QPS spike beyond HPA capacity | Scale manually, rate limit more aggressively |
| Multi-layer decoding | Entropy detection triggering excessive decode attempts | Tune entropy threshold |
| Memory pressure | Near OOM → GC pauses → latency spikes | Increase memory limits |

## Remediation

### CPU Saturation

```bash
# 1. Manually scale up (immediate relief)
kubectl scale deploy/proxy --replicas=5 -n sentinel-gateway

# 2. Verify HPA max allows this
kubectl get hpa proxy -n sentinel-gateway -o jsonpath='{.spec.maxReplicas}'

# 3. If at max, increase HPA max
kubectl patch hpa proxy -n sentinel-gateway --type=json -p='[
  {"op":"replace","path":"/spec/maxReplicas","value":10}
]'

# 4. Increase CPU request/limit for better scheduling
kubectl patch deploy proxy -n sentinel-gateway --type=json -p='[
  {"op":"replace","path":"/spec/template/spec/containers/0/resources/requests/cpu","value":"1000m"},
  {"op":"replace","path":"/spec/template/spec/containers/0/resources/limits/cpu","value":"2000m"}
]'
```

### Regex Backtracking (Specific Pattern)

```bash
# 1. Identify the problematic pattern (check logs for slow requests)
kubectl logs deploy/proxy -n sentinel-gateway --since=10m | \
  jq 'select(.guardrail_duration_ms > 500) | .matched_pattern' | sort | uniq -c

# 2. Disable the pattern temporarily
curl -X POST http://admin:8090/admin/guardrails/disable \
  -H "Content-Type: application/json" \
  -d '{"pattern_id": "<PATTERN_ID>"}'

# 3. Verify latency drops
# Watch: histogram_quantile(0.99, sum(rate(sentinel_request_duration_seconds_bucket{phase="input_guardrail"}[2m])) by (le))

# 4. Fix the regex (add atomic groups, possessive quantifiers, or rewrite)
# Then re-enable and test
```

### Large Payload Issue

```bash
# 1. Check if specific tenant is sending oversized messages
kubectl logs deploy/proxy -n sentinel-gateway --since=5m | \
  jq 'select(.message_length > 10000) | {tenant: .tenant_id, length: .message_length}'

# 2. Consider adding max_message_length to proxy config
kubectl set env deploy/proxy SENTINEL_MAX_MESSAGE_LENGTH=32768 -n sentinel-gateway

# 3. Alternatively, apply per-tenant rate limits on large messages
```

### High Request Rate Surge

```bash
# 1. Check current QPS
# Prometheus: sum(rate(sentinel_requests_total[1m]))

# 2. If from specific tenant, apply rate limit
kubectl exec deploy/redis -n sentinel-gateway -- \
  redis-cli SET sentinel:rate_limit:override:<TENANT_ID> 10

# 3. Scale up to handle load
kubectl scale deploy/proxy --replicas=8 -n sentinel-gateway
```

## Escalation

- If not resolved in 15 minutes → Page platform on-call lead
- If latency exceeds 500ms P99 → Escalate to P1 (SLO breach)
- If caused by regex backtracking and pattern is critical → Security + Platform joint review
- If scaling cannot resolve → Consider temporary guardrail bypass for unaffected tenants (requires IC approval)

## Related Alerts

- [`SentinelSLOLatencyBreach`](alert-guardrail-latency.md) — guardrail latency directly contributes to SLO
- [`SentinelMemoryPressure`](alert-guardrail-latency.md) — GC pauses can cause latency spikes
- [`SentinelBackendErrorRateHigh`](alert-backend-errors.md) — backend slowness may compound latency
- [`SentinelHighBlockRate`](alert-high-block-rate.md) — attack traffic can increase guardrail processing load
- [`SentinelMLScannerSlow`](alert-guardrail-latency.md) — ML phase adds to total latency

## Post-Incident

- [ ] Identify and fix any backtracking regex patterns
- [ ] Review CPU limits — are they appropriate for current traffic?
- [ ] Review HPA thresholds — is 70% CPU target appropriate?
- [ ] Add message size limits if large payloads caused the issue
- [ ] Benchmark guardrail performance after any pattern changes
- [ ] Create Jira ticket for root cause
- [ ] Update this runbook with lessons learned
