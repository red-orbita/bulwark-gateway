# Runbook: SentinelBackendErrorRateHigh

## Alert Details

- **Severity**: Critical
- **Alert rule**: `SentinelBackendErrorRateHigh`
- **Prometheus expression**:
  ```promql
  (
    sum(rate(sentinel_backend_errors_total[5m]))
    /
    clamp_min(sum(rate(sentinel_requests_total[5m])), 1)
  ) > 0.05
  ```
- **Fires when**: >5% of forwarded requests are failing at the LLM backend over 3 minutes
- **Team**: Platform

## Impact Assessment

- **Who is affected**: All tenants using the failing backend (may be subset if multi-backend)
- **What degrades**: AI agent requests return 502/504 errors, workflows broken
- **What still works**: Guardrails, rate limiting, health checks
- **Business impact**: Direct user-facing failures, SLA at risk

## Immediate Actions (First 5 Minutes)

1. **Acknowledge the alert** in PagerDuty
2. **Identify which backend(s) are failing**:
   ```bash
   # Check proxy logs for backend errors
   kubectl logs deploy/proxy -n sentinel-gateway --since=5m | \
     jq 'select(.event=="backend_error") | {backend: .backend_url, status: .status_code, error: .error}'
   ```
3. **Check backend health directly**:
   ```bash
   # Get configured backends from agent registry
   kubectl exec deploy/proxy -n sentinel-gateway -- \
     cat /app/config/agents.yaml | grep backend_url

   # Test backend health endpoint
   kubectl exec deploy/proxy -n sentinel-gateway -- \
     curl -s -o /dev/null -w "%{http_code}" http://ollama:11434/health
   ```
4. **Check if SSRF protection is blocking legitimate backend** (rare but possible after config change):
   ```bash
   kubectl logs deploy/proxy -n sentinel-gateway --since=5m | grep -i "ssrf"
   ```
5. **Decision point**: Is the backend overloaded, down, or is there a network issue?

## Investigation Steps

```bash
# 1. Error rate by backend (if multi-backend)
# Prometheus: sum by (backend)(rate(sentinel_backend_errors_total[5m]))

# 2. HTTP status code distribution from backend
kubectl logs deploy/proxy -n sentinel-gateway --since=10m | \
  jq 'select(.event=="backend_response") | .status_code' | sort | uniq -c

# 3. Backend response time (is it timing out?)
# Prometheus: histogram_quantile(0.99, sum(rate(sentinel_request_duration_seconds_bucket{phase="backend"}[5m])) by (le))

# 4. Check if backend DNS resolves
kubectl exec deploy/proxy -n sentinel-gateway -- nslookup ollama

# 5. Check backend pod/service status (if in-cluster)
kubectl get pods -l app=ollama -n sentinel-gateway
kubectl get svc -l app=ollama -n sentinel-gateway

# 6. Check ExternalName service (if backend is external)
kubectl get svc backend -n sentinel-gateway -o yaml

# 7. Network connectivity test
kubectl exec deploy/proxy -n sentinel-gateway -- \
  curl -v --connect-timeout 5 http://ollama:11434/api/tags

# 8. Check if rate limit on backend side (429s)
kubectl logs deploy/proxy -n sentinel-gateway --since=5m | \
  jq 'select(.status_code==429)'
```

### Common Causes

| Cause | Indicator | Fix |
|-------|-----------|-----|
| Backend OOMKill | Backend pod restarting, 502 errors | Increase backend memory limits |
| Backend overloaded | 429 or slow 200s, then timeouts | Scale backend or reduce concurrency |
| DNS resolution failure | `nslookup` fails, connection refused | Fix DNS/service config |
| Network policy blocking | Connection timeout, no response | Verify network policies allow proxy→backend |
| TLS certificate mismatch | SSL handshake errors in logs | Update backend TLS config |
| Backend config change | Works for some models, not others | Check model availability |
| Timeout too short | 504 errors, large model responses | Increase `SENTINEL_BACKEND_TIMEOUT` |

## Remediation

### Backend is Down (In-Cluster)

```bash
# 1. Check pod status
kubectl get pods -l app=ollama -n sentinel-gateway

# 2. If CrashLoopBackOff, check logs
kubectl logs -l app=ollama -n sentinel-gateway --previous --tail=50

# 3. Restart backend
kubectl rollout restart deploy/ollama -n sentinel-gateway

# 4. Monitor recovery
kubectl rollout status deploy/ollama -n sentinel-gateway
```

### Backend is Overloaded

```bash
# 1. Scale backend (if possible)
kubectl scale deploy/ollama --replicas=3 -n sentinel-gateway

# 2. Alternatively, reduce proxy concurrency temporarily
kubectl set env deploy/proxy SENTINEL_BACKEND_TIMEOUT=60 -n sentinel-gateway

# 3. Consider enabling request queuing or circuit breaker at proxy level
```

### Backend is External (Unreachable)

```bash
# 1. Check external connectivity
kubectl exec deploy/proxy -n sentinel-gateway -- \
  curl -v --connect-timeout 10 https://api.openai.com/v1/models

# 2. Check if egress network policy allows the connection
kubectl get networkpolicies -n sentinel-gateway -o yaml | grep -A5 "egress"

# 3. Check proxy environment for correct backend URL
kubectl get deploy/proxy -n sentinel-gateway -o jsonpath='{.spec.template.spec.containers[0].env}' | jq .

# 4. If cloud API, check status page and API key validity
```

### Timeout Issues

```bash
# 1. Check current timeout setting
kubectl exec deploy/proxy -n sentinel-gateway -- \
  env | grep SENTINEL_BACKEND_TIMEOUT

# 2. Increase timeout if requests are legitimately slow
kubectl set env deploy/proxy SENTINEL_BACKEND_TIMEOUT=180 -n sentinel-gateway

# 3. Verify with a test request
kubectl exec deploy/proxy -n sentinel-gateway -- \
  curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer <test-key>" \
  -H "X-Tenant-ID: default-corp" \
  -H "X-Agent-ID: support-bot" \
  -d '{"model":"tinyllama","messages":[{"role":"user","content":"hello"}]}'
```

## Escalation

- If not resolved in 15 minutes → Page platform on-call lead
- If backend is a third-party API (OpenAI, Azure) → Open vendor support ticket
- If affecting all tenants with no workaround → Escalate to P1
- If customer SLA breach imminent → Notify Customer Success for proactive communication

## Related Alerts

- [`SentinelGuardrailLatencyHigh`](alert-guardrail-latency.md) — backend slowness can cascade to overall latency
- [`SentinelProxyPodsDown`](alert-redis-down.md) — proxy pods may crash if backend causes resource exhaustion
- [`SentinelSLORequestSuccessLow`](alert-backend-errors.md) — backend errors directly impact success rate SLO
- [`SentinelSLOLatencyBreach`](alert-backend-errors.md) — timeouts contribute to latency SLO breach

## Post-Incident

- [ ] Verify no data loss during backend outage (requests should have returned 502, not been silently dropped)
- [ ] Review backend timeout settings — are they appropriate for the model size?
- [ ] Consider adding circuit breaker to prevent cascade failures
- [ ] Add backend health check to `validate-deployment.sh` if not present
- [ ] Create Jira ticket for root cause
- [ ] If vendor outage, document SLA violation for contract review
- [ ] Update this runbook with lessons learned
