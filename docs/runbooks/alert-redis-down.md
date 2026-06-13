# Runbook: SentinelRedisDown

## Alert Details

- **Severity**: Critical
- **Alert rule**: `SentinelRedisDown`
- **Prometheus expression**:
  ```promql
  up{job="sentinel-redis"} == 0
  ```
- **Fires when**: Redis instance is unreachable for more than 1 minute
- **Team**: Platform
- **Compliance**: SOC 2 CC7.2

## Impact Assessment

- **Who is affected**: All tenants (rate limiting degrades to in-memory per-pod)
- **What degrades**:
  - Rate limiting: falls back to non-distributed in-memory (each pod tracks independently)
  - Pattern sync: disabled (admin pattern changes won't propagate to proxy)
  - Global counters: unavailable (`sentinel:global:*` keys)
  - Recent blocks: not recorded (admin dashboard shows stale data)
  - SIEM stats: `sentinel:siem:*` counters stop updating
- **What continues working**: Guardrails still enforce (patterns compiled at startup), proxying still works, SIEM export still functions
- **Business impact**: Reduced visibility, rate limits less effective (per-pod instead of global), possible over/under-limiting

## Immediate Actions (First 5 Minutes)

1. **Acknowledge the alert** in PagerDuty
2. **Verify Redis is actually down** (not a network/scrape issue):
   ```bash
   # Check Redis pod status
   kubectl get pods -l app.kubernetes.io/name=redis -n sentinel-gateway

   # Check Redis pod events
   kubectl describe pod -l app.kubernetes.io/name=redis -n sentinel-gateway | tail -20

   # Try direct connectivity from proxy pod
   kubectl exec deploy/proxy -n sentinel-gateway -- \
     python -c "import redis; r=redis.from_url('redis://redis:6379'); print(r.ping())"
   ```
3. **Check if proxy is degraded gracefully**:
   ```bash
   # Proxy health should still be 200 (Redis is optional)
   kubectl exec deploy/proxy -n sentinel-gateway -- \
     curl -s http://localhost:8080/health | jq .
   ```
4. **Determine cause** — OOMKill, disk full, network policy, or crash

## Investigation Steps

```bash
# 1. Pod status and restart count
kubectl get pods -l app.kubernetes.io/name=redis -n sentinel-gateway -o wide

# 2. Pod events (OOMKill, eviction, scheduling failure)
kubectl describe pod -l app.kubernetes.io/name=redis -n sentinel-gateway

# 3. Redis logs (last restart)
kubectl logs -l app.kubernetes.io/name=redis -n sentinel-gateway --previous --tail=50

# 4. Current Redis logs
kubectl logs -l app.kubernetes.io/name=redis -n sentinel-gateway --tail=100

# 5. Resource usage (memory/CPU)
kubectl top pod -l app.kubernetes.io/name=redis -n sentinel-gateway

# 6. PVC status (disk full?)
kubectl get pvc -n sentinel-gateway
kubectl describe pvc redis-data -n sentinel-gateway

# 7. Network policy (connectivity blocked?)
kubectl get networkpolicies -n sentinel-gateway

# 8. Check if external Redis (if applicable)
# For Azure/AWS/GCP managed Redis, check cloud console
```

### Common Causes

| Cause | Indicator | Fix |
|-------|-----------|-----|
| OOMKill | `describe pod` shows OOMKilled | Increase memory limit in Helm values |
| Disk full | PVC at 100%, Redis AOF/RDB write failure | Expand PVC or clean snapshots |
| Network policy | New netpol blocking Redis port | Fix network policy selectors |
| Pod eviction | Node pressure, pod evicted | Check node resources, add PDB |
| Config error | Bad password, TLS mismatch | Check secrets mount, Redis URL |
| Node failure | Pod stuck in Pending/Unknown | Check node status, reschedule |

## Remediation

### Quick Recovery

```bash
# 1. If pod is CrashLoopBackOff, check and fix the cause, then:
kubectl delete pod -l app.kubernetes.io/name=redis -n sentinel-gateway
# (StatefulSet/Deployment will recreate it)

# 2. If OOMKilled, increase limit:
kubectl patch deploy redis -n sentinel-gateway --type=json -p='[
  {"op":"replace","path":"/spec/template/spec/containers/0/resources/limits/memory","value":"256Mi"}
]'

# 3. If disk full, expand PVC (if StorageClass supports it):
kubectl patch pvc redis-data -n sentinel-gateway -p '{"spec":{"resources":{"requests":{"storage":"2Gi"}}}}'

# 4. If network connectivity issue:
kubectl exec deploy/proxy -n sentinel-gateway -- nc -zv redis 6379
```

### After Redis Recovers

```bash
# 1. Verify Redis is responding
kubectl exec deploy/redis -n sentinel-gateway -- redis-cli PING

# 2. Check data persistence (counters should survive restart if AOF enabled)
kubectl exec deploy/redis -n sentinel-gateway -- redis-cli MGET \
  sentinel:global:requests_total sentinel:global:block

# 3. Force pattern re-sync from admin
curl -X POST http://admin:8090/admin/guardrails/sync

# 4. Verify rate limiting is distributed again
kubectl logs deploy/proxy -n sentinel-gateway --since=2m | grep -i "redis"

# 5. Verify SIEM stats are updating
kubectl exec deploy/redis -n sentinel-gateway -- redis-cli GET sentinel:siem:updated_at
```

### If Using External Redis (Azure/AWS/GCP)

```bash
# Check connection string
kubectl get secret sentinel-redis-secret -n sentinel-gateway -o jsonpath='{.data.url}' | base64 -d

# Test TLS connectivity
kubectl exec deploy/proxy -n sentinel-gateway -- \
  python -c "import redis; r=redis.from_url('rediss://...', ssl_cert_reqs=None); print(r.ping())"

# Check cloud provider status page for outage
# Azure: status.azure.com
# AWS: health.aws.amazon.com
# GCP: status.cloud.google.com
```

## Escalation

- If not resolved in 15 minutes → Page platform on-call lead
- If Redis cannot be recovered and rate limiting is critical → Consider emergency scale-up of proxy pods (more pods = finer-grained in-memory limiting)
- If data loss suspected (counters reset) → Inform security team (audit trail gap)
- If external Redis provider outage → Open support ticket with cloud provider, communicate ETA internally

## Related Alerts

- [`SentinelHighBlockRate`](alert-high-block-rate.md) — pattern sync failure may cause false positives
- [`SentinelProxyPodsDown`](alert-redis-down.md) — if proxy pods are crashing due to Redis dependency
- [`SentinelAuditLogFailures`](alert-redis-down.md) — Redis-backed audit may fail
- [`SentinelMemoryPressure`](alert-redis-down.md) — OOMKill often precedes Redis down

## Post-Incident

- [ ] Verify no audit trail gap (SOC 2 CC7.2 requirement)
- [ ] Check if global counters are accurate post-recovery
- [ ] Increase Redis memory limits if OOMKill was cause
- [ ] Add Redis PodDisruptionBudget if not present
- [ ] Consider Redis Sentinel/Cluster for HA if single-instance
- [ ] Create Jira ticket for root cause
- [ ] Update this runbook with lessons learned
