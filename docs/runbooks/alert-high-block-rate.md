# Runbook: SentinelHighBlockRate

## Alert Details

- **Severity**: Critical
- **Alert rule**: `SentinelHighBlockRate`
- **Prometheus expression**:
  ```promql
  (
    sum(rate(sentinel_verdicts_total{verdict="block"}[5m]))
    /
    clamp_min(sum(rate(sentinel_requests_total[5m])), 1)
  ) > 0.10
  ```
- **Fires when**: >10% of requests are being blocked over 2 minutes
- **Team**: Security
- **Compliance**: SOC 2 CC7.2
- **MITRE ATT&CK**: T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter)

## Impact Assessment

- **Who is affected**: All tenants (if global) or specific tenant (if targeted attack)
- **What degrades**: Legitimate requests may be incorrectly blocked (if false positive), or attack is in progress (if true positive)
- **Business impact**: Users receive 403 errors, AI agent workflows interrupted
- **Downstream**: Customer complaints, SLA breach risk

## Immediate Actions (First 5 Minutes)

1. **Acknowledge the alert** in PagerDuty
2. **Check if this is a targeted or global event**:
   ```bash
   # Per-tenant block rate breakdown
   kubectl exec deploy/redis -n sentinel-gateway -- \
     redis-cli LRANGE sentinel:recent_blocks 0 20
   ```
3. **Identify the blocking pattern(s)**:
   ```bash
   # Recent security events with block verdicts
   kubectl logs deploy/proxy -n sentinel-gateway --since=5m | \
     jq 'select(.verdict=="BLOCK") | {tenant: .tenant_id, category: .category, pattern: .matched_pattern}'
   ```
4. **Check current block rate** (Prometheus):
   ```promql
   sum by (category)(rate(sentinel_verdicts_total{verdict="block"}[5m]))
   ```
5. **Decision point**: Is this concentrated on one category/tenant or distributed?

## Investigation Steps

### Determine: Real Attack vs. False Positive

**Indicators of real attack**:
- Blocks concentrated in `prompt_injection`, `jailbreak`, or `exfiltration` categories
- Single source tenant/IP generating most blocks
- Payloads in `sentinel:recent_blocks` contain known attack patterns
- Correlated with IOC matches (`SentinelIOCMatchesElevated`)

**Indicators of false positive**:
- Blocks across many tenants simultaneously
- Recent pattern update or policy reload correlates with onset
- Blocked content appears legitimate on manual review
- New model deployment or API schema change

### Investigate queries

```bash
# 1. Category breakdown
# Prometheus: sum by (category)(rate(sentinel_verdicts_total{verdict="block"}[5m]))

# 2. Tenant breakdown
# Prometheus: sum by (tenant_id)(rate(sentinel_verdicts_total{verdict="block"}[5m]))

# 3. Check if a recent pattern change caused this
kubectl exec deploy/redis -n sentinel-gateway -- redis-cli GET sentinel:guardrails:version

# 4. View admin audit log for recent changes
kubectl logs deploy/admin -n sentinel-gateway --since=30m | \
  jq 'select(.event=="policy_reload" or .event=="pattern_change")'

# 5. Check global counters for trend
kubectl exec deploy/redis -n sentinel-gateway -- redis-cli MGET \
  sentinel:global:requests_total sentinel:global:block sentinel:global:allow

# 6. Dashboard: Grafana Security Overview
# /grafana/d/sentinel-security/security-overview
```

## Remediation

### If Real Attack

1. **Identify the attacker** (tenant ID, source IP if available):
   ```bash
   kubectl logs deploy/proxy -n sentinel-gateway --since=10m | \
     jq 'select(.verdict=="BLOCK") | .tenant_id' | sort | uniq -c | sort -rn | head -5
   ```
2. **Isolate the tenant** (rate limit override):
   ```bash
   kubectl exec deploy/redis -n sentinel-gateway -- \
     redis-cli SET sentinel:rate_limit:override:<TENANT_ID> 1
   ```
3. **Collect evidence** before any destructive actions:
   ```bash
   ./scripts/ir-collect-evidence.sh --namespace sentinel-gateway --since 30m
   ```
4. **Consider revoking tenant API key** if compromise is confirmed
5. **Monitor for adaptation** — attacker may change techniques
6. **Proceed to incident process** — see [ir-plan.md](ir-plan.md) section 3 (Containment)

### If False Positive

1. **Identify the offending pattern**:
   ```bash
   kubectl logs deploy/proxy -n sentinel-gateway --since=5m | \
     jq 'select(.verdict=="BLOCK") | .matched_pattern' | sort | uniq -c | sort -rn | head -5
   ```
2. **Disable the pattern temporarily** via admin API:
   ```bash
   curl -X POST http://admin:8090/admin/guardrails/disable \
     -H "Content-Type: application/json" \
     -d '{"pattern_id": "<PATTERN_ID>"}'
   ```
3. **Verify block rate drops** (watch Prometheus for 2-3 minutes)
4. **Fix the pattern** — adjust regex to avoid the false positive
5. **Re-enable with fix** and run security smoke test:
   ```bash
   python scripts/security-smoke-test.py --host http://proxy:8080
   ```
6. **Add regression test** in `tests/test_input_guardrail.py` for the legitimate content that was blocked

## Escalation

- If not resolved in 15 minutes → Page Security on-call lead
- If customer-impacting → Notify Customer Success Manager immediately
- If determined to be coordinated attack → Escalate to P1, open war room
- If regulatory data involved → Notify Legal/Compliance (see [incident-data-breach.md](incident-data-breach.md))

## Related Alerts

- [`SentinelPromptInjectionSpike`](alert-high-block-rate.md) — may fire concurrently
- [`SentinelRedisDown`](alert-redis-down.md) — if Redis is down, pattern sync may be broken causing false positives
- [`SentinelExfiltrationAttempts`](alert-high-block-rate.md) — specific exfiltration category blocks
- [`SentinelRateLimitRejectionsHigh`](alert-high-block-rate.md) — rate limiting may be concurrent

## Post-Incident

- [ ] Update alert threshold if current 10% is too sensitive/insensitive
- [ ] Create Jira ticket for root cause analysis
- [ ] Update guardrail patterns if attack was novel
- [ ] Add attack payload to test suite (`tests/qa/legit-flows.yaml` for FP cases)
- [ ] Update this runbook with lessons learned
- [ ] Schedule post-incident review if P1/P2
