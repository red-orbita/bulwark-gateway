# Incident Response Plan — Sentinel Gateway

**Document Classification**: Internal — SOC 2 CC7.3 / CC7.4  
**Framework**: NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide)  
**Scope**: All security incidents involving the Sentinel Gateway proxy, admin panel, and connected infrastructure  
**Owner**: Security Engineering Lead  
**Approval**: CISO  
**Review Cycle**: Quarterly or after any P1 incident

---

## Table of Contents

1. [Preparation](#1-preparation)
2. [Detection and Analysis](#2-detection-and-analysis)
3. [Containment](#3-containment)
4. [Eradication](#4-eradication)
5. [Recovery](#5-recovery)
6. [Lessons Learned](#6-lessons-learned)
7. [Appendices](#appendices)

---

## 1. Preparation

### 1.1 Incident Response Team

| Role | Responsibility | Contact Method |
|------|---------------|----------------|
| **Incident Commander (IC)** | Owns the incident lifecycle, makes containment decisions | PagerDuty escalation |
| **Security Analyst** | Investigates alerts, performs forensic analysis | On-call rotation |
| **Platform Engineer** | Infrastructure remediation, scaling, restarts | On-call rotation |
| **Communications Lead** | Internal/external stakeholder updates | Slack DM + email |
| **Legal/Compliance** | Regulatory notification decisions (GDPR, CCPA) | Email, phone |
| **Customer Success** | Customer-facing communication | Slack + Zendesk |

### 1.2 Communication Channels

| Channel | Purpose | When Used |
|---------|---------|-----------|
| `#sentinel-incidents` (Slack) | War room for active incidents | All P1/P2 |
| `#sentinel-alerts` (Slack) | Automated alert routing | Always |
| PagerDuty service: `sentinel-security` | P1 security incidents | Guardrail bypass, data breach |
| PagerDuty service: `sentinel-platform` | P2 infrastructure incidents | Redis down, pod failures |
| Zoom bridge: `[company-ir-bridge]` | Voice coordination for P1 | Complex multi-team incidents |
| `security-incidents@company.com` | Formal incident reports | Post-incident, regulatory |

### 1.3 Tools and Access

| Tool | Purpose | Access Procedure |
|------|---------|-----------------|
| Sentinel Admin UI (`:8090`) | Real-time blocks, pattern management | RBAC session login |
| Grafana (`:3000`) | Metrics dashboards, alert history | SSO |
| Prometheus (`:9090`) | Raw metric queries, alert status | Port-forward or ingress |
| Redis CLI | Rate limit state, recent blocks, counters | `kubectl exec` into Redis pod |
| `kubectl` | Pod management, log retrieval | Cluster RBAC |
| `scripts/ir-collect-evidence.sh` | Automated evidence preservation | Shell access to cluster |
| Wazuh SIEM | Correlated security events, MITRE mapping | SIEM dashboard |

### 1.4 Preparation Checklist

- [ ] All team members have PagerDuty accounts and are in rotation
- [ ] `kubectl` access to `sentinel-gateway` namespace confirmed for all responders
- [ ] Evidence collection script tested within last 30 days
- [ ] Communication templates reviewed and updated
- [ ] Regulatory contacts (DPA, legal counsel) current
- [ ] Backup alert channels verified (if primary Slack is down)
- [ ] IR plan reviewed within last 90 days

---

## 2. Detection and Analysis

### 2.1 Detection Sources

| Source | Mechanism | Alert Examples |
|--------|-----------|----------------|
| Prometheus alerting | Metric threshold breach | `SentinelHighBlockRate`, `SentinelRedisDown` |
| Sentinel SIEM exporter | Security event correlation | Clustered prompt injection attempts |
| Wazuh rules | MITRE ATT&CK pattern match | Rule 100101 (injection), 100103 (jailbreak) |
| Admin dashboard | Real-time block feed | Visual anomaly detection |
| Customer report | Support ticket | "My requests are being blocked" |
| External notification | Threat intel feed match | IOC hit on known C2 domain |

### 2.2 Severity Classification

| Severity | Criteria | Response SLA | Escalation |
|----------|----------|-------------|------------|
| **P1 — Critical** | Active data breach, guardrail bypass confirmed, credential exposure in production | 15 min acknowledge, 1 hr containment | Immediate: IC + Security + Legal |
| **P2 — High** | Service degradation affecting multiple tenants, sustained attack campaign, Redis/infra failure | 30 min acknowledge, 4 hr containment | 15 min: On-call SRE + Security |
| **P3 — Medium** | Single-tenant impact, elevated false positive rate, SIEM blind spot | 2 hr acknowledge, 24 hr resolution | Business hours: Security team |
| **P4 — Low** | Informational anomaly, performance degradation (within SLO), documentation gap | 24 hr acknowledge, 1 week resolution | Next standup: ticket creation |

### 2.3 Escalation Matrix

```
Alert fires
  │
  ├─ P4/Info → Log ticket → Monitor
  │
  ├─ P3/Warning → Slack #sentinel-alerts → On-call acknowledges
  │                                         └─ Not resolved in 2hr? → Escalate to P2
  │
  ├─ P2/High → PagerDuty page → On-call responds in 30min
  │                              └─ Not contained in 4hr? → Escalate to P1
  │
  └─ P1/Critical → PagerDuty page ALL → IC declares incident → War room opens
                                         └─ Legal notified within 1hr
                                         └─ Customer comms within 4hr
```

### 2.4 Initial Triage (First 5 Minutes)

1. **Acknowledge the alert** in PagerDuty (stops re-escalation)
2. **Classify severity** using criteria above
3. **Open war room** if P1/P2: post in `#sentinel-incidents`
4. **Preserve evidence** — run `scripts/ir-collect-evidence.sh --since 30m`
5. **Check related alerts** — single alert may be symptom of larger issue:
   - `SentinelHighBlockRate` + `SentinelRedisDown` → likely pattern sync failure
   - `SentinelBackendErrorRateHigh` + `SentinelGuardrailLatencyHigh` → backend overload cascading
   - `SentinelCertificateExpiringSoon` + `SentinelProxyTargetDown` → TLS handshake failures

### 2.5 Analysis Queries

```bash
# Current block rate
kubectl exec deploy/redis -n sentinel-gateway -- redis-cli GET sentinel:global:block

# Recent blocks (last 10)
kubectl exec deploy/redis -n sentinel-gateway -- redis-cli LRANGE sentinel:recent_blocks 0 9

# Per-tenant breakdown (Prometheus)
# sum by (tenant_id)(rate(sentinel_verdicts_total{verdict="block"}[5m]))

# Security events in last 5 minutes
kubectl logs deploy/proxy -n sentinel-gateway --since=5m | jq 'select(.verdict=="BLOCK")'

# Active alerts in Prometheus
curl -s http://prometheus:9090/api/v1/alerts | jq '.data.alerts[] | select(.state=="firing")'
```

---

## 3. Containment

### 3.1 Short-Term Containment (Minutes)

Goal: Stop the bleeding without full root cause analysis.

| Scenario | Action | Command |
|----------|--------|---------|
| **Single tenant under attack** | Isolate tenant (reduce rate limit to 1 RPM) | `kubectl exec deploy/redis -n sentinel-gateway -- redis-cli SET sentinel:rate_limit:override:<tenant> 1` |
| **Guardrail bypass confirmed** | Switch to fail-closed strict mode | `kubectl set env deploy/proxy SENTINEL_FAIL_MODE=closed -n sentinel-gateway` |
| **Compromised API key** | Revoke immediately | Remove key from `SENTINEL_API_KEYS` secret, restart proxy |
| **Malicious pattern evading detection** | Add emergency pattern via admin | POST `/admin/guardrails/` with new pattern |
| **Backend compromise suspected** | Block forwarding | `kubectl scale deploy/proxy --replicas=0 -n sentinel-gateway` |
| **Redis compromise** | Isolate Redis, proxy falls back to in-memory | `kubectl delete networkpolicy allow-proxy-redis -n sentinel-gateway` |

### 3.2 Long-Term Containment (Hours)

Goal: Sustainable containment that allows investigation.

1. **Deploy patched configuration** — update policies, restart with rolling update
2. **Enable enhanced logging** — `kubectl set env deploy/proxy SENTINEL_LOG_LEVEL=DEBUG`
3. **Increase monitoring** — reduce Prometheus scrape interval to 5s
4. **Notify affected tenants** — via Customer Success (see communication templates)
5. **Engage threat intel** — check IOC feeds for related indicators

### 3.3 Containment Decision Tree

```
Is the attack ongoing?
├─ YES → Is it affecting multiple tenants?
│        ├─ YES → Consider full service isolation (scale to 0)
│        │        Document justification for service disruption
│        └─ NO  → Isolate specific tenant (rate limit override)
│                  Continue service for unaffected tenants
└─ NO  → Was data exfiltrated?
         ├─ YES → Trigger data breach playbook (incident-data-breach.md)
         │        Preserve all evidence before any changes
         └─ NO  → Proceed to eradication with normal priority
```

---

## 4. Eradication

### 4.1 Remove the Threat

| Step | Action | Verification |
|------|--------|--------------|
| 1 | Identify all affected components | Review logs, Redis state, pod events |
| 2 | Remove malicious access | Rotate all compromised credentials |
| 3 | Update guardrail patterns | Add detection for the attack variant |
| 4 | Update IOC database | Add any new indicators discovered |
| 5 | Patch vulnerability (if applicable) | Code fix, dependency update |
| 6 | Update tool policies | Restrict permissions that were abused |

### 4.2 Pattern Update Procedure

```bash
# 1. Add new pattern via admin API
curl -X POST http://admin:8090/admin/guardrails/ \
  -H "Content-Type: application/json" \
  -d '{
    "pattern": "new_attack_pattern_regex",
    "category": "prompt_injection",
    "severity": "critical",
    "description": "Blocks variant discovered in INC-XXXX"
  }'

# 2. Verify pattern is active
curl http://admin:8090/admin/guardrails/status

# 3. Test pattern against attack payload (dry-run)
curl -X POST http://admin:8090/admin/guardrails/test \
  -d '{"content": "the actual attack payload", "pattern_id": "new_pattern_id"}'

# 4. Hot-reload policies on proxy
curl -X POST http://proxy:8080/admin/policies/reload

# 5. Verify with security smoke test
python scripts/security-smoke-test.py --host http://proxy:8080
```

### 4.3 Credential Rotation

If any credentials were potentially compromised:

```bash
# Regenerate all secrets
./secrets/init.sh --force

# Restart all services to pick up new secrets
kubectl rollout restart deploy/proxy deploy/admin -n sentinel-gateway

# Verify connectivity
./scripts/validate-deployment.sh
```

---

## 5. Recovery

### 5.1 Service Restoration

| Step | Action | Verification |
|------|--------|--------------|
| 1 | Remove containment measures | Restore rate limits, network policies |
| 2 | Scale back to normal replicas | `kubectl scale deploy/proxy --replicas=2` |
| 3 | Restore log level | `kubectl set env deploy/proxy SENTINEL_LOG_LEVEL=INFO` |
| 4 | Validate deployment | `./scripts/validate-deployment.sh` |
| 5 | Run security smoke test | `python scripts/security-smoke-test.py` |
| 6 | Monitor for recurrence | Watch dashboards for 24hr |

### 5.2 Validation Checklist

```bash
# Infrastructure health
./scripts/validate-deployment.sh

# Security posture
python scripts/security-smoke-test.py --rounds 3

# Redis state correct
kubectl exec deploy/redis -n sentinel-gateway -- redis-cli INFO keyspace

# All tenants operational
curl -s http://proxy:8080/health/stats | jq '.tenants'

# SIEM export flowing
kubectl exec deploy/redis -n sentinel-gateway -- redis-cli GET sentinel:siem:batches_sent
```

### 5.3 Communication — All Clear

Send "all clear" notification when:
- [ ] All validation checks pass
- [ ] No recurrence observed for 30 minutes (P2) or 4 hours (P1)
- [ ] IC confirms containment is no longer needed
- [ ] Affected tenants have been notified of restoration

---

## 6. Lessons Learned

### 6.1 Post-Incident Review (PIR)

**Timeline**: Within 5 business days of incident resolution.

**Attendees**: IC, all responders, relevant engineering leads, security team.

**Agenda**:
1. Timeline reconstruction (what happened, when)
2. Detection effectiveness (how quickly did we detect?)
3. Response effectiveness (did the runbook work?)
4. Root cause analysis (5 Whys)
5. Action items with owners and deadlines

### 6.2 PIR Document Template

```markdown
# Post-Incident Review: INC-XXXX

## Summary
- **Severity**: P[1-4]
- **Duration**: [start] to [end] (total: Xh Ym)
- **Impact**: [tenants affected, requests blocked/failed]
- **Root Cause**: [one sentence]

## Timeline
| Time (UTC) | Event |
|------------|-------|
| HH:MM | Alert fired: [alert name] |
| HH:MM | On-call acknowledged |
| HH:MM | Containment action taken |
| HH:MM | Root cause identified |
| HH:MM | Fix deployed |
| HH:MM | All-clear declared |

## What Went Well
- ...

## What Needs Improvement
- ...

## Action Items
| Action | Owner | Deadline | Status |
|--------|-------|----------|--------|
| Update guardrail pattern | @security | +7d | |
| Add alert for [gap] | @platform | +14d | |
| Update runbook [name] | @oncall | +7d | |
```

### 6.3 Required Updates After Every Incident

- [ ] Update relevant runbook with lessons learned
- [ ] Add new detection patterns if attack was novel
- [ ] Update alert thresholds if they were too sensitive/insensitive
- [ ] Update this IR plan if process gaps were identified
- [ ] File regulatory notification if required (see Appendix C)
- [ ] Close incident ticket with PIR link

---

## Appendices

### Appendix A: Communication Templates

#### Internal Incident Declaration (Slack)

```
:rotating_light: INCIDENT DECLARED — [P1/P2]

**Incident**: [Brief description]
**Impact**: [Who is affected, what is degraded]
**Incident Commander**: @[name]
**War Room**: #sentinel-incidents
**Status**: Investigating

Next update in 30 minutes.
```

#### Customer Notification (P1/P2 with customer impact)

```
Subject: [Sentinel Gateway] Service Incident — [Date]

We are currently investigating an issue affecting [description].

Impact: [What customers experience — blocked requests, latency, etc.]
Start time: [UTC timestamp]
Current status: [Investigating / Mitigated / Resolved]

We will provide updates every [30min / 1hr] until resolution.

If you have questions, contact your Customer Success Manager.
```

#### Regulatory Notification (Data Breach)

```
Subject: Data Protection Incident Notification — [Company Name]

Under [GDPR Article 33 / CCPA / applicable regulation], we are notifying
your office of a personal data incident.

Date of discovery: [date]
Nature of incident: [description]
Categories of data affected: [types]
Approximate number of data subjects: [count]
Measures taken: [containment actions]
Contact: [DPO name and contact]

A full impact assessment will follow within [timeframe].
```

### Appendix B: Evidence Preservation

**Chain of Custody Requirements**:
1. All evidence collected via `scripts/ir-collect-evidence.sh`
2. Tarball integrity verified via SHA-256 manifest
3. Evidence stored in write-once storage (S3 with Object Lock or equivalent)
4. Access to evidence requires IC or Legal approval
5. Evidence retained for minimum 1 year (or per regulatory requirement)

**What to collect** (script handles automatically):
- Pod logs (proxy, admin, Redis)
- Redis state snapshot (counters, recent blocks, rate limit keys)
- Kubernetes events and pod descriptions
- Prometheus alert history
- Network policy state
- Resource utilization at time of incident

**Do NOT**:
- Modify running pods before evidence collection
- Delete or restart anything before `ir-collect-evidence.sh` completes
- Share raw evidence outside the IR team without IC approval

### Appendix C: Regulatory Notification Requirements

| Regulation | Notification Deadline | Authority | Threshold |
|------------|----------------------|-----------|-----------|
| GDPR (EU) | 72 hours from discovery | Supervisory Authority (DPA) | Any personal data breach |
| CCPA (California) | "Most expedient time possible" | California AG | >500 residents |
| HIPAA (US Healthcare) | 60 days | HHS OCR | Any PHI breach |
| PCI DSS | Immediately | Card brands + acquirer | Any cardholder data |
| SOC 2 | Per trust services criteria | Auditor notification | Material breach of controls |
| NIS2 (EU) | 24hr early warning, 72hr full | CSIRT/competent authority | Significant incident |

**Decision authority**: Legal/Compliance team determines whether regulatory notification is required. Security team provides technical impact assessment.

### Appendix D: Related Documents

- [Runbook Index](README.md)
- [Alert: High Block Rate](alert-high-block-rate.md)
- [Alert: Redis Down](alert-redis-down.md)
- [Alert: Backend Errors](alert-backend-errors.md)
- [Alert: Guardrail Latency](alert-guardrail-latency.md)
- [Alert: Certificate Expiry](alert-certificate-expiry.md)
- [Incident: Data Breach](incident-data-breach.md)
- [Incident: Guardrail Bypass](incident-guardrail-bypass.md)
- [Evidence Collection Script](../../scripts/ir-collect-evidence.sh)
- [Operations Runbook](../OPERATIONS.md)
- [Security Hardening](../SECURITY-HARDENING.md)
- [Troubleshooting Guide](../TROUBLESHOOTING.md)
