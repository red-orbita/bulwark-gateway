# Runbook: Data Breach Response

## Classification

- **Incident Type**: Data breach (confirmed or suspected unauthorized data exposure)
- **Minimum Severity**: P1 — Critical
- **Regulatory Triggers**: GDPR Art. 33 (72h), CCPA, HIPAA, PCI DSS, NIS2
- **Owner**: Incident Commander + Legal/Compliance

## When to Use This Playbook

Activate this playbook when ANY of the following are confirmed or strongly suspected:

- Output filter failed to redact secrets/PII in a response
- Credentials (API keys, tokens, passwords) were exposed in LLM output to unauthorized user
- Tenant data was returned to a different tenant (cross-tenant data leak)
- Attack successfully exfiltrated data via prompt injection
- IOC match indicates data was sent to a known C2/exfiltration endpoint
- Audit logs show unauthorized access to sensitive resources

**Key principle**: When in doubt, activate this playbook. It is better to stand down after investigation than to miss a notification deadline.

---

## Phase 1: Immediate Response (0–30 Minutes)

### 1.1 Declare the Incident

```
Post to #sentinel-incidents:

:rotating_light: P1 INCIDENT DECLARED — Potential Data Breach

**Type**: Data breach (suspected/confirmed)
**Discovered**: [timestamp UTC]
**Discovered by**: [alert name / person / report]
**IC**: @[name]
**War Room**: #sentinel-incidents
**Bridge**: [zoom/meet link]

ALL: Do NOT restart services or delete logs until evidence is preserved.
```

### 1.2 Preserve Evidence (BEFORE ANY REMEDIATION)

```bash
# CRITICAL: Run evidence collection FIRST
./scripts/ir-collect-evidence.sh --namespace sentinel-gateway --since 2h

# Additional: Capture output filter state
kubectl logs deploy/proxy -n sentinel-gateway --since=2h > /tmp/proxy-logs-full.jsonl

# Capture Redis state (recent blocks contain the events)
kubectl exec deploy/redis -n sentinel-gateway -- redis-cli --no-auth-warning \
  LRANGE sentinel:recent_blocks 0 -1 > /tmp/redis-recent-blocks.json

# Capture admin audit log
kubectl logs deploy/admin -n sentinel-gateway --since=2h > /tmp/admin-audit-full.jsonl

# Package additional evidence
tar -czf /tmp/breach-evidence-additional-$(date +%Y%m%d_%H%M%S).tar.gz \
  /tmp/proxy-logs-full.jsonl /tmp/redis-recent-blocks.json /tmp/admin-audit-full.jsonl

# Generate integrity hash
sha256sum /tmp/breach-evidence-additional-*.tar.gz > /tmp/breach-evidence-additional.sha256
```

### 1.3 Assess Scope

Determine the following:

| Question | How to Check |
|----------|-------------|
| What data was exposed? | Check output filter logs, `sentinel:recent_blocks` |
| Which tenant(s) affected? | `jq '.tenant_id' proxy-logs-full.jsonl \| sort -u` |
| How many data subjects? | Count unique users in affected tenant's requests |
| Was data sent externally? | Check for exfiltration verdicts, IOC matches |
| Is exposure ongoing? | Check if the vulnerability is still active |
| What category of data? | PII, credentials, PHI, financial, business confidential? |

```bash
# Check for output filter failures (redaction missed)
kubectl logs deploy/proxy -n sentinel-gateway --since=2h | \
  jq 'select(.event=="output_filter" and .verdict!="REDACT") | {tenant: .tenant_id, content_snippet: .content[:100]}'

# Check for cross-tenant data leaks
kubectl logs deploy/proxy -n sentinel-gateway --since=2h | \
  jq 'select(.event=="response_sent") | {tenant: .tenant_id, response_tenant: .response_context_tenant}' | \
  jq 'select(.tenant != .response_context_tenant)'

# Check exfiltration-category blocks (some may have succeeded before detection)
kubectl logs deploy/proxy -n sentinel-gateway --since=2h | \
  jq 'select(.category=="exfiltration")'
```

### 1.4 Immediate Containment

| Scenario | Action | Command |
|----------|--------|---------|
| Output filter not redacting | Enable strict output filtering | `kubectl set env deploy/proxy SENTINEL_OUTPUT_FILTER_STRICT=true` |
| Cross-tenant leak | Isolate affected tenant | Scale proxy to 0, investigate routing |
| Credential exposure | Rotate exposed credentials immediately | Revoke keys, rotate secrets |
| Active exfiltration | Block the tenant/agent | Rate limit to 0, revoke API key |
| Vulnerability in guardrail | Emergency fail-closed | `kubectl set env deploy/proxy SENTINEL_FAIL_MODE=closed` |

---

## Phase 2: Investigation (30 Minutes – 4 Hours)

### 2.1 Root Cause Identification

```bash
# When did the breach start? (first occurrence)
kubectl logs deploy/proxy -n sentinel-gateway --since=24h | \
  jq 'select(.event=="output_filter_bypass" or .verdict=="ALLOW" and .contains_sensitive==true) | .timestamp' | \
  sort | head -1

# What pattern/filter failed?
kubectl logs deploy/proxy -n sentinel-gateway --since=24h | \
  jq 'select(.event=="output_filter") | {pattern: .matched_pattern, result: .verdict}' | \
  sort | uniq -c

# Was there a config change that caused the gap?
kubectl logs deploy/admin -n sentinel-gateway --since=24h | \
  jq 'select(.event=="config_change" or .event=="policy_reload")'

# Check guardrail version history
kubectl exec deploy/redis -n sentinel-gateway -- redis-cli GET sentinel:guardrails:version
```

### 2.2 Data Classification

| Category | Examples | Regulatory Impact |
|----------|----------|-------------------|
| **PII** | Names, emails, SSN, phone numbers | GDPR, CCPA, state privacy laws |
| **PHI** | Medical records, diagnoses, prescriptions | HIPAA (60-day notification) |
| **Financial** | Credit card numbers, bank accounts | PCI DSS (immediate notification) |
| **Credentials** | API keys, passwords, tokens | SOC 2, internal policy |
| **Business confidential** | Trade secrets, source code | Contract obligations |

### 2.3 Impact Quantification

Document for regulatory notification:

- **Number of affected data subjects**: _____
- **Categories of data exposed**: _____
- **Duration of exposure**: _____ to _____
- **Geographic scope**: (determines which DPAs to notify)
- **Was data accessed by unauthorized third party?**: Yes/No/Unknown
- **Was data sent to external endpoint?**: Yes/No/Unknown

---

## Phase 3: Regulatory Assessment (Within 24 Hours)

### 3.1 Notification Decision Matrix

| Regulation | Threshold | Deadline | Who Decides |
|------------|-----------|----------|-------------|
| GDPR Art. 33 | "Risk to rights and freedoms" | 72 hours | DPO + Legal |
| GDPR Art. 34 | "High risk to rights" | "Without undue delay" | DPO + Legal |
| CCPA | 500+ California residents | "Most expedient time" | Legal |
| HIPAA | Any unsecured PHI | 60 days (individuals), 60 days (HHS) | Privacy Officer |
| PCI DSS | Any cardholder data | Immediately | QSA + Legal |
| NIS2 | Significant incident | 24hr early warning, 72hr full | Legal + CSIRT |
| SOC 2 | Material control failure | Next audit cycle (immediate if severe) | Compliance |

### 3.2 Legal Notification

```
Email to: legal@company.com, dpo@company.com
Subject: URGENT — Data Breach Assessment Required — INC-[XXXX]

Security team has identified a potential data breach:

Discovery time: [UTC timestamp]
Brief description: [what happened]
Data categories potentially affected: [PII/PHI/credentials/etc.]
Estimated data subjects: [count or range]
Containment status: [contained/ongoing]

Regulatory notification deadlines:
- GDPR: [72h from discovery = specific date/time]
- CCPA: [if applicable]
- HIPAA: [if applicable]

Request: Legal assessment of notification obligations by [deadline].
Forensic evidence preserved and available.

Contact: [IC name and phone]
```

---

## Phase 4: Eradication and Recovery

### 4.1 Fix the Vulnerability

```bash
# 1. Identify the specific failure mode
# (output filter gap, cross-tenant routing bug, guardrail bypass, etc.)

# 2. Deploy fix
kubectl set image deploy/proxy sentinel-proxy=sentinel-gateway-proxy:<fixed-version> -n sentinel-gateway

# 3. Verify fix
python scripts/security-smoke-test.py --host http://proxy:8080 --rounds 3

# 4. Add detection pattern for this specific attack vector
curl -X POST http://admin:8090/admin/guardrails/ \
  -H "Content-Type: application/json" \
  -d '{"pattern": "<new_pattern>", "category": "exfiltration", "severity": "critical"}'
```

### 4.2 Credential Rotation (If Exposed)

```bash
# Rotate ALL potentially exposed secrets
./secrets/init.sh --force

# Notify affected tenants to rotate their API keys
# (Customer Success sends the notification)

# Revoke and reissue JWT signing key
kubectl delete secret sentinel-jwt-secret -n sentinel-gateway
kubectl create secret generic sentinel-jwt-secret \
  --from-literal=jwt-secret="$(openssl rand -base64 48)" -n sentinel-gateway
kubectl rollout restart deploy/proxy deploy/admin -n sentinel-gateway
```

### 4.3 Restore and Validate

```bash
# Full deployment validation
./scripts/validate-deployment.sh

# Security posture validation
python scripts/security-smoke-test.py --host http://proxy:8080 --rounds 5

# Verify output filter catches the specific data type that leaked
# (manually test with synthetic PII matching the exposed category)
```

---

## Phase 5: Communication

### 5.1 Internal "All Clear"

```
Post to #sentinel-incidents:

:white_check_mark: INCIDENT RESOLVED — INC-[XXXX]

**Duration**: [start] to [end]
**Root cause**: [brief]
**Impact**: [N data subjects, M tenants]
**Containment**: [what was done]
**Fix**: [what was deployed]
**Legal status**: [notification required/not required — per Legal assessment]

PIR scheduled for [date/time].
```

### 5.2 Customer Notification (If Required)

Coordinate with Legal and Customer Success. Never send without Legal approval.

### 5.3 Regulatory Filing (If Required)

Legal/DPO handles the actual filing. Security team provides:
- Technical incident report
- Timeline
- Impact assessment
- Measures taken and planned

---

## Phase 6: Post-Incident

- [ ] Complete Post-Incident Review within 5 business days
- [ ] File regulatory notifications within required deadlines
- [ ] Add regression tests for the specific failure mode
- [ ] Update output filter patterns if data type was not covered
- [ ] Update this playbook with lessons learned
- [ ] Verify evidence is stored in write-once storage
- [ ] Schedule follow-up with Legal on regulatory status
- [ ] Update risk register with this incident type

## Related Runbooks

- [IR Plan](ir-plan.md) — Overall incident response framework
- [Guardrail Bypass](incident-guardrail-bypass.md) — If breach was caused by guardrail failure
- [High Block Rate](alert-high-block-rate.md) — May indicate ongoing attack campaign
