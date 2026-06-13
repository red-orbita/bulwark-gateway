# Sentinel Gateway — Runbook Index

Operational runbooks for incident response, alert handling, and security event procedures.

**SOC 2 Compliance**: CC7.3 (Evaluate and Communicate Deficiencies), CC7.4 (Respond to Identified Anomalies)

---

## Incident Response

| Document | Purpose | Audience |
|----------|---------|----------|
| [ir-plan.md](ir-plan.md) | Formal IR plan (NIST SP 800-61) | SOC 2 auditors, security team, management |
| [incident-data-breach.md](incident-data-breach.md) | Data breach response procedure | Security team, legal, compliance |
| [incident-guardrail-bypass.md](incident-guardrail-bypass.md) | Guardrail bypass detection & response | Security team, platform engineering |

## Alert-Linked Runbooks

These runbooks are linked directly from Prometheus alert rules (`prometheus/rules.yml`).

| Alert | Severity | Runbook | Team |
|-------|----------|---------|------|
| `SentinelHighBlockRate` | Critical | [alert-high-block-rate.md](alert-high-block-rate.md) | Security |
| `SentinelRedisDown` | Critical | [alert-redis-down.md](alert-redis-down.md) | Platform |
| `SentinelBackendErrorRateHigh` | Critical | [alert-backend-errors.md](alert-backend-errors.md) | Platform |
| `SentinelGuardrailLatencyHigh` | Critical | [alert-guardrail-latency.md](alert-guardrail-latency.md) | Platform |
| `SentinelCertificateExpiringSoon` | Critical | [alert-certificate-expiry.md](alert-certificate-expiry.md) | Platform |

## Evidence Collection

| Script | Purpose |
|--------|---------|
| [../../scripts/ir-collect-evidence.sh](../../scripts/ir-collect-evidence.sh) | Automated forensic evidence collection |

## Quick Reference

### Severity Levels

| Level | Response SLA | Escalation | Examples |
|-------|-------------|------------|----------|
| P1 — Critical | 15 min acknowledge, 1 hr contain | Immediate page to on-call + security lead | Active breach, guardrail bypass, data exfiltration |
| P2 — High | 30 min acknowledge, 4 hr contain | Page on-call SRE | Redis down, high block rate, backend failures |
| P3 — Medium | 2 hr acknowledge, 24 hr resolve | Slack notification | Certificate expiry, SIEM export errors |
| P4 — Low | 24 hr acknowledge, 1 week resolve | Ticket creation | Memory pressure, low cache hit ratio |

### Communication Channels

| Channel | Purpose | Tool |
|---------|---------|------|
| `#sentinel-incidents` | Active incident coordination | Slack |
| `#sentinel-alerts` | Automated alert routing | Slack (PagerDuty integration) |
| Security on-call | P1/P2 escalation | PagerDuty |
| Platform on-call | Infrastructure issues | PagerDuty |
| `security-team@company.com` | Post-incident reports | Email |

---

## Maintenance

- Review all runbooks quarterly (minimum)
- Update after every post-incident review
- Test evidence collection script monthly
- Validate alert→runbook links when modifying `prometheus/rules.yml`

**Last review**: Document creation date  
**Next review**: +90 days  
**Owner**: Security Engineering
