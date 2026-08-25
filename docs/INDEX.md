# Bulwark Gateway — Documentation Index

> Security guardrail proxy for AI agents in cloud environments.

## Quick Links

| Document | Description |
|----------|-------------|
| [Architecture](ARCHITECTURE.md) | System design, request flow, component interactions, design decisions |
| [Deployment](DEPLOYMENT.md) | Kubernetes, Docker Compose, Redis, secrets management, TLS, ingress |
| [CI/CD](CICD.md) | Pipeline templates: GitHub Actions, Jenkins, Azure DevOps, GitLab, Tekton |
| [Operations](OPERATIONS.md) | Day-to-day runbook: restarts, secret rotation, policy reload, backups |
| [Observability](OBSERVABILITY.md) | Prometheus scrape model, metrics catalog, SLO recording rules, Grafana dashboards |
| [Troubleshooting](TROUBLESHOOTING.md) | Known issues and solutions (Redis, auth, SIEM, pods, empty Grafana panels) |
| [Notifications](NOTIFICATIONS.md) | Multi-channel alerting: Slack, Teams, Email, PagerDuty, etc. |
| [Security Hardening](SECURITY-HARDENING.md) | Living security log: audits, remediations, OWASP LLM coverage, posture |
| [API Reference](API-REFERENCE.md) | Proxy + Admin API endpoints, request/response formats |
| [E2E Validation](E2E-VALIDATION.md) | Validate the full proxy pipeline (forward + output filter) in K8s via a mock LLM |
| [Roadmap](ROADMAP.md) | Implementation plan: ML detection, multilingual, SDK mode, plugin hub |
| [Runbooks](runbooks/README.md) | Incident response plan, alert playbooks, evidence collection |

## Document Audience

| Role | Start Here |
|------|-----------|
| **DevOps / SRE** | [Deployment](DEPLOYMENT.md) → [CI/CD](CICD.md) → [Operations](OPERATIONS.md) → [Observability](OBSERVABILITY.md) |
| **Security Engineer** | [Architecture](ARCHITECTURE.md) → [Security Hardening](SECURITY-HARDENING.md) |
| **SOC Analyst** | [Notifications](NOTIFICATIONS.md) → [Troubleshooting](TROUBLESHOOTING.md) → [Observability](OBSERVABILITY.md) |
| **Developer** | [API Reference](API-REFERENCE.md) → [Architecture](ARCHITECTURE.md) → [Roadmap](ROADMAP.md) |
| **Auditor** | [Security Hardening](SECURITY-HARDENING.md) → [Runbooks/IR Plan](runbooks/ir-plan.md) → [API Reference](API-REFERENCE.md) |
| **Incident Responder** | [Runbooks](runbooks/README.md) → [Operations](OPERATIONS.md) → [Troubleshooting](TROUBLESHOOTING.md) |

## Project README

The main [README.md](../README.md) contains the project overview, quickstart guide, and feature summary.
