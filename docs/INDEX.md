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
| [Limitations](LIMITATIONS.md) | Accepted limitations & known gaps: vision OCR, multilingual, topic classifiers, WAF scope |
| [API Reference](API-REFERENCE.md) | Proxy + Admin API endpoints, request/response formats |
| [SOAR Playbooks](SOAR-PLAYBOOKS.md) | Runner-agnostic automation: signed event webhooks, service-account action API, 7 reference playbooks |
| [Writing a Custom Scanner](CUSTOM-SCANNERS.md) | Build, register, and test a scanner for the scanner framework |
| [Using Bulwark as a Library](SDK-LIBRARY-MODE.md) | Embed the scanner pipeline in-process (`Guard`) + framework adapters |
| [Creating and Publishing Plugins](PLUGINS.md) | Package a scanner as a sandboxed, installable plugin |
| [E2E Validation](E2E-VALIDATION.md) | Validate the full proxy pipeline (forward + output filter) in K8s via a mock LLM |
| [Roadmap](ROADMAP.md) | Implementation plan: ML detection, multilingual, SDK mode, plugin hub |
| [Runbooks](runbooks/README.md) | Incident response plan, alert playbooks, evidence collection |

## Document Audience

| Role | Start Here |
|------|-----------|
| **DevOps / SRE** | [Deployment](DEPLOYMENT.md) → [CI/CD](CICD.md) → [Operations](OPERATIONS.md) → [Observability](OBSERVABILITY.md) |
| **Security Engineer** | [Architecture](ARCHITECTURE.md) → [Security Hardening](SECURITY-HARDENING.md) → [Limitations](LIMITATIONS.md) |
| **SOC Analyst** | [Notifications](NOTIFICATIONS.md) → [Troubleshooting](TROUBLESHOOTING.md) → [Observability](OBSERVABILITY.md) |
| **Automation Engineer** | [SOAR Playbooks](SOAR-PLAYBOOKS.md) → [API Reference](API-REFERENCE.md) → [Security Hardening](SECURITY-HARDENING.md) |
| **Developer** | [API Reference](API-REFERENCE.md) → [Architecture](ARCHITECTURE.md) → [Roadmap](ROADMAP.md) |
| **Extension Developer** | [Custom Scanner](CUSTOM-SCANNERS.md) → [Library Mode](SDK-LIBRARY-MODE.md) → [Plugins](PLUGINS.md) |
| **Auditor** | [Security Hardening](SECURITY-HARDENING.md) → [Runbooks/IR Plan](runbooks/ir-plan.md) → [API Reference](API-REFERENCE.md) |
| **Incident Responder** | [Runbooks](runbooks/README.md) → [Operations](OPERATIONS.md) → [Troubleshooting](TROUBLESHOOTING.md) |

## Project README

The main [README.md](../README.md) contains the project overview, quickstart guide, and feature summary.
