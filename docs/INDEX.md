# Sentinel Gateway — Documentation Index

> Security guardrail proxy for AI agents in cloud environments.

## Quick Links

| Document | Description |
|----------|-------------|
| [Architecture](ARCHITECTURE.md) | System design, request flow, component interactions, design decisions |
| [Deployment](DEPLOYMENT.md) | Kubernetes, Docker Compose, Redis, secrets management, TLS, ingress |
| [CI/CD](CICD.md) | Pipeline templates: GitHub Actions, Jenkins, Azure DevOps, GitLab, Tekton |
| [Operations](OPERATIONS.md) | Day-to-day runbook: restarts, secret rotation, policy reload, backups |
| [Troubleshooting](TROUBLESHOOTING.md) | Known issues and solutions (Redis, auth, SIEM, pods) |
| [Notifications](NOTIFICATIONS.md) | Multi-channel alerting: Slack, Teams, Email, PagerDuty, etc. |
| [Security Hardening](SECURITY-HARDENING.md) | Pentest results, remediations, security posture |
| [API Reference](API-REFERENCE.md) | Proxy + Admin API endpoints, request/response formats |
| [Roadmap](ROADMAP.md) | Implementation plan: ML detection, multilingual, SDK mode, plugin hub |

## Document Audience

| Role | Start Here |
|------|-----------|
| **DevOps / SRE** | [Deployment](DEPLOYMENT.md) → [CI/CD](CICD.md) → [Operations](OPERATIONS.md) |
| **Security Engineer** | [Architecture](ARCHITECTURE.md) → [Security Hardening](SECURITY-HARDENING.md) |
| **SOC Analyst** | [Notifications](NOTIFICATIONS.md) → [Troubleshooting](TROUBLESHOOTING.md) |
| **Developer** | [API Reference](API-REFERENCE.md) → [Architecture](ARCHITECTURE.md) → [Roadmap](ROADMAP.md) |
| **Auditor** | [Security Hardening](SECURITY-HARDENING.md) → [API Reference](API-REFERENCE.md) |

## Project README

The main [README.md](../README.md) contains the project overview, quickstart guide, and feature summary.
