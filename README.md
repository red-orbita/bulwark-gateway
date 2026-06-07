# Sentinel Gateway

Security guardrail proxy for AI agents in cloud environments.

Intercepts, validates, and enforces policies on tool calls between users and LLM agents. Designed for environments where **the user is potentially adversarial** (fail-closed by default).

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Quick Start](#quick-start)
- [Configuration Summary](#configuration-summary)
- [Admin Portal](#admin-portal)
- [Documentation](#documentation)
- [Project Structure](#project-structure)
- [Development](#development)
- [License](#license)

---

## Overview

Sentinel Gateway sits between your users/applications and your LLM backends (OpenAI, Ollama, vLLM, Azure, etc.). Every request passes through multiple security layers before reaching the backend:

1. **Authentication** — JWT/API key validation (fail-closed)
2. **Input Guardrail** — Detects prompt injections, jailbreaks, encoding evasion
3. **IOC Check** — Scans for malicious URLs/IPs/domains from threat intel feeds
4. **Tool Policy** — RBAC enforcement per tenant/agent
5. **Output Filter** — Redacts secrets/PII, detects indirect injection in responses
6. **Rate Limiter** — Per-tenant request throttling via Redis

If any layer detects a threat, the request is **blocked immediately** (fail-closed).

---

## Architecture

```
                    ┌──────────────────────────────────────────────┐
                    │             Sentinel Gateway                  │
                    │                                              │
 User Request ─────►  Auth ► Input Guardrail ► IOC Check          │
  X-Tenant-ID      │                              │               │
  X-Agent-ID       │                    Agent Registry             │
                    │                    (multi-backend)            │
                    │                         │                    │
                    │              Forward to backend              │
                    │                         │                    │
                    │  Tool Policy ◄── Response ──► Output Filter  │
                    └──────────────┼──────────────────────────────┘
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         ▼                         ▼                         ▼
  Backend A (RAG)          Backend B (LLM)        Backend C (Agent)
```

| Component | Port | Description |
|-----------|------|-------------|
| **Proxy** | 8080 | Security hot path — intercepts all LLM requests |
| **Admin Portal** | 8090 | Web UI for configuration, monitoring, audit logs |
| **Redis** | 6379 | Rate limiting, state, session management |
| **Prometheus** | 9090 | Metrics collection |
| **Grafana** | 3000 | Dashboards and visualization |

> Full architecture details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

---

## Features

- **Multi-tenant, multi-agent** — Route requests to different backends per tenant/agent
- **Zero-LLM hot path** — Only regex + Pydantic + cache; p95 < 40ms overhead
- **78+ detection patterns** — Prompt injection, jailbreak, encoding evasion, multilingual (ES/ZH/AR)
- **4 threat intel feeds** — URLhaus, ThreatFox, AlienVault OTX, AbuseIPDB (+ MISP, OpenCTI, VirusTotal, Shodan)
- **Streaming tool call buffering** — Tool calls validated BEFORE yielding to client
- **Self-protection** — Blocks agents from modifying gateway config
- **Hot-reloadable** — Policies, IOCs, and agent registry reload without restart
- **Admin Portal** — Full web UI for managing all aspects of the gateway
- **SIEM integration** — Export to 13 platforms (Wazuh, Splunk, Elastic, QRadar, Datadog, etc.)
- **Notification channels** — Slack, Teams, Discord, PagerDuty, Opsgenie, Telegram, Email, Google Chat
- **Kubernetes-native** — Full K8s manifests with NetworkPolicies, HPA, PDB, Pod Security
- **Audit trail** — Immutable log of all administrative changes
- **Enterprise secrets** — Vault, AWS SM, Azure KV, GCP SM, CyberArk, SealedSecrets

---

## Quick Start

### Prerequisites

- Python 3.11+
- Docker 24+
- Kubernetes 1.28+ (production) or Docker Compose (development)
- Redis 7+

### Kubernetes (Production)

```bash
# 1. Generate secrets
./secrets/init.sh

# 2. Build images
docker build -t sentinel-gateway-proxy:latest -f Dockerfile .
docker build -t sentinel-gateway-admin:latest -f docker/Dockerfile.admin .

# For minikube:
minikube image load sentinel-gateway-proxy:latest
minikube image load sentinel-gateway-admin:latest

# 3. Deploy
./k8s/deploy.sh

# 4. Verify
kubectl get pods -n sentinel-gateway
```

### Docker Compose (Development)

```bash
# 1. Generate secrets
./secrets/init.sh

# 2. Start all services
docker compose up -d

# 3. Access
#    Proxy:  http://localhost:8080
#    Admin:  http://localhost:8090
#    Grafana: http://localhost:3000
```

### Access Services

```bash
# Port-forward (K8s)
kubectl port-forward svc/proxy 8080:8080 -n sentinel-gateway
kubectl port-forward svc/admin 8090:8090 -n sentinel-gateway

# Or via Ingress:
#   Proxy:  https://sentinel-gateway.local
#   Admin:  https://admin.sentinel-gateway.local
```

### Test the Proxy

```bash
# Health check
curl http://localhost:8080/health

# Send a request (replace with your API key)
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -H "X-Tenant-ID: default" \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]}'
```

> Full deployment guide: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)

---

## Configuration Summary

### Key Files

| File | Purpose |
|------|---------|
| `config/agents.yaml` | Tenant → backend mapping, auth config |
| `config/policies/*.yaml` | Per-tenant security policies (RBAC) |
| `config/notifications.yaml` | Notification channel definitions |
| `config/siem/*.yaml` | SIEM platform templates |
| `config/iocs.json` | IOC database (auto-updated by feeds) |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `SENTINEL_JWT_SECRET` | JWT signing key (or `*_FILE` variant) |
| `SENTINEL_REDIS_URL` | Redis connection URL |
| `SENTINEL_REDIS_PASSWORD` | Redis auth (or `*_FILE` variant) |
| `SENTINEL_API_KEYS` | Comma-separated API keys (or `*_FILE`) |
| `SENTINEL_WEBHOOK_ALERT_URLS` | Legacy notification webhooks |
| `SENTINEL_LOG_LEVEL` | Logging level (INFO, DEBUG, etc.) |

All secrets support the **`*_FILE` pattern** — point an env var to a mounted file:

```yaml
env:
  - name: SENTINEL_JWT_SECRET_FILE
    value: /run/secrets/jwt-secret
```

### Agent Registry Example

```yaml
# config/agents.yaml
tenants:
  example-corp:
    backend_url: "${SENTINEL_BACKEND_URL:-http://ollama:11434}"
    auth_token: "${BACKEND_AUTH_TOKEN}"
    allowed_models: ["gpt-4", "gpt-3.5-turbo"]
    rate_limit_rpm: 60
```

### Policy Example

```yaml
# config/policies/example-corp.yaml
tenant_id: example-corp
tools:
  allowed:
    - web_search
    - code_interpreter
  blocked:
    - file_system
    - shell_exec
guardrails:
  max_tokens: 4096
  block_on_injection: true
```

---

## Admin Portal

Web-based management interface at `/` (port 8090).

### Pages

| Page | Function |
|------|----------|
| Dashboard | Real-time metrics, recent blocks, sparklines |
| Policies | CRUD, validation, hot-reload |
| Guardrails | Pattern management, sandbox testing |
| SIEM Export | Transport configuration, connectivity testing |
| **Notifications** | Alert channel management (Slack, Teams, Email, etc.) |
| Audit Log | Immutable action history, export |
| Orchestrator | Automated security testing |
| Coverage Matrix | OWASP LLM Top 10 detection map |
| IOCs | Threat intel feed management |
| Tenants | Tenant registration and config |
| Agents | Backend health monitoring |
| Access Control | RBAC roles and permissions |
| Status | System health (Redis, proxy, telemetry) |

### Default Credentials

| User | Role | Default Password | Secret Key |
|------|------|-----------------|-----------|
| `admin` | Admin | `sentinel-admin` | `ADMIN_PASSWORD` |
| `security` | Security | `sentinel-security` | `SECURITY_PASSWORD` |
| `auditor` | Auditor | `sentinel-auditor` | `AUDITOR_PASSWORD` |

> Change these immediately in production via K8s secrets.

---

## Documentation

Detailed guides are in the [`docs/`](docs/) directory:

| Document | Description |
|----------|-------------|
| [**INDEX**](docs/INDEX.md) | Documentation table of contents |
| [**Architecture**](docs/ARCHITECTURE.md) | System design, request flow, design decisions, trust model |
| [**Deployment**](docs/DEPLOYMENT.md) | K8s, Docker Compose, secrets (9 providers), TLS, ingress, HA |
| [**Operations**](docs/OPERATIONS.md) | Runbook: account reset, secret rotation, backup, scaling |
| [**Troubleshooting**](docs/TROUBLESHOOTING.md) | Redis unhealthy, auth issues, SIEM, pod errors |
| [**Notifications**](docs/NOTIFICATIONS.md) | Multi-channel alerting setup (Slack, Teams, Email, PagerDuty) |
| [**Security Hardening**](docs/SECURITY-HARDENING.md) | Pentest results, remediations, OWASP LLM coverage |
| [**API Reference**](docs/API-REFERENCE.md) | Proxy + Admin endpoints, request/response formats |

---

## Project Structure

```
sentinel-gateway/
├── src/                        # Proxy source code
│   ├── main.py                 # FastAPI app entry point
│   ├── models.py               # Core data models (SecurityEvent, Verdict)
│   ├── guardrails/             # Detection engines
│   │   ├── input_guardrail.py  # Input analysis (78+ patterns)
│   │   ├── output_filter.py    # Output redaction
│   │   └── tool_policy.py      # RBAC enforcement
│   ├── routes/                 # API routes
│   │   ├── proxy.py            # Main proxy flow (hot path)
│   │   └── health.py           # Health/metrics endpoints
│   ├── telemetry/              # SIEM export + notifications
│   │   ├── exporter.py         # Background batch exporter
│   │   ├── notifications.py    # Multi-channel alert engine
│   │   ├── queue.py            # Non-blocking event queue
│   │   └── transports/         # SIEM output adapters
│   └── services/               # Shared services (IOC, registry)
├── admin/                      # Admin portal
│   ├── main.py                 # Admin FastAPI app
│   ├── routes/                 # Admin API routes
│   ├── services/               # Auth, audit, user store
│   └── templates/              # Jinja2 HTML templates (UI)
├── config/                     # Configuration
│   ├── agents.yaml             # Agent/tenant registry
│   ├── policies/               # Security policy YAML files
│   ├── notifications.yaml      # Notification channels
│   └── siem/                   # SIEM platform templates
├── docs/                       # Detailed documentation
├── k8s/                        # Kubernetes manifests
│   ├── base/                   # Core resources (deployments, services)
│   ├── secrets/                # Secret generation scripts
│   └── monitoring/             # Prometheus + Grafana
├── tests/                      # Test suite (pytest, 185+ tests)
├── Dockerfile                  # Proxy image
├── docker-compose.yml          # Development environment
└── pyproject.toml              # Python project metadata
```

---

## Development

```bash
# Setup
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run server
python -m uvicorn src.main:app --reload --port 8080

# Run tests
pytest -v

# Lint
ruff check src/ tests/

# Type check
mypy src/
```

---

## License

GPL-3.0-or-later
