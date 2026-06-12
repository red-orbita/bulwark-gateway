# API Reference

Complete API documentation for Sentinel Gateway proxy and admin services.

## Table of Contents

- [Authentication](#authentication)
- [Proxy API (Data Plane)](#proxy-api-data-plane)
- [Admin API (Control Plane)](#admin-api-control-plane)

---

## Authentication

### Proxy API

All proxy requests require one of:
- **JWT Bearer token**: `Authorization: Bearer <token>`
- **API Key**: `X-API-Key: <key>`

Additionally, tenant identification:
- **Header**: `X-Tenant-ID: <tenant-id>`

### Admin API

All admin endpoints (except `/admin/health` and `/admin/auth/login`) require:
- **JWT Bearer token**: `Authorization: Bearer <token>`

Obtain a token via `POST /admin/auth/login`.

---

## Proxy API (Data Plane)

Base URL: `https://sentinel.corp.com` (port 8080)

### POST /v1/chat/completions

Proxied chat completion request. Applies input guardrails, tool policy, and output filters.

**Request**: OpenAI-compatible chat completion format.

```json
{
  "model": "gpt-4",
  "messages": [{"role": "user", "content": "..."}],
  "tools": [...],
  "stream": false
}
```

**Response**: OpenAI-compatible response (potentially with redacted content).

**Error Responses**:
- `403` — Input blocked by guardrail or tool policy
- `429` — Rate limit exceeded
- `401` — Invalid authentication
- `502` — Backend LLM error

### GET /health

Basic health check (unauthenticated).

```json
{"status": "healthy", "version": "0.2.0"}
```

### GET /health/stats

Detailed statistics (requires authentication + tenant ID).

```json
{
  "requests_total": 1500,
  "blocked": 23,
  "warned": 45,
  "redacted": 12,
  "avg_latency_ms": 8.3
}
```

### POST /v1/embeddings

Proxied embeddings request (same auth/guardrail chain).

### POST /v1/completions

Proxied legacy completions request.

---

## Admin API (Control Plane)

Base URL: `https://admin.sentinel.corp.com` (port 8090)

### Authentication

#### POST /admin/auth/login

```json
// Request
{"username": "admin", "password": "...", "mfa_code": "123456"}

// Response
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 28800,
  "user": {"username": "admin", "role": "admin"}
}
```

#### POST /admin/auth/refresh

Refresh an expiring token.

#### GET /admin/auth/me

Get current user info.

#### POST /admin/auth/change-password

```json
{"current_password": "old", "new_password": "new"}
```

---

### Health & Metrics

#### GET /admin/health

Unauthenticated health check.
```json
{"status": "healthy"}
```

#### GET /admin/health/detailed

Authenticated detailed health with Redis status.
```json
{
  "status": "healthy",
  "timestamp": "2026-06-04T12:00:00Z",
  "uptime_seconds": 3600,
  "redis": "connected",
  "redis_latency_ms": 1.2,
  "redis_version": "7.4.9",
  "redis_memory": "2.5M",
  "requests_total": 1500,
  "blocked": 23
}
```

#### GET /admin/health/stream

SSE stream for real-time dashboard updates. Auth via `?token=<jwt>`.

#### GET /admin/health/metrics

Prometheus exposition format.

---

### Policies

#### GET /admin/policies

List all policies.

#### GET /admin/policies/{tenant_id}

Get policy for specific tenant.

#### POST /admin/policies

Create/update a policy.

#### DELETE /admin/policies/{tenant_id}

Delete a tenant policy.

#### POST /admin/policies/reload

Hot-reload policies from disk (no restart needed).

---

### Guardrails

#### GET /admin/guardrails/patterns

List all active detection patterns.

#### POST /admin/guardrails/patterns

Add a new detection pattern.

#### PUT /admin/guardrails/patterns/{id}

Update an existing pattern.

#### DELETE /admin/guardrails/patterns/{id}

Remove a pattern.

#### POST /admin/guardrails/test

Test a pattern against sample input.

```json
// Request
{"pattern": "(?i)ignore.*previous.*instructions", "test_input": "Please ignore all previous instructions"}

// Response
{"matched": true, "groups": [...], "latency_ms": 0.5}
```

---

### SIEM / Event Export

#### GET /admin/siem/platforms

List available SIEM platform templates.

#### GET /admin/siem/config

Get all configured transports.

#### POST /admin/siem/transport

Create a new SIEM transport.

#### PUT /admin/siem/transport/{id}

Update transport configuration.

#### DELETE /admin/siem/transport/{id}

Remove a transport.

#### POST /admin/siem/transport/{id}/test

Test transport connectivity.

#### GET /admin/siem/status

Get export statistics.

---

### Notification Channels

#### GET /admin/notifications/channels

List all configured notification channels (secrets masked).

```json
{
  "channels": [
    {
      "id": "abc12345",
      "name": "#security-alerts",
      "type": "slack",
      "enabled": true,
      "min_severity": "high",
      "verdicts": ["block", "warn"],
      "url": "https://hooks.slack.com/ser***"
    }
  ]
}
```

#### POST /admin/notifications/channels

Create a new notification channel.

```json
// Request
{
  "name": "#security-alerts",
  "type": "slack",
  "url": "https://hooks.slack.com/services/T.../B.../xxx",
  "min_severity": "high",
  "verdicts": ["block", "warn"]
}

// Response
{"channel": {...}, "message": "Channel created"}
```

#### PUT /admin/notifications/channels/{id}

Update channel configuration.

#### DELETE /admin/notifications/channels/{id}

Delete a notification channel.

#### POST /admin/notifications/channels/{id}/test

Send a test notification.

```json
// Response
{"success": true, "message": "Test notification sent successfully"}
```

#### POST /admin/notifications/channels/{id}/toggle

Enable/disable a channel.

```json
{"enabled": false, "message": "Channel disabled"}
```

#### POST /admin/notifications/reload

Reload channels from disk (YAML + JSON).

---

### IOC Management

#### GET /admin/iocs

List current IOC database stats.

#### POST /admin/iocs/upload

Upload new IOC indicators.

#### POST /admin/iocs/feeds/sync

Trigger feed synchronization.

---

### Audit Log

#### GET /admin/audit

Query audit log entries (paginated).

Query params: `?limit=50&offset=0&action=login&user=admin`

#### GET /admin/audit/export

Export full audit log as JSON.

---

### Users & RBAC

#### GET /admin/users

List all users.

#### POST /admin/users

Create a new user.

#### PUT /admin/users/{username}

Update user (role, active status).

#### DELETE /admin/users/{username}

Delete a user.

#### GET /admin/rbac/matrix

Get full RBAC permission matrix.

#### PUT /admin/rbac/roles/{role}

Update permissions for a role.

---

### Configuration

#### GET /admin/config/validate

Validate current configuration.

#### POST /admin/config/rollback

Rollback to previous configuration version.

---

### Plugin Management

#### GET /admin/plugins/

List all installed plugins.

**Response**: Array of plugin specs (name, version, type, blocking, enabled status).

#### GET /admin/plugins/{name}

Get specific plugin specification.

#### POST /admin/plugins/install

Install a plugin from hub or local source.

**Body**:
```json
{
  "name": "my-scanner",
  "source": "hub"
}
```

#### POST /admin/plugins/uninstall

Uninstall an installed plugin.

**Body**: `{"name": "my-scanner"}`

#### POST /admin/plugins/{name}/enable

Enable a disabled plugin.

#### POST /admin/plugins/{name}/disable

Disable an enabled plugin.

#### POST /admin/plugins/scaffold

Create a new plugin scaffold (development template).

**Body**: `{"name": "new-scanner"}`

#### POST /admin/plugins/{name}/security-check

Run security audit on plugin source code. Returns list of security warnings (eval, subprocess, pickle, etc.).

---

### Security Evaluation (Red Teaming)

#### GET /admin/evaluation/status

Return framework status: available categories, scanner count, dataset sizes.

#### POST /admin/evaluation/run

Run adversarial evaluation against the scanner pipeline.

**Body**:
```json
{
  "categories": ["prompt_injection", "jailbreak", "exfiltration"],
  "count_per_category": 10,
  "include_benign": true
}
```

**Response**: Full EvaluationReport with detection_rate, false_positive_rate, bypass_rate, latency percentiles, per-category breakdown.

#### POST /admin/evaluation/run/quick

Quick scan with 5 attacks per category across all supported categories.

#### GET /admin/evaluation/attacks/preview

Preview generated attacks (query params: categories, count).

#### GET /admin/evaluation/datasets/benign

Return the standard benign dataset (30 legitimate prompts for FP testing).

#### POST /admin/evaluation/report

Generate formatted report from evaluation data.

**Body**:
```json
{
  "report": { ... },
  "format": "text|json|html"
}
```

---

### Agent Discovery

#### GET /admin/discovery/status

Discovery capabilities status (available scanners, known ports/paths).

#### POST /admin/discovery/scan/network

Scan network targets for LLM API endpoints.

**Body**:
```json
{
  "targets": ["192.168.1.0/24", "10.0.0.1"],
  "timeout": 5.0
}
```

**Response**: Array of discovered agents (host, port, service_type, confidence).

#### POST /admin/discovery/scan/kubernetes

Scan a Kubernetes namespace for LLM services.

**Body**: `{"namespace": "default"}`

#### GET /admin/discovery/shadow-ai/endpoints

Return the full AI endpoint blocklist (30+ known AI API hostnames).

#### POST /admin/discovery/shadow-ai/analyze

Analyze traffic logs for unauthorized AI usage.

**Body**:
```json
{
  "entries": [
    {"hostname": "api.openai.com", "source_ip": "10.0.1.5", "timestamp": "2024-01-01T12:00:00Z"}
  ]
}
```

**Response**: Array of ShadowAIAlerts (hostname, service, risk_level).

#### POST /admin/discovery/shadow-ai/classify

Classify a single hostname as AI service or not.

**Body**: `{"hostname": "api.openai.com"}`

**Response**: `{"service": "OpenAI"}` or `{"service": null}`

#### GET /admin/discovery/mcp/status

MCP inventory scanner status.

#### POST /admin/discovery/mcp/assess-risk

Assess risk of an MCP tool based on its capabilities.

**Body**:
```json
{
  "name": "execute_command",
  "description": "Runs shell commands",
  "capabilities": ["shell_exec", "network_access"]
}
```

**Response**: RiskAssessment (score 0-10, findings, recommendations).

#### POST /admin/discovery/mcp/enumerate

Enumerate tools on an MCP server via JSON-RPC.

**Body**: `{"server_url": "http://localhost:3000"}`

---

## Error Format

All error responses follow this format:

```json
{
  "detail": "Human-readable error message"
}
```

HTTP status codes:
- `400` — Bad request (validation error)
- `401` — Unauthorized (missing/invalid token)
- `403` — Forbidden (insufficient permissions)
- `404` — Resource not found
- `429` — Rate limit exceeded
- `500` — Internal server error (generic message, details in logs)
