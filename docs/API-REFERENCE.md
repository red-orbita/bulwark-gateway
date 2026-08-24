# API Reference

Complete API documentation for Bulwark Gateway proxy and admin services.

## Table of Contents

- [Authentication](#authentication)
- [Proxy API (Data Plane)](#proxy-api-data-plane)
- [Admin API (Control Plane)](#admin-api-control-plane)

---

## Authentication

### Proxy API

All proxy requests require a bearer credential in the `Authorization` header —
either a JWT or an API key (both use the `Bearer` scheme):
- **JWT**: `Authorization: Bearer <token>`
- **API Key**: `Authorization: Bearer <api-key>`

Additionally, tenant/agent identification:
- **Header**: `X-Tenant-ID: <tenant-id>` (required)
- **Header**: `X-Agent-ID: <agent-id>` (optional; defaults to `default`)

### Admin API

All admin endpoints (except `/admin/health` and `/admin/auth/login`) require:
- **JWT Bearer token**: `Authorization: Bearer <token>`

Obtain a token via `POST /admin/auth/login`.

---

## Proxy API (Data Plane)

Base URL: `https://bulwark.corp.com` (port 8080)

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
{"status": "ok", "service": "bulwark-gateway"}
```

### GET /health/stats

Detailed statistics (requires authentication + tenant ID).

```json
{
  "scope": "global",
  "uptime_seconds": 3600.0,
  "requests_total": 1500,
  "requests_per_second": 0.42,
  "blocked": 23,
  "warned": 45,
  "allowed": 1420,
  "redacted": 12,
  "errors": 0,
  "latency_p50_ms": 3.1,
  "latency_p95_ms": 8.3,
  "latency_p99_ms": 14.7
}
```

### POST /v1/tool/validate

Pre-execution tool-call validation (sidecar mode). Validates a proposed tool call
against the agent's RBAC/tool policy without proxying to a backend. Requires the
same auth + `X-Tenant-ID`/`X-Agent-ID` headers as `/v1/chat/completions`.

**Response**: a `GuardrailResult` — `verdict` (`allow`/`block`), `events`, and
`blocked_tools`.

---

## Admin API (Control Plane)

Base URL: `https://admin.bulwark.corp.com` (port 8090)

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

#### POST /admin/auth/logout

Invalidate the current session/token.

#### GET /admin/auth/me

Get current user info.

#### POST /admin/auth/change-password

```json
{"current_password": "old", "new_password": "new"}
```

> A `POST /admin/auth/force-change-password` variant is also available for the
> first-login forced password rotation flow.

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

#### GET /admin/policies/{name}

Get a specific policy by its file name.

#### POST /admin/policies

Create/update a policy.

#### DELETE /admin/policies/{name}

Delete a policy by name.

#### POST /admin/policies/{name}/rollback

Roll a policy back to a previous version (`GET /admin/policies/{name}/versions`
lists available versions).

> **Note:** The live hot-reload endpoint `POST /admin/policies/reload` is served
> by the **proxy** (port 8080, internal), not the admin API. Editing a policy via
> the admin API triggers the proxy reload automatically.

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

#### Allow-Exceptions (Allowlist)

Per-tenant/agent exceptions that degrade a would-be **BLOCK** to **WARN** for a
specific `tenant:agent` scope **without disabling the pattern globally**. The
request still emits an auditable security event tagged `allowed_by_exception`.
Exceptions sync to the proxy hot path via Redis (`bulwark:guardrails:exceptions`).

##### GET /admin/guardrails/exceptions

List all allow-exceptions as `{pattern_id: [scopes]}`. Requires `guardrails:read`.

```json
// Response
{"exceptions": {"pi-001": ["default-corp:support-bot"]}}
```

##### GET /admin/guardrails/patterns/{id}/exceptions

List the scopes exempted for a single pattern. Requires `guardrails:read`.

```json
// Response
{"pattern_id": "pi-001", "scopes": ["default-corp:support-bot"]}
```

##### POST /admin/guardrails/patterns/{id}/exceptions

Add an allow-exception. Requires `guardrails:write`. Returns 404 if the pattern
does not exist. All changes are audited.

```json
// Request (either form is accepted)
{"scope": "default-corp:support-bot"}
{"tenant_id": "default-corp", "agent_id": "support-bot"}

// Response
{"pattern_id": "pi-001", "scopes": ["default-corp:support-bot"], "added": true}
```

##### DELETE /admin/guardrails/patterns/{id}/exceptions

Remove an allow-exception. Requires `guardrails:write`.

```json
// Request
{"scope": "default-corp:support-bot"}

// Response
{"pattern_id": "pi-001", "scopes": [], "removed": true}
```

---

### Security Events

Durable, queryable history of security events (BLOCK + WARN) stored in the
admin's `security_events` table. This is separate from the proxy's capped Redis
live buffer: a background `events_sync` task (started unconditionally at admin
startup) drains the buffer into the table every `sync_interval_seconds`, so the
history survives Redis flushes/restarts and is not bounded by the per-tenant cap.

#### GET /admin/events

List security events from the durable store. Requires `guardrails:read`.

Query params: `tenant`, `category`, `severity`, `verdict`, `limit` (1–200,
default 50), `offset` (default 0).

- Default feed = **BLOCK + WARN** (the security feed).
- `verdict=blocked` / `verdict=warned` filter that feed.
- `verdict=allowed` reads the **separate, opt-in** allowed-event feed (only
  populated when the proxy runs with `BULWARK_LOG_ALLOWED=true`), so legitimate
  traffic is browsable without drowning the security-relevant events.

#### GET /admin/events/summary

Aggregated counts over the *full retained* security feed: `by_tenant`,
`by_category`, `by_severity`, `total`, plus `allowed_recorded` (count of
browsable allowed-event records; 0 unless `BULWARK_LOG_ALLOWED` is on). Requires
`guardrails:read`.

#### GET /admin/events/tenant-analytics

Combined per-tenant analytics: live Redis usage counters (total/blocked/allowed,
block rate) enriched with a category breakdown from recent blocks. Requires
`guardrails:read`.

#### GET /admin/events/settings

Return retention/storage settings for the portal: current overrides, the
effective values, and where each value comes from (portal → env → SIEM-aware
default). Requires `guardrails:read`.

#### POST /admin/events/settings

Persist retention/storage overrides and apply them to the live sync task
immediately. Requires `guardrails:write`. Invalid values return 400.

```json
// Request — keep events for 30 days
{"retention_mode": "custom", "retention_days": 30}

// Request — keep forever
{"retention_mode": "custom", "retention_days": 0}

// Request — back to automatic (SIEM-aware) default
{"retention_mode": "auto"}
```

Body keys (all optional): `retention_mode` (`auto`|`custom`), `retention_days`
(required for `custom`; `0` = keep forever, max 3650), `max_per_tenant` (or
`null` to clear the override), `sync_interval_seconds` (5–3600, or `null`).

> **Retention precedence:** portal override → `BULWARK_EVENTS_RETENTION_DAYS`
> env → SIEM-aware default (90 days when a SIEM exporter is enabled, otherwise
> 0 = keep forever). See `docs/OPERATIONS.md` →
> *Security Events History & Retention*.

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

#### POST /admin/siem/test

Test SIEM export connectivity.

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

List the current IOC entries. (Use `GET /admin/iocs/stats` for database statistics.)

#### POST /admin/iocs

Add a single IOC indicator. Use `POST /admin/iocs/bulk` to add many at once.

#### POST /admin/iocs/feeds/update

Trigger threat-intel feed synchronization.

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

#### PUT /admin/users/{user_id}

Update user (role, active status).

#### DELETE /admin/users/{user_id}

Delete a user.

#### GET /admin/rbac/matrix

Get full RBAC permission matrix.

#### PUT /admin/rbac/role/{role_name}

Update permissions for a role.

---

### Configuration

#### POST /admin/config/validate

Validate a submitted configuration payload.

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

### Enrichment (Attack Replay & Regex Candidates)

The enrichment surface exposes blocked-attack telemetry (attack replay DB,
evasion metrics) and the review queue for auto-derived regex candidates. All
endpoints require RBAC permissions (added in v1.0.0 — previously this router was
unauthenticated). Read endpoints require `guardrails:read`; the review action
requires `guardrails:write`.

#### GET /admin/enrichment/status

Enrichment pipeline status (enabled scanners, DB availability). Requires `guardrails:read`.

#### GET /admin/enrichment/stats

Aggregate enrichment counters. Requires `guardrails:read`.

#### GET /admin/enrichment/evasions

Evasion / decode telemetry (encoded-payload attempts observed). Requires `guardrails:read`.

#### GET /admin/enrichment/entries

Recent stored blocked-attack entries from the replay DB. Requires `guardrails:read`.

#### GET /admin/enrichment/regex-candidates

Auto-derived regex candidates pending review. Requires `guardrails:read`.

#### POST /admin/enrichment/regex-candidates/review

Approve or reject a candidate. The reviewer is recorded from the authenticated
session (`sub`), not a fixed value. Requires `guardrails:write`.

**Body**: `{"candidate_id": "...", "action": "approve" | "reject"}`

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
