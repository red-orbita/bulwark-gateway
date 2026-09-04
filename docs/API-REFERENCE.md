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

Prometheus exposition format. Exposes global request/verdict counters, the
`bulwark_correlation_*` counters, and the `bulwark_correlation_eval_duration_seconds`
inline-evaluation latency histogram (all sourced from the shared Redis correlation
hash), plus in-process gauges. The histogram measures the hot-path cost the opt-in
correlation engine adds (origin-risk read + input↔output correlation, including
their Redis round-trips); it renders as stable zeros when the engine has not fired.

**Authentication (either):**

1. **Metrics scrape token** — a dedicated least-privilege static bearer:
   `Authorization: Bearer <token>`. The token is read from
   `BULWARK_METRICS_SCRAPE_TOKEN` (or `..._FILE`); it is verified server-side with
   `hmac.compare_digest`. When the token is unset/empty the scrape-token path is
   **inert** (no insecure default) and this endpoint requires a JWT instead.
2. **Admin JWT** with the `admin:read` permission (session fallback).

This is the only admin endpoint that accepts the scrape token; it grants no other
access. Rotate/revoke by changing the secret. In-cluster deployments project the
token from `bulwark-admin-secrets` (key `metrics-scrape-token`) into Prometheus,
which references it via `authorization.credentials_file`.

> Full metrics catalog, scrape topology, SLO recording rules and dashboard
> mapping: [Observability](OBSERVABILITY.md).

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

#### POST /admin/plugins/install/upload

Install a plugin from an uploaded archive (`multipart/form-data`, field `file`:
a `.zip`/`.tar.gz` containing `bulwark-plugin.yaml`). The archive is extracted
to a temp dir, AST-analysed, and installed only if the security check passes.
Decompression-bomb protected.

#### POST /admin/plugins/install/url

Install a plugin from an HTTPS Git repository. The repo is shallow-cloned
(`--depth 1`, 30s timeout, non-interactive), the URL is SSRF-validated
(HTTPS-only, DNS-resolved against private/loopback/reserved IPs), the branch
name is injection-validated, and the tree is AST-analysed before install.

**Body**:
```json
{
  "url": "https://github.com/example/my-scanner.git",
  "branch": "main"
}
```

> There is **no** public plugin hub/registry. Remote installs are Git-based
> (endpoint above) or local (`bulwark plugin install <path> --source local`).
> The CLI also supports `--source git <url> [--branch <name>]`.

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

Return framework status. Reports what an evaluation would run against *right now*:
the proxy's live input-blocking scanners (`pipeline_source=proxy-full-pipeline`,
`scanner_names`, `proxy_reachable=true`) when the proxy is reachable, or the
admin-local regex floor otherwise.

#### POST /admin/evaluation/run

Run adversarial evaluation against the **real** guardrail pipeline. The admin
delegates to the proxy's internal endpoint (`POST /internal/evaluation/run`,
network-isolated, no auth) so ML/multilingual/RAG scanners are actually
exercised. If the proxy is unreachable the admin honors `BULWARK_FAIL_MODE`:
`open` degrades to a labeled regex-only local run
(`pipeline_source=admin-local-regex-only`), `closed` returns 503 rather than
report regex-only numbers as the full defense.

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

#### POST /admin/evaluation/corpus

Evaluate the guardrail pipeline against the **external labeled corpora** (ground
truth) rather than gateway-authored attacks. The corpora ship in the image
(`src/evaluation/data/`: AdvBench, HarmBench, jailbreak / regular in-the-wild),
so the benchmark is defensible — the labels were not written by Bulwark. Same
delegation + `BULWARK_FAIL_MODE` semantics as `/run` (proxy's real pipeline via
`POST /internal/evaluation/corpus`; degrade to labeled regex floor when `open`,
503 when `closed`).

**Body** (all optional):
```json
{
  "sources": ["advbench", "harmbench"],
  "limit_per_source": 50,
  "include_external_dir": true
}
```

`sources` restricts to specific bundled corpora (default: all). `limit_per_source`
caps samples per source for fast smoke runs. `include_external_dir=false` forces
the hermetic bundled floor, ignoring `$BULWARK_EVAL_DATASET_DIR`. A
misconfigured/empty corpus (e.g. an unknown source name) returns 400 rather than
a silent zero-sample benchmark.

**Response**: EvaluationReport (verdict-scored `confusion_block`/`confusion_flag`
matrices) plus `corpus_stats` (per-source provenance, licenses) and `per_source`
recall.

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

Analyze traffic logs for unauthorized AI usage. Optionally dispatch detected
alerts to the configured notification channels (advisory `warn` verdict).

**Body**:
```json
{
  "log_entries": [
    {"hostname": "api.openai.com", "source_ip": "10.0.1.5", "timestamp": "2024-01-01T12:00:00Z"}
  ],
  "notify": false,
  "tenant_id": "unknown"
}
```

- `notify` (default `false`): when `true`, each detected alert is dispatched to
  the notification engine. Off by default so analysis stays side-effect-free.
- `tenant_id` (default `"unknown"`): drives per-channel tenant filtering on dispatch.

**Response**:
```json
{
  "alerts": [
    {"hostname": "api.openai.com", "service": "OpenAI", "timestamp": "...", "source_ip": "10.0.1.5", "risk_level": "high"}
  ],
  "total_found": 1,
  "notified": 0
}
```

`notified` is the number of alerts handed to the notification engine (`0` when
`notify` is false or no channels are configured).

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

#### POST /admin/discovery/mcp/suggest-policy

Derive a conservative **deny-by-default** starter `AgentPolicy` from enumerated
MCP tools. Grounded entirely in each tool's inferred capabilities + risk score;
returned for operator review, never auto-applied.

**Body**:
```json
{
  "tools": [
    {"name": "run_shell", "description": "Runs shell commands", "capabilities": ["shell_exec"]},
    {"name": "search_docs", "description": "Search the knowledge base", "capabilities": ["search"]}
  ],
  "tenant_id": "acme",
  "agent_id": "mcp-agent"
}
```

**Response**:
```json
{
  "policy": { "tenant": "acme", "agents": [ ... ], "_rationale": [ ... ] },
  "policy_yaml": "tenant: acme\nagents:\n- id: mcp-agent\n  ...",
  "rationale": [ {"tool": "run_shell", "score": 8.0, "decision": "deny", "reason": "..."} ]
}
```

- `policy_yaml` is a ready-to-review file for `config/policies/` (no `_rationale`);
  it round-trips through the production policy loader.
- Execution/write-class tools (`shell_exec`, `code_execution`, `process_spawn`,
  `file_write`) are denied by default; `allow_network_access` reflects whether any
  *allowed* tool needs network egress; `sandbox_level` is `strict` when anything
  was denied or any allowed tool is high-risk.

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

### Correlation (Inline Origin-Risk Engine)

The proxy's opt-in correlation engine (`BULWARK_CORRELATION_ENABLED`, off by default) keeps a
decaying, per-origin **risk score** in Redis. Risk accrues from (a) confirmed input↔output
exfiltration incidents and (b) ongoing WARN/BLOCK security events. When an origin's decayed score
crosses a threshold, the *next* request from that origin is hardened (WARN, or BLOCK when blocking is
enabled). This surface exposes observability plus **real** runtime tuning — overrides are written to
`bulwark:correlation:config` and the proxy re-reads them within ~5s without a restart.

Risk keys are irreversible SHA-256 digests of the origin (`scope_type` ∈ `tenant`/`session`/`input`,
`digest` = 16 hex chars); they are never a raw tenant/agent/IP and cannot be mapped back to an
identity. Read endpoints require `correlation:read` (all roles); mutations require `correlation:write`
(admin + security).

#### GET /admin/correlation/status

Effective enforcement config (defaults merged with any runtime override), override state, Redis
connectivity, and active-origin count. Requires `correlation:read`.

```json
{
  "redis_connected": true,
  "can_write": true,
  "effective": {
    "blocking": false,
    "window_seconds": 30.0,
    "risk_block_threshold": 7.0,
    "risk_warn_threshold": 4.0,
    "risk_decay_seconds": 900.0,
    "event_bump_warn": 0.5,
    "event_bump_block": 1.0,
    "severity_high_mult": 1.5,
    "severity_critical_mult": 2.0
  },
  "defaults": { "...": "..." },
  "override": {},
  "overridden": false,
  "active_origins": 0,
  "note": null
}
```

#### GET /admin/correlation/config/fields

Read-only catalog of tunable fields and their numeric bounds. Requires `correlation:read`.

```json
{
  "boolean_fields": ["blocking"],
  "numeric_fields": {
    "window_seconds": {"min": 1.0, "max": 3600.0},
    "risk_block_threshold": {"min": 0.1, "max": 10.0},
    "risk_warn_threshold": {"min": 0.1, "max": 10.0},
    "risk_decay_seconds": {"min": 10.0, "max": 604800.0},
    "event_bump_warn": {"min": 0.0, "max": 10.0},
    "event_bump_block": {"min": 0.0, "max": 10.0},
    "severity_high_mult": {"min": 0.1, "max": 10.0},
    "severity_critical_mult": {"min": 0.1, "max": 10.0},
    "confidence_block_threshold": {"min": 0.0, "max": 1.0}
  },
  "latent_fields": ["window_seconds"]
}
```

> **`window_seconds` is latent/reserved — not currently enforced.** The input↔output
> correlator is strictly *same-request*: a request's input and its own output are
> inherently paired, so no time window is needed and the proxy deliberately does not
> feed the correlator a detection timestamp. The field is still accepted and bounded
> (so existing overrides don't break and a future cross-request/async correlator can
> adopt it) but changing it has **no effect on enforcement today**. The admin UI shows
> it read-only and omits it from the live tuning form.

#### GET /admin/correlation/origins

List active origins with their current decayed risk score (highest first). Requires
`correlation:read`.

**Query**: `limit` (default 200, max 1000)

```json
{
  "redis_connected": true,
  "count": 1,
  "origins": [
    {
      "scope_type": "session",
      "digest": "24d52a99be7b756a",
      "score": 9.32,
      "stored_score": 10.0,
      "updated_ts": 1766600000.0,
      "ttl_seconds": 7180
    }
  ]
}
```

#### PUT /admin/correlation/config

Set a runtime override for correlation enforcement. Only provided fields are written; passing no
fields is rejected (400) to avoid silent no-ops. Bounds mirror the proxy so an override can never
disable enforcement with a nonsensical value. Requires `correlation:write`.

```json
// Request (all fields optional)
{"blocking": true, "risk_block_threshold": 6.0, "risk_decay_seconds": 1200}

// Response
{"message": "Correlation override updated", "override": {"blocking": true, "risk_block_threshold": 6.0, "risk_decay_seconds": 1200.0}}
```

Numeric bounds: `window_seconds` 1–3600 (**latent/reserved — not enforced**, see above),
`risk_block_threshold`/`risk_warn_threshold` >0–10,
`risk_decay_seconds` 10–604800, `confidence_block_threshold` 0–1, `event_bump_warn`/`event_bump_block` 0–10,
`severity_high_mult`/`severity_critical_mult` >0–10.

#### DELETE /admin/correlation/config

Remove the runtime override so the proxy reverts to built-in defaults. Requires `correlation:write`.

#### DELETE /admin/correlation/origin/{scope_type}/{digest}

Clear the accumulated risk for a single origin. `scope_type` must be one of `tenant`/`session`/`input`
and `digest` must be 16 hex chars (else 400). Requires `correlation:write`.

```json
{"message": "Origin risk cleared", "keys_deleted": 1}
```

#### POST /admin/correlation/reset

Clear ALL accumulated origin risk (keeps the runtime config override). Requires `correlation:write`.

```json
{"message": "All origin risk cleared", "keys_deleted": 12}
```

All mutations are recorded in the admin audit log (`correlation.config_update`,
`correlation.config_clear`, `correlation.origin_delete`, `correlation.reset`).

---

### Investigation Center (Cases)

The Investigation Center turns triage signals (incidents, origins, sessions) into durable,
analyst-owned **cases**. A case carries metadata (status, severity, assignee, tags), linked
subjects, an append-only note trail, a reconstructed chronological timeline, first-class
**observables** (atomic indicators), and a **task** checklist. Cases can be seeded from a
**template** and exported to native (`json`/`md`) or interop (`stix`/`thehive`/`iris`) shapes.

Everything is **tenant-scoped**: a scoped operator only ever sees and mutates cases in their own
tenant — a cross-tenant id returns `404` (no existence leak). Reads require `investigation:read`;
mutations require `investigation:write` (admin + security roles hold both; auditor/viewer are
read-only). All mutations are recorded in the admin audit log (`investigation.*`).

All endpoints below are prefixed `/admin/investigation/cases`.

**Enum vocabularies** (returned in list responses so a UI never hardcodes them):
- Case status: `open`, `investigating`, `contained`, `resolved`, `closed`
- Case / observable severity: `low`, `medium`, `high`, `critical`
- Observable type: `ip`, `domain`, `url`, `hash`, `email`, `filename`, `user`, `other`
- TLP / PAP level: `red`, `amber`, `green`, `white` (default `amber`)
- Observable source: `manual`, `ioc-check`, `cortex`, `opencti`
- Task status: `todo`, `in_progress`, `done`, `cancelled`
- Subject type: `incident`, `origin`, `session`
- Export format: `json`, `md`, `stix`, `thehive`, `iris`

#### Cases

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `` | `investigation:read` | List cases. Query: `status`, `severity`, `assignee`, `search`, `sort` (`updated_at`\|`created_at`\|`title`\|`status`\|`severity`), `order` (`asc`\|`desc`), `limit` (1–500), `offset` |
| GET | `/stats` | `investigation:read` | Case counts by status/severity (+ optional `assignee` "my work" roll-up) |
| GET | `/analytics` | `investigation:read` | MTTR, opened-vs-resolved trend, top recurring origins. Query: `trend_days` (1–365), `top_origins` (1–100) |
| GET | `/templates` | `investigation:read` | List case templates (blueprints) |
| POST | `` | `investigation:write` | Create a case (see body below) |
| GET | `/for-subject/{subject_type}/{subject_key}` | `investigation:read` | Cases linked to a given subject |
| GET | `/{case_id}` | `investigation:read` | Full case detail (metadata, subjects, notes) |
| GET | `/{case_id}/timeline` | `investigation:read` | Reconstructed chronological timeline. Query: `limit` (1–1000, default 500) |
| GET | `/{case_id}/export` | `investigation:read` | Download the case. Query: `format` (`json`\|`md`\|`stix`\|`thehive`\|`iris`) |
| GET | `/{case_id}/related` | `investigation:read` | Other cases sharing a subject (campaign signal) |
| POST | `/{case_id}/state` | `investigation:write` | Set `status` / `severity` / `assignee` |
| POST | `/{case_id}/note` | `investigation:write` | Append a free-text note |
| POST | `/{case_id}/subject` | `investigation:write` | Link a subject (`subject_type`, `subject_key`) |
| DELETE | `/{case_id}/subject` | `investigation:write` | Unlink a subject. Query: `subject_type`, `subject_key` |
| POST | `/{case_id}/tags` | `investigation:write` | Replace the case tag (TTP/label) list |
| POST | `/{case_id}/timeline` | `investigation:write` | Add a manual timeline entry |

```json
// POST /admin/investigation/cases
// Request — template_id seeds severity/summary/tags/tasks the request omits
{"title": "Suspected prompt-injection campaign", "severity": "high",
 "summary": "Repeated override attempts from one origin", "template_id": "prompt-injection-campaign"}

// Response
{"message": "Case created", "case": {"case_id": "case_...", "title": "...", "severity": "high",
  "status": "open", "tags": ["ttp:prompt-injection"], "subjects": [], "notes": [ ... ]}}
```

#### Observables

First-class atomic indicators attached to a case (idempotent per `type`+`value`). Network/host/hash
indicators can be **promoted** into the shared IOC database.

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/{case_id}/observables` | `investigation:read` | List observables (most-recently-seen first) + enum vocabularies |
| POST | `/{case_id}/observables` | `investigation:write` | Add an observable (see body below) |
| DELETE | `/{case_id}/observables/{observable_id}` | `investigation:write` | Remove an observable |
| POST | `/{case_id}/observables/{observable_id}/promote-ioc` | `investigation:write` | Promote `ip`/`domain`/`url`/`hash` into the IOC database |

```json
// POST /admin/investigation/cases/{case_id}/observables
{"type": "ip", "value": "203.0.113.7", "is_ioc": false,
 "tlp": "amber", "pap": "amber", "tags": ["c2"], "source": "manual"}

// Response
{"message": "Observable added",
 "observable": {"observable_id": "obs_...", "type": "ip", "value": "203.0.113.7", "is_ioc": false}}
```

> Promotion only accepts `ip`/`domain`/`url`/`hash`; a hash must be 32 (MD5) or 64 (SHA-256) hex chars.
> `email`/`filename`/`user`/`other` have no IOC-database representation and are rejected `400`. On
> success the observable is marked `is_ioc` and the created IOC is tagged `investigation`.

#### Tasks

An ordered checklist per case, with a progress roll-up.

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/{case_id}/tasks` | `investigation:read` | List tasks (manual order) + `progress` roll-up |
| POST | `/{case_id}/tasks` | `investigation:write` | Add a task (`title`, optional `assignee`, `due_at`) |
| POST | `/{case_id}/tasks/{task_id}/state` | `investigation:write` | Set `status` / `assignee` / `due_at` |
| POST | `/{case_id}/tasks/{task_id}/note` | `investigation:write` | Append a note to a task |
| DELETE | `/{case_id}/tasks/{task_id}` | `investigation:write` | Delete a task |

```json
// POST /admin/investigation/cases/{case_id}/tasks
{"title": "Block C2 IP at the edge", "assignee": "alice", "due_at": "2026-09-05"}

// Response
{"message": "Task added",
 "task": {"task_id": "task_...", "title": "Block C2 IP at the edge", "status": "todo"}}
```

#### Export

`GET /{case_id}/export?format=…` returns the case as a downloadable attachment
(`Content-Disposition: attachment`). Native shapes (`json`, `md`) additionally carry the compliance
roll-up and reconstructed timeline; interop shapes carry the case's observables and tasks:

| Format | Media type | Filename | Shape |
|--------|-----------|----------|-------|
| `json` | `application/json` | `{case_id}.json` | Native `{ "case": { … } }` (compliance + timeline) |
| `md` | `text/markdown` | `{case_id}.md` | Human-readable Markdown record |
| `stix` | `application/json` | `{case_id}.stix.json` | STIX 2.1 bundle |
| `thehive` | `application/json` | `{case_id}.thehive.json` | TheHive case |
| `iris` | `application/json` | `{case_id}.iris.json` | DFIR-IRIS case |

---

### Integrations (Outbound Case Connectors)

Outbound **connectors** push investigation cases into an external case-management / SOAR / threat-intel
platform. Five connector types ship: **TheHive 5** (`thehive`), **DFIR-IRIS** (`dfir_iris`),
**Cortex** (`cortex`, enrichment/response), **OpenCTI** (`opencti`), and **MISP** (`misp`) — the last
two are both case-push targets *and* observable-lookup / sighting-feedback platforms. Each connector
is a flat config record (`name`, `type`, `base_url`, optional `api_key`, `verify_tls`, `enabled`)
persisted to `data/integrations.json` (override with `BULWARK_INTEGRATIONS_FILE`).

**Secrets**: an inline `api_key` is optional — an environment / Docker-secret value
(`BULWARK_INTEGRATION_<ID>_API_KEY`, `_FILE` supported) takes precedence and is never returned by
the API. Secrets are **masked** on every read (`••••…`).

**Push is idempotent and fail-open.** The first push to a connector creates the remote case and
records a row in the `integration_link` store (keyed by connector + local case); subsequent pushes
**update** the existing remote case instead of creating a duplicate. A connector/transport failure
returns `502` (audited) and **never mutates the local case**. Transient HTTP failures are retried
with a circuit breaker (shared `CircuitBreaker`, 3 attempts).

Reads require `integrations:read`; mutations require `integrations:write` (admin + security hold
both; auditor/viewer are read-only). All mutations are recorded in the admin audit log
(`integrations.*`). All endpoints below are prefixed `/admin/integrations`.

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/status` | `integrations:read` | Registry status + `can_write` flag for the caller |
| GET | `/sightings/status` | `integrations:read` | Sighting feedback dispatcher snapshot (enabled/running + reported/suppressed/failed) |
| GET | `` | `integrations:read` | List connectors (secrets masked) |
| GET | `/{id}` | `integrations:read` | Get one connector config (secret masked) |
| POST | `` | `integrations:write` | Create a connector (`type` = `thehive`\|`dfir_iris`\|`cortex`\|`opencti`\|`misp`\|`taxii`) |
| PUT | `/{id}` | `integrations:write` | Update a connector config |
| DELETE | `/{id}` | `integrations:write` | Delete a connector |
| POST | `/{id}/toggle` | `integrations:write` | Enable / disable a connector |
| POST | `/{id}/test` | `integrations:write` | Live `test_connection` probe against the platform |
| GET | `/{id}/health` | `integrations:read` | Cached connector health (TTL 30s) |
| POST | `/reload` | `integrations:write` | Reload the connector registry from disk |
| POST | `/push/case/{case_id}` | `integrations:write` | Idempotent push of a case to TheHive/IRIS/OpenCTI/MISP/TAXII (create-or-update; fail-open) |
| GET | `/push/case/{case_id}/links` | `integrations:read` | List remote links (`remote_id` / `remote_url` / `last_synced_at`) for a case |

```json
// POST /admin/integrations
{"name": "SOC TheHive", "type": "thehive",
 "base_url": "https://thehive.soc.example", "api_key": "•optional•", "verify_tls": true}

// POST /admin/integrations/push/case/{case_id}
{"integration_id": "int_a1b2c3"}

// Response (create)
{"ok": true, "created": true,
 "remote_id": "~40988", "remote_url": "https://thehive.soc.example/cases/~40988",
 "detail": "Case created",
 "link": {"connector": "thehive", "local_type": "case", "local_id": "case_...",
          "remote_id": "~40988", "remote_url": "https://thehive.soc.example/cases/~40988",
          "last_synced_at": "2026-09-01T12:00:00Z", "etag": ""}}
```

#### Event Webhooks (SOAR trigger seed)

Outbound **event webhooks** are the trigger surface a SOAR runner (Shuffle / n8n) subscribes to. A
subscription (`name`, `url`, optional `events` filter, `enabled`, `verify_tls`) is persisted to
`data/integration_webhooks.json` (override with `BULWARK_INTEGRATION_WEBHOOKS_FILE`) and reuses the
`integrations:read` / `integrations:write` permission namespace.

On a case **lifecycle** transition the emitter POSTs a stable JSON envelope to every matching
subscription: `case.opened`, `case.severity_raised` (only a genuine severity *escalation*), and
`case.resolved` (only a transition *into* resolved). A subscription with an empty `events` list
receives every event.

Fan-out is best-effort and **fail-open**: an empty subscription list costs nothing, deliveries run
concurrently under a short timeout, and a slow/dead endpoint never delays or breaks case management.
HMAC signing and the inbound action API are deferred to Phase 3. All endpoints below are prefixed
`/admin/integrations/webhooks`.

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `` | `integrations:read` | List subscriptions + available event types |
| GET | `/events` | `integrations:read` | List lifecycle event types a subscription can filter on |
| POST | `` | `integrations:write` | Create a subscription (`name` + `url` required) |
| PUT | `/{id}` | `integrations:write` | Update a subscription |
| DELETE | `/{id}` | `integrations:write` | Delete a subscription |
| POST | `/{id}/toggle` | `integrations:write` | Enable / disable a subscription |
| POST | `/{id}/test` | `integrations:write` | Send a synthetic `test.ping` (ignores filters / enabled) |
| POST | `/reload` | `integrations:write` | Reload subscriptions from disk |

```json
// POST /admin/integrations/webhooks
{"name": "SOAR trigger", "url": "https://soar.example/hooks/bulwark",
 "events": ["case.opened", "case.severity_raised"], "verify_tls": true}

// Delivered envelope (POST to the subscription url)
{"event": "case.severity_raised",
 "event_id": "evt_9f3c1a20b7d84e56",
 "timestamp": "2026-09-01T12:00:00Z",
 "tenant": "acme",
 "data": {"case_id": "case_...", "title": "Exfil", "severity": "critical",
          "status": "open", "from_severity": "medium", "to_severity": "critical"}}
```

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
