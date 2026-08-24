# Architecture

Bulwark Gateway is a security guardrail proxy that intercepts tool calls between users/applications and LLM agents, enforcing security policies in real-time.

## Table of Contents

- [High-Level Flow](#high-level-flow)
- [Components](#components)
- [Request Lifecycle](#request-lifecycle)
- [Security Layers](#security-layers)
- [Data Flow](#data-flow)
- [Inline Correlation (Opt-in)](#inline-correlation-opt-in)
- [Design Decisions](#design-decisions)
- [Trust Model](#trust-model)
- [Verdict System](#verdict-system)

---

## High-Level Flow

```
                    ┌──────────────────────────────────────────────────────┐
                    │                  Bulwark Gateway                     │
                    │                                                       │
User/Agent ───────▶│  [Auth] → [Input Guardrail] → [Tool Policy] → [LLM] │
                    │                                                  │    │
              ◀────│  [Output Filter] ← [Response] ←──────────────────┘    │
                    │       │                                               │
                    │       ├── [SIEM Export]                               │
                    │       ├── [Notifications]                             │
                    │       └── [Metrics]                                   │
                    └──────────────────────────────────────────────────────┘
```

## Components

### Data Plane (Proxy)

| Component | Path | Purpose |
|-----------|------|---------|
| FastAPI App | `src/main.py` | HTTP server, middleware chain |
| Proxy Route | `src/routes/proxy.py` | Main request handler, streaming buffer |
| Input Guardrail | `src/guardrails/input_guardrail.py` | Detect prompt injection, data exfil, malicious patterns |
| Output Filter | `src/guardrails/output_filter.py` | Redact secrets, PII, sensitive data from responses |
| Tool Policy | `src/guardrails/tool_policy.py` | Enforce per-tenant tool allowlists/blocklists |
| Agent Registry | `src/services/agent_registry.py` | Resolve tenant → backend mapping, auth config |
| Auth Middleware | `src/middleware/auth.py` | JWT/API key validation, fail-closed |
| Rate Limiter | `src/middleware/rate_limit.py` | Per-tenant rate limiting via Redis |
| Correlation Engine | `src/correlation/` | Opt-in inline origin-risk + input↔output exfiltration correlation (off by default) |
| Telemetry | `src/telemetry/` | SIEM export, notifications, metrics |

### Control Plane (Admin)

| Component | Path | Purpose |
|-----------|------|---------|
| Admin App | `admin/main.py` | Separate FastAPI instance (port 8090) |
| Policy CRUD | `admin/routes/policies.py` | Create/update/delete/reload policies |
| Guardrail Mgmt | `admin/routes/guardrails.py` | Pattern management + sandbox testing |
| SIEM Config | `admin/routes/siem.py` | Transport configuration + testing |
| Correlation Admin | `admin/routes/correlation.py` | Correlation status, origin-risk viewer, runtime tuning/reset (RBAC `correlation:*`) |
| Notifications | `admin/routes/notifications.py` | Alert channel CRUD + testing |
| User Store | `admin/services/user_store.py` | SQLite user database (bcrypt hashes) |
| Audit Logger | `admin/services/audit_logger.py` | Immutable audit trail |
| RBAC | `admin/routes/rbac.py` | Role-based access control |

### Supporting Services

| Service | Purpose |
|---------|---------|
| Redis | Rate limiting, session cache, recent blocks list, correlation origin-risk state |
| Prometheus | Metrics collection |
| Grafana | Dashboards and visualization |

---

## Request Lifecycle

### Non-Streaming Request

```
1. Client sends POST /v1/chat/completions
2. Auth middleware validates JWT/API key (fail-closed)
3. Rate limiter checks per-tenant quota (Redis)
4. Tenant resolved via Agent Registry
5. Input Guardrail scans request body:
   - Regex pattern matching (prompt injection, data exfil)
   - IOC detection (known malicious indicators)
   - Tool policy validation (allowed tools per tenant)
6. If BLOCK → return 403 + fire notifications + log to SIEM
   - (opt-in) Correlation: origin-risk check may harden ALLOW → WARN/BLOCK based on decayed session/tenant risk
7. If ALLOW/WARN → forward to backend LLM
8. Receive response from backend
9. Output Filter scans response:
   - Secret detection (API keys, tokens, passwords)
   - PII detection (emails, phones, SSNs)
   - Sensitive data patterns
10. If REDACT → mask matched content
    - (opt-in) Correlation: input↔output correlator flags exfiltration within the pairing window
11. Return response to client
12. Async: export to SIEM, fire notifications, update metrics
    - (opt-in) Correlation: event tap accrues origin risk from each WARN/BLOCK event
```

> **Inline correlation** (steps annotated *opt-in*) is gated by `BULWARK_CORRELATION_ENABLED`
> (default off). When disabled the engine is inert — no Redis reads, no added latency. See
> [Inline Correlation (Opt-in)](#inline-correlation-opt-in).

### Streaming Request (SSE)

```
1-6. Same as non-streaming
7. Forward to backend, receive SSE stream
8. BUFFER entire tool_call content (do NOT yield incrementally)
9. When tool_call complete → run Tool Policy validation
10. If BLOCK → close stream, return error
11. If ALLOW → yield buffered chunks to client
12. Continue streaming non-tool-call content normally
13. Output Filter runs on each text chunk
```

**Critical**: Tool calls are NEVER streamed incrementally to the client. They are buffered entirely and validated before any data is yielded. This prevents a malicious tool call from executing before policy can evaluate it.

---

## Security Layers

```
Layer 1: Network (NetworkPolicy, Ingress rules, TLS)
Layer 2: Authentication (JWT with aud/iss, API keys, fail-closed)
Layer 3: Rate Limiting (per-tenant, Redis-backed)
Layer 4: Input Guardrails (regex patterns, IOC matching)
Layer 5: Tool Policy (per-tenant allowlist/blocklist)
Layer 6: Output Filtering (secret/PII redaction)
Layer 7: Audit & Alerting (SIEM export, notifications)
```

Each layer is independent — failure in one doesn't bypass others.

> **Optional overlay** — when `BULWARK_CORRELATION_ENABLED=true`, an inline correlation layer sits
> alongside layers 4–6: it hardens verdicts based on decayed per-origin risk (after the input
> guardrail) and flags input↔output exfiltration (after output filtering). It is off by default and
> inert when disabled. See [Inline Correlation (Opt-in)](#inline-correlation-opt-in).

---

## Data Flow

### Shared Data (Proxy ↔ Admin)

| Data | Path | Owner | Consumer |
|------|------|-------|----------|
| Policies | `/app/config/policies/*.yaml` | Admin (write) | Proxy (read-only) |
| SIEM config | `/app/shared/siem/siem_transports.json` | Admin (write) | Proxy (read-only) |
| SIEM stats | `/app/shared/siem/siem_stats.json` | Proxy (write) | Admin (read) |
| Notifications | `/app/shared/notifications/channels.json` | Admin (write) | Proxy (read) |

### Correlation State (Redis, opt-in)

| Key | Type | Owner | Purpose |
|-----|------|-------|---------|
| `bulwark:risk:{scope}:{digest}` | HASH `{score, ts}` | Proxy (event tap) | Decayed per-origin risk; `scope` ∈ `tenant`/`session`/`input`, `digest` = `sha256(scope_type:scope_id)[:16]` |
| `bulwark:correlation:config` | HASH | Admin (write) | Runtime-tunable overrides (blocking, thresholds, decay, window, bumps); proxy re-reads throttled (~5s) |

The digest is a one-way hash of the origin identity (tenant/agent), never a raw IP —
origin keys cannot be spoofed by clients and carry no PII.

### Kubernetes Volumes

```
PVC: policies        → /app/config/policies (ReadWriteOnce)
PVC: siem-stats      → /app/shared/siem (ReadWriteOnce)
PVC: admin-data      → /app/data (admin only, SQLite DBs)
emptyDir: telemetry  → /app/shared/telemetry (memory-backed, 50Mi)
```

---

## Inline Correlation (Opt-in)

The correlation engine (`src/correlation/`) adds cross-request awareness **without** turning the
proxy into a SIEM. It is disabled by default (`BULWARK_CORRELATION_ENABLED=false`) and, when off,
performs no Redis reads and adds no measurable latency. Its scope is deliberately narrow: only
**inline enforcement** lives here; multi-source, forensic, historical, and cross-tenant analysis are
delegated to the downstream SIEM, which already receives every event.

### Components

| Module | Responsibility |
|--------|----------------|
| `risk_state.py` | Decayed per-origin risk store (Redis-backed, in-memory fallback). Score decays on a half-life and clamps to 10.0 |
| `event_tap.py` | Async event bus subscribed to the proxy's event sink; every WARN/BLOCK accrues origin risk (skips correlation's own events to avoid feedback) |
| `incident.py` | (a) Adaptive origin-risk check consulted inline after the input guardrail; (b) input↔output correlator that pairs a request with its response inside a time window to flag exfiltration |
| `runtime.py` | Throttled, Redis-overlaid tunable config — thresholds/decay/window/blocking can change without a restart (re-read every ~5s) |

### How Enforcement Works

1. **Accrual (async, off hot path)** — the event tap observes each emitted WARN/BLOCK `SecurityEvent`
   and bumps the origin's risk (base bumps scaled by severity: high ×1.5, critical ×2.0). Risk is keyed
   by **session** (`tenant:agent`) with tenant as weaker context (0.25×).
2. **Decay** — stored risk decays with a configurable half-life
   (`BULWARK_CORRELATION_RISK_DECAY_SECONDS`, default 900s), so bursts fade over time.
3. **Inline check (hot path)** — after the input guardrail, the request's current decayed session
   score is compared to thresholds: `≥ warn` → verdict hardened to WARN; `≥ block` → BLOCK (category
   `POLICY_VIOLATION`). Blocking is gated by `BULWARK_CORRELATION_BLOCKING` (default off → WARN only).
4. **Exfiltration correlation** — after output filtering, the input↔output correlator pairs the
   request's input signals with response signals inside `BULWARK_CORRELATION_WINDOW_SECONDS`
   (default 30s) and emits a correlated incident when an exfiltration pattern spans both sides.

### Emitted Events

Correlation events carry `source="correlation_engine"` and structured `metadata`:

- **Adaptive enforcement**: `correlation`, `adaptive_enforcement`, `origin_risk_score`,
  `origin_tenant_score`, `threshold`.
- **Input↔output incident**: `correlation`, `incident_id`, `kind=input_output_exfiltration`,
  `input_categories`, `output_categories`, `input_hash`, `risk_score`.

These flow through the same telemetry path as every other event (SIEM export, notifications) and are
surfaced in the admin Events viewer with a dedicated correlation panel (origin-risk meter, session/
tenant/threshold breakdown, input→output chain, `CORRELATED` badge).

### Operability

Runtime status and tuning are exposed under `/admin/correlation/*` (RBAC `correlation:read` /
`correlation:write`): view engine status and effective config, list active origins with their decayed
scores and TTLs, adjust thresholds/decay/window/blocking live, clear a single origin's risk, or reset
all accrued risk. See [API-REFERENCE](API-REFERENCE.md) for the full endpoint contract.

---

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Regex-only in hot path** | No LLM calls for detection — deterministic, <5ms latency, no API dependency |
| **Fail-closed auth** | If Redis/JWT validation fails, request is DENIED (security over availability) |
| **Separate admin service** | Zero impact on proxy latency; admin can crash without affecting traffic |
| **Buffered streaming** | Tool calls must be fully received before policy check (prevents partial execution) |
| **SQLite for admin** | Simple, no external dependency, encrypted via SQLCipher |
| **Per-tenant isolation** | Each tenant has own policies, rate limits, backend — no cross-contamination |
| **Backend auth from config** | No client header injection — auth token comes from agent registry only |
| **Structured events (ECS)** | Compatible with any SIEM, standardized format |
| **Async notifications** | Fire-and-forget — notification failure never blocks request processing |
| **Memory-backed telemetry** | emptyDir (RAM) prevents disk I/O on hot path |
| **Correlation opt-in, inert when off** | Zero hot-path cost by default; only inline enforcement lives in the proxy — multi-source/forensic/cross-tenant analysis is delegated to the SIEM |
| **WARN before BLOCK; time decay** | Correlation prefers flagging over blocking, and accrued risk decays (half-life) so a single burst doesn't permanently penalize an origin |
| **Hashed origin keys (no IP)** | Correlation scope keys are `sha256(scope)` digests — non-spoofable, no PII, safe to store |

---

## Trust Model

| Entity | Trust Level | Rationale |
|--------|-------------|-----------|
| User/Client | **Untrusted** | Potentially adversarial (prompt injection, tool abuse) |
| Backend LLM | **Semi-trusted** | May leak training data, hallucinate tool calls |
| Admin users | **Trusted but audited** | All actions logged, RBAC-limited |
| Redis | **Trusted** | Internal network only, password-protected |
| Config files | **Trusted** | Mounted read-only in proxy, written by admin only |

---

## Verdict System

Every security check produces a `Verdict`:

| Verdict | Action | Client Response | Notification |
|---------|--------|-----------------|--------------|
| `ALLOW` | Pass through | Normal response | No |
| `BLOCK` | Reject request | 403 + generic error | Yes (configurable) |
| `WARN` | Allow but flag | Normal response | Yes (configurable) |
| `REDACT` | Mask content | Modified response | Yes (configurable) |

Verdicts are immutable and attached to `SecurityEvent` objects for SIEM export.
