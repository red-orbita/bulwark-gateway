# Architecture

Sentinel Gateway is a security guardrail proxy that intercepts tool calls between users/applications and LLM agents, enforcing security policies in real-time.

## Table of Contents

- [High-Level Flow](#high-level-flow)
- [Components](#components)
- [Request Lifecycle](#request-lifecycle)
- [Security Layers](#security-layers)
- [Data Flow](#data-flow)
- [Design Decisions](#design-decisions)
- [Trust Model](#trust-model)
- [Verdict System](#verdict-system)

---

## High-Level Flow

```
                    ┌──────────────────────────────────────────────────────┐
                    │                  Sentinel Gateway                     │
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
| Rate Limiter | `src/middleware/rate_limiter.py` | Per-tenant rate limiting via Redis |
| Telemetry | `src/telemetry/` | SIEM export, notifications, metrics |

### Control Plane (Admin)

| Component | Path | Purpose |
|-----------|------|---------|
| Admin App | `admin/main.py` | Separate FastAPI instance (port 8090) |
| Policy CRUD | `admin/routes/policies.py` | Create/update/delete/reload policies |
| Guardrail Mgmt | `admin/routes/guardrails.py` | Pattern management + sandbox testing |
| SIEM Config | `admin/routes/siem.py` | Transport configuration + testing |
| Notifications | `admin/routes/notifications.py` | Alert channel CRUD + testing |
| User Store | `admin/services/user_store.py` | SQLite user database (bcrypt hashes) |
| Audit Logger | `admin/services/audit_logger.py` | Immutable audit trail |
| RBAC | `admin/routes/rbac.py` | Role-based access control |

### Supporting Services

| Service | Purpose |
|---------|---------|
| Redis | Rate limiting, session cache, recent blocks list |
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
7. If ALLOW/WARN → forward to backend LLM
8. Receive response from backend
9. Output Filter scans response:
   - Secret detection (API keys, tokens, passwords)
   - PII detection (emails, phones, SSNs)
   - Sensitive data patterns
10. If REDACT → mask matched content
11. Return response to client
12. Async: export to SIEM, fire notifications, update metrics
```

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

---

## Data Flow

### Shared Data (Proxy ↔ Admin)

| Data | Path | Owner | Consumer |
|------|------|-------|----------|
| Policies | `/app/config/policies/*.yaml` | Admin (write) | Proxy (read-only) |
| SIEM config | `/app/shared/siem/siem_transports.json` | Admin (write) | Proxy (read-only) |
| SIEM stats | `/app/shared/siem/siem_stats.json` | Proxy (write) | Admin (read) |
| Notifications | `/app/shared/notifications/channels.json` | Admin (write) | Proxy (read) |

### Kubernetes Volumes

```
PVC: policies        → /app/config/policies (ReadWriteOnce)
PVC: siem-stats      → /app/shared/siem (ReadWriteOnce)
PVC: admin-data      → /app/data (admin only, SQLite DBs)
emptyDir: telemetry  → /app/shared/telemetry (memory-backed, 50Mi)
```

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
