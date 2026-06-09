# Sentinel Gateway — Project Context

Complete reference for understanding, operating, and developing Sentinel Gateway.
This file is designed so that any AI agent or developer can fully operate the project.

---

## 1. What Is This Project

Sentinel Gateway is a **security guardrail proxy** for AI agents in cloud environments. It sits between users/applications and LLM backends (OpenAI, Ollama, Azure OpenAI, etc.) and enforces security policies on every request in real-time.

- **Language**: Python 3.11+ (FastAPI, Pydantic, httpx)
- **Trust model**: Fail-closed. Users and agent outputs are treated as potentially adversarial.
- **Hot path**: Pure regex detection (4600+ lines of patterns). No LLM calls during request processing.
- **Multi-tenant**: Each tenant has isolated policies, rate limits, and agent configurations.
- **License**: GPL-3.0-or-later

### What It Does

```
User → [Sentinel Gateway Proxy :8080] → LLM Backend
         │
         ├── 1. Input Guardrail (prompt injection, jailbreak, encoded attacks)
         ├── 2. IOC Scanner (URLs/IPs/hashes against threat intel feeds)
         ├── 3. Forward to Backend (per-tenant routing, SSRF protection)
         ├── 4. Tool Policy Engine (RBAC validation on tool calls)
         ├── 5. Output Filter (secret/PII/credential redaction)
         └── 6. Async Enrichment (attack replay DB, embedding scan)
         │
         └── Events → SIEM Exporter (ECS-formatted, batched, multi-transport)
                    → Notifications (Telegram, Slack, Teams, PagerDuty, webhook)
                    → Redis Counters (distributed metrics persistence)
```

### Request Flow (src/routes/proxy.py)

1. **AuthMiddleware** validates JWT/API-key → extracts `tenant_id` + `agent_id`
2. **RateLimitMiddleware** checks sliding-window counter in Redis → 429 if exceeded
3. **Input Guardrail** scans all user messages (Unicode NFKC normalization + entropy detection + regex) → 403 if malicious
4. **IOC Check** scans message content against threat intel database → 403 if match
5. **Agent Registry** resolves backend URL per tenant/agent (env var expansion in config)
6. **Forward** via httpx with SSRF protection (blocks RFC1918, CGNAT, cloud metadata IPs, DNS rebinding)
7. **Tool Policy** validates any tool_calls in response against per-agent RBAC → strips blocked tools
8. **Output Filter** redacts secrets/PII/credentials in response content
9. **Telemetry** fires async: security events to SIEM, counters to Redis, alerts to notification channels
10. **Return** filtered response to client

**Streaming**: SSE responses are filtered with a 256-char sliding window buffer.

---

## 2. Project Structure

```
sentinel-gateway/
├── src/                          # Proxy service (FastAPI, port 8080)
│   ├── main.py                   # App entry point, lifespan, middleware registration
│   ├── config.py                 # Pydantic Settings (SENTINEL_* env vars)
│   ├── models.py                 # Core data models (Verdict, SecurityEvent, ChatRequest)
│   ├── routes/
│   │   ├── proxy.py              # 6-phase request pipeline (757 lines)
│   │   ├── health.py             # /health, /health/stats
│   │   └── admin.py              # /admin/policies/reload
│   ├── guardrails/
│   │   ├── input_guardrail.py    # 4615 lines of regex patterns + multi-layer decoding
│   │   ├── output_filter.py      # Secret/PII redaction patterns
│   │   ├── tool_policy.py        # Per-agent RBAC enforcement
│   │   └── dynamic_registry.py   # Redis-synced pattern enable/disable
│   ├── middleware/
│   │   ├── auth.py               # JWT + API key authentication
│   │   └── rate_limit.py         # Redis sliding window rate limiter
│   ├── ioc/
│   │   └── manager.py            # IOC database (URLs, IPs, hashes, domains)
│   ├── services/
│   │   ├── agent_registry.py     # Multi-backend routing per tenant/agent
│   │   ├── ioc_feeds.py          # Threat intel feed integrator (ThreatFox, URLhaus, OTX)
│   │   └── domain_intel.py       # Domain reputation checks
│   ├── enrichment/
│   │   ├── manager.py            # Enrichment pipeline coordinator
│   │   ├── attack_replay_db.py   # Stores blocked attacks for analysis
│   │   ├── embedding_scanner.py  # Semantic similarity detection
│   │   └── base.py               # Base enrichment protocol
│   ├── telemetry/
│   │   ├── exporter.py           # Background worker: batching + circuit breaker + retry
│   │   ├── notifications.py      # Multi-channel alerts (fire-and-forget async)
│   │   ├── webhooks.py           # Webhook alert dispatcher
│   │   ├── counters.py           # Redis-backed distributed counters
│   │   ├── queue.py              # In-memory event queue
│   │   ├── schema.py             # ECS schema mapping
│   │   └── transports/
│   │       ├── file_shipper.py   # NDJSON file output (→ Filebeat/Fluentd)
│   │       ├── http_rest.py      # HTTP REST (→ Splunk HEC, Elastic, Datadog)
│   │       ├── syslog.py         # RFC 5424 syslog (→ QRadar, ArcSight)
│   │       └── tcp_tls.py        # Raw TCP+TLS (→ custom collectors)
│   ├── policies/
│   │   └── loader.py             # YAML policy loader with hot-reload (5s interval)
│   └── filters/
│       └── __init__.py
│
├── admin/                        # Admin dashboard service (FastAPI, port 8090)
│   ├── main.py                   # Admin app entry (286 lines), RBAC, UI routing
│   ├── routes/
│   │   ├── auth.py               # Login/logout, session management
│   │   ├── health.py             # /admin/health, /admin/health/detailed, SSE metrics
│   │   ├── policies.py           # Policy CRUD + hot-reload trigger
│   │   ├── guardrails.py         # Pattern CRUD (add/disable/test)
│   │   ├── siem.py               # SIEM config + export status
│   │   ├── tenants.py            # Tenant lifecycle management
│   │   ├── users.py              # User management (RBAC)
│   │   ├── rbac.py               # Role-based access control
│   │   ├── audit.py              # Audit log viewer
│   │   ├── config.py             # Global config management
│   │   ├── iocs.py               # IOC database management
│   │   ├── notifications.py      # Alert channel configuration
│   │   ├── skills.py             # Skill security scanner endpoints (scan/upload/status/history)
│   │   └── validate.py           # Config validation endpoints
│   ├── services/
│   │   ├── redis_sync.py         # get_redis_client(), pattern sync, version tracking
│   │   ├── auth_service.py       # Password hashing, JWT, sessions
│   │   ├── guardrails_store.py   # Pattern CRUD operations
│   │   ├── skill_scanner.py      # SkillSpector hybrid scanner (138 patterns, 5-stage pipeline)
│   │   ├── mcp_poisoning.py      # MCP Tool Poisoning detection (TP1-TP4, 20 patterns)
│   │   ├── mcp_privilege.py      # MCP Least Privilege analysis (LP1-LP4, 29 patterns)
│   │   ├── tenant_manager.py     # Tenant CRUD + agent assignment
│   │   ├── user_store.py         # User persistence
│   │   ├── config_manager.py     # Persistent config store
│   │   ├── config_validator.py   # Schema validation
│   │   ├── audit_logger.py       # Structured audit trail
│   │   ├── feed_scheduler.py     # Background feed refresh
│   │   ├── ioc_store.py          # IOC persistence
│   │   ├── orchestrator_bridge.py # Proxy↔Admin coordination
│   │   ├── prometheus_client.py  # Prometheus scrape
│   │   └── secrets.py            # Secret file reader
│   ├── models/
│   │   ├── auth.py               # Auth models
│   │   ├── config.py             # Config models
│   │   ├── tenants.py            # Tenant models
│   │   ├── iocs.py               # IOC models
│   │   └── metrics.py            # Metrics models
│   ├── templates/                # Jinja2 HTML (HTMX + Alpine.js + TailwindCSS)
│   │   ├── base.html             # Layout with CSP headers
│   │   └── pages/                # 18 pages (dashboard, login, policies, etc.)
│   └── static/                   # Vendored JS/CSS (no CDN dependencies)
│       ├── css/tailwind.min.css
│       └── js/vendor/            # htmx, alpine, lucide-icons
│
├── config/
│   ├── agents.yaml               # Agent registry (tenants → agents → backends)
│   ├── policies/                 # Per-tenant RBAC policies
│   │   ├── default-deny.yaml     # Base deny-all policy
│   │   ├── example-default.yaml  # Example: support-bot + code-assistant
│   │   └── healthcare-tenant.yaml # Example: healthcare-specific constraints
│   ├── notifications.yaml        # Notification channel config
│   ├── feeds/README.md           # Threat intel feed configuration docs
│   ├── examples/                 # Additional configuration examples
│   └── siem/                     # SIEM platform configs
│       ├── splunk_es.yaml
│       ├── elastic_elk.yaml
│       ├── ibm_qradar.yaml
│       ├── microsoft_sentinel.yaml
│       ├── datadog.yaml
│       └── wazuh_graylog_security_onion.yaml
│
├── helm/sentinel-gateway/        # Helm chart (recommended deployment)
│   ├── Chart.yaml                # v0.5.0, appVersion 0.4.3
│   ├── values.yaml               # 337 lines of configurable parameters
│   ├── .helmignore
│   └── templates/
│       ├── _helpers.tpl          # Redis URL logic, validation, label helpers
│       ├── proxy.yaml            # Proxy Deployment + Service + HPA
│       ├── admin.yaml            # Admin Deployment + Service
│       ├── redis.yaml            # Internal Redis (conditional)
│       ├── configmap.yaml        # agents.yaml, notifications, siem configs
│       ├── secrets.yaml          # Auto-generated secrets (JWT, passwords, API keys)
│       ├── ingress.yaml          # nginx + TLS + cert-manager
│       ├── network-policies.yaml # Zero-trust network isolation
│       ├── external-backends.yaml # ExternalName/ClusterIP services for LLM backends
│       ├── volumes.yaml          # PVCs for persistence
│       ├── monitoring.yaml       # Prometheus + Grafana (conditional)
│       ├── wazuh.yaml            # Wazuh SIEM (conditional)
│       ├── namespace.yaml
│       ├── NOTES.txt             # Post-install instructions
│       └── tests/
│           ├── test-connection.yaml # Health check validation
│           └── test-security.yaml   # Guardrail smoke test
│
├── k8s/                          # Kustomize manifests (alternative)
│   ├── kustomization.yaml        # Version 0.4.3
│   ├── namespace.yaml
│   ├── deploy.sh                 # Deployment script
│   ├── base/                     # Core: proxy, admin, redis, ingress, netpol, pdb
│   ├── monitoring/               # Prometheus, Grafana, Wazuh
│   └── secrets/                  # Secret generation scripts + sealed-secrets
│
├── ci/                           # CI/CD pipeline templates
│   ├── Jenkinsfile               # Jenkins Declarative Pipeline
│   ├── azure-pipelines.yml       # Azure DevOps
│   ├── .gitlab-ci.yml            # GitLab CI/CD
│   ├── tekton/pipeline.yaml      # Tekton (Kubernetes-native)
│   ├── values-staging.yaml       # Helm values for staging
│   └── values-production.yaml    # Helm values for production
│
├── .github/workflows/deploy.yml  # GitHub Actions pipeline
│
├── docker/
│   ├── Dockerfile.admin          # Admin container image
│   └── wazuh/                    # Wazuh decoder + rules for Sentinel events
│       ├── ossec-sentinel.conf
│       ├── sentinel-decoders.xml
│       └── sentinel-rules.xml
│
├── prometheus/                   # Prometheus configuration
│   ├── prometheus.yml            # Scrape configs
│   ├── rules.yml                 # Alert rules
│   └── web.yml                   # Basic auth config
│
├── scripts/                      # Operational scripts (client-facing)
│   ├── validate-deployment.sh    # Post-deploy validation (15 checks)
│   ├── security-smoke-test.py    # E2E security validation
│   ├── policy-rollback.sh        # Policy rollback with hot-reload
│   └── build-ui.sh              # Vendor admin UI dependencies
│
├── tests/                        # pytest test suite
│   ├── conftest.py               # Shared fixtures
│   ├── test_input_guardrail.py   # Input guardrail unit tests
│   ├── test_output_filter.py     # Output filter unit tests
│   ├── test_tool_policy.py       # Tool policy unit tests
│   ├── test_ioc.py               # IOC detection tests
│   ├── test_agent_registry.py    # Agent registry tests
│   ├── test_security_hardening.py # Auth, rate limiting, middleware tests
│   ├── test_streaming_guardrail.py # Streaming response filtering
│   ├── test_enrichment.py        # Attack replay and enrichment
│   ├── test_integration_ioc.py   # IOC integration tests
│   ├── test_admin_integration.py # Admin API integration (requires container)
│   ├── telemetry/                # Telemetry subsystem tests
│   │   ├── test_telemetry_unit.py
│   │   ├── test_telemetry_integration.py
│   │   └── test_telemetry_performance.py
│   └── qa/
│       └── legit-flows.yaml      # Legitimate request patterns for validation
│
├── docs/                         # Full documentation set
│   ├── INDEX.md                  # Documentation index + role-based navigation
│   ├── ARCHITECTURE.md           # System design, request flow, decisions
│   ├── DEPLOYMENT.md             # K8s, Helm, Docker Compose, Redis, TLS
│   ├── CICD.md                   # Pipeline guides (5 platforms)
│   ├── OPERATIONS.md             # Runbook: scripts, secrets, scaling
│   ├── TROUBLESHOOTING.md        # Common issues + solutions
│   ├── NOTIFICATIONS.md          # Multi-channel alerting
│   ├── SECURITY-HARDENING.md     # Security posture, audit results
│   └── API-REFERENCE.md          # Full API specification
│
├── Dockerfile                    # Proxy container (multi-stage, read-only, no-root)
├── docker-compose.yml            # Local development stack (proxy+admin+redis+prometheus+grafana)
├── pyproject.toml                # Python project metadata + dependencies
├── requirements.lock             # Pinned proxy dependencies
├── requirements-admin.lock       # Pinned admin dependencies
├── package.json                  # Node (TailwindCSS build for admin UI)
├── tailwind.config.js            # Tailwind config
├── README.md                     # Quick-start guide
├── .env.example                  # Example environment file
└── secrets/init.sh               # Generate all secrets for fresh deploy
```

---

## 3. Core Data Models (src/models.py)

### Verdict System

Every security check produces a `Verdict`:

| Verdict | Meaning | Action |
|---------|---------|--------|
| `ALLOW` | Safe to proceed | Forward to backend |
| `BLOCK` | Malicious or policy violation | Return 403, log event |
| `WARN` | Suspicious but allowed | Forward + emit security event |
| `REDACT` | Contains sensitive data | Mask content, then forward |

### Threat Categories

```python
class ThreatCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    TOOL_ABUSE = "tool_abuse"
    EXFILTRATION = "exfiltration"
    CREDENTIAL_ACCESS = "credential_access"
    REVERSE_SHELL = "reverse_shell"
    MALICIOUS_DOMAIN = "malicious_domain"
    PII_LEAK = "pii_leak"
    POLICY_VIOLATION = "policy_violation"
    RATE_LIMIT = "rate_limit"
    INSECURE_OUTPUT = "insecure_output"       # OWASP LLM02
    DENIAL_OF_SERVICE = "denial_of_service"   # OWASP LLM04
    EXCESSIVE_AGENCY = "excessive_agency"     # OWASP LLM08/LLM09
    MODEL_THEFT = "model_theft"               # OWASP LLM10
    PRIVACY_ATTACK = "privacy_attack"         # Model inversion / membership inference
    PLAN_CORRUPTION = "plan_corruption"       # CoT/reasoning manipulation
    CROSS_AGENT_INJECTION = "cross_agent_injection"  # Inter-agent propagation
    MEMORY_MANIPULATION = "memory_manipulation"      # RAG/vector store poisoning
```

### Security Event

All detections emit a `SecurityEvent` (Pydantic model):
- `timestamp`, `tenant_id`, `agent_id`
- `verdict`, `category`, `severity` (low/medium/high/critical)
- `description`, `source` (which guardrail)
- `matched_pattern`, `tool_name`, `request_id`
- `metadata` (dict, extra context)

Events are formatted as ECS (Elastic Common Schema) for SIEM ingestion.

### Request/Response Models

```python
class ChatRequest(BaseModel):
    """OpenAI-compatible chat completion request."""
    model: str
    messages: list[Message]
    tools: list[dict] | None = None
    tool_choice: str | dict | None = None
    temperature: float | None = None
    max_tokens: int | None = None
    stream: bool = False

class GuardrailResult(BaseModel):
    verdict: Verdict
    events: list[SecurityEvent] = []
    modified_content: str | None = None   # For redaction
    blocked_tools: list[str] = []
```

---

## 4. Guardrail Engines

### Input Guardrail (src/guardrails/input_guardrail.py)

4615 lines. Scans user messages BEFORE forwarding to LLM.

**Defense layers**:
1. Unicode NFKC normalization (homoglyphs, zero-width chars)
2. Shannon entropy detection (catches base64/hex encoded payloads)
3. Multi-layer decoding: base64, hex, URL, Unicode escapes, Morse, Braille, NATO phonetic
4. Pre-compiled regex patterns organized by threat category

**Pattern structure**:
```python
@dataclass
class Pattern:
    regex: re.Pattern
    category: ThreatCategory
    severity: str          # low, medium, high, critical
    description: str
    pattern_id: str
```

**Detection categories**: prompt injection, jailbreak, SSTI, XXE, command injection, reverse shell, path traversal, SQL injection, encoded payloads, exfiltration attempts.

### Tool Policy Engine (src/guardrails/tool_policy.py)

Validates tool calls in LLM responses against per-agent RBAC policies:
- **allowed_tools** / **denied_tools** lists
- **Argument pattern matching** (regex on tool arguments)
- **denied_arguments** (blocklist specific argument values)
- **max_tool_calls** per request
- **Path traversal detection** in file paths
- **Sandbox levels**: `strict` (deny by default), `standard` (allow unless denied)

### Output Filter (src/guardrails/output_filter.py)

Scans LLM responses BEFORE returning to user:
- API keys (AWS, GCP, Azure, GitHub, OpenAI, Stripe, etc.)
- Passwords and connection strings
- JWT tokens, session tokens
- PII (SSN, credit cards, phone numbers, emails)
- Cloud credentials (service account keys, SAS tokens)
- Private keys (RSA, EC, SSH)

### Skill Scanner — SkillSpector (admin/services/skill_scanner.py)

Pre-deployment security scanner for AI agent skills and MCP servers. Accessible
via admin UI (`/skills`) and API (`/admin/skills/scan/*`). Version 2.1.0-sentinel.

**5-stage pipeline**:
```
Stage 1: NVIDIA SkillSpector     (64 patterns, if installed)
Stage 2a: MCP Tool Poisoning     (20 patterns — always runs)
Stage 2b: MCP Least Privilege    (29 patterns — always runs)
Stage 3: Sentinel Overlay        (25 patterns — always runs)
Stage 4: Structural Checks       (RBAC/agency validation)
```

**Total patterns**: 138 (64 + 49 + 25)

**MCP Tool Poisoning** (`admin/services/mcp_poisoning.py`):
| Rule | Severity | Description |
|------|----------|-------------|
| SEN-MCP-TP1 | high/critical | Hidden instructions (HTML comments, zero-width chars, base64, Unicode Tags encoding) |
| SEN-MCP-TP2 | high | Unicode deception (RTL overrides, homoglyphs, mixed-script identifiers) |
| SEN-MCP-TP3 | medium/high | Parameter description injection (system prompt overrides, token injection) |
| SEN-MCP-TP4 | medium | Description-behavior mismatch (deceptive naming vs actual capabilities) |

**MCP Least Privilege** (`admin/services/mcp_privilege.py`):
| Rule | Severity | Description |
|------|----------|-------------|
| SEN-MCP-LP1 | high | Underdeclared capability — code uses capabilities not in permissions |
| SEN-MCP-LP2 | medium | Wildcard permission — overly broad access declaration |
| SEN-MCP-LP3 | medium | Missing permissions — no declaration but code has capabilities |
| SEN-MCP-LP4 | low | Overdeclared permission — declared but unused (suspicious) |

**Sentinel Overlay** (25 rules, `SEN-TP-*` through `SEN-PV-*`):
- Tool abuse (shell exec, file write, code eval, DB modification)
- Privilege escalation (sudo, sandbox bypass, wildcard permissions)
- Data exfiltration (external URLs, upload tools, DNS exfil)
- Prompt injection (instruction override, role manipulation)
- Credential access (hardcoded keys, cloud credential patterns)
- Reverse shell / RCE (nc, socat, python socket, curl|sh)
- Excessive agency (no restrictions, autonomous execution)
- Cross-agent injection (inter-agent relay without validation)
- Memory manipulation (vector store poisoning)
- IOC indicators (malicious TLDs, IP URLs, DNS patterns)
- Policy violation (proxy bypass, config tampering)

**Scoring**: 0-10 scale. Combines all engines via weighted max.
- Block threshold: >= 7.0 (configurable: `SENTINEL_SKILLSPECTOR_BLOCK_THRESHOLD`)
- Warn threshold: >= 4.0 (configurable: `SENTINEL_SKILLSPECTOR_WARN_THRESHOLD`)

**FP suppression**: Tool names appearing in `denied_tools` lists (YAML or JSON format)
are not flagged — they represent BLOCKED capabilities, not vulnerabilities.

**API endpoints**:
| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/skills/status` | Scanner status, engine breakdown, pattern counts |
| POST | `/admin/skills/scan/content` | Scan inline YAML/JSON content |
| POST | `/admin/skills/scan/upload` | Scan uploaded file |
| POST | `/admin/skills/scan/path` | Scan server-side path |
| GET | `/admin/skills/history` | Recent scan results |
| GET | `/admin/skills/history/{scan_id}` | Detailed result for specific scan |

---

## 5. Multi-Tenant Architecture

### Agent Registry (config/agents.yaml)

```yaml
defaults:
  backend_url: ${SENTINEL_BACKEND_URL:-http://ollama:11434}
  timeout: 120.0
  auth_header: null
  health_endpoint: /health

tenants:
  default-corp:
    agents:
      support-bot:
        path_prefix: /v1
        timeout: 30.0
        model: tinyllama
        description: Ollama local LLM for support
        status: active
      code-assistant:
        path_prefix: /v1
        timeout: 120.0
        model: tinyllama
        description: Ollama for code generation
        status: active
    _meta:
      status: active
```

Supports `${VAR:-default}` expansion in all string values.

### Policy Files (config/policies/*.yaml)

```yaml
tenant: default-corp
agents:
  - id: support-bot
    sandbox_level: strict
    allowed_tools: [web_search, read_knowledge_base, get_ticket_info]
    denied_tools: [run_command, bash, write_file, delete_file]
    allow_command_execution: false
    allow_file_write: false
    allow_network_access: true
    max_tool_calls: 10
    tool_policies:
      - name: web_search
        max_calls: 5
        denied_arguments:
          query: ["site:pastebin.com", "filetype:env", "169.254.169.254"]
```

### Redis Usage

Redis is used for 5 purposes (optional — falls back to in-memory if unavailable):
1. **Rate limiting** — distributed sliding window counters per tenant
2. **Pattern sync** — admin publishes pattern changes, proxy picks them up via version tracking
3. **Global metrics** — `sentinel:global:{requests_total,block,allow,warn}` survive pod restarts
4. **SIEM stats** — `sentinel:siem:{batches_sent,events_exported,export_errors,...}`
5. **Recent blocks** — last N blocked requests for admin dashboard

Redis keys:
```
sentinel:global:requests_total    # Total proxy requests
sentinel:global:block             # Total blocked
sentinel:global:allow             # Total allowed
sentinel:global:warn              # Total warned
sentinel:siem:batches_sent        # SIEM export stats
sentinel:siem:events_exported
sentinel:siem:export_errors
sentinel:siem:transports
sentinel:siem:queue_memory_depth
sentinel:siem:updated_at
sentinel:guardrails:disabled      # SET of disabled pattern IDs
sentinel:guardrails:custom        # HASH { id: JSON(pattern) }
sentinel:guardrails:version       # INT (incremented on change)
sentinel:rate_limit:{tenant}      # Sorted set (sliding window)
sentinel:recent_blocks            # List (last N blocked requests)
```

TLS supported via `rediss://` URL scheme. External Redis (Azure/AWS/GCP) fully supported.

---

## 6. Configuration (src/config.py)

All settings via `SENTINEL_` env prefix (Pydantic BaseSettings, 162 lines):

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SENTINEL_HOST` | str | `0.0.0.0` | Bind address |
| `SENTINEL_PORT` | int | `8080` | Proxy listen port |
| `SENTINEL_WORKERS` | int | `4` | Uvicorn workers |
| `SENTINEL_DEBUG` | bool | `false` | Debug mode (enables /docs) |
| `SENTINEL_MODE` | str | `proxy` | `proxy` or `sidecar` |
| `SENTINEL_JWT_SECRET` | str | required | JWT signing key (32+ chars) |
| `SENTINEL_JWT_ALGORITHM` | str | `HS256` | JWT algorithm |
| `SENTINEL_JWT_AUDIENCE` | str | `sentinel-proxy` | JWT audience |
| `SENTINEL_JWT_ISSUER` | str | `sentinel-gateway` | JWT issuer |
| `SENTINEL_API_KEYS_ENABLED` | bool | `true` | Enable API key auth |
| `SENTINEL_API_KEYS` | str | `""` | Comma-separated valid API keys |
| `SENTINEL_BACKEND_URL` | str | `http://localhost:11434` | Default LLM backend |
| `SENTINEL_BACKEND_TIMEOUT` | float | `120.0` | Backend timeout (seconds) |
| `SENTINEL_POLICIES_DIR` | Path | `config/policies` | Policy YAML directory |
| `SENTINEL_AGENTS_CONFIG` | Path | `config/agents.yaml` | Agent registry path |
| `SENTINEL_IOC_PATH` | Path | `config/iocs.json` | IOC database path |
| `SENTINEL_URLHAUS_KEY` | str | `""` | URLhaus feed API key |
| `SENTINEL_THREATFOX_KEY` | str | `""` | ThreatFox feed API key |
| `SENTINEL_OTX_KEY` | str | `""` | AlienVault OTX API key |
| `SENTINEL_ABUSEIPDB_KEY` | str | `""` | AbuseIPDB API key |
| `SENTINEL_RATE_LIMIT_ENABLED` | bool | `true` | Enable rate limiting |
| `SENTINEL_RATE_LIMIT_RPM` | int | `60` | Requests/min/tenant |
| `SENTINEL_RATE_LIMIT_RPM_BURST` | int | `10` | Burst allowance |
| `SENTINEL_REDIS_URL` | str\|None | `None` | Redis URL (`redis://` or `rediss://`) |
| `SENTINEL_REDIS_PASSWORD` | str\|None | `None` | Redis password |
| `SENTINEL_REDIS_TLS_INSECURE` | bool | `false` | Skip TLS cert verification |
| `SENTINEL_LOG_FORMAT` | str | `json` | `json` or `console` |
| `SENTINEL_LOG_LEVEL` | str | `INFO` | Python log level |
| `SENTINEL_FAIL_MODE` | str | `closed` | `closed` (block on error) or `open` |
| `SENTINEL_CORS_ORIGINS` | List | `[]` | Allowed CORS origins |
| `SENTINEL_WEBHOOK_ALERT_URLS` | str | `""` | Webhook URLs for alerts |

### Docker Secrets Support

For Kubernetes, secrets are mounted as files:
```
SENTINEL_JWT_SECRET_FILE=/run/secrets/jwt-secret
SENTINEL_REDIS_PASSWORD_FILE=/run/secrets/redis-password
SENTINEL_API_KEYS_FILE=/run/secrets/api-keys
```

The config loader reads `*_FILE` env vars and uses the file content as the value.

### Startup Validation

- JWT secret must be 32+ chars
- JWT secret must NOT be in blocklist (`change-me-in-production`, etc.)
- If validation fails, app refuses to start (unless `debug=true`)

---

## 7. Key Commands

```bash
# ─── Development ─────────────────────────────────────────────────────────────

# Activate virtualenv
source .venv/bin/activate

# Run proxy server locally
python -m uvicorn src.main:app --reload --port 8080

# Run admin server locally
python -m uvicorn admin.main:app --reload --port 8090

# Run full test suite (~140 tests)
pytest tests/ -q --tb=short

# Run tests excluding container-only tests
pytest tests/ -q --ignore=tests/test_admin_integration.py

# Lint
ruff check src/ tests/ admin/

# Type check
mypy src/ --ignore-missing-imports

# Build admin UI CSS (requires node_modules)
./scripts/build-ui.sh

# ─── Docker ──────────────────────────────────────────────────────────────────

# Build images
docker build -t sentinel-gateway-proxy:0.4.3 -f Dockerfile .
docker build -t sentinel-gateway-admin:0.4.2 -f docker/Dockerfile.admin .

# Run full stack locally (proxy + admin + redis)
docker-compose up -d

# Run with monitoring (adds prometheus + grafana)
docker-compose --profile monitoring up -d

# Run everything (adds grafana)
docker-compose --profile full up -d

# ─── Kubernetes (Helm — recommended) ─────────────────────────────────────────

# Deploy with internal Redis
helm install sentinel ./helm/sentinel-gateway \
  --set backend.ip=<LLM_BACKEND_IP> \
  --namespace sentinel-gateway --create-namespace

# Deploy with external Redis (e.g., Azure Cache)
helm install sentinel ./helm/sentinel-gateway \
  --set backend.ip=<LLM_BACKEND_IP> \
  --set redis.enabled=false \
  --set externalRedis.host=my-redis.cache.windows.net \
  --set externalRedis.port=6380 \
  --set externalRedis.tls=true \
  --set externalRedis.password=<PASSWORD>

# Upgrade existing deployment
helm upgrade sentinel ./helm/sentinel-gateway \
  --set proxy.image.tag=0.4.3 \
  --set admin.image.tag=0.4.2

# Run post-deploy Helm tests
helm test sentinel -n sentinel-gateway

# ─── Kubernetes (Kustomize — alternative) ────────────────────────────────────

BACKEND_IP=192.168.49.1 ./k8s/deploy.sh

# ─── Validation ──────────────────────────────────────────────────────────────

# Infrastructure validation (15 checks, uses kubectl exec + python3)
./scripts/validate-deployment.sh

# Skip backend checks if LLM is offline
./scripts/validate-deployment.sh --skip-backend

# Security posture validation (fires real test requests)
python scripts/security-smoke-test.py --host http://localhost:8080

# Policy rollback
./scripts/policy-rollback.sh [version]
```

---

## 8. API Endpoints

### Proxy (port 8080)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/v1/chat/completions` | JWT/API key | Main proxy endpoint (OpenAI-compatible) |
| POST | `/v1/tool/validate` | JWT/API key | Pre-execution tool call validation (sidecar mode) |
| GET | `/health` | None | Health check (JSON) |
| GET | `/health/stats` | None | Request counters, latency P95, uptime |
| POST | `/admin/policies/reload` | Internal | Hot-reload policies from disk |

### Admin (port 8090)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/admin/auth/login` | Credentials | Login, returns session cookie |
| POST | `/admin/auth/logout` | Session | Logout, invalidate session |
| GET | `/admin/health` | Session | Basic health check |
| GET | `/admin/health/detailed` | Session | Redis, pods, latency |
| GET | `/admin/health/sse` | Session | Real-time metrics stream (SSE) |
| GET | `/admin/health/recent-blocks` | Session | Last N blocked requests |
| GET/POST | `/admin/guardrails/*` | Session | Pattern CRUD (add/disable/test) |
| GET/POST | `/admin/policies/*` | Session | Policy management + reload |
| GET/POST | `/admin/siem/*` | Session | SIEM config + export status |
| GET/POST | `/admin/tenants/*` | Session | Tenant lifecycle |
| GET/POST | `/admin/users/*` | Session | User management |
| GET | `/admin/audit/*` | Session | Audit log viewer |
| GET/POST | `/admin/iocs/*` | Session | IOC database management |
| GET/POST | `/admin/notifications/*` | Session | Alert channel configuration |
| GET/POST | `/admin/config/*` | Session | Global configuration |
| GET/POST | `/admin/rbac/*` | Session | Role-based access control |
| GET | `/admin/skills/status` | Session | SkillSpector scanner status + pattern counts |
| POST | `/admin/skills/scan/content` | Session | Scan inline YAML/JSON skill definition |
| POST | `/admin/skills/scan/upload` | Session | Scan uploaded skill file |
| POST | `/admin/skills/scan/path` | Session | Scan server-side file path |
| GET | `/admin/skills/history` | Session | Recent scan results (filterable by verdict) |
| GET | `/admin/skills/history/{id}` | Session | Detailed result for specific scan |

### Authentication

- **JWT**: `Authorization: Bearer <token>` — token must have `sub`, `aud=sentinel-proxy`
- **API Key**: `Authorization: Bearer <api-key>` — matched against `SENTINEL_API_KEYS` list
- **Tenant/Agent**: `X-Tenant-ID` and `X-Agent-ID` headers (required for proxy)
- **Admin session**: HTTP-only cookie set by `/admin/auth/login`
- **Admin roles**: admin, security, auditor, viewer (RBAC enforced)

---

## 9. Deployment Options

### Docker Compose (Local Development)

```bash
docker-compose up -d
# Proxy: http://localhost:8080
# Admin: http://localhost:8090
# Redis: localhost:6379 (internal only)
```

Security: read-only filesystem, `cap_drop: ALL`, `no-new-privileges`, separate networks.

### Helm Chart (Production)

52 Kubernetes resources rendered. Key parameters in `values.yaml`:

| Section | Key Parameters |
|---------|----------------|
| `backend` | type (ip/externalName/none), ip, port |
| `proxy` | replicas=2, resources (512Mi/1CPU), HPA (2-10), PDB |
| `admin` | replicas=1, resources (256Mi/500m) |
| `redis` | enabled=true, redis:7-alpine, 128Mi, 1Gi storage |
| `externalRedis` | host, port, password, existingSecret, tls, tlsInsecure |
| `ingress` | nginx, TLS, cert-manager |
| `telemetry` | batchSize=100, flushInterval=1.0, transport type |
| `notifications` | telegram, slack (configurable channels) |
| `wazuh` | enabled=true, image 4.9.2, custom decoder/rules |
| `monitoring` | prometheus 2.51.0, grafana 10.4.0 |
| `networkPolicies` | enabled=true (zero-trust) |
| `persistence` | policies, siemStats, telemetryData, adminData |

### Redis Options

| Provider | Config | Port | TLS |
|----------|--------|------|-----|
| Internal (default) | `redis.enabled=true` | 6379 | No |
| Azure Cache for Redis | `externalRedis.host=*.redis.cache.windows.net` | 6380 | Yes |
| AWS ElastiCache | `externalRedis.host=*.cache.amazonaws.com` | 6379 | Yes |
| GCP Memorystore | `externalRedis.host=<private-ip>` | 6379 | Optional |
| On-premise | `externalRedis.host=redis.internal.company.com` | 6379 | Optional |

### CI/CD Pipelines

| Platform | File | Pattern |
|----------|------|---------|
| GitHub Actions | `.github/workflows/deploy.yml` | Test → Build → Deploy Staging → Deploy Production |
| Jenkins | `ci/Jenkinsfile` | Same + manual gate + rollback on failure |
| Azure DevOps | `ci/azure-pipelines.yml` | Same + approval environments |
| GitLab CI | `ci/.gitlab-ci.yml` | Same + `when: manual` production gate |
| Tekton | `ci/tekton/pipeline.yaml` | Kubernetes-native + kaniko builds |

All pipelines follow: **Test → Build → Deploy Staging → (Manual Gate) → Deploy Production**

---

## 10. Development Conventions

### Code Style

- Pydantic models for all data structures
- Type hints everywhere (`mypy --strict` on `src/`)
- Pure regex in hot path — never call external services during request processing
- `asyncio.create_task()` for fire-and-forget operations (notifications, enrichment)
- All Redis connections via `get_redis_client()` helper with TLS support
- Graceful degradation: if Redis unavailable, fall back to in-memory

### Security Patterns

- Environment variables prefixed with `SENTINEL_`
- Secrets via file mount (`*_FILE` env vars), never hardcoded
- Fail-closed: on unhandled error in `/v1/` paths, return 403
- No `eval()`, no dynamic code execution, no `pickle`
- SSRF protection: DNS resolution at request-time, full CIDR blocklist
- Container hardening: read-only filesystem, no capabilities, no root

### Commit Messages

```
feat: <description>     — New guardrail, endpoint, or capability
fix: <description>      — Bug fix or pattern correction
test: <description>     — New tests
docs: <description>     — Documentation
refactor: <description> — Code restructuring
ci: <description>       — CI/CD pipeline changes
chore: <description>    — Maintenance, dependencies
```

### Testing Requirements

- All new guardrail patterns MUST have tests
- Tests cover both positive (should block) and negative (should allow) cases
- Run `pytest` before every commit
- Current: ~140 tests, all passing
- Container-only tests: `test_admin_integration.py`, `test_security_hardening.py` (require `/app` path)

### File Ownership

Security-critical files — review carefully before modifying:

| File | Reason |
|------|--------|
| `src/models.py` | Core data models used everywhere |
| `src/middleware/auth.py` | Authentication logic |
| `src/guardrails/input_guardrail.py` | Detection patterns (4600+ lines, regex) |
| `src/guardrails/output_filter.py` | Secret redaction patterns |
| `src/routes/proxy.py` | Main request pipeline, SSRF protection |
| `admin/services/skill_scanner.py` | SkillSpector hybrid engine (138 patterns, scoring) |
| `admin/services/mcp_poisoning.py` | MCP tool poisoning detection (20 patterns) |
| `admin/services/mcp_privilege.py` | MCP least privilege analysis (29 patterns) |
| `helm/sentinel-gateway/templates/secrets.yaml` | Secret generation |
| `helm/sentinel-gateway/templates/network-policies.yaml` | Network isolation |

---

## 11. Adding New Features

### Add a New Detection Pattern

1. Choose layer: `input_guardrail.py` (user input) or `output_filter.py` (LLM output)
2. Add `Pattern(regex, category, severity, description, pattern_id)` to the appropriate list
3. Write tests: at least one positive (blocks attack) and one negative (allows legit traffic)
4. Test: `pytest tests/test_input_guardrail.py -v` or `pytest tests/test_output_filter.py -v`
5. Dynamic patterns can also be added via admin UI (`/admin/guardrails/`)

### Add a New Tenant

1. Add tenant block in `config/agents.yaml` under `tenants:`
2. Create `config/policies/<tenant-name>.yaml` with agent RBAC rules
3. Hot-reload: `POST /admin/policies/reload` or wait 5s for auto-reload
4. Write test in `tests/test_tool_policy.py`

### Add a SIEM Transport

1. Create transport class implementing `TransportProtocol` in `src/telemetry/transports/`
2. Implement `name` property, `send_batch()`, and `close()` methods
3. Register in `src/telemetry/exporter.py`
4. Add platform config in `config/siem/`

### Add a Notification Channel

1. Configure via admin UI (`/admin/notifications/`) or `config/notifications.yaml`
2. Supported: Telegram, Slack, Microsoft Teams, Email, PagerDuty, Opsgenie, generic webhook
3. Implementation in `src/telemetry/notifications.py`

### Add a Threat Intel Feed

1. Implement feed class in `src/services/ioc_feeds.py`
2. Add API key env var in `src/config.py` (with `*_FILE` support)
3. Register in `admin/services/feed_scheduler.py`
4. Add key to `secrets/init.sh`

---

## 12. Monitoring & Observability

### Redis Counters (Real-time)

```
sentinel:global:requests_total  — total proxy requests
sentinel:global:block           — total blocked
sentinel:global:allow           — total allowed
sentinel:global:warn            — total warned
```

### SIEM Integration

Events exported in ECS (Elastic Common Schema) format:
- File (ndjson) → Wazuh/Filebeat/Fluentd
- HTTP/REST → Splunk HEC, Elastic, Datadog
- Syslog (RFC 5424) → QRadar, ArcSight
- TCP+TLS → Custom collectors

Exporter features: batch flush (100 events or 1s), circuit breaker, exponential backoff retry.

### Wazuh Rules (MITRE ATT&CK Mapped)

| Rule ID | Alert Level | MITRE | Description |
|---------|-------------|-------|-------------|
| 100100 | 3 | — | Security event (generic) |
| 100101 | 12 | T1059 | Prompt injection attempt |
| 100102 | 10 | T1041 | Data exfiltration attempt |
| 100103 | 14 | T1190 | Jailbreak attempt |
| 100104 | 12 | T1552 | Credential access in output |
| 100105 | 8 | T1552.005 | PII leak detected |
| 100106 | 10 | — | Tool policy violation |
| 100107 | 6 | — | Rate limit exceeded |

### Dashboards

- **Admin UI** (port 8090): Real-time SSE metrics, recent blocks, tenant usage, bypass rate
- **Grafana**: Pre-configured dashboards via Helm chart
- **Prometheus**: Alert rules for high block rate, latency spikes, Redis failures

---

## 13. Current Version State

| Component | Version | Image Tag |
|-----------|---------|-----------|
| Proxy | 0.4.3 | `sentinel-gateway-proxy:0.4.3` |
| Admin | 0.4.3-sp2 | `sentinel-gateway-admin:0.4.3-sp2` |
| SkillSpector Engine | 2.1.0-sentinel | — |
| Helm Chart | 0.5.0 | — |
| Kustomize | 0.4.3 | — |

### What Gets Deployed

- Proxy: 2 replicas (HPA 2-10, target 70% CPU)
- Admin: 1 replica
- Redis: 1 replica (internal) or external managed
- Ingress: nginx with TLS (cert-manager)
- Monitoring: Prometheus + Grafana (optional)
- SIEM: Wazuh with custom decoder/rules (optional)
- PodDisruptionBudgets on proxy and redis
- NetworkPolicies (zero-trust): proxy↔redis, admin↔redis, proxy→backend, deny all else

---

## 14. Container Security

Both Dockerfiles use multi-stage builds:

```
Builder stage: python:3.11-slim → install dependencies
Runtime stage: python:3.11-slim → copy only installed packages + source

Hardening:
- Non-root user: `sentinel` (UID 10001)
- Read-only filesystem (tmpfs for /tmp)
- No pip/setuptools in runtime image
- No shell utilities (curl, wget) — only python stdlib
- CAP_DROP ALL
- No new privileges
```

---

## 15. Troubleshooting Quick Reference

| Issue | Fix |
|-------|-----|
| Pod CrashLoopBackOff | Check `SENTINEL_JWT_SECRET` is 32+ chars: `kubectl logs deploy/proxy` |
| Redis connection refused | Verify `SENTINEL_REDIS_URL` and password file mount |
| 403 on all requests | Check API key or JWT in Authorization header + X-Tenant-ID + X-Agent-ID |
| 401 Unauthorized | API key not in `SENTINEL_API_KEYS` list, or JWT expired/invalid |
| Policies not loading | Verify `config/policies/` mount, file permissions, YAML syntax |
| High latency (>100ms) | Notifications are async; check Redis connectivity |
| SIEM not exporting | Verify `SENTINEL_TELEMETRY_ENABLED=true` and transport config |
| Admin readiness probe failing | Transient: liveness probe kills pod on overload; check memory limits |
| Guardrail false positive | Test pattern with `pytest -k test_input_guardrail -v`; disable via admin UI |
| Rate limit too aggressive | Increase `SENTINEL_RATE_LIMIT_RPM` (default: 60) |
| Backend 502/504 | Check `SENTINEL_BACKEND_URL`, backend health, and timeout settings |

Full troubleshooting: `docs/TROUBLESHOOTING.md`

---

## 16. Dependencies

### Runtime (proxy)

| Package | Version | Purpose |
|---------|---------|---------|
| fastapi | >= 0.115 | Web framework |
| uvicorn[standard] | >= 0.30 | ASGI server |
| httpx | >= 0.27 | Async HTTP client (backend forwarding) |
| pyyaml | >= 6.0 | Config/policy parsing |
| pydantic | >= 2.7 | Data validation |
| pydantic-settings | >= 2.3 | Settings management |
| structlog | >= 24.1 | Structured logging |
| PyJWT | >= 2.8 | JWT authentication |
| redis | >= 5.0 | Redis client (rate limiting, counters) |
| cachetools | >= 5.3 | In-memory LRU caches |

### Development

| Package | Purpose |
|---------|---------|
| pytest >= 8.0 | Test runner |
| pytest-asyncio >= 0.23 | Async test support |
| pytest-httpx >= 0.30 | HTTP mocking |
| ruff >= 0.5 | Linting + formatting |
| mypy >= 1.10 | Type checking |

---

## 17. Documentation Map

| Need | Read |
|------|------|
| System design | `docs/ARCHITECTURE.md` |
| Deploy to K8s | `docs/DEPLOYMENT.md` |
| Configure Redis | `docs/DEPLOYMENT.md` → Redis Configuration |
| Set up CI/CD | `docs/CICD.md` |
| Day-to-day ops | `docs/OPERATIONS.md` |
| Fix issues | `docs/TROUBLESHOOTING.md` |
| Configure alerts | `docs/NOTIFICATIONS.md` |
| API details | `docs/API-REFERENCE.md` |
| Security posture | `docs/SECURITY-HARDENING.md` |
| All docs (index) | `docs/INDEX.md` |
