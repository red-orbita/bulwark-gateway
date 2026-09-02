# Bulwark Gateway — Project Context

Complete reference for understanding, operating, and developing Bulwark Gateway.
This file is designed so that any AI agent or developer can fully operate the project.

---

## 1. What Is This Project

Bulwark Gateway is a **security guardrail proxy** for AI agents in cloud environments. It sits between users/applications and LLM backends (OpenAI, Ollama, Azure OpenAI, etc.) and enforces security policies on every request in real-time.

- **Language**: Python 3.11+ (FastAPI, Pydantic, httpx)
- **Trust model**: Fail-closed. Users and agent outputs are treated as potentially adversarial.
- **Hot path**: Pure regex detection (4600+ lines of patterns). No LLM calls during request processing.
- **Multi-tenant**: Each tenant has isolated policies, rate limits, and agent configurations.
- **License**: GPL-3.0-or-later

### What It Does

```
User → [Bulwark Gateway Proxy :8080] → LLM Backend
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

**Inline correlation (opt-in, `BULWARK_CORRELATION_ENABLED`, off by default)**: when enabled, an
adaptive origin-risk check runs **after step 3** (input guardrail) — if the request's origin
(session/tenant) has accrued enough decayed risk, the verdict is hardened to WARN or BLOCK before
forwarding. After the response is filtered, an input↔output correlator flags exfiltration patterns
within a time window, and an async event tap accrues origin risk from every WARN/BLOCK event. When
disabled the engine is fully inert (zero hot-path cost). See §5 (Redis), §6 (config), §8 (admin API).

---

## 2. Project Structure

```
bulwark-gateway/
├── src/                          # Proxy service (FastAPI, port 8080)
│   ├── main.py                   # App entry point, lifespan, middleware registration
│   ├── config.py                 # Pydantic Settings (BULWARK_* env vars)
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
│   ├── correlation/               # Inline correlation engine (opt-in, off by default)
│   │   ├── incident.py           # Input↔output exfiltration correlator + adaptive origin-risk
│   │   ├── risk_state.py         # Decayed per-origin risk store (Redis + in-memory fallback)
│   │   ├── event_tap.py          # Async event bus: WARN/BLOCK events → origin risk accrual
│   │   └── runtime.py            # Throttled Redis-overlaid tunable config (no restart)
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
│   │   ├── schema.py             # ECS schema mapping (+ bulwark.compliance.*)
│   │   ├── compliance.py         # Declarative ThreatCategory→OWASP/MITRE/NIST AI RMF/EU AI Act
│   │   └── transports/
│   │       ├── file_shipper.py   # NDJSON file output (→ Filebeat/Fluentd)
│   │       ├── http_rest.py      # HTTP REST (→ Splunk HEC, Elastic, Datadog)
│   │       ├── syslog.py         # RFC 5424 syslog (→ QRadar, ArcSight)
│   │       └── tcp_tls.py        # Raw TCP+TLS (→ custom collectors)
│   ├── policies/
│   │   └── loader.py             # YAML policy loader with hot-reload (5s interval)
│   ├── scanners/                  # Scanner framework (Phase 1-5)
│   │   ├── protocol.py           # InputScanner/OutputScanner ABCs
│   │   ├── pipeline.py           # 4-lane pipeline orchestrator
│   │   ├── discovery.py          # Plugin discovery (entry_points + drop-in)
│   │   ├── builtin/              # Builtin scanners (regex, output, tool_policy)
│   │   ├── ml/                   # ML detection (injection, toxicity, topic, intent)
│   │   ├── artifacts/            # Binary model-artifact opcode scanner (stdlib pickletools, never deserializes; BWK-ART-*) — shared by admin SkillSpector + proxy output lane
│   │   ├── multilingual/         # Language detection + 10-language patterns
│   │   ├── multimodal/           # OCR + vision scanner
│   │   ├── output/               # Hallucination, schema, grounding, relevance, artifact (insecure-output)
│   │   └── rag/                  # RAG chunk scanner + memory guard
│   ├── dialog/                    # Dialog flow engine (YAML-based state machine)
│   │   └── engine.py
│   ├── sdk/                       # Library mode SDK
│   │   ├── guard.py              # Guard class (scan_input/output, protect, wrap)
│   │   └── integrations/         # LangChain, LlamaIndex integrations
│   ├── plugins/                   # Plugin hub (Phase 7)
│   │   ├── spec.py               # PluginSpec model, validation
│   │   ├── manager.py            # Lifecycle + security audit
│   │   └── cli.py                # CLI: install/uninstall/list/create
│   ├── evaluation/                # Red teaming framework (Phase 8)
│   │   ├── attacks.py            # AttackGenerator (template/mutation/encoding)
│   │   ├── runner.py             # EvaluationRunner + EvaluationReport
│   │   ├── datasets.py           # Benign + standard attack datasets
│   │   └── cli.py                # CLI: evaluate with thresholds
│   ├── discovery/                 # Agent discovery (Phase 9)
│   │   ├── agent_discovery.py    # Network/K8s LLM endpoint scanning
│   │   ├── shadow_ai.py          # Shadow AI monitor (30 endpoints)
│   │   └── mcp_inventory.py      # MCP risk assessment
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
│   │   ├── plugins.py            # Plugin management (install/uninstall/enable/disable/scaffold)
│   │   ├── evaluation.py         # Red teaming evaluation (run/quick/preview/report)
│   │   ├── discovery.py          # Agent discovery + Shadow AI + MCP risk assessment
│   │   └── validate.py           # Config validation endpoints
│   ├── services/
│   │   ├── redis_sync.py         # get_redis_client(), pattern sync, version tracking
│   │   ├── auth_service.py       # Password hashing, JWT, sessions
│   │   ├── guardrails_store.py   # Pattern CRUD operations
│   │   ├── skill_scanner.py      # SkillSpector hybrid scanner (5-stage pipeline; default ~77 text patterns + 63-entry artifact catalog, stage 1 optional)
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
│   │   └── pages/                # 21 pages (dashboard, login, policies, plugins, evaluation, discovery, etc.)
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
│       ├── microsoft_bulwark.yaml
│       ├── datadog.yaml
│       └── wazuh_graylog_security_onion.yaml
│
├── helm/bulwark-gateway/        # Helm chart (recommended deployment)
│   ├── Chart.yaml                # v1.0.0, appVersion 1.0.0
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
│   ├── kustomization.yaml        # Version 1.0.0
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
│   └── wazuh/                    # Wazuh decoder + rules for Bulwark events
│       ├── ossec-bulwark.conf
│       ├── bulwark-decoders.xml
│       └── bulwark-rules.xml
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
│   ├── test_scanner_framework.py # Scanner pipeline + builtin (37 tests)
│   ├── test_ml_scanners.py       # ML scanner mocking (35 tests)
│   ├── test_multilingual_multimodal.py # Language + vision (43 tests)
│   ├── test_output_validation.py # Hallucination, schema, grounding (30 tests)
│   ├── test_phase5_phase6.py     # RAG, dialog, SDK (27 tests)
│   ├── test_phase7_plugins.py    # Plugin system (21 tests)
│   ├── test_phase8_evaluation.py # Red teaming framework (19 tests)
│   ├── test_phase9_discovery.py  # Agent discovery (25 tests)
│   ├── test_exhaustive_integration.py # Cross-phase integration (41 tests)
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

**Detection categories** (input layer): prompt injection, jailbreak, SSTI, XXE, command injection, reverse shell, encoded payloads, exfiltration attempts.

> **Scope honesty**: classic SQL injection (`'; DROP TABLE …`, `admin' OR 1=1 --`), XSS, and bare path traversal (`../../../etc/passwd`) are **not** reliably matched on free-form chat input, and by design. Those threats are enforced where the payload actually reaches a database / filesystem: the **tool-argument layer** (`tool_policy.py` — path-traversal detection, `denied_arguments`, argument allow/deny) and the **output filter**. Some `UNION SELECT`-style SQLi is caught incidentally by exfiltration / tool-abuse patterns. Do not rely on the input guardrail as a SQLi/XSS WAF.

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
via admin UI (`/skills`) and API (`/admin/skills/scan/*`). Version 2.1.0-bulwark.

**Pipeline** (Stage 1 runs ONLY when the optional NVIDIA `skillspector` package
is installed; the default deployment does NOT bundle it → 4 active text stages
plus a binary-artifact stage that fires only on model files):
```
Stage 0: Model Artifact Scanner  (binary pickle/torch/joblib/HDF5 — fires on model files)
Stage 1: NVIDIA SkillSpector     (OPTIONAL — skipped when package absent)
Stage 2a: MCP Tool Poisoning     (20 patterns — always runs)
Stage 2b: MCP Least Privilege    (29 patterns — always runs)
Stage 3: Bulwark Overlay        (28 rules — always runs)
Stage 4: Structural Checks       (RBAC/agency validation)
```

**Total patterns (default, `skillspector` absent)**: ~77 text patterns
(0 + 20 + 29 + 28) plus a 63-entry dangerous-symbol catalog for the binary
model-artifact stage (`model_artifact_patterns`, reported separately by
`status()`; total_patterns = 140). Installing `skillspector` adds its own pattern
set on top (mode `skillspector+bulwark`). `skill_scanner.status()` reports live
counts + mode.

**Model Artifact Scanner** (`src/scanners/artifacts/model_artifact_scanner.py`):
Stdlib-only (`pickletools.genops`) opcode analysis that **never deserializes** a
model file. Detects load-time RCE gadgets (`REDUCE`/`BUILD`/`INST` wired to
dangerous `GLOBAL`/`STACK_GLOBAL` imports) across raw pickle, PyTorch zip, numpy
`.npy/.npz`, gzip/bz2/xz/zlib-compressed joblib, and HDF5/Keras Lambda
heuristics; validates `.safetensors` as code-free. Bounded against zip/decompress
bombs. A binary artifact file skips the UTF-8 text stages. Rules `BWK-ART-*`;
`BWK-ART-PICKLE-RCE` is a hard-veto BLOCK. Lives in `src/` (pure stdlib, zero
`admin`/`src` coupling) so it is shared by BOTH the admin SkillSpector pipeline
and the proxy's opt-in output-path `ArtifactOutputScanner`
(`src/scanners/output/artifact_scanner.py`) without `src` ever importing `admin`.


**MCP Tool Poisoning** (`admin/services/mcp_poisoning.py`):
| Rule | Severity | Description |
|------|----------|-------------|
| BWK-MCP-TP1 | high/critical | Hidden instructions (HTML comments, zero-width chars, base64, Unicode Tags encoding) |
| BWK-MCP-TP2 | high | Unicode deception (RTL overrides, homoglyphs, mixed-script identifiers) |
| BWK-MCP-TP3 | medium/high | Parameter description injection (system prompt overrides, token injection) |
| BWK-MCP-TP4 | medium | Description-behavior mismatch (deceptive naming vs actual capabilities) |

**MCP Least Privilege** (`admin/services/mcp_privilege.py`):
| Rule | Severity | Description |
|------|----------|-------------|
| BWK-MCP-LP1 | high | Underdeclared capability — code uses capabilities not in permissions |
| BWK-MCP-LP2 | medium | Wildcard permission — overly broad access declaration |
| BWK-MCP-LP3 | medium | Missing permissions — no declaration but code has capabilities |
| BWK-MCP-LP4 | low | Overdeclared permission — declared but unused (suspicious) |

**Bulwark Overlay** (28 rules, `BWK-TP-*` through `BWK-PV-*`):
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
- Block threshold: >= 7.0 (configurable: `BULWARK_SKILLSPECTOR_BLOCK_THRESHOLD`)
- Warn threshold: >= 4.0 (configurable: `BULWARK_SKILLSPECTOR_WARN_THRESHOLD`)

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
  backend_url: ${BULWARK_BACKEND_URL:-http://ollama:11434}
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

Redis is used for 6 purposes (optional — falls back to in-memory if unavailable):
1. **Rate limiting** — distributed sliding window counters per tenant
2. **Pattern sync** — admin publishes pattern changes, proxy picks them up via version tracking
3. **Global metrics** — `bulwark:global:{requests_total,block,allow,warn}` survive pod restarts
4. **SIEM stats** — `bulwark:siem:{batches_sent,events_exported,export_errors,...}`
5. **Recent blocks** — last N blocked requests for admin dashboard
6. **Correlation state** — decayed per-origin risk scores + runtime-tunable correlation config + Prometheus counters (opt-in)

Redis keys:
```
bulwark:global:requests_total    # Total proxy requests
bulwark:global:block             # Total blocked
bulwark:global:allow             # Total allowed
bulwark:global:warn              # Total warned
bulwark:siem:batches_sent        # SIEM export stats
bulwark:siem:events_exported
bulwark:siem:export_errors
bulwark:siem:transports
bulwark:siem:queue_memory_depth
bulwark:siem:updated_at
bulwark:guardrails:disabled      # SET of disabled pattern IDs
bulwark:guardrails:custom        # HASH { id: JSON(pattern) }
bulwark:guardrails:version       # INT (incremented on change)
bulwark:rate_limit:{tenant}      # Sorted set (sliding window)
bulwark:recent_blocks            # List (last N blocked requests)
bulwark:risk:{scope}:{digest}    # HASH {score, ts} — decayed origin risk (scope: tenant|session|input)
bulwark:correlation:config       # HASH — runtime-tunable correlation overrides (throttled re-read)
bulwark:correlation:counters     # HASH — replica-safe HINCRBY correlation metrics (incidents_*, origin_risk_*, tap_*, eval_lat_* inline-evaluation latency histogram)
```

TLS supported via `rediss://` URL scheme. External Redis (Azure/AWS/GCP) fully supported.

---

## 6. Configuration (src/config.py)

All settings via `BULWARK_` env prefix (Pydantic BaseSettings, 162 lines):

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `BULWARK_HOST` | str | `0.0.0.0` | Bind address |
| `BULWARK_PORT` | int | `8080` | Proxy listen port |
| `BULWARK_WORKERS` | int | `4` | Uvicorn workers |
| `BULWARK_DEBUG` | bool | `false` | Debug mode (enables /docs) |
| `BULWARK_MODE` | str | `proxy` | `proxy` or `sidecar` |
| `BULWARK_JWT_SECRET` | str | required | JWT signing key (32+ chars) |
| `BULWARK_JWT_ALGORITHM` | str | `HS256` | JWT algorithm |
| `BULWARK_JWT_AUDIENCE` | str | `bulwark-proxy` | JWT audience |
| `BULWARK_JWT_ISSUER` | str | `bulwark-gateway` | JWT issuer |
| `BULWARK_API_KEYS_ENABLED` | bool | `true` | Enable API key auth |
| `BULWARK_API_KEYS` | str | `""` | Comma-separated valid API keys |
| `BULWARK_BACKEND_URL` | str | `http://localhost:11434` | Default LLM backend |
| `BULWARK_BACKEND_TIMEOUT` | float | `120.0` | Backend timeout (seconds) |
| `BULWARK_POLICIES_DIR` | Path | `config/policies` | Policy YAML directory |
| `BULWARK_AGENTS_CONFIG` | Path | `config/agents.yaml` | Agent registry path |
| `BULWARK_IOC_PATH` | Path | `config/iocs.json` | IOC database path |
| `BULWARK_URLHAUS_KEY` | str | `""` | URLhaus feed API key |
| `BULWARK_THREATFOX_KEY` | str | `""` | ThreatFox feed API key |
| `BULWARK_OTX_KEY` | str | `""` | AlienVault OTX API key |
| `BULWARK_ABUSEIPDB_KEY` | str | `""` | AbuseIPDB API key |
| `BULWARK_RATE_LIMIT_ENABLED` | bool | `true` | Enable rate limiting |
| `BULWARK_RATE_LIMIT_RPM` | int | `60` | Requests/min/tenant |
| `BULWARK_RATE_LIMIT_RPM_BURST` | int | `10` | Burst allowance |
| `BULWARK_REDIS_URL` | str\|None | `None` | Redis URL (`redis://` or `rediss://`) |
| `BULWARK_REDIS_PASSWORD` | str\|None | `None` | Redis password |
| `BULWARK_REDIS_TLS_INSECURE` | bool | `false` | Skip TLS cert verification |
| `BULWARK_LOG_FORMAT` | str | `json` | `json` or `console` |
| `BULWARK_LOG_LEVEL` | str | `INFO` | Python log level |
| `BULWARK_FAIL_MODE` | str | `closed` | `closed` (block on error) or `open` |
| `BULWARK_CORS_ORIGINS` | List | `[]` | Allowed CORS origins |
| `BULWARK_REDACT_EMAIL` | bool | `false` | Opt-in: redact emails in LLM output (`[REDACTED:EMAIL]`) |
| `BULWARK_REDACT_PHONE` | bool | `false` | Opt-in: redact phone numbers in LLM output (`[REDACTED:PHONE]`) |
| `BULWARK_WEBHOOK_ALERT_URLS` | str | `""` | Webhook URLs for alerts |
| `BULWARK_ML_ENABLED` | bool | `false` | Master switch for ML scanners (injection/toxicity). Requires provisioned ONNX models + `ml` extra |
| `BULWARK_ML_BLOCKING` | bool | `false` | When on, ML scanner verdicts BLOCK; otherwise WARN/async-only |
| `BULWARK_MULTILINGUAL_ENABLED` | bool | `false` | Master switch for language detector + 10-language attack patterns |
| `BULWARK_RAG_ENABLED` | bool | `false` | Master switch for RAG retrieval scanner + memory guard |
| `BULWARK_SCHEMA_VALIDATION_ENABLED` | bool | `false` | Opt-in: wire the model-free `SchemaValidator` (BETA) into the output pipeline |
| `BULWARK_RELEVANCE_SCANNING_ENABLED` | bool | `false` | Opt-in: register the `RelevanceScanner` (BETA, OUTPUT_ASYNC). Requires `sentence-embeddings` model (`download-models.py --embeddings`) |
| `BULWARK_HALLUCINATION_SCANNING_ENABLED` | bool | `false` | Opt-in: register the `HallucinationScanner` (BETA, OUTPUT_ASYNC). Requires `nli-classifier` model (`download-models.py --nli`) |
| `BULWARK_GROUNDING_SCANNING_ENABLED` | bool | `false` | Opt-in: register the `GroundingScanner` (BETA, OUTPUT_ASYNC). Shares the `nli-classifier` model |
| `BULWARK_VISION_SCANNING_ENABLED` | bool | `false` | Opt-in: register the `VisionScanner` (INPUT_ASYNC). Zero-dep deterministic image-hygiene guards ship active; OCR layer stays inert/EXPERIMENTAL without pillow + an OCR backend |
| `BULWARK_ARTIFACT_OUTPUT_SCANNING_ENABLED` | bool | `false` | Opt-in: register the `ArtifactOutputScanner` (OUTPUT_ASYNC, BETA, **detective**). Decodes inline base64/`data:` URIs in LLM output and runs the shared stdlib pickle-opcode engine (never deserializes) to WARN on serialized-artifact RCE gadgets (OWASP LLM02). Never blocks/rewrites the response; zero deps |
| `BULWARK_CORRELATION_ENABLED` | bool | `false` | Master switch for the inline correlation engine (starts event tap at boot) |
| `BULWARK_CORRELATION_BLOCKING` | bool | `false` | When on, correlated exfiltration / origin-risk decisions BLOCK; otherwise WARN. Runtime-tunable |
| `BULWARK_CORRELATION_RISK_BLOCK_THRESHOLD` | float | `7.0` | Origin risk score (0–10) at/above which requests are hardened to BLOCK. Runtime-tunable |
| `BULWARK_CORRELATION_RISK_WARN_THRESHOLD` | float | `4.0` | Origin risk score at/above which requests are flagged WARN. Runtime-tunable |
| `BULWARK_CORRELATION_RISK_DECAY_SECONDS` | float | `900.0` | Half-life for decaying accumulated origin risk. Runtime-tunable |
| `BULWARK_CORRELATION_WINDOW_SECONDS` | float | `30.0` | **Latent/reserved — not currently enforced.** Same-request input↔output pairing needs no time window; retained (accepted, bounded) for a future cross-request/async correlator. Wiring it to the backend round-trip would false-negative on slow LLM responses. Admin UI shows it read-only |
| `BULWARK_CORRELATION_CONFIDENCE_BLOCK_THRESHOLD` | float | `0.5` | Min content-corroboration confidence (0–1) to escalate a correlated exfiltration incident from WARN to BLOCK (only when blocking is on). Runtime-tunable |
| `BULWARK_METRICS_SCRAPE_TOKEN` | str | `""` | **Admin-side** (read via `read_secret`, `*_FILE` supported). Dedicated least-privilege bearer that gates `GET /admin/health/metrics` for Prometheus (`hmac.compare_digest`). Empty ⇒ scrape-token path inert, endpoint requires `admin:read` JWT |

### Docker Secrets Support

For Kubernetes, secrets are mounted as files:
```
BULWARK_JWT_SECRET_FILE=/run/secrets/jwt-secret
BULWARK_REDIS_PASSWORD_FILE=/run/secrets/redis-password
BULWARK_API_KEYS_FILE=/run/secrets/api-keys
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

# Run full test suite (~1,300 tests)
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
docker build -t bulwark-gateway-proxy:1.0.0 -f Dockerfile .
docker build -t bulwark-gateway-admin:1.0.0 -f docker/Dockerfile.admin .

# Run full stack locally (proxy + admin + redis)
docker-compose up -d

# Run with monitoring (adds prometheus + grafana)
docker-compose --profile monitoring up -d

# Run everything (adds grafana)
docker-compose --profile full up -d

# ─── Kubernetes (Helm — recommended) ─────────────────────────────────────────

# Deploy with internal Redis
helm install bulwark ./helm/bulwark-gateway \
  --set backend.ip=<LLM_BACKEND_IP> \
  --namespace bulwark-gateway --create-namespace

# Deploy with external Redis (e.g., Azure Cache)
helm install bulwark ./helm/bulwark-gateway \
  --set backend.ip=<LLM_BACKEND_IP> \
  --set redis.enabled=false \
  --set externalRedis.host=my-redis.cache.windows.net \
  --set externalRedis.port=6380 \
  --set externalRedis.tls=true \
  --set externalRedis.password=<PASSWORD>

# Upgrade existing deployment
helm upgrade bulwark ./helm/bulwark-gateway \
  --set proxy.image.tag=1.0.0 \
  --set admin.image.tag=1.0.0

# Run post-deploy Helm tests
helm test bulwark -n bulwark-gateway

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
| GET | `/admin/health/metrics` | Scrape token OR `admin:read` | Prometheus exposition (global counters + `bulwark_correlation_*` counters + the `bulwark_correlation_eval_duration_seconds` inline-evaluation latency histogram). Accepts a dedicated least-privilege bearer (`BULWARK_METRICS_SCRAPE_TOKEN`, `hmac.compare_digest`) so Prometheus scrapes without a session; inert/JWT-only when the token is empty |
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
| GET | `/admin/plugins/` | Session | List installed plugins |
| GET | `/admin/plugins/{name}` | Session | Get plugin specification |
| POST | `/admin/plugins/install` | Session | Install plugin from source |
| POST | `/admin/plugins/uninstall` | Session | Uninstall plugin |
| POST | `/admin/plugins/{name}/enable` | Session | Enable plugin |
| POST | `/admin/plugins/{name}/disable` | Session | Disable plugin |
| POST | `/admin/plugins/scaffold` | Session | Create plugin template |
| POST | `/admin/plugins/{name}/security-check` | Session | Run security audit |
| GET | `/admin/evaluation/status` | Session | Evaluation framework status |
| POST | `/admin/evaluation/run` | Session | Run adversarial evaluation |
| POST | `/admin/evaluation/run/quick` | Session | Quick scan (5 per category) |
| GET | `/admin/evaluation/attacks/preview` | Session | Preview attack payloads |
| GET | `/admin/evaluation/datasets/benign` | Session | Standard benign dataset |
| POST | `/admin/evaluation/report` | Session | Generate formatted report |
| GET | `/admin/discovery/status` | Session | Discovery capabilities |
| POST | `/admin/discovery/scan/network` | Session | Scan network for LLM agents |
| POST | `/admin/discovery/scan/kubernetes` | Session | Scan K8s namespace |
| GET | `/admin/discovery/shadow-ai/endpoints` | Session | AI endpoint blocklist |
| POST | `/admin/discovery/shadow-ai/analyze` | Session | Analyze traffic for shadow AI (opt-in `notify` flag dispatches advisory `warn` alerts to notification channels) |
| POST | `/admin/discovery/shadow-ai/classify` | Session | Classify hostname |
| GET | `/admin/discovery/mcp/status` | Session | MCP inventory status |
| POST | `/admin/discovery/mcp/assess-risk` | Session | Assess MCP tool risk |
| POST | `/admin/discovery/mcp/suggest-policy` | Session | Derive a deny-by-default starter AgentPolicy (loadable YAML) from enumerated MCP tools |
| POST | `/admin/discovery/mcp/enumerate` | Session | Enumerate MCP server tools |
| GET | `/admin/correlation/status` | Session | Correlation engine status (enabled/blocking, effective config, Redis health) |
| GET | `/admin/correlation/config/fields` | Session | Tunable field metadata (defaults + numeric bounds) |
| GET | `/admin/correlation/origins` | Session | Active origins with decayed risk score, scope, digest, TTL |
| PUT | `/admin/correlation/config` | Session | Set runtime overrides (blocking/thresholds/decay/window/bumps) — `correlation:write` |
| DELETE | `/admin/correlation/config` | Session | Clear all runtime overrides (revert to env defaults) — `correlation:write` |
| DELETE | `/admin/correlation/origin/{scope_type}/{digest}` | Session | Clear one origin's accrued risk — `correlation:write` |
| POST | `/admin/correlation/reset` | Session | Clear all accrued origin risk — `correlation:write` |
| GET | `/admin/investigation/cases` | Session | List investigation cases (filter/search/sort/page) — `investigation:read` |
| GET | `/admin/investigation/cases/stats` | Session | Case counts by status/severity (+ optional "my work") — `investigation:read` |
| GET | `/admin/investigation/cases/analytics` | Session | MTTR, opened-vs-resolved trend, top recurring origins — `investigation:read` |
| GET | `/admin/investigation/cases/templates` | Session | List case templates (blueprints) — `investigation:read` |
| POST | `/admin/investigation/cases` | Session | Create a case (optional `template_id` seeds severity/summary/tags/tasks) — `investigation:write` |
| GET | `/admin/investigation/cases/{id}` | Session | Full case detail (metadata, subjects, notes) — `investigation:read` |
| GET | `/admin/investigation/cases/{id}/timeline` | Session | Reconstructed chronological timeline — `investigation:read` |
| GET | `/admin/investigation/cases/{id}/export` | Session | Download case: `format`=`json`\|`md`\|`stix`\|`thehive`\|`iris` — `investigation:read` |
| GET | `/admin/investigation/cases/{id}/related` | Session | Cross-case correlation (shared subjects) — `investigation:read` |
| POST | `/admin/investigation/cases/{id}/state` | Session | Set status/severity/assignee — `investigation:write` |
| POST | `/admin/investigation/cases/{id}/note` | Session | Append a note — `investigation:write` |
| POST/DELETE | `/admin/investigation/cases/{id}/subject` | Session | Link/unlink a triage subject — `investigation:write` |
| POST | `/admin/investigation/cases/{id}/tags` | Session | Replace case tag (TTP/label) list — `investigation:write` |
| POST | `/admin/investigation/cases/{id}/timeline` | Session | Add a manual timeline entry — `investigation:write` |
| GET | `/admin/investigation/cases/{id}/observables` | Session | List observables (atomic indicators) — `investigation:read` |
| POST | `/admin/investigation/cases/{id}/observables` | Session | Add an observable (idempotent per type+value) — `investigation:write` |
| DELETE | `/admin/investigation/cases/{id}/observables/{obs}` | Session | Remove an observable — `investigation:write` |
| POST | `/admin/investigation/cases/{id}/observables/{obs}/promote-ioc` | Session | Promote ip/domain/url/hash to the IOC database — `investigation:write` |
| POST | `/admin/investigation/cases/{id}/observables/{obs}/enrich` | Session | Enrich an observable via a Cortex integration's analyzers (folds worst-level verdict into `enrichment['cortex']`, flags `is_ioc` on malicious; a malicious verdict auto-raises origin-risk on every `origin` subject linked to the case — best-effort/fail-open, returns `origin_risk.raised`; fail-open 502) — `investigation:write` |
| POST | `/admin/investigation/cases/{id}/observables/{obs}/respond` | Session | Run a Cortex **responder** (response action) against an observable; records the outcome under `enrichment['cortex_responder']` (never flags `is_ioc` — an action, not a verdict; fail-open 502) — `investigation:write` |
| POST | `/admin/investigation/cases/{id}/observables/{obs}/lookup` | Session | Look up an observable against an **OpenCTI** integration's indicator graph (GraphQL); folds the worst-level active (non-revoked) indicator into `enrichment['opencti']` with a `not_found`/`clean`/`suspicious`/`malicious` verdict, flags `is_ioc` + auto-raises origin-risk on `malicious` (same fail-open path as enrich; fail-open 502) — `investigation:write` |
| GET | `/admin/investigation/cases/{id}/tasks` | Session | List checklist tasks + progress roll-up — `investigation:read` |
| POST | `/admin/investigation/cases/{id}/tasks` | Session | Add a checklist task — `investigation:write` |
| POST | `/admin/investigation/cases/{id}/tasks/{task}/state` | Session | Set task status/assignee/due — `investigation:write` |
| POST | `/admin/investigation/cases/{id}/tasks/{task}/note` | Session | Append a note to a task — `investigation:write` |
| DELETE | `/admin/investigation/cases/{id}/tasks/{task}` | Session | Delete a task — `investigation:write` |
| GET | `/admin/integrations` | Session | List outbound connectors (secrets masked) — `integrations:read` |
| GET | `/admin/integrations/status` | Session | Registry status + `can_write` flag — `integrations:read` |
| GET | `/admin/integrations/{id}` | Session | Get one connector config (secret masked) — `integrations:read` |
| POST | `/admin/integrations` | Session | Create connector (`thehive`\|`dfir_iris`\|`cortex`) — `integrations:write` |
| PUT | `/admin/integrations/{id}` | Session | Update connector config — `integrations:write` |
| DELETE | `/admin/integrations/{id}` | Session | Delete connector — `integrations:write` |
| POST | `/admin/integrations/{id}/toggle` | Session | Enable/disable connector — `integrations:write` |
| POST | `/admin/integrations/{id}/test` | Session | Live `test_connection` probe — `integrations:write` |
| GET | `/admin/integrations/{id}/health` | Session | Cached health (TTL 30s) — `integrations:read` |
| GET | `/admin/integrations/{id}/analyzers` | Session | List a Cortex integration's analyzer catalog (cortex-only; fail-open 502) — `integrations:read` |
| GET | `/admin/integrations/{id}/responders` | Session | List a Cortex integration's responder catalog (cortex-only; fail-open 502) — `integrations:read` |
| POST | `/admin/integrations/reload` | Session | Reload connector registry from disk — `integrations:write` |
| POST | `/admin/integrations/push/case/{case_id}` | Session | Idempotent push of a case to TheHive/IRIS (create-or-update via link store; fail-open) — `integrations:write` |
| GET | `/admin/integrations/push/case/{case_id}/links` | Session | List remote links (remote_id/url/last_synced_at) for a case — `integrations:read` |
| GET | `/admin/integrations/webhooks` | Session | List event-webhook subscriptions (SOAR trigger seed) + available event types — `integrations:read` |
| GET | `/admin/integrations/webhooks/events` | Session | List lifecycle event types a subscription can filter on — `integrations:read` |
| POST | `/admin/integrations/webhooks` | Session | Create an event-webhook subscription (name/url/events) — `integrations:write` |
| PUT | `/admin/integrations/webhooks/{id}` | Session | Update a subscription — `integrations:write` |
| DELETE | `/admin/integrations/webhooks/{id}` | Session | Delete a subscription — `integrations:write` |
| POST | `/admin/integrations/webhooks/{id}/toggle` | Session | Enable/disable a subscription — `integrations:write` |
| POST | `/admin/integrations/webhooks/{id}/test` | Session | Send a synthetic `test.ping` (ignores filters/enabled) — `integrations:write` |
| POST | `/admin/integrations/webhooks/reload` | Session | Reload subscriptions from disk — `integrations:write` |

Event webhooks fire a stable JSON envelope (`event`/`event_id`/`timestamp`/`tenant`/`data`) to
admin-configured HTTP endpoints on case **lifecycle** transitions — `case.opened`,
`case.severity_raised` (escalation only), `case.resolved` (transition into resolved only). Fan-out is
best-effort and **fail-open**: an empty subscription list costs nothing, deliveries run concurrently
under a short timeout, and a slow/dead endpoint never delays or breaks case management. HMAC signing
and the inbound action API are deferred to Phase 3.

### Authentication

- **JWT**: `Authorization: Bearer <token>` — token must have `sub`, `aud=bulwark-proxy`
- **API Key**: `Authorization: Bearer <api-key>` — matched against `BULWARK_API_KEYS` list
- **Tenant/Agent**: `X-Tenant-ID` and `X-Agent-ID` headers (required for proxy)
- **Admin session**: HTTP-only cookie set by `/admin/auth/login`
- **Admin roles**: admin, security, auditor, viewer (RBAC enforced)
- **Correlation RBAC**: `correlation:read` (status/origins/config view) and `correlation:write` (tuning/reset) — dedicated permission namespace, not reused from `sessions:*`
- **Investigation RBAC**: `investigation:read` (case/observable/task/timeline view + export) and `investigation:write` (create/mutate/promote-ioc) — admin + security hold both; auditor/viewer are read-only. All cases are tenant-scoped (cross-tenant id ⇒ 404, no existence leak)
- **Integrations RBAC**: `integrations:read` (list/status/health/links view) and `integrations:write` (create/update/delete/toggle/test/reload/push) — admin + security hold both; auditor/viewer are read-only. Connector secrets are masked on read; push is idempotent (link store) and fail-open (never mutates the local case)

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

- Environment variables prefixed with `BULWARK_`
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
- Current: ~1,300 tests, all passing
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
| `admin/services/skill_scanner.py` | SkillSpector hybrid engine (5-stage pipeline; default ~77 text patterns / 4 active stages + binary-artifact stage, stage 1 optional) |
| `src/scanners/artifacts/model_artifact_scanner.py` | Binary model-artifact opcode scanner (stdlib pickletools, never deserializes; BWK-ART-*) |
| `admin/services/mcp_poisoning.py` | MCP tool poisoning detection (20 patterns) |
| `admin/services/mcp_privilege.py` | MCP least privilege analysis (29 patterns) |
| `helm/bulwark-gateway/templates/secrets.yaml` | Secret generation |
| `helm/bulwark-gateway/templates/network-policies.yaml` | Network isolation |

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
bulwark:global:requests_total  — total proxy requests
bulwark:global:block           — total blocked
bulwark:global:allow           — total allowed
bulwark:global:warn            — total warned
```

### SIEM Integration

Events exported in ECS (Elastic Common Schema) format:
- File (ndjson) → Wazuh/Filebeat/Fluentd
- HTTP/REST → Splunk HEC, Elastic, Datadog
- Syslog (RFC 5424) → QRadar, ArcSight
- TCP+TLS → Custom collectors

Exporter features: batch flush (100 events or 1s), circuit breaker, exponential backoff retry.

### Compliance Mapping (`bulwark.compliance.*`)

Every exported event carries declarative regulatory/standards references derived
from its `ThreatCategory`, so a SIEM can pivot a detection to a framework without
its own lookup table. The single source of truth is `src/telemetry/compliance.py`
(a pure, side-effect-free table; a unit test enforces that **every** ThreatCategory
has a non-empty mapping). The admin UI's threat-intel reference badges (events
viewer) fetch this same table via `GET /admin/events/compliance-mappings` instead
of keeping their own copy, and the `/v2/scan` API derives its MITRE ATT&CK tag from
it too — so no surface re-hardcodes the mapping. Emitted under `bulwark.compliance`
in ECS, and summarised in the CEF (`cs6Label=Compliance`) and LEEF (`owaspLlm` /
`mitreAtlas` / `mitreAttack` / `euAiAct`) converters:

| Field | Framework | Example |
|-------|-----------|---------|
| `owasp_llm` (+ `owasp_llm_version`) | OWASP Top 10 for LLM Apps (**2025**) | `["LLM01"]` |
| `mitre_atlas` | MITRE ATLAS AI-specific techniques | `["AML.T0051"]` |
| `mitre_attack` | MITRE ATT&CK techniques | `["T1041"]` |
| `nist_ai_rmf` | NIST AI RMF (AI 100-1) subcategories | `["MEASURE-2.7","MANAGE-4.1"]` |
| `eu_ai_act` | EU AI Act (Reg. 2024/1689) articles | `["Article 15"]` |

`REFERENCE_CATALOG` in the same module gives every OWASP/ATLAS/ATT&CK code its
human label + canonical URL (a unit test enforces that no mapping references a code
absent from the catalog). OWASP codes use the **2025** revision — notably the
former *LLM10 Model Theft* is folded into **LLM10 Unbounded Consumption**, *Insecure
Output Handling* became **LLM05 Improper Output Handling**, and *Sensitive
Information Disclosure* moved to **LLM02**; `owasp_llm_version` records the revision
on every event.

Mappings are intentionally conservative (each ref is auditor-defensible, not an
exhaustive spray). Empty axes are dropped from the export; unmapped/ad-hoc category
strings emit no compliance block at all (no fabricated tags). Anchors: Art. 15
(cybersecurity/robustness) for adversarial threats, Art. 10 (data governance) for
poisoning/PII, Art. 14 (human oversight) for agency/tool abuse, Art. 9 (risk mgmt)
for policy; MEASURE-2.7 (security & resilience) + MANAGE-4.1 (post-deployment
monitoring) recur because Bulwark is itself a runtime monitor.

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
| Proxy | 1.0.0 | `bulwark-gateway-proxy:1.0.0` |
| Admin | 1.0.0 | `bulwark-gateway-admin:1.0.0` |
| SkillSpector Engine | 2.1.0-bulwark | — |
| Helm Chart | 1.0.0 | — |
| Kustomize | 1.0.0 | — |

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

Both Dockerfiles use multi-stage builds with a Google Distroless runtime:

```
Builder stage:  python:3.13-slim-trixie (digest-pinned) → install dependencies
Runtime stage:  gcr.io/distroless/python3-debian13:nonroot (digest-pinned)
                → copy only installed packages + source

Hardening:
- Distroless runtime: NO shell (no /bin/sh), no package manager, no
  coreutils — only the Python 3.13 interpreter + its stdlib
- Non-root user: distroless `nonroot` (UID/GID 65532)
- Read-only filesystem (tmpfs for /tmp)
- No pip/setuptools in runtime image
- CAP_DROP ALL
- No new privileges
```

**Distroless implications** (important for anyone editing deploy manifests):
- The proxy entrypoint is `docker/proxy_launcher.py` (derives `BULWARK_WORKERS`
  then `os.execv`'s uvicorn) — there is no shell wrapper. The admin image uses an
  exec-form uvicorn ENTRYPOINT.
- **initContainers that run on the app image MUST use `python3`, not `sh`** —
  `init-policies` / `init-models` use `python3 -c` (shutil.copy2 / hashlib).
  initContainers on other images (e.g. `wait-postgresql` on the postgres image,
  Filebeat sidecar) may still use `sh`.
- The admin image encrypts `users.db` with SQLCipher via the self-contained
  `sqlcipher3-binary` wheel (no native `.so` to copy into distroless).
- **UID migration (999 → 65532)**: releases before the distroless migration ran
  as UID 999. Existing PVCs are re-owned automatically on Kubernetes via
  `fsGroup: 65532` + `fsGroupChangePolicy: Always`. For Docker Compose, `chown`
  the volumes manually — see `docs/DEPLOYMENT.md` → "Upgrading (Distroless UID
  Migration)".
- Base images are pinned by SHA256 digest per the secure-coding standards.
  Current OS-package CVE posture: 0 Python-library CVEs; residual CVEs are
  base-OS only and unpatchable without a distroless base refresh.

---

## 15. Troubleshooting Quick Reference

| Issue | Fix |
|-------|-----|
| Pod CrashLoopBackOff | Check `BULWARK_JWT_SECRET` is 32+ chars: `kubectl logs deploy/proxy` |
| Redis connection refused | Verify `BULWARK_REDIS_URL` and password file mount |
| 403 on all requests | Check API key or JWT in Authorization header + X-Tenant-ID + X-Agent-ID |
| 401 Unauthorized | API key not in `BULWARK_API_KEYS` list, or JWT expired/invalid |
| Policies not loading | Verify `config/policies/` mount, file permissions, YAML syntax |
| High latency (>100ms) | Notifications are async; check Redis connectivity |
| SIEM not exporting | Verify `BULWARK_TELEMETRY_ENABLED=true` and transport config |
| Admin readiness probe failing | Transient: liveness probe kills pod on overload; check memory limits |
| Guardrail false positive | Test pattern with `pytest -k test_input_guardrail -v`; disable via admin UI |
| Rate limit too aggressive | Increase `BULWARK_RATE_LIMIT_RPM` (default: 60) |
| Backend 502/504 | Check `BULWARK_BACKEND_URL`, backend health, and timeout settings |

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
| **Secure coding rules** | **`.opencode/SECURE-CODING-STANDARDS.md`** (MANDATORY before writing ANY code) |
| System design | `docs/ARCHITECTURE.md` |
| Deploy to K8s | `docs/DEPLOYMENT.md` |
| Configure Redis | `docs/DEPLOYMENT.md` → Redis Configuration |
| Set up CI/CD | `docs/CICD.md` |
| Day-to-day ops | `docs/OPERATIONS.md` |
| Fix issues | `docs/TROUBLESHOOTING.md` |
| Configure alerts | `docs/NOTIFICATIONS.md` |
| API details | `docs/API-REFERENCE.md` |
| Validate pipeline e2e (K8s) | `docs/E2E-VALIDATION.md` |
| Security posture | `docs/SECURITY-HARDENING.md` |
| Accepted limitations / known gaps | `docs/LIMITATIONS.md` |
| All docs (index) | `docs/INDEX.md` |
