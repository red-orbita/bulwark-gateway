# Sentinel Gateway — Full Project Context

## Overview

**Sentinel Gateway** is a security guardrail proxy for AI agents deployed in cloud environments. It sits between users and LLM/agent backends, intercepting requests and responses to enforce security policies at the tool-call level.

**Key differentiator**: Unlike text-level guardrails (Lakera, Azure AI Content Safety), Sentinel Gateway operates at the **tool call layer** — inspecting and enforcing RBAC on individual tool invocations (run_command, read_file, etc.), not just text content.

## Threat Model

The **user is potentially adversarial**. This is the inverse of opencode-security-agent (where the user is trusted and the LLM is the threat). Here we protect the system/infrastructure from malicious users attempting to abuse AI agents.

| Threat | Vector | Mitigation |
|--------|--------|-----------|
| Prompt injection | User overrides system prompt | Input guardrail pattern matching |
| Jailbreak | DAN, roleplay, chat template injection | Input guardrail + severity blocking |
| Tool abuse | User tricks agent into running commands | Tool policy RBAC engine |
| Data exfiltration | Agent leaks secrets via tools/responses | Output filter + IOC blocking |
| Credential theft | User requests sensitive file reads | Tool policy denied_arguments |
| Reverse shell | Agent executes shell payloads | Input guardrail + tool policy |
| Brute-force | Repeated jailbreak attempts | Rate limiting per tenant |

## Architecture

```
User Request
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  SENTINEL GATEWAY (FastAPI, port 8080)              │
│                                                     │
│  ┌─────────┐  ┌──────────┐  ┌─────────────┐       │
│  │  Auth   │→ │  Rate    │→ │   Input     │       │
│  │ (JWT/   │  │  Limit   │  │  Guardrail  │       │
│  │  API Key)│  │(per-tenant)│ │(PI/jailbreak)│      │
│  └─────────┘  └──────────┘  └─────────────┘       │
│                                     │               │
│                                     ▼               │
│                              ┌─────────────┐       │
│                              │  IOC Check  │       │
│                              │(domain/IP)  │       │
│                              └─────────────┘       │
│                                     │               │
│                                     ▼               │
│                           ┌──── BACKEND ────┐      │
│                           │  (upstream LLM) │      │
│                           └─────────────────┘      │
│                                     │               │
│                                     ▼               │
│                              ┌─────────────┐       │
│                              │ Tool Policy │       │
│                              │   Engine    │       │
│                              │(RBAC/tenant)│       │
│                              └─────────────┘       │
│                                     │               │
│                                     ▼               │
│                              ┌─────────────┐       │
│                              │  Output     │       │
│                              │  Filter     │       │
│                              │(redact PII/ │       │
│                              │ secrets)    │       │
│                              └─────────────┘       │
│                                     │               │
└─────────────────────────────────────┼───────────────┘
                                      ▼
                               User Response
```

## Modes of Operation

### 1. Proxy Mode (default)
Drop-in replacement for OpenAI API. Client points to Sentinel Gateway instead of the LLM API directly.

```
Client → POST /v1/chat/completions → Sentinel → Backend LLM
```

### 2. Sidecar Mode
Agent framework calls Sentinel before executing each tool call.

```
Agent → POST /v1/tool/validate → Sentinel → {verdict: allow|block}
```

## Tech Stack

- **Language**: Python 3.11+
- **Framework**: FastAPI + Uvicorn
- **HTTP client**: httpx (async)
- **Auth**: python-jose (JWT) + API keys
- **Config**: pydantic-settings (env vars)
- **Logging**: structlog (JSON Lines for SIEM)
- **Rate limiting**: In-memory token bucket (Redis optional for distributed)
- **Container**: Docker + docker-compose
- **Testing**: pytest + pytest-asyncio

## File Structure

```
sentinel-gateway/
├── pyproject.toml                  # Project metadata, deps, scripts
├── Dockerfile                      # Production container
├── docker-compose.yaml             # Gateway + Redis
├── README.md                       # User documentation
├── config/
│   ├── policies/
│   │   └── example-acme.yaml      # Example tenant policy
│   └── iocs.json                  # IOC database
├── src/
│   ├── __init__.py
│   ├── main.py                    # FastAPI app, lifespan, create_app()
│   ├── config.py                  # Settings (env: SENTINEL_*)
│   ├── models.py                  # Pydantic models: Verdict, SecurityEvent, ToolCall, etc.
│   ├── guardrails/
│   │   ├── input_guardrail.py     # Prompt injection/jailbreak/tool abuse detection
│   │   ├── output_filter.py       # Secret/PII/internal path redaction
│   │   └── tool_policy.py         # RBAC engine: AgentPolicy, ToolPolicy, ToolPolicyEngine
│   ├── ioc/
│   │   └── manager.py            # IOC database: load, check domain/IP/URL/content
│   ├── policies/
│   │   └── loader.py             # YAML policy loader → ToolPolicyEngine
│   ├── middleware/
│   │   ├── auth.py               # JWT/API key validation middleware
│   │   └── rate_limit.py         # Token bucket rate limiter
│   ├── filters/
│   │   └── __init__.py           # (placeholder for custom filters)
│   └── routes/
│       ├── health.py             # GET /health, GET /ready
│       ├── proxy.py              # POST /v1/chat/completions, POST /v1/tool/validate
│       └── admin.py              # POST /admin/policies/reload, GET /admin/policies
└── tests/
    ├── test_input_guardrail.py   # 17 tests: injection, jailbreak, tool abuse, social eng
    ├── test_output_filter.py     # 8 tests: secrets, PII redaction
    ├── test_tool_policy.py       # 10 tests: RBAC, rate limit, batch eval
    └── test_ioc.py               # 9 tests: domain, IP, URL, content matching
```

## Core Components

### Input Guardrail (`src/guardrails/input_guardrail.py`)
Pattern-based detection engine. Categorized patterns:
- **INJECTION_PATTERNS**: "ignore previous instructions", system prompt override, chat template tags, instruction bypass
- **TOOL_ABUSE_PATTERNS**: curl|bash, reverse shells, credential reads, exfil to known services, encoded payloads
- **SOCIAL_ENGINEERING_PATTERNS**: urgency manipulation, authority claims

Severity levels: `low` → WARN, `medium` → WARN, `high` → BLOCK, `critical` → BLOCK

### Tool Policy Engine (`src/guardrails/tool_policy.py`)
RBAC enforcement per tenant/agent:
- **AgentPolicy**: defines allowed_tools, denied_tools, permissions (command execution, file write, network), sandbox_level
- **ToolPolicy**: per-tool constraints (denied_arguments, argument_patterns as regex allowlists, max calls)
- **Default policy**: if no explicit policy configured, blocks dangerous tools (run_command, write_file, delete_file, bash, shell)

### Output Filter (`src/guardrails/output_filter.py`)
Regex-based redaction:
- Secrets: AWS keys, Stripe, GitHub tokens, DB URLs, private keys, JWT secrets
- PII: credit cards, SSN, phone numbers
- Internal: home paths, system files, internal IPs

### IOC Manager (`src/ioc/manager.py`)
Threat intel matching:
- Loads from JSON (compatible with opencode-security-agent format)
- Checks: exact domain, subdomain matching, IP, URL (with domain extraction)
- `check_content()`: scans free text for any IOC matches

### Proxy Route (`src/routes/proxy.py`)
Main request flow:
1. Parse OpenAI-compatible request
2. Input guardrail on all user messages
3. IOC check on all message content
4. Forward to backend
5. Intercept response tool_calls → tool policy evaluation
6. Output filter on response content
7. Return (with blocked tools removed or redacted content)

## Configuration

### Environment Variables (prefix: `SENTINEL_`)
- `SENTINEL_PORT` (8080)
- `SENTINEL_BACKEND_URL` (http://localhost:11434)
- `SENTINEL_JWT_SECRET`
- `SENTINEL_FAIL_MODE` (closed|open)
- `SENTINEL_RATE_LIMIT_RPM` (60)
- `SENTINEL_REDIS_URL` (optional)
- `SENTINEL_POLICIES_DIR` (config/policies)
- `SENTINEL_LOG_FORMAT` (json|console)

### Policy YAML Schema
```yaml
tenant: <string>
agents:
  - id: <string>
    sandbox_level: minimal|standard|strict
    allowed_tools: [<string>]        # empty = all allowed
    denied_tools: [<string>]
    allow_command_execution: bool
    allow_file_write: bool
    allow_network_access: bool
    max_tool_calls: int
    tool_policies:
      - name: <tool_name>
        max_calls: int
        denied_arguments:
          <arg_name>: [<substring_to_block>]
        required_arguments: [<arg_name>]
        argument_patterns:
          <arg_name>: <regex_allowlist>
```

## API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Liveness check |
| GET | `/ready` | Readiness (policies + IOCs loaded) |
| POST | `/v1/chat/completions` | Proxy mode: OpenAI-compatible with guardrails |
| POST | `/v1/tool/validate` | Sidecar mode: validate single tool call |
| POST | `/admin/policies/reload` | Hot-reload policies |
| GET | `/admin/policies` | List loaded policies |
| GET | `/admin/iocs/stats` | IOC database statistics |

## Security Verdicts

```python
class Verdict(str, Enum):
    ALLOW = "allow"    # Request passes all checks
    BLOCK = "block"    # Request denied (403)
    WARN = "warn"      # Logged but allowed
    REDACT = "redact"  # Content modified before returning
```

## Relationship to opencode-security-agent

| Aspect | opencode-security-agent | sentinel-gateway |
|--------|------------------------|-----------------|
| Trust model | User=trusted, LLM=untrusted | User=untrusted, system=protected |
| Fail mode | Open (never break IDE) | Closed (block on doubt) |
| Integration | TypeScript plugin hooks | HTTP proxy/sidecar |
| Deployment | Single user, local machine | Multi-tenant, cloud |
| Scope | Protect user from agent | Protect infrastructure from user |
| Detection engine | sentinel_preflight.py | input_guardrail.py (same patterns, adapted) |
| IOC source | Same format (iocs.json) | Compatible, can share feeds |

### What was reused:
- Pattern matching approach (regex-based, no LLM cost)
- IOC database format and concept
- Threat categories (prompt_injection, exfiltration, credential_access, etc.)
- Fail-fast design (30-80ms evaluation time)

### What is new:
- Multi-tenant RBAC (AgentPolicy per tenant/agent)
- Tool-call level enforcement (not just content inspection)
- Output redaction (secrets, PII)
- HTTP API (proxy + sidecar modes)
- Rate limiting per tenant
- Structured logging for SIEM

## Running Tests

```bash
source .venv/bin/activate
pytest -v                    # 44 tests, ~0.5s
ruff check src/ tests/      # Linting
mypy src/                   # Type checking
```

## Next Steps / Roadmap

1. **Redis rate limiting** — distributed token bucket for multi-instance
2. **Streaming support** — SSE proxy for streaming responses
3. **Webhook alerts** — notify on critical blocks (Slack, PagerDuty)
4. **Policy hot-reload via API** — POST policy YAML, no file system needed
5. **Metrics** — Prometheus /metrics endpoint (block rate, latency histograms)
6. **ML-based detection** — complement regex with lightweight classifier for novel jailbreaks
7. **Audit log storage** — persist SecurityEvents to DB for forensics
8. **Integration SDKs** — Python/JS client libraries for sidecar mode
9. **OpenTelemetry** — distributed tracing through the proxy
10. **OWASP LLM Top 10 coverage** — map all 10 risks to guardrail rules
