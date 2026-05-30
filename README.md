# Sentinel Gateway

Security guardrail proxy for AI agents in cloud environments.

Intercepts, validates, and enforces policies on tool calls between users and LLM agents. Designed for environments where **the user is potentially adversarial** — the opposite trust model of a local IDE plugin.

## Architecture

```
User Request → [Auth] → [Input Guardrail] → [IOC Check] → Backend LLM/Agent
                                                                    │
Agent Response ← [Output Filter] ← [Tool Policy] ←─────────────────┘
```

### Security Layers

| Layer | What it does | Fail mode |
|-------|-------------|-----------|
| **Input Guardrail** | Blocks prompt injection, jailbreaks, encoded payloads | BLOCK (fail-closed) |
| **IOC Check** | Matches domains/IPs/URLs against threat intel feeds | BLOCK |
| **Tool Policy Engine** | RBAC enforcement on tool calls per tenant/agent | BLOCK |
| **Output Filter** | Redacts secrets, PII, internal paths from responses | REDACT |
| **Rate Limiter** | Per-tenant request throttling | 429 |

## Quick Start

```bash
# Install
pip install -e .

# Run (default: proxy to localhost:11434)
SENTINEL_BACKEND_URL=https://api.openai.com sentinel-gateway

# Or with Docker
docker compose up
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SENTINEL_PORT` | `8080` | Listen port |
| `SENTINEL_BACKEND_URL` | `http://localhost:11434` | Upstream LLM API |
| `SENTINEL_JWT_SECRET` | — | JWT signing key |
| `SENTINEL_FAIL_MODE` | `closed` | `closed` (block on error) or `open` |
| `SENTINEL_RATE_LIMIT_RPM` | `60` | Requests per minute per tenant |
| `SENTINEL_REDIS_URL` | — | Redis for distributed rate limiting |
| `SENTINEL_POLICIES_DIR` | `config/policies` | Policy YAML directory |

### Policy Files

Define per-tenant, per-agent tool access policies:

```yaml
# config/policies/acme.yaml
tenant: acme-corp

agents:
  - id: support-bot
    sandbox_level: strict
    allowed_tools: [web_search, read_kb]
    denied_tools: [run_command, write_file]
    allow_command_execution: false
    max_tool_calls: 10
    tool_policies:
      - name: web_search
        denied_arguments:
          query: ["site:pastebin.com", "filetype:env"]
```

## API Endpoints

### Proxy Mode (OpenAI-compatible)

```bash
# Drop-in replacement for OpenAI API — add guardrails transparently
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: acme-corp" \
  -H "X-Agent-ID: support-bot" \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]}'
```

### Sidecar Mode (validate before execute)

```bash
# Call from your agent framework before executing a tool
curl http://localhost:8080/v1/tool/validate \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: acme-corp" \
  -H "X-Agent-ID: support-bot" \
  -d '{"name": "run_command", "arguments": {"command": "rm -rf /"}}'

# Response: {"verdict": "block", "allowed": false, "blocked_tools": ["run_command"]}
```

### Admin

```bash
# Reload policies
curl -X POST http://localhost:8080/admin/policies/reload

# List policies
curl http://localhost:8080/admin/policies

# IOC stats
curl http://localhost:8080/admin/iocs/stats
```

## Threat Model

| Threat | Mitigation |
|--------|-----------|
| User prompt injection → jailbreak agent | Input guardrail pattern matching |
| User tricks agent into tool abuse | Tool policy RBAC enforcement |
| Agent leaks secrets in response | Output filter redaction |
| User connects to malicious endpoints | IOC domain/IP blocking |
| Brute-force jailbreak attempts | Rate limiting per tenant |
| Stolen tokens | JWT with short expiry + API key rotation |

## Differences from opencode-security-agent

| | opencode-security-agent | sentinel-gateway |
|---|---|---|
| Trust model | User trusted, LLM untrusted | User untrusted, system protected |
| Fail mode | Open (never break IDE) | Closed (block on doubt) |
| Integration | Local plugin hooks | HTTP proxy/sidecar |
| Deployment | Single user, local | Multi-tenant, cloud |
| Scope | Protect user from agent | Protect system from user |

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src/ tests/
mypy src/
```

## License

GPL-3.0-or-later
