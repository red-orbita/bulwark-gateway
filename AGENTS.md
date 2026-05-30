# Sentinel Gateway — Agent Instructions

## Project
Sentinel Gateway is a security guardrail proxy for AI agents in cloud environments.
- **Language**: Python 3.11+ (FastAPI)
- **Purpose**: Intercept and enforce security policies on tool calls between users and LLM agents
- **Trust model**: User is potentially adversarial (fail-closed)

## Architecture
- Entry: `src/main.py` (FastAPI app)
- Core engines: `src/guardrails/` (input_guardrail, output_filter, tool_policy)
- Config: `config/policies/*.yaml` (per-tenant RBAC), `config/iocs.json`
- Routes: `src/routes/` (proxy.py = main flow, admin.py, health.py)
- Tests: `tests/` (pytest, 44 tests)

## Key Commands
```bash
# Run server
source .venv/bin/activate && python -m uvicorn src.main:app --reload --port 8080

# Run tests
pytest -v

# Lint
ruff check src/ tests/

# Type check
mypy src/
```

## Conventions
- All security detections use `Verdict` enum: ALLOW, BLOCK, WARN, REDACT
- Security events are structured (`SecurityEvent` model) for SIEM ingestion
- Patterns are pure regex — no LLM calls in the hot path
- Policies are YAML, loaded at startup, hot-reloadable via `/admin/policies/reload`
- Environment variables prefixed with `SENTINEL_`

## Commit Messages
- `feat: <description>` — New guardrail, endpoint, or capability
- `fix: <description>` — Bug fix or pattern correction
- `test: <description>` — New tests
- `docs: <description>` — Documentation
- `refactor: <description>` — Code restructuring

## Testing Requirements
- All new guardrail patterns MUST have corresponding tests
- Tests must cover both positive (should block) and negative (should allow) cases
- Run `pytest` before every commit

## Files NOT to Modify Without Review
- `src/models.py` — Core data models used everywhere
- `config/iocs.json` — Only via IOC update scripts
- `src/middleware/auth.py` — Security-critical

## Available Skills
Use the `skill` tool to load detailed instructions:
- `add-guardrail` — Add a new detection pattern to input/output guardrails
- `add-policy` — Create a new tenant policy YAML
- `run-tests` — Run and fix tests
- `audit-patterns` — Audit detection patterns for false positives/negatives
- `add-ioc-feed` — Add a new threat intel feed integration
- `security-architecture` — Design/review guardrail architecture with trade-offs
- `threat-modeling` — Update threat matrix (STRIDE + OWASP LLM Top 10)
- `secure-design-review` — Static security review of FastAPI code
- `incident-response` — Post-incident containment, forensics, and remediation
- `compliance-audit` — OWASP LLM, GDPR, SOC2 compliance validation
- `performance-hardening` — Hot path profiling, regex optimization, tuning

### Red Team Skills (offensive testing)
- `redteam-prompt-injection` — Adversarial prompt injection variants against input guardrail
- `redteam-tool-hijack` — Tool call manipulation: path traversal, command injection, SSRF
- `redteam-exfiltration` — Context leak testing: secrets, PII, system prompts, encoding evasion
- `redteam-dos-abuse` — Resource exhaustion: oversized payloads, rate limit saturation, ReDoS
- `redteam-policy-bypass` — RBAC evasion: tenant hopping, JWT manipulation, privilege escalation
- `redteam-llm-fuzzing` — Evasion fuzzing: base64, Unicode smuggling, leetspeak, multilingual
