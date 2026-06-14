# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-06-14

### Added
- GDPR compliance service (Art.15, Art.17, Art.30) with PostgreSQL backend
- Scanner plugin system with 6-layer sandbox (AST, imports, network, filesystem, timeout, combined)
- Red teaming evaluation framework (template, mutation, encoding attacks)
- Agent discovery module (network scan, Kubernetes scan, Shadow AI, MCP inventory)
- Python SDK with LangChain and OpenAI integrations
- TypeScript SDK with streaming support
- Multi-channel notifications (Telegram, Slack, Teams, PagerDuty, webhook)
- Dialog flow engine (YAML-based state machine)
- OpenTelemetry tracing (optional, graceful degradation)
- Pre-commit hooks configuration (ruff, gitleaks, yaml validation)
- Makefile for common development tasks
- SECURITY.md, CONTRIBUTING.md, CHANGELOG.md

### Changed
- Pydantic models now use `extra="forbid"` and `max_length` validation
- JWT validation requires `jti` claim (revocation now mandatory)
- Virtual key encryption upgraded from XOR to Fernet (backward-compatible migration)
- Docker base images pinned to SHA256 digests
- Helm NetworkPolicies restrict DNS to kube-system only
- Telemetry transport defaults changed from localhost to empty (explicit config required)
- Input guardrail refactored from 1 file (5464 lines) into 5 modules (max 1665 lines)
- Version reconciled to 0.2.0 across all components

### Fixed
- 52 findings from Security Audit Round 3
- Async DNS resolution in SSRF check (was blocking event loop)
- Tool call streaming buffer unbounded growth (now capped at 1MB)
- Token revocation circuit breaker (30s grace period on Redis failure)
- Silent `except: pass` blocks replaced with structured logging
- 142 unused imports removed
- 65 mypy type errors resolved
- SQL LIKE wildcard injection in GDPR queries

### Removed
- python-jose dependency (replaced by PyJWT, which was already in use)
- XOR encryption fallback (cryptography package now mandatory)
- Unsigned tenant routing format (HMAC signing now required)

### Security
- 0 CRITICAL vulnerabilities (was 2)
- 0 HIGH vulnerabilities (was 8)
- Pydantic strict validation prevents parameter injection
- Pod selector restrictions on backend NetworkPolicies
- Rate limiting dual-layer (IP + tenant) with Redis atomic scripts
