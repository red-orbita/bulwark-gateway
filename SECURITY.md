# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Sentinel Gateway, please report it responsibly.

**Email**: security@sentinel-gateway.dev  
**Response time**: 48h acknowledgment, 7 days initial assessment  
**Disclosure**: Coordinated disclosure after fix is available

Please include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

## Security Design Principles

Sentinel Gateway follows a fail-closed security model:

- All user inputs are treated as potentially adversarial
- LLM outputs are treated as untrusted (may contain injected instructions)
- Tool calls are validated against per-agent RBAC policies
- Secrets are never logged or returned in error responses
- Network access is restricted by default (zero-trust NetworkPolicies)

## Known Limitations

- Input guardrail uses regex-based detection (no ML in the hot path by design)
- Rate limiting falls back to per-worker in-memory when Redis is unavailable
- Streaming responses use a 256-char sliding window (very short payloads may evade)
