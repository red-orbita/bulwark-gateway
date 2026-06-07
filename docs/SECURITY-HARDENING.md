# Security Hardening

Summary of security audits, penetration tests, and remediations applied to Sentinel Gateway.

## Table of Contents

- [Security Posture](#security-posture)
- [Audit 1: Initial Security Review (37 findings)](#audit-1-initial-security-review)
- [Audit 2: Penetration Test (17 findings)](#audit-2-penetration-test)
- [Threat Coverage (OWASP LLM Top 10)](#threat-coverage)
- [Defense-in-Depth Layers](#defense-in-depth-layers)
- [Ongoing Security Practices](#ongoing-security-practices)

---

## Security Posture

| Aspect | Implementation |
|--------|----------------|
| Auth model | Fail-closed (deny on error) |
| Network | Default-deny egress, minimal ingress |
| Secrets | Mounted read-only, never in env vars directly |
| Database | SQLCipher (AES-256) optional encryption |
| Containers | Non-root, read-only rootfs, no capabilities |
| Pod Security | Restricted PSS (proxy/admin), Baseline (Wazuh) |
| Supply chain | Pinned dependencies, no eval/exec |

---

## Audit 1: Initial Security Review

**37 findings remediated** across Critical (8), High (12), Medium (11), Low (5).

### Critical Findings (C-01 to C-08)

| ID | Finding | Remediation |
|----|---------|-------------|
| C-01 | Hardcoded JWT secret in config | Moved to Docker/K8s secrets with _FILE pattern |
| C-02 | No rate limiting | Redis-backed per-tenant rate limiter |
| C-03 | SQL injection in user store | Parameterized queries throughout |
| C-04 | Unrestricted admin access | RBAC with 4 roles + per-endpoint permissions |
| C-05 | Plaintext passwords in DB | bcrypt mandatory (with salt) |
| C-06 | No input validation on policies | YAML schema validation + sandbox testing |
| C-07 | CORS wildcard (*) | Configurable origins, no wildcard in production |
| C-08 | No audit logging | Immutable audit log (SQLite, exportable) |

### High Findings (H-02 to H-13)

| ID | Finding | Remediation |
|----|---------|-------------|
| H-02 | No session revocation | Redis-backed session store with revocation |
| H-03 | API keys in plaintext config | Moved to secrets files |
| H-04 | No HTTPS enforcement | HSTS headers + ssl-redirect |
| H-05 | Verbose error messages | Generic errors externally, detailed internal logging |
| H-06 | No request size limits | nginx proxy-body-size + FastAPI limit |
| H-07 | Unmasked secrets in API | _mask_transport() on all sensitive responses |
| H-08 | No MFA support | TOTP-based MFA added |
| H-09 | Session fixation risk | New session ID on login |
| H-10 | No login rate limiting | IP + username rate limiting with lockout |
| H-11 | Unrestricted file paths | Path traversal prevention |
| H-12 | No integrity check on config | SHA256 hash verification on reload |
| H-13 | Redis without auth | Password required, dangerous commands blocked |

### Medium and Low

Covered various hardening: CSP headers, cookie security, log injection prevention, dependency updates, documentation gaps.

---

## Audit 2: Penetration Test

**17 findings remediated** (5 Critical, 7 High, 5 Medium).

### Critical (C-01 to C-05)

| ID | Finding | Remediation | File |
|----|---------|-------------|------|
| C-01 | Streaming tool_calls bypassed policy | Tool calls now BUFFERED entirely, policy validated BEFORE yielding | `src/routes/proxy.py` |
| C-02 | SIEM transport config writable by proxy | Mounted `readOnly: true` + SSRF validation on endpoints | `k8s/base/proxy.yaml`, `src/telemetry/transports/http_rest.py` |
| C-03 | Policies PVC writable by proxy | Mounted `readOnly: true` in proxy | `k8s/base/proxy.yaml` |
| C-04 | Service account tokens auto-mounted | `automountServiceAccountToken: false` for Grafana + Prometheus | `k8s/monitoring/prometheus-grafana.yaml` |
| C-05 | `/health/stats` unauthenticated | Explicit tenant auth check added | `src/routes/health.py` |

### High (H-01 to H-07)

| ID | Finding | Remediation | File |
|----|---------|-------------|------|
| H-01 | Admin NetworkPolicy too permissive | Requires BOTH namespaceSelector AND podSelector for ingress-nginx | `k8s/base/network-policies.yaml` |
| H-02 | SSRF in Wazuh API URL config | DNS resolution + private IP check before request | `admin/routes/siem.py` |
| H-03 | JWT missing audience/issuer claims | Configurable `jwt_audience` + `jwt_issuer` validation | `src/middleware/auth.py` |
| H-04 | Client could inject backend auth header | Backend auth sourced from config `auth_token` field ONLY | `src/routes/proxy.py` |
| H-05 | Redis dangerous commands available | KEYS, DEBUG, EVAL, SCRIPT, SHUTDOWN, SLAVEOF blocked via rename-command | `k8s/base/redis.yaml` |
| H-06 | K8s API accessible from pods | Blocked by 10.0.0.0/8 egress exclusion in NetworkPolicy | `k8s/base/network-policies.yaml` |
| H-07 | Grafana unrestricted egress | Dedicated NetworkPolicy: only Prometheus:9090 + kube-system DNS | `k8s/base/network-policies.yaml` |

### Medium (M-01 to M-05)

| ID | Finding | Remediation | File |
|----|---------|-------------|------|
| M-01 | Backend errors disclosed architecture | Generic "Backend processing error" message | `src/routes/proxy.py` |
| M-02 | Unregistered tenants got default backend | `resolve()` returns None → proxy returns 403 | `src/services/agent_registry.py` |
| M-03 | Internal IPs in agent config | Uses `${SENTINEL_BACKEND_URL:-http://ollama:11434}` env expansion | `config/agents.yaml` |
| M-04 | Telemetry PVC could persist sensitive data | Changed to `emptyDir` (Memory, 50Mi) — ephemeral | `k8s/base/proxy.yaml` |
| M-05 | No default-deny egress | Added default-deny + explicit allow rules | `k8s/base/network-policies.yaml` |

---

## Threat Coverage (OWASP LLM Top 10)

| # | Threat | Coverage | Detection |
|---|--------|----------|-----------|
| LLM01 | Prompt Injection | Input Guardrail | Regex patterns, known injection signatures |
| LLM02 | Insecure Output Handling | Output Filter | Secret/PII/credential redaction |
| LLM03 | Training Data Poisoning | N/A | Out of scope (LLM provider responsibility) |
| LLM04 | Model Denial of Service | Rate Limiter | Per-tenant rate limits, request size limits |
| LLM05 | Supply Chain Vulnerabilities | N/A | Pinned deps, no dynamic code loading |
| LLM06 | Sensitive Information Disclosure | Output Filter + Input Guardrail | Pattern matching for secrets, PII |
| LLM07 | Insecure Plugin Design | Tool Policy | Per-tenant tool allowlist/blocklist |
| LLM08 | Excessive Agency | Tool Policy + Streaming Buffer | Tool calls validated before execution |
| LLM09 | Overreliance | WARN verdict | Flag suspicious but non-blocking patterns |
| LLM10 | Model Theft | Auth + Network | JWT/API key auth, network segmentation |

---

## Defense-in-Depth Layers

```
Layer 1: Network
  - Default-deny NetworkPolicies
  - Ingress with TLS termination
  - Separate subdomains (data plane vs control plane)
  - Private IP egress blocked

Layer 2: Authentication
  - JWT with audience + issuer validation
  - API key validation
  - Fail-closed on any auth error
  - Session revocation via Redis

Layer 3: Authorization
  - Per-tenant RBAC policies
  - Tool allowlists/blocklists
  - Admin portal: 4 roles with granular permissions

Layer 4: Input Validation
  - Request size limits
  - Regex-based injection detection
  - IOC matching (threat intelligence)
  - Tool policy enforcement

Layer 5: Output Protection
  - Secret/credential redaction
  - PII detection and masking
  - Response size limits

Layer 6: Runtime Hardening
  - Non-root containers
  - Read-only root filesystem
  - No capabilities (drop ALL)
  - Memory-backed ephemeral storage
  - automountServiceAccountToken: false

Layer 7: Monitoring & Response
  - Structured security events (ECS format)
  - SIEM export (13 platforms)
  - Real-time notifications (9 channels)
  - Prometheus metrics + Grafana dashboards
  - Immutable audit log
```

---

## Ongoing Security Practices

### Before Each Release

1. Run full test suite (`pytest -v`) — 185+ tests
2. Run `ruff check src/ tests/` — zero warnings
3. Run `mypy src/` — type safety
4. Review any changes to `src/middleware/auth.py` or `src/models.py`

### Periodic Tasks

| Task | Frequency | Procedure |
|------|-----------|-----------|
| Rotate JWT secrets | Monthly | See [Operations](OPERATIONS.md#jwt-secret-rotation) |
| Update IOC database | Daily (automated via feeds) | `config/feeds/` YAML configs |
| Review audit logs | Weekly | Admin portal → Audit Log |
| Dependency updates | Monthly | `pip-audit`, `safety check` |
| Pentest / red team | Quarterly | Use built-in red team skills |
| Certificate renewal | Before expiry | cert-manager (automatic) or manual |

### Red Team Testing

Built-in adversarial testing capabilities:
- Prompt injection variants
- Tool call manipulation (path traversal, SSRF)
- Context leak testing (encoding evasion)
- Resource exhaustion
- RBAC/policy bypass attempts
- Unicode/encoding fuzzing
