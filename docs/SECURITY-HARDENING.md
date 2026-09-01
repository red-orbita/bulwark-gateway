# Security Hardening & Assurance

This document is the authoritative record of the security posture of Bulwark
Gateway: the audits and penetration tests it has undergone, the remediations
applied, the threats it covers, and — going forward — a **living log of every
security improvement** shipped after the 1.0.0 release.

It is written to be read by three audiences: security engineers reviewing the
design, auditors verifying due diligence, and maintainers who must keep the
record accurate as the product evolves.

## Table of Contents

- [How This Document Is Maintained](#how-this-document-is-maintained)
- [Security Posture](#security-posture)
- [Security Update Log](#security-update-log)
- [Audit History](#audit-history)
  - [Audit 1: Initial Security Review (37 findings)](#audit-1-initial-security-review)
  - [Audit 2: Penetration Test (17 findings)](#audit-2-penetration-test)
  - [Audit 3: 1.0.0 Release Hardening (5 findings)](#audit-3-100-release-hardening)
- [Threat Coverage (OWASP LLM Top 10 — 2025)](#threat-coverage-owasp-llm-top-10--2025)
- [Defense-in-Depth Layers](#defense-in-depth-layers)
- [Scope & Known Limitations](#scope--known-limitations)
- [Ongoing Security Practices](#ongoing-security-practices)

---

## How This Document Is Maintained

This is a **living document**, not a point-in-time snapshot. It is part of the
definition of done for security-relevant work.

**Update rule.** Any change that alters the security posture — authentication,
authorization, network policy, container/runtime hardening, cryptography,
dependency/supply-chain, secret handling, or guardrail coverage — MUST add a
dated entry to the [Security Update Log](#security-update-log) **in the same pull
request** that makes the change.

**Entry format.** Each entry is stamped with a date and the release or commit it
applies to, states *what changed*, *why it matters*, and *how it was verified*
(test, scan, or live validation), and references the files touched.

**Relationship to the CHANGELOG.** `CHANGELOG.md` records *all* user-facing
changes. This document records the **security-relevant subset** with the extra
remediation and verification detail an auditor needs. When both apply, the
CHANGELOG entry is the summary and the Security Update Log entry is the evidence.

**Accuracy over precision.** Prefer descriptive, verifiable statements over
fragile hard-coded counts. Where a count is given, it is a floor ("1,300+
tests") or is explicitly tied to a source of truth in the repository.

**Ownership.** Changes to `src/middleware/auth.py`, `src/models.py`,
`src/routes/proxy.py`, the guardrail engines, and the Helm/Kustomize
`securityContext` / NetworkPolicy templates require security review and a
corresponding Security Update Log entry.

---

## Security Posture

| Aspect | Implementation |
|--------|----------------|
| Auth model | Fail-closed (deny on error) |
| Network | Default-deny egress, minimal ingress, zero-trust NetworkPolicies |
| Secrets | Mounted read-only via `*_FILE`, never in env vars directly |
| Database | SQLCipher (AES-256) encryption for the admin `users.db` |
| Containers | Google Distroless runtime — non-root (UID 65532), read-only rootfs, no shell, all capabilities dropped |
| Pod Security | Restricted PSS (proxy/admin), Baseline (Wazuh) |
| Supply chain | Digest-pinned base images, hash-pinned lockfiles, SBOM generated in CI, no `eval`/`exec`/`pickle` |
| Hot path | Pure regex, no LLM calls, no external I/O during request processing |

---

## Security Update Log

Reverse-chronological. Newest entries first. Every security-relevant change lands
here (see [How This Document Is Maintained](#how-this-document-is-maintained)).

### 2026-08-19 — Deployment audit remediation (H-1/H-2/H-3 + kustomize fix)

Follow-up hardening/robustness pass on the deployment manifests and container
entrypoint after a full 4-phase audit (SAST + infra review). No hot-path or
detection-logic changes; all 1301 unit tests pass, 3 skipped.

| ID | Area | Change | Why it matters | File(s) |
|----|------|--------|----------------|---------|
| H-1 | Storage HA | Added `persistence.accessMode` (default `ReadWriteOnce`) applied to the 5 PVCs shared between proxy and admin (`policies`, `siem-stats`, `admin-data`, `notifications-data`, `enrichment-data`); admin-only PVCs (`telemetry-data`, `reports`) stay RWO by design | With HPA (2-10) + `podAntiAffinity` spreading proxy replicas across nodes, shared RWO PVCs cause Kubernetes **Multi-Attach** errors and block scale-out. Operators can now set `ReadWriteMany` + an RWX StorageClass for multi-node HA; the RWO default stays portable to block-storage CSI drivers and single-node clusters | `helm/.../values.yaml`, `helm/.../templates/volumes.yaml`, `k8s/base/volumes.yaml` (documented) |
| H-2 | Entrypoint | `docker/proxy_launcher.py::_resolve_workers` treats an empty `BULWARK_WORKERS` as unset → defaults to 4 (historical `${VAR:-4}` semantics); stale `docker/entrypoint-proxy.sh` removed; `tests/test_docker_entrypoint.py` rewritten to unit-test the launcher | Prevents a CrashLoop when `BULWARK_WORKERS=""` is injected; removes dead shell script that cannot run under distroless (no shell); test now matches the real entrypoint (15/15 pass) | `docker/proxy_launcher.py`, `docker/entrypoint-proxy.sh` (deleted), `tests/test_docker_entrypoint.py` |
| H-3 | Image hygiene | Inline image tags in `k8s/base/proxy.yaml` + `k8s/base/admin.yaml` pinned to `1.0.0` (were `0.4.9-hardened` / `0.7.3-hardened`); the kustomize `images:` transformer already overrode them, so this is direct-`apply` consistency | Avoids confusion / accidental deploy of stale tags when applying base manifests without the kustomize overlay | `k8s/base/proxy.yaml`, `k8s/base/admin.yaml` |
| — | Kustomize | Removed the global `namespace: bulwark-gateway` directive from `k8s/kustomization.yaml`; every resource already declares its own namespace | The global transformer rewrote **both** Namespace objects (`bulwark-gateway` + `bulwark-siem`) to the same name, producing an ID conflict that broke `kubectl apply -k` / `deploy.sh`. Build now renders 48 resources cleanly (39 `bulwark-gateway` + 7 `bulwark-siem`) | `k8s/kustomization.yaml` |

**Verification.**
- `kubectl kustomize k8s/` — exit 0, 48 resources, image tags `1.0.0`, no resource missing a namespace.
- `helm template` — shared PVCs render `ReadWriteOnce` by default and `ReadWriteMany` under `--set persistence.accessMode=ReadWriteMany`; admin-only PVCs stay RWO.
- `pytest tests/ --ignore=tests/test_admin_integration.py` — 1301 passed, 3 skipped.

---

### 2026-08-19 — Distroless container migration & runtime hardening (post-1.0.0)

Both container images were migrated to a **Google Distroless** runtime, removing
the shell and OS toolchain from the attack surface and eliminating all
Python-library CVEs.

| Area | Change | Why it matters | File(s) |
|------|--------|----------------|---------|
| Base image | Runtime is `gcr.io/distroless/python3-debian13:nonroot` (SHA256-pinned), built from a `python:3.13-slim-trixie` builder (SHA256-pinned) | No shell (`/bin/sh` absent), no package manager, no coreutils — only the Python 3.13 interpreter + stdlib. A compromised process has no shell to pivot from | `Dockerfile`, `docker/Dockerfile.admin` |
| Entry point | Proxy starts via `docker/proxy_launcher.py` (`os.execv` uvicorn after deriving `BULWARK_WORKERS`); admin uses an exec-form uvicorn ENTRYPOINT | Removes the shell wrapper that distroless can no longer provide | `docker/proxy_launcher.py` |
| Runtime user | Container user changed from UID 999 to distroless `nonroot` **UID/GID 65532** | Aligns with the distroless image and PSS `restricted` | `Dockerfile`, `docker/Dockerfile.admin` |
| PVC migration | Kubernetes manifests set `fsGroup: 65532` + `fsGroupChangePolicy: Always` | Existing PersistentVolumes owned by UID 999 are re-owned automatically on the next mount — zero-touch upgrade | `helm/.../proxy.yaml`, `helm/.../admin.yaml`, `helm/.../dedicated-tenants.yaml`, `k8s/base/proxy.yaml`, `k8s/base/admin.yaml` |
| initContainers | `init-policies` / `init-models` rewritten from `sh` to `python3 -c` (shutil.copy2, hashlib) | The app image has no shell; other images (postgres, Filebeat) still use `sh` | `helm/.../proxy.yaml`, `helm/.../dedicated-tenants.yaml`, `k8s/base/proxy.yaml` |
| Admin DB crypto | `pysqlcipher3` replaced with the self-contained `sqlcipher3-binary` wheel | No native `.so` to copy into the distroless image; SQLCipher AES-256 encryption of `users.db` preserved | `admin/services/user_store.py`, `requirements-admin.lock` |
| Helm test hooks | `test-connection` / `test-security` given PSS-compliant `securityContext`, `dnsConfig ndots:2`, API-key auth (bare key, `:tenant` suffix stripped), and a dedicated `test-hook-access` NetworkPolicy | Post-deploy validation runs safely inside a `restricted` namespace under zero-trust egress | `helm/.../tests/*.yaml`, `helm/.../network-policies.yaml` |

**CVE posture.** 0 Python-library CVEs. Residual CVEs are base-OS only (e.g. one
fixable `libexpat1` finding), unpatchable without a distroless base refresh and
tracked as such.

**Verification.**
- `helm test bulwark-gateway` — both hooks pass on a live minikube deployment.
- `scripts/validate-deployment.sh --skip-backend` — 16 PASS / 0 FAIL (0 critical).
- UID 999 → 65532 migration proven live: the enrichment PVC was re-owned on mount
  via `fsGroupChangePolicy: Always` and remained writable.
- CI (`.github/workflows/security.yml`) green: Bandit, Semgrep, Trivy, pip-audit,
  gitleaks/TruffleHog, SBOM, license compliance.

---

## Audit History

Point-in-time audits that predate the living log above. Retained verbatim as the
historical remediation record.

### Audit 1: Initial Security Review

**37 findings remediated** across Critical (8), High (12), Medium (11), Low (5).

#### Critical Findings (C-01 to C-08)

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

#### High Findings (H-02 to H-13)

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

#### Medium and Low

Covered various hardening: CSP headers, cookie security, log injection prevention, dependency updates, documentation gaps.

### Audit 2: Penetration Test

**17 findings remediated** (5 Critical, 7 High, 5 Medium).

#### Critical (C-01 to C-05)

| ID | Finding | Remediation | File |
|----|---------|-------------|------|
| C-01 | Streaming tool_calls bypassed policy | Tool calls now BUFFERED entirely, policy validated BEFORE yielding | `src/routes/proxy.py` |
| C-02 | SIEM transport config writable by proxy | Mounted `readOnly: true` + SSRF validation on endpoints | `k8s/base/proxy.yaml`, `src/telemetry/transports/http_rest.py` |
| C-03 | Policies PVC writable by proxy | Mounted `readOnly: true` in proxy | `k8s/base/proxy.yaml` |
| C-04 | Service account tokens auto-mounted | `automountServiceAccountToken: false` for Grafana + Prometheus | `k8s/monitoring/prometheus-grafana.yaml` |
| C-05 | `/health/stats` unauthenticated | Explicit tenant auth check added | `src/routes/health.py` |

#### High (H-01 to H-07)

| ID | Finding | Remediation | File |
|----|---------|-------------|------|
| H-01 | Admin NetworkPolicy too permissive | Requires BOTH namespaceSelector AND podSelector for ingress-nginx | `k8s/base/network-policies.yaml` |
| H-02 | SSRF in Wazuh API URL config | DNS resolution + private IP check before request | `admin/routes/siem.py` |
| H-03 | JWT missing audience/issuer claims | Configurable `jwt_audience` + `jwt_issuer` validation | `src/middleware/auth.py` |
| H-04 | Client could inject backend auth header | Backend auth sourced from config `auth_token` field ONLY | `src/routes/proxy.py` |
| H-05 | Redis dangerous commands available | KEYS, DEBUG, EVAL, SCRIPT, SHUTDOWN, SLAVEOF blocked via rename-command | `k8s/base/redis.yaml` |
| H-06 | K8s API accessible from pods | Blocked by 10.0.0.0/8 egress exclusion in NetworkPolicy | `k8s/base/network-policies.yaml` |
| H-07 | Grafana unrestricted egress | Dedicated NetworkPolicy: only Prometheus:9090 + kube-system DNS | `k8s/base/network-policies.yaml` |

#### Medium (M-01 to M-05)

| ID | Finding | Remediation | File |
|----|---------|-------------|------|
| M-01 | Backend errors disclosed architecture | Generic "Backend processing error" message | `src/routes/proxy.py` |
| M-02 | Unregistered tenants got default backend | `resolve()` returns None → proxy returns 403 | `src/services/agent_registry.py` |
| M-03 | Internal IPs in agent config | Uses `${BULWARK_BACKEND_URL:-http://ollama:11434}` env expansion | `config/agents.yaml` |
| M-04 | Telemetry PVC could persist sensitive data | Changed to `emptyDir` (Memory, 50Mi) — ephemeral | `k8s/base/proxy.yaml` |
| M-05 | No default-deny egress | Added default-deny + explicit allow rules | `k8s/base/network-policies.yaml` |

### Audit 3: 1.0.0 Release Hardening

Findings closed as part of the 1.0.0 stable release. See `CHANGELOG.md` for the
full release entry.

| ID | Finding | Remediation | File |
|----|---------|-------------|------|
| R-01 | `/admin/enrichment` router shipped with no auth dependency — unauthenticated read access to captured attack-payload telemetry and an unauthenticated regex-candidate approval (state-changing) endpoint (broken access control, OWASP A01) | RBAC enforced on all six endpoints: reads require `guardrails:read`, the review action requires `guardrails:write` | `admin/routes/enrichment.py` |
| R-02 | Regex-candidate reviews recorded a hardcoded placeholder as the approver, breaking the audit trail | `reviewed_by` now sourced from the authenticated session (`user.sub`) | `admin/routes/enrichment.py` |
| R-03 | Admin CSP allowed `'unsafe-inline'` in `script-src` | Per-request nonce-based `script-src`; `'unsafe-inline'` removed | `admin/main.py`, `admin/templates/base.html` |
| R-04 | Admin and proxy shared a single JWT signing secret — compromise of one could forge tokens for the other | Separate admin JWT secret in the Helm chart; existing deployments preserve their current secret on upgrade | `helm/bulwark-gateway/templates/secrets.yaml` |
| R-05 | Admin Status page reported the proxy engine unhealthy / scanner degraded even with both proxy pods ready: the health probe forwarded the full `key:tenant` line from the shared api-keys secret instead of the bare key the proxy binds, yielding 401 on `/health/stats` and `/internal/scanners/status` | Admin now extracts and sends the exact bare key | `admin/routes/health.py` |

End-to-end RBAC enforcement tests were added that drive the real ASGI dependency
graph, proving under-privileged callers are rejected at the HTTP boundary
(`tests/test_rbac_enforcement.py`).

---

## Threat Coverage (OWASP LLM Top 10 — 2025)

Mapped to the **2025** revision of the OWASP Top 10 for LLM Applications. Coverage
is stated honestly: ✅ enforced control, ◑ partial / defense-in-depth, — out of
scope (provider responsibility).

| # | Threat (2025) | Coverage | Control |
|---|---------------|----------|---------|
| LLM01 | Prompt Injection | ✅ | Input Guardrail: regex signatures, Unicode NFKC normalization, entropy detection, multi-layer decoding |
| LLM02 | Sensitive Information Disclosure | ✅ | Output Filter (secret/PII/credential redaction) + Input Guardrail exfiltration patterns |
| LLM03 | Supply Chain | ✅ | Digest-pinned base images, hash-pinned lockfiles, SBOM in CI, no dynamic code loading |
| LLM04 | Data and Model Poisoning | ◑ | RAG chunk scanner + memory guard for retrieval/vector poisoning; training-time poisoning is provider responsibility |
| LLM05 | Improper Output Handling | ✅ | Output Filter + streaming (SSE) sliding-window buffer |
| LLM06 | Excessive Agency | ✅ | Tool Policy engine (per-agent RBAC, allow/deny, `max_tool_calls`) + tool_call buffering before execution |
| LLM07 | System Prompt Leakage | ✅ | Output Filter + Input Guardrail detection of system-prompt override/leak attempts |
| LLM08 | Vector and Embedding Weaknesses | ◑ | Embedding scanner + RAG memory guard (semantic similarity, poisoning detection) |
| LLM09 | Misinformation | ◑ | WARN verdict + output-validation scanners (hallucination, grounding, relevance) — BETA, model-backed (`nli-classifier` / `sentence-embeddings`), opt-in per agent |
| LLM10 | Unbounded Consumption | ✅ | Per-tenant rate limiter, request/response size limits, `max_tokens` enforcement |

> This mapping was updated from the 2023 list. The most material changes: former
> "Training Data Poisoning" (LLM03) is now "Data and Model Poisoning" (LLM04);
> "Model Theft" was retired in favor of "Unbounded Consumption" (LLM10); and
> "System Prompt Leakage" (LLM07) and "Vector and Embedding Weaknesses" (LLM08)
> are new categories, both of which Bulwark now maps explicit controls to.

---

## Defense-in-Depth Layers

```
Layer 1: Network
  - Default-deny NetworkPolicies (zero-trust)
  - Ingress with TLS termination
  - Separate subdomains (data plane vs control plane)
  - Private IP egress blocked; K8s API unreachable from app pods

Layer 2: Authentication
  - JWT with audience + issuer validation
  - API key validation (bare key, tenant-scoped)
  - Fail-closed on any auth error
  - Session revocation via Redis; TOTP MFA

Layer 3: Authorization
  - Per-tenant RBAC policies
  - Tool allowlists/blocklists, argument allow/deny
  - Admin portal: 4 roles with granular permissions

Layer 4: Input Validation
  - Request size limits
  - Regex-based injection detection (Unicode-normalized, entropy-aware)
  - IOC matching (threat intelligence)
  - Tool policy enforcement (validated before execution)

Layer 5: Output Protection
  - Secret/credential/private-key redaction
  - PII detection and masking
  - Response size limits; streaming buffered before yield

Layer 6: Runtime Hardening
  - Google Distroless runtime: no shell, no package manager, no coreutils
  - Non-root (UID 65532), read-only root filesystem
  - No capabilities (drop ALL), no new privileges
  - Memory-backed ephemeral storage; automountServiceAccountToken: false
  - Digest-pinned base images; 0 Python-library CVEs

Layer 7: Monitoring & Response
  - Structured security events (ECS format)
  - SIEM export: 4 transports (file/HTTP/syslog/TCP-TLS) covering 13+ platforms
  - Real-time notifications across 8 channels
  - Prometheus metrics + Grafana dashboards
  - Immutable audit log
```

---

## Scope & Known Limitations

Stated plainly so operators do not over-rely on any single layer.

- **Not a WAF for classic web attacks.** The input guardrail targets LLM-layer
  threats. Classic SQL injection (`'; DROP TABLE …`), XSS, and bare path
  traversal on free-form chat input are **not** reliably matched by design — they
  are enforced where the payload actually reaches a database or filesystem: the
  tool-argument layer (`tool_policy.py` path-traversal detection, `denied_arguments`)
  and the output filter. Some `UNION SELECT`-style SQLi is caught incidentally by
  exfiltration/tool-abuse patterns.
- **Model/training-time poisoning is out of scope** (LLM04) — it is the LLM
  provider's responsibility. Bulwark covers retrieval/vector-store poisoning on
  the RAG path.
- **Regex hot path is signature-based.** Novel, heavily obfuscated attacks may
  evade static patterns; the ML scanners and red-team framework exist to close
  this gap, and the `WARN` verdict surfaces suspicious-but-non-blocking traffic.
- **Residual base-OS CVEs.** The distroless runtime carries base-OS CVEs that
  cannot be patched without a base-image refresh; these are tracked and are
  refreshed when a fixed digest is published.

---

## Ongoing Security Practices

### Before Each Release

1. Run full test suite (`pytest -q`) — 1,300+ tests
2. Run `ruff check src/ tests/ admin/` — zero warnings
3. Run `mypy src/` — type safety
4. Review any changes to `src/middleware/auth.py` or `src/models.py`
5. Confirm the [Security Update Log](#security-update-log) reflects every
   security-relevant change in the release

### Periodic Tasks

| Task | Frequency | Procedure |
|------|-----------|-----------|
| Rotate JWT secrets | Monthly | See [Operations](OPERATIONS.md#jwt-secret-rotation) |
| Update IOC database | Daily (automated via feeds) | Admin portal → IOCs → Feeds |
| Review audit logs | Weekly | Admin portal → Audit Log |
| Dependency updates | Monthly | `pip-audit`, hash-pinned lockfiles |
| Refresh distroless base image | On fixed-CVE digest publish | Re-pin the SHA256 digest in `Dockerfile` / `docker/Dockerfile.admin` |
| Pentest / red team | Quarterly | Use built-in red team framework |
| Certificate renewal | Before expiry | cert-manager (automatic) or manual |

### Red Team Testing

Built-in adversarial testing capabilities:
- Prompt injection variants
- Tool call manipulation (path traversal, SSRF)
- Context leak testing (encoding evasion)
- Resource exhaustion
- RBAC/policy bypass attempts
- Unicode/encoding fuzzing
