# Changelog

All notable changes to Bulwark Gateway are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Output-validation scanners graduated to BETA (opt-in, off by default).**
  The `RelevanceScanner` (backed by a provisioned `sentence-embeddings` ONNX
  model) and the `HallucinationScanner` + `GroundingScanner` (sharing a
  provisioned `nli-classifier` ONNX model) now carry real forward-pass tests and
  are wired into the proxy pipeline behind `BULWARK_RELEVANCE_SCANNING_ENABLED`,
  `BULWARK_HALLUCINATION_SCANNING_ENABLED` and `BULWARK_GROUNDING_SCANNING_ENABLED`.
  Both models gained `config/model_manifest.json` entries and download paths in
  `scripts/download-models.py` (`--embeddings` / `--nli`). All three are
  OUTPUT_ASYNC (fire-and-forget, no LLM call, off the hot path) and stay inert
  until the owning agent opts in via its `output_validation` policy.
- **Model-free `SchemaValidator` wired into the output pipeline** (opt-in via
  `BULWARK_SCHEMA_VALIDATION_ENABLED`) — deterministic JSON-schema validation of
  structured LLM output, declared `MaturityTier.BETA`.
- **Deterministic image-hygiene guards activated for the vision scanner**
  (opt-in via `BULWARK_VISION_SCANNING_ENABLED`): inline `data:image` extraction,
  base64 validation, DoS size limit, `allow_images` policy gate, and magic-byte
  format-signature (MIME-confusion) detection — all zero-dependency, no OCR
  backend required. The OCR content layer remains inert/EXPERIMENTAL.
- **Per-scanner maturity tiers pinned** (GA / BETA / EXPERIMENTAL) for all shipped
  scanners, propagated through `list_scanners()`, `/internal/scanners/status` and
  the admin UI as an honesty signal for triage/IR.
- **Red-team evaluation upgraded** to grade the real scanner pipeline against
  external labeled corpora with a WARN/BLOCK-separated confusion matrix, exposed
  over the admin API and gated in CI on recall/FPR of the guardrail floor.
- `persistence.accessMode` Helm value (default `ReadWriteOnce`) applied to the
  PVCs shared between proxy and admin (`policies`, `siem-stats`, `admin-data`,
  `notifications-data`, `enrichment-data`). Set it to `ReadWriteMany` with an
  RWX-capable `storageClass` for multi-node HA — otherwise scaling the proxy
  across nodes triggers Kubernetes `Multi-Attach` errors. Admin-only PVCs
  (`telemetry-data`, `reports`) remain `ReadWriteOnce`. See `docs/DEPLOYMENT.md`
  → "Shared Storage Access Mode (Multi-Node)".

### Changed

- Migrated both container images (proxy and admin) to a **Google Distroless**
  runtime (`gcr.io/distroless/python3-debian13:nonroot`, digest-pinned) built
  from a `python:3.13-slim-trixie` builder stage. The runtime ships no shell, no
  package manager and no coreutils — only the Python 3.13 interpreter and its
  stdlib — shrinking the attack surface and reducing base-OS CVEs (0 Python-library
  CVEs; residual CVEs are base-OS only).
- The proxy now starts via `docker/proxy_launcher.py` (derives `BULWARK_WORKERS`
  then `os.execv`'s uvicorn) instead of a shell entrypoint; the admin image uses
  an exec-form uvicorn ENTRYPOINT.
- The admin image encrypts `users.db` with SQLCipher via the self-contained
  `sqlcipher3-binary` wheel (replacing `pysqlcipher3`), avoiding a native `.so`
  copy into the distroless image.
- Container user changed from UID 999 to the distroless `nonroot` **UID/GID
  65532**. Kubernetes manifests set `fsGroup: 65532` + `fsGroupChangePolicy:
  Always` so existing PersistentVolumes are re-owned automatically on upgrade.
  Helm and Kustomize `securityContext` blocks were aligned accordingly.
- `initContainers` running on the app image (`init-policies`, `init-models`) now
  use `python3` instead of `sh`, since the distroless image has no shell.
- Helm test hooks (`test-connection`, `test-security`) hardened for
  PSS-restricted namespaces: compliant `securityContext`, `dnsConfig` `ndots:2`
  for reliable in-cluster FQDN resolution, API-key authentication (bare key,
  `:tenant` suffix stripped), and a dedicated `test-hook-access` NetworkPolicy.

### Fixed

- **P0 ML model-load path bug**: a blocking scanner whose model failed to load
  (or was never provisioned) could fail-closed and BLOCK *all* traffic silently.
  Startup now resolves blocking-scanner readiness explicitly per
  `BULWARK_FAIL_MODE` (`closed` refuses to start with an actionable error;
  `open` disables the degraded scanner and serves on the regex floor).
- Kustomize build (`kubectl apply -k k8s/`) no longer fails with a namespace
  ID conflict: the global `namespace:` directive rewrote both the
  `bulwark-gateway` and `bulwark-siem` Namespace objects to the same name.
  Every resource already declares its own namespace, so the directive was
  removed. The overlay now renders 48 resources cleanly.
- `docker/proxy_launcher.py` now treats an empty `BULWARK_WORKERS` value as
  unset (falls back to 4 workers), preventing a CrashLoopBackOff when the
  variable is injected empty.
- Pinned the inline image tags in `k8s/base/proxy.yaml` and
  `k8s/base/admin.yaml` to `1.0.0` (were `0.4.9-hardened` / `0.7.3-hardened`),
  matching the kustomize `images:` transformer for direct `kubectl apply`.

### Removed

- Dead ML scanner stubs `src/scanners/ml/intent_scanner.py` and
  `src/scanners/ml/topic_scanner.py` (and `scripts/export_models.py`): they had no
  provisioned model, no download path, no manifest entry and only mock-based
  tests, violating the "no capability ships without a real model + real-inference
  tests" bar. The correct way to add either later is documented in
  `docs/ROADMAP.md` §2.5/2.6.
- Dead `docker/entrypoint-proxy.sh` shell entrypoint (superseded by
  `docker/proxy_launcher.py`; cannot run under the shell-less distroless
  runtime). Its `.dockerignore` exception was removed too.

### Migration notes

- **Kubernetes**: no manual action required — `fsGroupChangePolicy: Always`
  re-owns existing PVCs from UID 999 to 65532 on the next mount.
- **Docker Compose**: `chown` persistent volumes to `65532:65532` before
  upgrading. See `docs/DEPLOYMENT.md` → "Upgrading (Distroless UID Migration)".

## [1.0.0] - 2026-08-18

First stable release. Bulwark Gateway is a fail-closed security guardrail proxy
that sits between AI agents/applications and LLM backends (OpenAI, Ollama, Azure
OpenAI, and other OpenAI-compatible APIs), enforcing security policy on every
request on a pure-regex hot path with no LLM calls in the request pipeline.

### Added

**Proxy pipeline (port 8080)**
- Six-phase request pipeline: input guardrail → IOC scan → backend forwarding →
  tool-policy validation → output filter → async enrichment/telemetry.
- Input guardrail with Unicode NFKC normalization, Shannon-entropy detection and
  multi-layer decoding (base64, hex, URL, Unicode escapes, Morse, Braille, NATO)
  in front of pre-compiled regex pattern sets organized by threat category.
- Tool Policy engine with per-agent RBAC: allowed/denied tools, argument
  allow/deny lists, path-traversal detection, `max_tool_calls`, and `strict`/
  `standard` sandbox levels.
- Output filter that redacts secrets, credentials, private keys and PII (API
  keys, JWTs, connection strings, SSNs, credit cards). Opt-in email/phone
  redaction via `BULWARK_REDACT_EMAIL` / `BULWARK_REDACT_PHONE`.
- Streaming (SSE) response filtering with a sliding-window buffer.
- SSRF protection on backend forwarding: request-time DNS resolution, RFC1918 /
  CGNAT / cloud-metadata CIDR blocklist, and DNS-rebinding defense.
- IOC scanning of message content against a threat-intel database (URLs, IPs,
  hashes, domains) with ThreatFox / URLhaus / OTX / AbuseIPDB feed integration.
- Multi-tenant agent registry with per-tenant/per-agent backend routing and
  `${VAR:-default}` environment expansion.
- JWT and API-key authentication, sliding-window rate limiting, and hot-reload of
  policy YAML (5s interval).

**Scanner framework**
- Pluggable four-lane scanner pipeline with entry-point and drop-in discovery.
- ML detection (injection/toxicity/topic/intent), multilingual (10-language)
  detection, multimodal OCR/vision scanning, output validation (hallucination,
  schema, grounding, relevance), and RAG chunk / memory guards.

**Admin dashboard (port 8090)**
- FastAPI + HTMX + Alpine.js + TailwindCSS UI (fully vendored, no CDN
  dependencies), covering policies, guardrails, SIEM, tenants, users, RBAC,
  audit, IOCs, notifications, enrichment, skills, plugins, evaluation and
  discovery.
- SkillSpector hybrid skill/MCP security scanner (138 patterns across a 5-stage
  pipeline: MCP tool-poisoning, MCP least-privilege, Bulwark overlay and
  structural checks).
- Red-team evaluation framework and agent/shadow-AI/MCP discovery tooling.

**Telemetry & observability**
- Background SIEM exporter with batching, circuit breaker and exponential-backoff
  retry, emitting ECS-formatted events over file (NDJSON), HTTP/REST, syslog
  (RFC 5424) and TCP+TLS transports.
- Multi-channel notifications (Telegram, Slack, Teams, PagerDuty, Opsgenie,
  email, generic webhook).
- Redis-backed distributed counters and recent-block tracking with graceful
  in-memory fallback when Redis is unavailable.

**Deployment**
- Helm chart (internal or external managed Redis, HPA, PodDisruptionBudgets,
  zero-trust NetworkPolicies, optional Prometheus/Grafana and Wazuh).
- Kustomize manifests, Docker Compose stack, and hardened multi-stage container
  images (non-root, read-only filesystem, all capabilities dropped, no shell
  utilities).
- CI/CD templates for GitHub Actions, Jenkins, Azure DevOps, GitLab CI and
  Tekton.

### Security

- Enforced RBAC on the `/admin/enrichment` router, which previously shipped with
  no authentication dependency — closing an unauthenticated read path to captured
  attack-payload telemetry and an unauthenticated regex-candidate approval
  (state-changing) endpoint. Reads now require `guardrails:read`; the review
  action requires `guardrails:write`. (Broken access control, OWASP A01.)
- Content-Security-Policy hardened: `script-src` is now per-request nonce-based
  and `'unsafe-inline'` was removed from the admin UI.
- Separated the admin JWT signing secret from the proxy JWT secret in the Helm
  chart so a compromise of one does not forge tokens for the other. Existing
  deployments preserve their current secret on upgrade.
- Added end-to-end RBAC enforcement tests that drive the real ASGI dependency
  graph, proving under-privileged callers are rejected at the HTTP boundary.

### Fixed

- Admin Status page reported the proxy engine as unhealthy and the scanner as
  degraded even when both proxy pods were ready: the health probe forwarded the
  full `key:tenant` line from the shared api-keys secret instead of the bare key
  the proxy binds, yielding 401 on `/health/stats` and
  `/internal/scanners/status`. The admin now sends the exact bare key.
- Enrichment regex-candidate reviews now record the authenticated user as
  `reviewed_by` instead of a hardcoded placeholder.
- Users page returned a 500 on the PostgreSQL backend; RBAC modals are now
  centered and viewport-anchored.
- Numerous admin-UI correctness and accessibility fixes: mutating controls now
  honour the server response (no fabricated success), real load-error/empty
  states, honest audit pagination and coverage counts, WCAG target-size and
  contrast compliance, accessible names for icon-only controls, keyboard
  operability, and token-driven motion respecting `prefers-reduced-motion`.
- SIEM connectivity test performs a real probe instead of reporting fabricated
  success; IOC and feed toggles revert to authoritative server state on failure.
- Resolved an audit-log schema drift with a versioned migration.

### Changed

- Replaced emoji iconography with vendored Lucide icons and unified admin data
  tables on a shared table component and Alpine transition helper.
- Aligned all version strings across the codebase, Helm chart (`appVersion`),
  Kustomize image tags and OpenAPI spec to `1.0.0`.

[Unreleased]: https://github.com/anomalyco/bulwark-gateway/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/anomalyco/bulwark-gateway/releases/tag/v1.0.0
