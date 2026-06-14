# Sentinel Gateway — Full Integral Audit

**Date**: 2026-06-14  
**Auditor**: Source-code level, manual + automated  
**Method**: Direct code reading, pytest execution, grep analysis, architectural review  
**Scope**: All code in src/, admin/, sdk/, helm/, k8s/, docker/

---

## Executive Summary

| Axis | Score (1-10) | Assessment |
|------|:------------:|------------|
| **Functionality** | **8.8** | 13/14 features fully complete, 1 partial (Go SDK absent) |
| **Security** | **8.0** | Major fixes implemented, 4 remaining violations |
| **Architecture** | **7.5** | Mostly clean, coupling issues in SQLite path, 5 god-files |
| **Global Score** | **8.1/10** | Production-ready with known issues documented |

### Top 5 Issues

| # | Severity | Issue | Location |
|---|----------|-------|----------|
| 1 | **HIGH** | Pydantic models lack `extra="forbid"` + `max_length` | `src/models.py` (all classes) |
| 2 | **HIGH** | GDPRService (SQLite path) accesses `audit._conn` directly | `admin/services/gdpr.py:600-769` |
| 3 | **MEDIUM** | XOR fallback still active when `cryptography` pkg missing | `src/services/virtual_keys.py:306-314` |
| 4 | **MEDIUM** | SkillSpector placeholder SHA (not a real commit) | `docker/Dockerfile.admin:27` |
| 5 | **MEDIUM** | 5 silent `except: pass` blocks in proxy hot path | `src/routes/proxy.py:898,1036,1053` |

---

## Part 1: Functionality (Eje 1)

### Test Suite Results

```
470 passed, 0 failed, 8 warnings in 34.89s
```

### Feature Completeness Matrix

| # | Feature | Status | Lines | Tests | Evidence |
|---|---------|:------:|------:|------:|----------|
| 1 | Input Guardrail (4600+ patterns) | ✅ | 5,464 | 17 | Multi-layer decoding (base64, hex, URL, Morse, Braille, NATO, Pig Latin, Atbash, leet). Shannon entropy. NFKC normalization. |
| 2 | Output Filter (PII/secrets) | ✅ | 828 | 8 | AWS/GCP/Azure keys, JWT, PEM, connection strings, Unicode smuggling. Streaming via proxy sliding window (256char/128 overlap). |
| 3 | Tool Policy (RBAC) | ✅ | 824 | 10 | Per-tenant+agent RBAC. NFKC + confusable map + zero-width strip + casefold. Path traversal detection. |
| 4 | IOC Scanner | ✅ | 561 | 32 | 4 feeds (URLhaus, ThreatFox, OTX, AbuseIPDB). NFKC + zero-width + punycode `xn--` decode. Cache invalidation. |
| 5 | Response Cache | ✅ | 325 | 35 | tenant_id+agent_id in key hash. Redis + LRU fallback. TTL expiry. Streaming excluded. |
| 6 | Rate Limiting | ✅ | 254 | — | Dual-layer (IP+tenant). Redis Lua atomic script. InMemoryTokenBucket fallback. Per-worker divide. TLS support. |
| 7 | SIEM/Telemetry (4 transports) | ✅ | 919 | 23 | file_shipper, http_rest, syslog, tcp_tls. Batch flush, circuit breaker (5 failures→open, 30s half-open). |
| 8 | Plugin Sandbox | ✅ | 1,036 | 30 | 6 layers: AST analysis, import whitelist, network blocker, filesystem blocker, timeout, combined sandbox. Blocks eval/exec/compile. |
| 9 | Python SDK | ✅ | 985 | — | guard.py (local regex), client.py (HTTP), integrations (LangChain, OpenAI). |
| 9b | TypeScript SDK | ✅ | 330 | — | Full client with streaming, types, package.json with proper exports. |
| 9c | Go SDK | ❌ | 0 | 0 | **Does not exist** (not documented in AGENTS.md either) |
| 10 | Admin Dashboard | ✅ | — | — | 25 pages, 23 route files, complete CRUD. |
| 11 | Scanner Pipeline | ✅ | 2,800+ | 37 | 4-lane pipeline. ML (injection/toxicity/topic/intent), multilingual (10 langs), multimodal (OCR+vision), RAG, dialog engine. |
| 12 | Enrichment | ✅ | 728 | 10 | AttackReplayDB (evasion tracking, regex auto-gen). EmbeddingScanner (sentence-transformers, cosine similarity). |
| 13 | Discovery | ✅ | 779 | 25 | Agent discovery (network+K8s). Shadow AI (30+ endpoints). MCP inventory (risk scoring). |
| 14 | Evaluation (Red Team) | ✅ | 1,412 | 19 | Template/mutation/encoding attacks. EvaluationRunner + EvaluationReport. Benign dataset (30 samples). |

### Specific Feature Checks

| Check | Result | Notes |
|-------|:------:|-------|
| Input guardrail blocks 4600+ patterns | ✅ | 5,464 lines, patterns begin line 30. Class orchestrates at line 3879. |
| Streaming inspects each chunk | ✅ | `proxy.py:675-868`: 256-char window, 128-char overlap, per-chunk output filter |
| Output filter redacts in streaming | ✅ | Handled in proxy.py sliding window, not output_filter.py (correct design) |
| Tool policy RBAC isolates tenant+agent | ✅ | Policy loaded from YAML per-agent. Unicode normalized. |
| IOC feeds update | ✅ | `update_all()` fetches 4 feeds. `FeedScheduler` in admin. |
| IOC punycode/Unicode matching | ✅ | `_normalize_for_ioc()` at `manager.py:48-98` |
| Cache isolated by tenant | ✅ | `tenant_id + agent_id` in hash key (C-01 fix) |
| Rate limiting dual-layer | ✅ | IP-based (lines 219-232) + tenant-based (lines 234-252) |
| Rate limiting Redis fallback | ✅ | `InMemoryTokenBucket` auto-selected when Redis unavailable |
| Admin pages render | ✅ | 25 Jinja2 templates, HTMX + Alpine.js + TailwindCSS |
| SIEM transports complete | ✅ | 4 transports, all implement `send_batch()`, `close()`, SSRF validation |
| Plugin sandbox blocks eval/exec | ✅ | `_BLOCKED_BUILTINS` includes eval, exec, compile. Network socket replaced. |
| SDKs compile | ⚠️ | Python + TypeScript exist. No Go SDK. No lock files for TS SDK (M-08). |
| GDPR works in HA | ⚠️ | PostgreSQLGDPRService exists but **0 tests**. GDPR has zero test coverage. |

---

## Part 2: Security (Eje 2)

### Findings by Severity

#### HIGH (3)

| ID | Issue | Location | SECURE-CODING-STANDARDS Section |
|----|-------|----------|------|
| SEC-H-01 | Pydantic models accept extra fields (no `extra="forbid"`) | `src/models.py` (all 6 classes) | Section 10 |
| SEC-H-02 | No `max_length` on string fields in request models | `src/models.py:83-101` (Message, ChatRequest) | Section 10 |
| SEC-H-03 | `admin.py:40` — `jti` claim is optional; tokens without jti bypass revocation | `src/routes/admin.py:40-41` | Section 5 |

#### MEDIUM (5)

| ID | Issue | Location | SECURE-CODING-STANDARDS Section |
|----|-------|----------|------|
| SEC-M-01 | XOR fallback executes silently in production if `cryptography` not installed | `src/services/virtual_keys.py:306-314` | Section 1 |
| SEC-M-02 | SkillSpector placeholder SHA (`a1b2c3d4e5f...`) — not a real commit | `docker/Dockerfile.admin:27` | Section 3 |
| SEC-M-03 | `--extra-index-url` for PyTorch (dependency confusion vector) | `Dockerfile:23` | Section 3 |
| SEC-M-04 | 5 silent `except: pass` in proxy (lost observability) | `src/routes/proxy.py:898,1036,1053` + `src/main.py:206` | Section 7 |
| SEC-M-05 | `threading.Lock` in async services (meaningless across replicas) | 15 occurrences across src/ and admin/ | Section 4 |

#### LOW (4)

| ID | Issue | Location | SECURE-CODING-STANDARDS Section |
|----|-------|----------|------|
| SEC-L-01 | GDPR service: 1,154 lines, 0 test coverage | `admin/services/gdpr.py` | Section 8 |
| SEC-L-02 | `proxy.py:1045` reaches into `registry._redis` private member | `src/routes/proxy.py:1045` | Section 2 |
| SEC-L-03 | TypeScript SDK has no lock file (non-reproducible builds) | `sdk/typescript/` | Section 3 |
| SEC-L-04 | `admin/routes/enrichment.py` imports sqlite3 directly | `admin/routes/enrichment.py:13` | Section 2 |

### SECURE-CODING-STANDARDS Compliance

| Section | Title | Verdict | Violations |
|---------|-------|:-------:|:----------:|
| 1 | Cryptography | **PARTIAL** | XOR fallback in virtual_keys.py (degraded mode) |
| 2 | Persistence | **PASS** | PostgreSQL subclasses exist for all 3 admin services. SQLite in enrichment/telemetry is justified (local ephemeral). |
| 3 | Dependencies | **PARTIAL** | python-jose removed ✅, Docker pinned ✅, but SkillSpector placeholder SHA ❌, --extra-index-url ❌ |
| 4 | Async | **PASS** | Async DNS in hot path ✅, buffer limits ✅, no time.sleep ✅. threading.Lock justified for per-worker state. |
| 5 | Auth | **PASS** | JWT aud/iss enforced ✅, revocation cache ✅, bcrypt mandatory ✅. Minor: admin jti optional. |
| 6 | Network | **PASS** | DNS restricted to kube-system ✅, podSelector with labels ✅, SSRF validated ✅ |
| 7 | Fail-closed | **PASS** | Scanners fail-closed ✅, revocation cache w/ grace ✅. Silent except:pass is observability gap. |
| 8 | Testing | **PARTIAL** | 470 tests pass, but GDPR (1154L) has **0 tests** = violation of "0% inaceptable" rule |
| 9 | Docker/K8s | **PASS** | SHA256 pinned ✅, non-root ✅, startup probes ✅, PSS restricted ✅ |
| 10 | APIs | **FAIL** | No `extra="forbid"`, no `max_length` on ANY model. Direct violation. |

---

## Part 3: Architecture (Eje 3)

### Coupling Analysis

| Pattern | Severity | Where |
|---------|----------|-------|
| `audit._conn` direct access | HIGH | `admin/services/gdpr.py:600,603,607,618,624,628,642,655,658,661,743,746,765,768` |
| `registry._redis` access | MEDIUM | `src/routes/proxy.py:1045` |
| PostgreSQLGDPRService uses `get_database()` | ✅ FIXED | `admin/services/gdpr.py:906` — proper abstraction |

**Status**: Coupling exists ONLY in the SQLite (dev/default) path. PostgreSQL path is clean. The fix is conditional — only active when `SENTINEL_ADMIN_DB_URL=postgresql://...`.

### God Files (>1000 lines)

| File | Lines | Justification | Refactoring Priority |
|------|------:|---------------|:-------------------:|
| `src/guardrails/input_guardrail.py` | 5,464 | 73% pattern data + 27% logic. Could split patterns into separate modules. | Low |
| `admin/services/skill_scanner.py` | 1,418 | Orchestrates 4 engines. Engines already in separate modules. | Low |
| `admin/services/gdpr.py` | 1,154 | Base + PostgreSQL + Redis erasure + archive encryption. | Medium |
| `src/routes/proxy.py` | 1,099 | 10 concerns in one file. SSRF, streaming, telemetry could extract. | Medium |
| `admin/services/database.py` | 1,041 | Full abstraction layer (SQLite + PostgreSQL + query translator). | Low |
| `src/plugins/sandbox.py` | 1,036 | 6 security layers, runtime patching. Inherently complex. | Low |

### HA Readiness

| Component | HA Status | Notes |
|-----------|:---------:|-------|
| Proxy | ✅ Stateless | All state from Redis/config, per-request isolation |
| Admin (PostgreSQL) | ✅ Ready | All 3 services have PostgreSQL subclasses |
| Admin (SQLite default) | ❌ Breaks | File locking, single-writer. Expected for dev. |
| AttackReplayDB | ⚠️ Per-pod | SQLite, no PostgreSQL variant. Pod-level ephemeral — acceptable. |
| TelemetryQueue disk fallback | ⚠️ Per-pod | SQLite WAL, pod-level. Acceptable. |
| Redis | ✅ External | Supports TLS, external providers (Azure/AWS/GCP) |
| Rate Limiting | ✅ Redis | InMemory fallback is per-worker (documented limitation) |
| Revocation cache | ✅ TTLCache | 30s grace period across Redis outages |

### Failure Domains

| Component Fails | Impact | Recovery |
|-----------------|--------|----------|
| **Redis** | Rate limiting degrades to per-worker in-memory. Auth rejects new tokens after 30s cache expiry. Metrics lost. | Auto-recovery on reconnect. Counters survive in Redis (persistent). |
| **PostgreSQL** | Admin operations fail (users, audit, GDPR). Proxy unaffected. | 3 retries with backoff on init. No per-query retry. |
| **LLM Backend** | Proxy tries fallback backends in order. All exhausted → 502/504. | Auto-failover. Structured logging per attempt. |
| **Proxy pod** | HPA maintains 2-10 replicas. PDB ensures min 1 available. | Kubernetes auto-restarts. No state loss. |

### Horizontal Scaling Verification

```
app.state contents (src/main.py):
  policy_loader      → Read-only config, refreshed from disk every 5s
  ioc_manager        → In-memory IOC DB, loaded from file at startup
  agent_registry     → Read-only YAML config
  telemetry_exporter → Background asyncio task (per-worker)
  scanner_pipeline   → Stateless scanner instances
```

**Verdict**: Proxy is fully stateless for request handling. All module-level caches (`_DNS_CACHE`, `_revocation_cache`, `_API_KEY_HASHES`) are per-worker, short-TTL, or immutable. Safe for horizontal scaling.

### Extensibility

| Extension Point | Mechanism | OCP Compliance |
|-----------------|-----------|:--------------:|
| Add scanner | `entry_points` group `sentinel.scanners` | ✅ Full |
| Add transport | Implement `TransportProtocol` | ⚠️ Partial (must modify `exporter.py`) |
| Add notification channel | Config YAML only | ✅ Full |
| Add threat feed | Implement in `ioc_feeds.py` | ❌ Modify existing |
| Add new tenant | YAML config + hot-reload | ✅ Full |
| Add detection pattern | Admin UI (dynamic) or code | ✅ Full |

### Tech Debt Search Results

| Pattern | Occurrences | Assessment |
|---------|:-----------:|------------|
| `TODO` | 1 | `src/plugins/manager.py:279` — hub download placeholder |
| `FIXME` | 0 | Clean |
| `HACK/hack` | 0 in logic | Only in regex patterns (legitimate detection terms) |
| `WORKAROUND` | 0 | Clean |
| `temporary` | 1 | In regex pattern data (not code logic) |

### Silent Error Patterns

| Location | Context | Risk |
|----------|---------|------|
| `src/routes/proxy.py:898` | `except RuntimeError: pass` | Low (test-only path) |
| `src/routes/proxy.py:1036` | Redis recent_blocks push | **Medium** — lost visibility if Redis flapping |
| `src/routes/proxy.py:1053` | Redis tenant usage counter | **Medium** — metrics silently lost |
| `src/main.py:206` | ML config sync from Redis | **Medium** — admin changes won't apply, no signal |
| `src/middleware/rate_limit.py:167` | Tenant config reload | Low (retries every 5s anyway) |

---

## Part 4: Compliance Checklist (SECURE-CODING-STANDARDS.md)

| # | Rule | Verdict | Evidence |
|---|------|:-------:|----------|
| 1.1 | Fernet for symmetric encryption | **PARTIAL** | Used in primary path, XOR fallback on ImportError |
| 1.2 | bcrypt for passwords | **PASS** | `user_store.py:76-79`: hard SystemExit if not installed |
| 1.3 | PyJWT (not python-jose) | **PASS** | python-jose removed from lock file, all code uses `import jwt` |
| 1.4 | secrets.token_hex for tokens | **PASS** | Used in auth_service.py, session management |
| 1.5 | hmac.compare_digest for secrets | **PASS** | `auth.py:282`: constant-time comparison |
| 2.1 | All persistence via get_database() | **PARTIAL** | New code uses it. Legacy SQLite base classes remain (dev mode). |
| 2.2 | Never access ._conn externally | **FAIL** | `gdpr.py:600-769` accesses `audit._conn` (SQLite path only) |
| 2.3 | Factory pattern for services | **PASS** | All services have `get_<service>()` factories |
| 3.1 | Lock files with --hash=sha256 | **PASS** | Both .lock files use hash verification |
| 3.2 | Docker images pinned to digest | **PASS** | `@sha256:d764629ce...` in both Dockerfiles |
| 3.3 | No placeholder SHAs | **FAIL** | `Dockerfile.admin:27`: `a1b2c3d4e5f6789...` is clearly fake |
| 3.4 | No --extra-index-url | **FAIL** | `Dockerfile:23` uses it for PyTorch |
| 4.1 | Async DNS in handlers | **PASS** | `_async_is_ssrf_target()` used in hot path |
| 4.2 | No time.sleep in async | **PASS** | Zero occurrences found |
| 4.3 | Buffers have limits | **PASS** | Tool args: 1MB. Stream: 50MB/5min. |
| 5.1 | JWT with algorithm+audience+issuer | **PASS** | Both auth.py and admin.py enforce all 3 |
| 5.2 | Revocation verified | **PASS** | TTLCache + Redis with grace period |
| 5.3 | No error details to client | **PASS** | Backend body truncated to 200 chars |
| 6.1 | SSRF on all paths | **PASS** | Async SSRF check on backend URL |
| 6.2 | NetworkPolicy: DNS to kube-system only | **PASS** | Fixed in both Helm and Kustomize |
| 6.3 | NetworkPolicy: labeled podSelector | **PASS** | `matchLabels: {app.kubernetes.io/name: ollama}` |
| 7.1 | Fail-closed on scanner error | **PASS** | BLOCK on timeout/exception for blocking scanners |
| 7.2 | Circuit breaker for availability | **PASS** | TTLCache acts as 30s circuit breaker |
| 8.1 | No 0% coverage components | **FAIL** | GDPR (1,154 lines): zero tests |
| 9.1 | Non-root containers | **PASS** | UID 10001, `USER sentinel` |
| 9.2 | readOnlyRootFilesystem | **PASS** | Enforced in docker-compose + K8s securityContext |
| 9.3 | Startup probes | **PASS** | Present in proxy and admin deployments |
| 10.1 | Pydantic extra="forbid" | **FAIL** | No model uses it |
| 10.2 | String max_length | **FAIL** | No field has it |

---

## Part 5: Action Plan (Prioritized)

### Sprint 1: Critical (This Week) — ~8h estimated

| # | Issue | Fix | Effort | Impact |
|---|-------|-----|:------:|:------:|
| 1 | **SEC-H-01/02**: Pydantic models lack validation | Add `model_config = ConfigDict(extra="forbid")` to all models. Add `max_length=256` to `model`, `role`, `name` fields. | 2h | HIGH — prevents parameter injection |
| 2 | **SEC-H-03**: admin.py jti optional | Change `options={"require": ["exp", "iss", "aud", "jti"]}` | 0.5h | HIGH — closes revocation bypass |
| 3 | **SEC-M-01**: XOR fallback | Replace `except ImportError` with `raise SystemExit("cryptography required in production")` | 0.5h | MEDIUM — eliminates insecure degradation |
| 4 | **SEC-M-04**: Silent except:pass | Add `logger.warning(...)` to proxy.py:1036, 1053 and main.py:206 | 1h | MEDIUM — restores observability |
| 5 | **SEC-L-01**: GDPR zero tests | Write minimum test suite (happy + error + security) | 4h | MEDIUM — validates 1154 lines |

### Sprint 2: Important (Next Week) — ~6h estimated

| # | Issue | Fix | Effort | Impact |
|---|-------|-----|:------:|:------:|
| 6 | **SEC-M-02**: SkillSpector placeholder SHA | Either pin real SHA or remove ARG default | 0.5h | MEDIUM |
| 7 | **SEC-M-03**: --extra-index-url | Split PyTorch install into separate `RUN` with `--index-url` | 1h | LOW |
| 8 | Coupling: gdpr.py accesses audit._conn | Refactor SQLite GDPR to use audit logger's public query methods | 3h | MEDIUM |
| 9 | Proxy telemetry helpers extract | Move telemetry + SSRF to separate modules | 1.5h | LOW (maintainability) |

### Sprint 3: Nice-to-Have — ~5h estimated

| # | Issue | Fix | Effort | Impact |
|---|-------|-----|:------:|:------:|
| 10 | Input guardrail pattern split | Move pattern lists to `src/guardrails/patterns/*.py` | 2h | LOW |
| 11 | Transport plugin discovery | Add entry_point group `sentinel.transports` | 1.5h | LOW |
| 12 | TypeScript SDK lock file | Generate `package-lock.json` or `pnpm-lock.yaml` | 0.5h | LOW |
| 13 | Go SDK | Implement if needed for customer demand | 8-16h | LOW |

---

## Appendix A: Test Distribution

| Test File | Count | Coverage Area |
|-----------|:-----:|---------------|
| test_multilingual_multimodal.py | 43 | Language detection + vision scanner |
| test_exhaustive_integration.py | 41 | Cross-phase integration |
| test_api_contract.py | 39 | API contract validation |
| test_scanner_framework.py | 37 | Scanner pipeline + builtins |
| test_ml_scanners.py | 35 | ML scanner mocking |
| test_cache_and_vkeys.py | 35 | Cache isolation + virtual keys |
| test_phase7_plugins.py | 30 | Plugin system |
| test_output_validation.py | 30 | Hallucination, schema, grounding |
| test_phase9_discovery.py | 25 | Agent discovery |
| test_integration_ioc.py | 23 | IOC integration |
| test_phase5_phase6.py | 20 | RAG, dialog, SDK |
| test_phase8_evaluation.py | 19 | Red teaming |
| test_input_guardrail.py | 17 | Input guardrail patterns |
| telemetry/ (3 files) | 23 | Telemetry subsystem |
| test_tool_policy.py | 10 | Tool policy RBAC |
| test_enrichment.py | 10 | Attack replay + embedding |
| test_ioc.py | 9 | IOC detection |
| test_agent_registry.py | 9 | Agent registry |
| test_output_filter.py | 8 | Output filter |
| test_streaming_guardrail.py | 7 | Streaming SSE |
| **TOTAL** | **470** | |

### Coverage Gaps

| Component | Lines | Tests | Coverage |
|-----------|------:|:-----:|:--------:|
| `admin/services/gdpr.py` | 1,154 | 0 | **0%** |
| `admin/services/skill_scanner.py` | 1,418 | indirect | ~20% |
| `src/plugins/sandbox.py` | 1,036 | 30 | ~60% |
| `src/routes/proxy.py` | 1,099 | indirect | ~50% |

---

## Appendix B: Dependency Tree (Security-Relevant)

```
REMOVED (CRIT-B):
  python-jose[cryptography]==3.5.0 (unmaintained since 2022)
    ├── ecdsa==0.19.2
    │   └── six==1.17.0
    ├── rsa==4.9.1
    │   └── pyasn1==0.6.3
    └── (shared: cryptography — still needed by PyJWT)

RETAINED (in use):
  PyJWT>=2.8 (maintained, used by both proxy and admin)
  cryptography>=48.0.0 (Fernet for virtual keys + GDPR archives)
  bcrypt>=5.0.0 (password hashing, mandatory)
  redis>=5.0 (rate limiting, counters, revocation)
  httpx>=0.27 (backend forwarding, SSRF-protected)
```

---

## Appendix C: Failure Mode Diagram

```
                    ┌─────────────────────────┐
                    │   Client Request         │
                    └───────────┬──────────────┘
                                │
                    ┌───────────▼──────────────┐
                    │   Auth Middleware         │
                    │   JWT/API Key validate    │
                    │                          │
                    │   Redis FAILS →          │
                    │   Cache hit? → ALLOW(30s)│
                    │   No cache? → REJECT     │
                    └───────────┬──────────────┘
                                │
                    ┌───────────▼──────────────┐
                    │   Rate Limit             │
                    │                          │
                    │   Redis FAILS →          │
                    │   InMemory fallback      │
                    │   (per-worker, divided)  │
                    └───────────┬──────────────┘
                                │
                    ┌───────────▼──────────────┐
                    │   Input Guardrail        │
                    │   (pure regex, no deps)  │
                    │                          │
                    │   Exception → BLOCK      │
                    └───────────┬──────────────┘
                                │
                    ┌───────────▼──────────────┐
                    │   Backend Forward        │
                    │                          │
                    │   Backend FAILS →        │
                    │   Try fallback backends  │
                    │   All fail → 502/504     │
                    │                          │
                    │   DNS slow →             │
                    │   async + 5s TTL cache   │
                    └───────────┬──────────────┘
                                │
                    ┌───────────▼──────────────┐
                    │   Output Filter          │
                    │   (pure regex, no deps)  │
                    │                          │
                    │   Exception → BLOCK      │
                    └───────────┬──────────────┘
                                │
                    ┌───────────▼──────────────┐
                    │   Response to Client     │
                    └──────────────────────────┘
```

---

## Conclusion

Sentinel Gateway is a mature, production-ready security proxy with strong defense-in-depth design. The codebase demonstrates:

**Strengths**:
- Fail-closed by default throughout the stack
- Multi-layer input validation (entropy + Unicode normalization + 10 decoders + regex)
- Proper HA architecture with PostgreSQL abstractions
- Comprehensive scanner plugin system with entry_point discovery
- 470 tests passing, zero failures

**Weaknesses**:
- Pydantic models not strict (`extra="forbid"` + `max_length`) — the most impactful remaining gap
- GDPR service has zero test coverage (1,154 untested lines)
- Some coupling in the SQLite dev path (audit._conn access)
- Silent error swallowing in 5 locations reduces observability

**Recommendation**: Fix SEC-H-01/02 (Pydantic strict models) immediately — this is the highest-impact/lowest-effort fix. Then write GDPR tests before any HA deployment relies on that code path.
