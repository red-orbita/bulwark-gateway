# Investigation Center — Evolution Roadmap & Integration Design

Status: **Phases 0–5 DELIVERED** · Owner: SOC platform · Scope: `admin/` (off proxy hot-path)

This document tracks how the Investigation / Triage / Cases workspace grew into a
SOC-grade IR platform, and how Bulwark Gateway integrates with **TheHive**,
**Cortex**, **DFIR-IRIS**, **OpenCTI**, and automation runners (**Shuffle**,
**n8n**). It is implemented in reviewable slices: Phases 0–3 have landed; Phases
4–5 are planned (scope to be finalised with product). The product-input decisions
in §8 also remain open.

> Nothing here touches the proxy hot path. All work lives in `admin/` and the
> durable SQL store; the fail-closed request pipeline in `src/` is unchanged.

---

## 0. Context — what exists today

The current workspace is already a functional "mini-TheHive", all admin-side and
durable in SQL (SQLite/PostgreSQL via `admin/services/database.py`; schema at
**migration v7** in `admin/services/migrations.py`):

| Concern | Route module | Store | Table(s) |
|---------|--------------|-------|----------|
| Triage | `admin/routes/investigation.py` (`/admin/investigation`) | `investigation_store.py` (`TriageStore`) | `investigation_triage` (v6) |
| Cases | `admin/routes/investigation_cases.py` (`/admin/investigation/cases`) | `investigation_case_store.py` (`CaseStore`) | `investigation_case`, `investigation_case_subject` (v7) |
| Evidence | — | `security_events_store.py` | `security_events` (+`incident_id`,`scope_digests`) |
| UI | `admin/main.py:622` → `pages/investigation.html` | Alpine `investigationPage()` | — |

Already present: Alert Queue → triage → add-to-case, notes (append-only), bulk
triage, case timeline (reconstructed), related-cases (shared-subject self-join),
MTTR/analytics, MD/JSON export with compliance roll-up, bounded response actions
(`raise_risk`/`clear_risk`/`notify`), local IOC-check, and per-event compliance
mapping (OWASP 2025 / ATLAS / ATT&CK / NIST AI RMF / EU AI Act) from
`src/telemetry/compliance.py`.

**Known gaps** (drive the phases below):
- "Subjects" (incident/origin/session) are not classic **observables** (ip/domain/url/hash) with type/TLP/tags.
- No **tasks/checklist**, no **case templates**, no editable **tags/TTP** on a case.
- Enrichment is local exact-match only (no Cortex analyzers, no OpenCTI lookup).
- **No outbound connector layer** to case/CTI platforms.
- **Doc↔code discrepancy to close**: docstrings + `AGENTS.md` reference MISP/OpenCTI
  IOC feeds, but `src/services/ioc_feeds.py` implements only URLhaus/ThreatFox/OTX/AbuseIPDB.
- No automation trigger (outbound) nor service-account action API (inbound) for SOAR.

---

## 1. Design principles (non-negotiable)

1. **`src/` never imports `admin/`.** Cases live admin-side, so connectors live in
   `admin/services/integrations/`. The proxy's opt-in correlation engine stays the
   producer; the admin is the consumer/orchestrator.
2. **Off the hot path.** Everything is admin-side, async, and durable. No new proxy
   request cost.
3. **Fail-OPEN for integrations, fail-CLOSED for the proxy.** A dead TheHive/Cortex
   MUST NOT break the SOC workspace or the proxy. Integration failures are retried,
   audit-logged, and surfaced in a health panel — never raised to the analyst as a 500.
4. **Zero new hard dependencies.** Use `httpx` (already a dep) for REST **and**
   GraphQL. STIX 2.1 is JSON → build plain dicts; do **not** pull `thehive4py`,
   `pycti`, `cortex4py`, or `stix2`. If a vendor SDK is ever justified, it goes
   behind an **optional extra**, never in the core lock.
5. **Secrets via `*_FILE`**, RBAC-gated, per-tenant scoped, audit-logged. Config
   through the admin UI, mirroring the existing `NotificationEngine` channel model
   (`data/notifications_channels.json`) and secret-file reader.
6. **TLP/PAP-aware sharing.** Never push restricted-marking data to OpenCTI /
   community feeds. Marking is enforced at the connector boundary.
7. **Outbound SSRF hygiene.** Integration endpoints are admin-configured (trusted)
   but still validated; reuse the SSRF mindset from the proxy.
8. **Every new pattern/endpoint gets tests** (positive + negative), per repo policy.

---

## 2. Phase 0 — Deepen the workspace (in-repo, no external tools)

Highest value and a prerequisite for every integration. New DB migration **v8**.

### 2.1 First-class Observables

Promote IOC-check hits (and manual entries) to persistent case observables — the
bridge that TheHive/Cortex/OpenCTI all consume.

New table `investigation_observable` (v8):

| Column | Notes |
|--------|-------|
| `observable_id` | `obs_<hex16>` |
| `case_id` | FK → `investigation_case` (nullable: can attach to triage subject too) |
| `type` | `ip` \| `domain` \| `url` \| `hash` \| `email` \| `filename` \| `user` \| `other` |
| `value` | normalized (reuse `src/ioc/manager._normalize_for_ioc`) |
| `is_ioc` | bool — flagged malicious |
| `tlp` | `clear` \| `green` \| `amber` \| `amber+strict` \| `red` (default `amber`) |
| `pap` | `clear` \| `green` \| `amber` \| `red` |
| `tags` | JSON list |
| `source` | `ioc-check` \| `manual` \| `cortex` \| `opencti` |
| `enrichment` | JSON list of analyzer/CTI reports (Phase 2 fills this) |
| `first_seen` / `last_seen` / `added_by` | provenance |

New endpoints under `/admin/investigation/cases/{case_id}`:
`GET/POST /observables`, `DELETE /observables/{id}`, `POST /observables/{id}/promote-ioc`
(pushes into `admin/services/ioc_store.py` → live blocking).

### 2.2 Case Tasks (the biggest felt gap vs TheHive/IRIS)

New table `investigation_task` (v8): `task_id`, `case_id`, `title`, `status`
(`todo`\|`in_progress`\|`done`\|`cancelled`), `assignee`, `order`, `due_at`,
`notes` (append-only, same shape as triage notes), `created_by/at`, `updated_at`.

Endpoints: `GET/POST /cases/{id}/tasks`, `POST /tasks/{id}/state`,
`POST /tasks/{id}/note`, `DELETE /tasks/{id}`.

### 2.3 Case Templates / Playbooks

Declarative, keyed by `ThreatCategory` (prompt-injection, exfiltration, jailbreak…).
A template pre-seeds: default severity, tag set, and an ordered task checklist.
Storage: YAML under `config/investigation/templates/` (hot-reloadable like policies)
+ optional per-tenant overrides in DB. `POST /cases` accepts `template_id` to
auto-populate tasks/tags/severity.

### 2.4 Tags + TTP surfacing

- Add `tags` (JSON) to `investigation_case` (v8 `ALTER`).
- Surface the **already-computed** compliance mapping as ATT&CK/ATLAS badges on the
  case (read from `src/telemetry/compliance.py` via the existing
  `/admin/investigation/compliance-mappings`), and allow analyst-added manual TTP tags.

### 2.5 Manual timeline entries (IRIS-style)

Extend the reconstructed timeline (`_reconstruct_case_timeline`) with an
analyst-authored entry type (stored as a `kind:"timeline"` note or a small
`investigation_timeline` table). Merge-sorted with durable events on read.

### 2.6 New export formats (enables integration by manual import today)

Add to `export_case` alongside `md`/`json`:
- **STIX 2.1 bundle** — case → `x-bulwark-case` / grouping; observables →
  SCOs + `indicator`s; TTPs → `attack-pattern` refs. Plain dicts, no `stix2` lib.
- **TheHive-JSON** and **IRIS-JSON** shapes — direct import targets for Phase 1
  before live push exists.

### Phase 0 acceptance
Analyst can: attach/normalize observables, promote one to a live IOC, run a
checklist of assignable tasks, open a case from a template, tag with ATT&CK, add
manual timeline entries, and export STIX/TheHive/IRIS JSON. All covered by unit
tests in `tests/` (store CRUD + endpoint contracts + export shape golden tests).

---

## 3. Phase 1 — Connector abstraction + push to TheHive / DFIR-IRIS

New package `admin/services/integrations/`:

```
integrations/
  base.py       # Connector Protocol + result types + retry/circuit-breaker mixin
  registry.py   # config load/validate, secret-file resolution, health cache
  thehive.py    # TheHive 5 REST (/api/v1)
  dfir_iris.py  # DFIR-IRIS REST (API v2)
  # (cortex.py, opencti.py land in Phase 2)
```

### 3.1 `Connector` protocol (modelled on `TransportProtocol` + generic channel)

```python
class Connector(Protocol):
    name: str
    @property
    def configured(self) -> bool: ...
    async def test_connection(self) -> HealthResult: ...
    async def push_case(self, case: CaseView) -> SyncResult: ...          # create/update remote case
    async def push_alert(self, alert: AlertView) -> SyncResult: ...       # promote a queue alert
    async def enrich_observable(self, obs: ObservableView) -> list[Report]: ...   # Phase 2 (Cortex/OpenCTI)
    async def run_responder(self, action: ResponderAction) -> SyncResult: ...     # Phase 2 (Cortex responders)
    async def sync_status(self, mapping: RemoteRef) -> SyncResult | None: ...     # optional inbound reconcile
```

- **Transport**: `httpx.AsyncClient` with timeout, retry + exponential backoff and a
  circuit breaker (reuse the exporter's proven pattern).
- **Idempotency**: a local `integration_link` table maps
  `(connector, local_type, local_id) → remote_id + last_synced_at + etag` so
  re-push updates instead of duplicating.
- **Config**: `data/integrations.json` + `*_FILE` secrets; UI page `/integrations`
  mirroring `/notifications` (add/test/enable/disable/health). RBAC: new
  permission namespace `integrations:read` / `integrations:write` added to
  `ROLE_PERMISSIONS` (admin+security write; auditor/viewer read).
- **Health**: `GET /admin/integrations/status` (per-connector `configured`,
  `reachable`, last error, circuit state) feeding a UI badge strip.

### 3.2 Data mapping

**TheHive** (`push_case`): Bulwark case → TheHive Case; `title/description/severity`
(map low/med/high/critical → 1–4); `tags` incl. `bulwark:<category>` + ATT&CK;
observables → TheHive observables (dataType from our `type`, `tlp`/`pap` passthrough);
tasks → TheHive tasks; notes → task log / case comments; `case_id` stored in
`integration_link`. Optionally: use TheHive **Alerts** API for queue alerts and let
the analyst promote in TheHive.

**DFIR-IRIS** (`push_case`): Bulwark case → IRIS case; observables → IOCs + assets;
manual+reconstructed timeline → IRIS timeline events; tasks → IRIS tasks; notes →
IRIS notes. IRIS API v2 with `cid` correlation stored in `integration_link`.

### 3.3 Outbound event webhook (SOAR trigger seed)

Add an **event-webhook** emitter (reuse `NotificationEngine` `generic` channel or a
dedicated dispatcher) that fires structured JSON on lifecycle events
(`case.opened`, `case.severity_raised`, `alert.high_confidence`,
`origin.blocked`). This is what Shuffle/n8n subscribe to in Phase 3, and it is
cheap to ship now.

### Phase 1 acceptance
From a case, one click pushes to TheHive and/or IRIS (create or update, idempotent);
health panel shows connector state; failures are retried + audited, never block the
UI. Tests mock the remote REST (pytest-httpx) with positive + failure + idempotent-update cases.

---

## 4. Phase 2 — Enrichment: Cortex analyzers + OpenCTI

### 4.1 Cortex (`cortex.py`)
- `enrich_observable`: submit observable to selected Cortex **analyzers**, poll the
  job, normalize the report into the observable's `enrichment` JSON, set `is_ioc` on
  malicious verdicts, optionally auto-`raise_risk` (reusing the existing
  `_raise_origin_risk` arithmetic).
- `run_responder`: map our bounded response actions to Cortex **responders**.
- Analyzer/responder catalog fetched from Cortex and cached; per-observable-type
  routing configurable in the UI.
  - **DONE (connector core)**: `admin/services/integrations/cortex.py` —
    `CortexConnector` (reuses `HttpConnectorBase` retry + circuit breaker) with
    `test_connection`, `list_analyzers`, `enrich_observable` (submit→bounded-poll→
    report, folds `summary.taxonomies` into a worst-level verdict blob) and
    `run_responder`. Pure helpers `cortex_datatype` / taxonomy extraction / worst-
    level folding. Fail-open + bounded polling. Tests: `tests/test_cortex_connector.py`
    (15).
  - **DONE (registry + endpoint wiring)**: `cortex` is now an
    `INTEGRATION_TYPES` member built via `registry.build_enrichment_connector`
    (separate from the push-only `build_connector`); `registry.health` probes a
    Cortex through the enrichment factory. `GET /admin/integrations/{id}/analyzers`
    lists a Cortex's analyzer catalog (cortex-only, fail-open 502).
    `POST /admin/investigation/cases/{case_id}/observables/{observable_id}/enrich`
    runs the requested `analyzer_ids`, folds the verdict into
    `enrichment['cortex']` via the new bounded
    `ObservableStore.set_enrichment` (evicts oldest key past the cap), flags
    `is_ioc` on a malicious verdict, and is fully fail-open (a failing Cortex
    surfaces an audited 502 and never mutates the observable). Tests:
    `tests/test_integrations.py` (registry + analyzers route),
    `tests/test_investigation_cases.py` (`TestObservableStore.set_enrichment*`,
    `TestObservableEnrichEndpoint`).
   - **DONE (responders + auto-raise + UI action)**: `cortex.py` grew
     `list_responders` (shared `_list_catalog` helper) →
     `GET /admin/integrations/{id}/responders` (cortex-only, fail-open 502).
     `POST /admin/investigation/cases/{case_id}/observables/{observable_id}/respond`
     runs a bounded Cortex **responder** and records the outcome under
     `enrichment['cortex_responder']` (a responder is an action, never a verdict —
     it never flags `is_ioc`; fail-open audited 502). A confirmed-**malicious**
     enrich verdict now auto-hardens **every `origin` subject linked to the case**
     (`_auto_raise_case_origins` → reuses `_raise_origin_risk`, best-effort /
     fail-open: Redis down ⇒ `skipped_reason`, enrich still returns 200; journals an
     action note; the response carries `origin_risk.raised`). The Investigation UI
     (`investigation.html` Observables section) gained a per-observable **Enrich**
     panel — pick a Cortex integration, check analyzers, run enrich (shows the
     verdict badge + hardened-origin count), and dispatch a responder. Tests:
     `tests/test_cortex_connector.py` (`test_list_responders`),
     `tests/test_integrations.py` (responders route ×4),
     `tests/test_investigation_cases.py` (`TestEnrichAutoRaiseOrigins` ×6,
     `TestObservableResponderEndpoint` ×8).

### 4.2 OpenCTI (`opencti.py`)
- **Pull** (closes the MISP/OpenCTI feed gap): query indicators via OpenCTI GraphQL
  (raw `httpx`, no `pycti`) on a schedule via `feed_scheduler.py`; upsert into
  `admin/services/ioc_store.py` → live proxy blocking. Also **first fix the
  doc↔code discrepancy**: either implement or correct the MISP/OpenCTI references in
  `ioc_feeds.py` docstrings + `AGENTS.md`.
  - **DONE (pull + doc↔code fix)**: `IOCStore._fetch_opencti` now queries the
    `indicators` collection, parses STIX-2 patterns
    (`_parse_stix_indicator_pattern`), drops revoked + sub-confidence indicators,
    carries labels through as tags, and validates the URL against the SSRF
    blocklist (parity added to `_fetch_misp` too). Scheduled via the existing
    `feed_scheduler` → `trigger_feed_update` path. README + `config/feeds/README.md`
    now declare OpenCTI honestly. Tests: `tests/test_opencti_feed.py` (13).
    Remaining for later: push (SCO/indicator/sighting + TLP) and lookup-on-IOC-check.
 - **Push**: observables → SCOs, `is_ioc` → `indicator` + `sighting` (with TLP
   marking-definitions), case → `grouping`/`report`. TLP/PAP gate enforced here.
   - **DONE**: `OpenCTIConnector` implements the `Connector` push protocol
     (`push_case`) so it reuses the shared `/push/case` route + link-store
     idempotency. It materialises the case via raw GraphQL create mutations (no
     `pycti`): one Cyber-observable (SCO) per mappable observable, an `indicator`
     + a `sighting` per flagged IOC, and a container `report` tying them together
     (the report's internal id is the `remote_id`; a re-push patches that report
     and best-effort re-attaches new object refs — SCOs/indicators upsert
     server-side via `update: true`). **TLP data-sharing gate**: `TLP:RED`
     observables are excluded and a wholly-restricted (no shareable/mappable
     observable) case is refused with `TlpGateError` → `400` **before** any remote
     call — included objects carry the case's most-restrictive remaining TLP
     marking-definition. `registry.build_connector` now returns an
     `OpenCTIConnector` for the `opencti` type; the push menu is filtered to
     push-capable connectors (thehive/dfir_iris/opencti). Markings are referenced
     by standard STIX id (no `markingDefinitions` round-trip); labels/tags are not
     propagated in v1 (`objectLabel` resolves by id, follow-up). Tests:
     `tests/test_opencti_connector.py` (push helpers + create/exclude-red/gate/
     sighting-failure/update/no-id flows) + `test_integrations.py` route push
     (create + TLP-gate 400).
 - **Lookup**: on IOC-check, also query OpenCTI for context (score, labels, related
   campaigns) and attach to the observable.
   - **DONE (interactive lookup)**: `admin/services/integrations/opencti.py`
     (`OpenCTIConnector`, raw `httpx` GraphQL, no `pycti`) exposes
     `lookup_observable()` — queries `indicators(search,orderBy:x_opencti_score)`,
     filters to STIX patterns literally containing the value, folds the worst-level
     **active** (non-revoked) indicator into a `not_found`/`clean`/`suspicious`/
     `malicious` verdict (`score_verdict`, thresholds 40/70). Wired via
     `POST /admin/investigation/cases/{id}/observables/{obs}/lookup` (mirrors the
     Cortex enrich path: folds into `enrichment['opencti']`, marks `is_ioc` +
     auto-raises origin-risk on `malicious`, fail-open 502). Registry adds the
     `opencti` type + `build_lookup_connector` + health probe. Admin UI: OpenCTI
     verdict badge + "Threat-intel lookup" panel on the observables card. Tests:
     `tests/test_opencti_connector.py` (17), plus `test_integrations.py` +
     `test_investigation_cases.py` coverage.

### Phase 2 acceptance
An observable can be enriched by Cortex and looked up in OpenCTI with reports
attached; malicious verdicts can auto-raise origin risk; OpenCTI indicators flow
into the live IOC store; MISP/OpenCTI docs match code. Tests mock analyzer jobs +
GraphQL responses.

---

## 5. Phase 3 — Automation loop (Shuffle / n8n / SOAR)

Two directions close the loop.

### 5.1 Outbound triggers ✅ DONE
The Phase 1 event-webhook is the workflow trigger surface. The envelope now carries
a `schema_version` (stable, versioned contract) and each subscription may hold an
HMAC-SHA256 signing secret: every delivery is signed as
`X-Bulwark-Signature: sha256=<hex>` over the exact JSON bytes POSTed (alongside
`X-Bulwark-Event` / `X-Bulwark-Delivery`), so Shuffle/n8n can verify authenticity +
integrity. The secret is write-only (resolved from
`BULWARK_INTEGRATION_WEBHOOK_<ID>_SECRET` / `_FILE` over the inline value; never
echoed back — responses expose only `has_secret`).

### 5.2 Inbound Action API + service-account auth
Playbooks need to act back. The verbs already exist (`/respond`,
`/triage/state`, `/triage/note`, cases CRUD, observables, tasks). Progress:

- **Service-account auth** distinct from the session cookie ✅ DONE (3.2a): a scoped
  API key with a dedicated `automation:*` permission namespace (least-privilege;
  e.g. a playbook token that may `investigation:write` + `automation:respond` but
  not manage users). Raw key `bwk_sa_<hex>` (192-bit) is shown exactly once at mint
  and stored SHA-256-hashed at rest in the `service_account` table (migration v10);
  the grantable set is a whitelist (`AUTOMATION_GRANTABLE_PERMISSIONS`) that
  deliberately excludes `automation:manage`, so a leaked playbook key can never
  mint/toggle/revoke service accounts (including itself). Verification is an indexed
  `key_hash` lookup enforcing `enabled` + optional `expires_at`, stamping
  `last_used_at`. A dedicated `require_permission_automation(perm)` resolver is wired
  ONLY onto automation-enabled endpoints (minimal blast radius): a `bwk_sa_…` bearer
  is resolved exclusively on the service-account path (401 unknown/disabled/expired,
  403 missing permission) and yields the lowest-privilege `TokenPayload`; any other
  token falls back to standard session/JWT + RBAC. Management routes
  (`/admin/service-accounts/*`) are session-only (`automation:manage`).
- **Idempotency-Key header** ✅ DONE (3.2b): honored on the mutating automation
  endpoints under `/admin/investigation` (dedupe retried playbook steps) — backed by
  the `automation_idempotency` table (migration v11) with a 24h TTL. A repeated
  service-account `Idempotency-Key` replays the stored 2xx response (stamped
  `Idempotency-Replay: true`) without re-executing; the dedupe scope is per-credential
  (SHA-256 of the presented key) × method × path, and the whole layer is fail-open
  (any storage error degrades to normal execution). Also wired: the action endpoints
  now accept a service-account key via `require_permission_automation` (`/respond` →
  `automation:respond`; case/observable/task/triage writes → `investigation:write`),
  and a `Bearer bwk_sa_…` request is exempt from CSRF (bearer auth is CSRF-immune;
  cookie sessions keep full enforcement).
- **Rate limits + audit** on the automation surface ✅ DONE (3.2c): every
  authenticated service-account request that passes `require_permission_automation`
  consumes one token from a per-key sliding-window budget
  (`admin/services/automation_rate_limit.py`); exceeding it returns `429`
  (`Retry-After: 60`) and writes a `service_account.rate_limited` audit record
  instead of executing. The limit is the account's optional `rate_limit_rpm`
  override (migration v12 — positive int caps the key, `0` opts it out) else the
  `BULWARK_AUTOMATION_RATE_LIMIT_RPM` env default (120; `<= 0` disables). Redis-first
  sliding window (`bulwark:automation:ratelimit:{account_id}`, shared across
  replicas) with a per-process in-memory fallback — a Redis error degrades to local
  enforcement rather than unthrottling or hard-denying. Operator sessions/JWTs are
  never throttled by it. UI management page + `*_FILE` seeding delivered in 3.2d.

- **Management UI + declarative seeding** ✅ DONE (3.2d): the **Govern → Service
  Accounts** admin page (`/service-accounts`, `pages/service_accounts.html`) is the
  session-only (`automation:manage`) operator control plane — list (metadata only),
  mint (name + grantable-permission checkboxes + optional `rate_limit_rpm`/`expires_at`),
  one-time copy-to-clipboard key reveal, toggle/delete; a `403` on load degrades to an
  "insufficient permission" notice. For GitOps/unattended deploys,
  `seed_service_accounts()` (`admin/services/service_account_seed.py`, run best-effort in
  the admin lifespan) provisions accounts from a JSON-array spec read from
  `BULWARK_SERVICE_ACCOUNTS_SEED` (or its `_FILE` variant). The operator supplies the
  plaintext `key` so the SOAR side can be configured out-of-band; only its SHA-256 is
  stored. `ServiceAccountStore.seed_from_spec` validates the key shape + grantable
  whitelist, is idempotent by key hash (safe to re-run every boot), and is fail-open (a
  bad spec/entry is logged and skipped, never crashes startup).

### 5.3 Reference playbooks (documented, runner-agnostic) ✅ DONE
Documented in `docs/SOAR-PLAYBOOKS.md` — a runner-agnostic reference covering the
signed event-webhook envelope + verification, the service-account action API
(auth/idempotency/rate-limits), the mutating endpoint catalogue, and all seven
recipes below:
1. **Auto-open case** when incident confidence ≥ threshold or origin crosses BLOCK.
2. **Auto-enrich** new alert → extract IOCs → Cortex + OpenCTI → attach → raise risk if malicious.
3. **Auto-contain** repeated exfil origin → responder → `/respond raise_risk` to BLOCK + notify war-room.
4. **Ticketing** high-sev case → Jira/ServiceNow via n8n.
5. **CTI sync** new OpenCTI indicator → IOC store → live blocking.
6. **FP feedback loop** triage dismissed as FP → webhook → tune correlation / suppress pattern.
7. **Daily digest** cases + MTTR summary via n8n.

### Phase 3 acceptance
A Shuffle/n8n workflow can be triggered by a signed Bulwark event and call back via
a scoped service key to open a case, enrich, and contain — idempotently, rate-limited,
and fully audited. Tests cover auth scoping, idempotency replay, and signature verify.

---

## 6. Phase 4 — Bidirectional case federation (close the §10.1 loop)

> **Status: PROPOSED — for review.** Scope drafted from the §10 open decisions +
> the remaining Phase 0–3 gaps; approve/adjust before implementation.

**Goal.** Phases 1–3 made Bulwark a *producer* — push a case out, fire events out,
accept scoped actions in. Phase 4 closes the other half of §10.1: reconcile remote
case state **inbound** so a case worked in TheHive / DFIR-IRIS (or by a SOAR
playbook) stays consistent in Bulwark — **without conflict loops**.

**Design stance (resolves §10.1).** Bulwark stays **authoritative for
detection-derived facts** (subjects, observables, enrichment, origin-risk,
compliance) — a remote can never overwrite those. Remote systems are authoritative
for **workflow state** (status, assignee, analyst notes, task completion). Reconcile
is therefore **field-partitioned**, not last-writer-wins, which *structurally*
removes the conflict-loop risk the original roadmap flagged. Fail-OPEN for the
integration, off the proxy hot path, every change audited.

### 6.1 Add the `sync_status` connector method
`sync_status` appears in the §3.1 *design sketch* but was never implemented — the
shipped `Connector` protocol (`base.py`) declares only `kind` / `test_connection`
/ `push_case`, and later capabilities (`enrich_observable`, `lookup_observable`,
`run_responder`) are added **ad-hoc on the concrete connectors** and called by
duck-typing from the routes. Phase 4 follows that same established pattern rather
than widening the base `Protocol`: add `sync_status` to `thehive` + `dfir_iris`
(no base-protocol change; route-layer `hasattr`/capability check like the Cortex
/ OpenCTI paths already use). Each implementation:
- Reads the remote case by the `remote_id` stored in `integration_link`.
- Returns a normalized `RemoteState` dataclass (status, severity, assignee,
  `closed?`, `last_remote_update`, comments added since `last_synced_at`) — a new
  result type added to `base.py` alongside `PushResult`.
- Is fail-open + circuit-breaker-guarded (reuse `HttpConnectorBase._request`); a
  dead remote yields `None`, never raises.

### 6.2 Reconcile engine (`admin/services/integrations/reconcile.py`)
- Maps remote workflow state → local case through a **whitelist** of reconcilable
  fields only: `status`, `severity` (escalate-only unless configured), `assignee`,
  and remote comments → local notes tagged `source:remote`.
- **Never** touches subjects / observables / enrichment / origin-risk.
- **Never** auto-reopens a locally-`closed`/`resolved` case: a remote reopen becomes
  an audited note + a surfaced `reconcile.conflict` for an operator to adjudicate —
  the hard anti-ping-pong guard.
- Every applied change is audit-logged (`case.reconciled`, actor `integration:<id>`)
  and re-emits the existing lifecycle event webhooks so downstream SOAR sees the
  reconciled state too (loop-safe: reconcile-origin events are marked to avoid
  re-triggering a push back to the same remote).

### 6.3 Two trigger paths (webhook-first, poll-fallback)
- **Inbound webhook receiver** `POST /admin/integrations/inbound/{integration_id}` —
  accepts a remote's case-updated callback, **HMAC-verified** against a per-integration
  inbound secret (`BULWARK_INTEGRATION_<ID>_INBOUND_SECRET` / `_FILE`, mirroring the
  outbound-webhook secret model), **fail-CLOSED on a bad signature** (auth boundary)
  but fail-open on a downstream processing error. Debounced per `remote_id`.
- **Poll fallback**: a `feed_scheduler`-driven periodic `sync_status` sweep of
  linked, non-closed cases (configurable interval, bounded + jittered batch) for
  connectors that cannot push inbound webhooks.

### 6.4 Link store + UI
- Extend `integration_link` with `last_remote_update`, `last_reconciled_at`,
  `reconcile_state` (`synced` | `pending` | `conflict`) — migration **v13**.
- Case-detail UI gains a per-link **Remote sync** strip: state badge, last-synced,
  a pending-conflict banner with an operator **accept remote / keep local** action,
  and a manual **Sync now** button.
- Add `reconcile_state` to the existing
  `GET /admin/integrations/push/case/{id}/links` output.

### 6.5 Endpoints + RBAC
| Method + Path | Auth | Purpose |
|---------------|------|---------|
| `POST /admin/integrations/sync/case/{case_id}` | `integrations:write` (session **or** service-account) | Manual reconcile trigger |
| `POST /admin/integrations/inbound/{integration_id}` | HMAC (no session) | Remote lifecycle callback |
| `POST /admin/integrations/sync/case/{case_id}/resolve-conflict` | `integrations:write` | Operator adjudication of a `conflict` |

### Phase 4 acceptance
A case pushed to TheHive/IRIS, then progressed or closed remotely (or by a
playbook), reconciles back into Bulwark: status/assignee/notes update, detection
facts stay untouched, a locally-closed case is never silently reopened, and every
reconcile is audited + re-emitted. Tests mock the remote REST (pytest-httpx) for
status-change, remote-close, comment-sync, the local-closed-vs-remote-open conflict,
HMAC verify (valid + forged), and webhook-vs-poll parity.

---

## 7. Phase 5 — Threat-intel federation: MISP + STIX/TAXII + sightings

> **Status: 7.1 MISP connector ✅ · 7.2 TAXII 2.1 feeds ✅ · 7.3 Sighting feedback
> loop ✅ · 7.4 Config/docs ✅ — Phase 5 DELIVERED.** STIX 2.1 as plain dicts,
> MISP + TAXII over raw `httpx` (no `pymisp`/`taxii2-client`/`stix2`); TLP-gated,
> admin-side, off the hot path, fail-open.

**Goal.** Phase 2 made Bulwark a CTI *consumer* (OpenCTI pull/lookup, Cortex
enrich). Phase 5 makes it a bidirectional CTI *citizen*: consume standards-based
feeds (MISP, TAXII 2.1), contribute back sightings + case intel under TLP
governance, and finally promote MISP from a bare `_fetch_misp` pull to a
first-class connector — closing §10.6 and the doc gap for good.

**Design stance.** Standards over SDKs — **STIX 2.1 as plain dicts**, MISP + TAXII
over raw `httpx` (no `pymisp`, `taxii2-client`, or `stix2`). The TLP/PAP gate is
enforced at every outbound boundary (reuse the Phase-2 OpenCTI `TlpGateError`
model). All admin-side, off the hot path, fail-open.

### 7.1 MISP first-class connector (`admin/services/integrations/misp.py`) ✅ DONE
Promote the pull-only `IOCStore._fetch_misp` into a full `Connector`:
- **Pull** (exists) — keep feeding the live IOC store; add attribute→observable-type
  mapping parity with the OpenCTI path.
- **Push** (`push_case`): case → MISP **Event**; observables → **Attributes**
  (type-mapped); `is_ioc` → `to_ids=true`; tags → MISP tags incl. `bulwark:<category>`
  + ATT&CK galaxy; TLP → MISP `tlp:` tag. Idempotent via `integration_link`
  (event UUID = `remote_id`).
- **Lookup** (`lookup_observable`): `/attributes/restSearch` for context (event
  count, tags, sightings) → fold into `enrichment['misp']` with a
  `not_found`/`clean`/`suspicious`/`malicious` verdict; same auto-raise-origin-risk
  path as Cortex/OpenCTI.
- Registry: add `misp` to `INTEGRATION_TYPES` with push + lookup factories + health.

### 7.2 TAXII 2.1 collection feeds (`admin/services/integrations/taxii.py`) ✅ DONE
- **Consume**: poll configured TAXII 2.1 collections (raw httpx, STIX 2.1 envelope),
  parse `indicator` SDOs (reuse the Phase-2 `_parse_stix_indicator_pattern`), drop
  revoked/sub-confidence, upsert into the live IOC store via `feed_scheduler` — a
  vendor-neutral feed source alongside OpenCTI/MISP.
- **Publish** (optional, TLP-gated): expose case STIX bundles (Phase 0
  `export_case --format stix` already builds them) to an outbound TAXII collection.
- SSRF-validate every collection URL (parity with the OpenCTI/MISP fetchers).

### 7.3 Sighting feedback loop (the real bidirectional win) ✅ DONE
When a promoted IOC (Phase 0 → live proxy blocking) actually matches proxy traffic,
report a **sighting** back to the CTI platform so the community sees Bulwark's
telemetry:
- The proxy stamps `metadata.ioc_matches` on each IOC-match block event (zero
  hot-path cost — the atoms were already computed); the admin ingests them into the
  durable store as today. A background `SightingDispatcher`
  (`admin/services/integrations/sighting_dispatcher.py`, mirrors `ReconcilePoller`)
  sweeps freshly-blocked IOC events on an interval, resolves each atom's feed
  provenance (via the IOC store's `source`), and — only for indicators sourced from
  a lookup-capable platform with an enabled connector — reports the sighting to
  OpenCTI (`stixSightingRelationshipAdd`, resolving an active STIX indicator by
  value; never fabricates one) and/or MISP (`/sightings/add`).
- Fully fail-open, **TLP-gated** (a `TLP:RED`-tagged indicator is suppressed, never
  shared to a broader-audience platform), bounded (per-sweep cap + LRU event dedupe
  + Redis watermark so a cold start never replays history). Every outcome
  (`sighting.reported`/`suppressed`/`failed`/`noop`) is audited.
- **No hot-path cost**: the proxy emits its event exactly as today; all sighting
  logic is admin-side / async. `src/` never imports `admin/`.
- Off by default (`BULWARK_SIGHTING_FEEDBACK_ENABLED`); tuned via
  `BULWARK_SIGHTING_{POLL_INTERVAL_SECONDS,SWEEP_LIMIT,MAX_PER_SWEEP}`.

### 7.4 Config, RBAC, docs ✅ DONE
- Connector configs via the existing `data/integrations.json` + `*_FILE` secrets
  model; `integrations:{read,write}` RBAC (unchanged namespace).
- New endpoint: `GET /admin/integrations/{id}/collections` (TAXII); lookup/push reuse
  the generic observable/case routes.
- **Close §10.6 + the standing doc gap**: reconcile `AGENTS.md`,
  `config/feeds/README.md`, and `docs/API-REFERENCE.md` so the MISP/OpenCTI/TAXII
  claims match code exactly.

### Phase 5 acceptance
An analyst can: subscribe a TAXII 2.1 collection and a MISP feed that flow into live
IOC blocking; push a case's observables to MISP as a TLP-tagged event; look an
observable up in MISP; and — when a promoted IOC fires on live traffic — have a
sighting reported back to OpenCTI/MISP automatically, TLP-gated and audited. Tests
mock MISP REST + a TAXII 2.1 server + OpenCTI GraphQL (pytest-httpx) for pull, push
(create + idempotent update), lookup verdicts, TLP-gate refusal, sighting emission,
and SSRF rejection.

---

## 8. Cross-cutting concerns

| Concern | Approach |
|---------|----------|
| **DB migrations** | New tables/columns as migrations **v8+** in `migrations.py` (SQLite + Postgres branches), version-tracked, idempotent. |
| **RBAC** | New namespaces `integrations:{read,write}` and `automation:*` added to `ROLE_PERMISSIONS` (`admin/models/auth.py`). |
| **Secrets** | All connector creds via `*_FILE`; never logged; redacted in health output. |
| **Dependencies** | `httpx` only. No vendor SDKs in core lock. STIX/GraphQL as plain dicts. Any SDK → optional extra. |
| **Tenancy** | Every connector call and observable/task is tenant-scoped via existing `_authorize_subject` evidence checks. |
| **Failure model** | Integrations fail-open (retry + circuit breaker + audited health); proxy stays fail-closed and untouched. |
| **TLP/PAP** | Enforced at connector boundary before any outbound share. |
| **Testing** | Store CRUD, endpoint contracts, export golden files, mocked remote REST/GraphQL (pytest-httpx), auth/idempotency negative tests. Target: keep the suite green (~1,300 tests). |
| **Docs** | Update `AGENTS.md` (routes/services tables), `docs/API-REFERENCE.md`, and reconcile the MISP/OpenCTI feed claim. |

---

## 9. Suggested sequencing

```
Phase 0  Observables · Tasks · Templates · Tags/TTP · Manual timeline · STIX/TheHive/IRIS export
   └─> unblocks everything; valuable standalone
Phase 1  Connector protocol + registry + health UI · TheHive push · DFIR-IRIS push · event-webhook
Phase 2  Cortex analyzers/responders · OpenCTI pull (fix feed gap) + push + lookup
Phase 3  Service-account auth + idempotency · signed triggers · Shuffle/n8n playbooks
Phase 4  Bidirectional case federation · sync_status · field-partitioned reconcile · inbound HMAC webhook + poll
Phase 5  MISP first-class connector · TAXII 2.1 feeds · STIX publish · sighting feedback loop (TLP-gated)
```

Each phase ships behind config flags (off by default), is independently testable,
and leaves the proxy hot path untouched. Phases 0–5 are delivered (§2–§7).

---

## 10. Open decisions (need product input)

1. **Case source of truth** once TheHive/IRIS are live: does Bulwark remain
   authoritative (push-only) or do we reconcile status inbound (bidirectional)?
   Bidirectional is more work and risks conflict loops. *(Phase 4 §6 proposes a
   field-partitioned resolution — needs sign-off.)*
2. **Observable model depth**: minimal (type/value/tlp/tags) vs richer (kill-chain
   phase, confidence, sightings count).
3. **Templates location**: YAML-in-repo only, or DB-editable per tenant via UI.
4. **Automation auth**: reuse the proxy API-key scheme vs a dedicated admin
   service-account store. *(Resolved in Phase 3.2 — dedicated least-privilege store.)*
5. **OpenCTI**: pull-only (safe, fills feed gap) first, or push observables/sightings
   from day one (needs TLP governance sign-off). *(Pull + push + lookup delivered in
   Phase 2; sightings proposed in Phase 5 §7.3.)*
6. **MISP**: in scope alongside OpenCTI, or defer? (It's already half-referenced in
   docs.) *(Phase 5 §7.1 proposes a first-class MISP connector — needs sign-off.)*
```
