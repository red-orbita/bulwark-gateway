# Investigation Center — Evolution Roadmap & Integration Design

Status: **DRAFT / for review** · Owner: SOC platform · Scope: `admin/` (off proxy hot-path)

This document proposes how to grow the Investigation / Triage / Cases workspace
into a SOC-grade IR platform, and how to prepare Bulwark Gateway to integrate with
**TheHive**, **Cortex**, **DFIR-IRIS**, **OpenCTI**, and automation runners
(**Shuffle**, **n8n**). It is written to be implemented in reviewable slices.

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
    Remaining for later: **push** (SCO/indicator/sighting + TLP, case→report).

### Phase 2 acceptance
An observable can be enriched by Cortex and looked up in OpenCTI with reports
attached; malicious verdicts can auto-raise origin risk; OpenCTI indicators flow
into the live IOC store; MISP/OpenCTI docs match code. Tests mock analyzer jobs +
GraphQL responses.

---

## 5. Phase 3 — Automation loop (Shuffle / n8n / SOAR)

Two directions close the loop.

### 5.1 Outbound triggers
The Phase 1 event-webhook is the workflow trigger surface. Add per-event payload
schemas (stable, versioned) and HMAC signing so Shuffle/n8n can verify authenticity.

### 5.2 Inbound Action API + service-account auth
Playbooks need to act back. The verbs already exist (`/respond`,
`/triage/state`, `/triage/note`, cases CRUD, observables, tasks). What's missing:

- **Service-account auth** distinct from the session cookie: a scoped API key /
  service JWT with a dedicated `automation:*` permission namespace (least-privilege;
  e.g. a playbook token that may `investigation:write` + `automation:respond` but
  not manage users). Keys minted/revoked in the UI, stored hashed, `*_FILE` seedable.
- **Idempotency-Key header** honored on all mutating automation endpoints (dedupe
  retried playbook steps) — backed by a small `automation_idempotency` table with TTL.
- **Rate limits + audit** on the automation surface (reuse audit logger; per-key rpm).

### 5.3 Reference playbooks (documented, runner-agnostic)
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

## 6. Cross-cutting concerns

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

## 7. Suggested sequencing

```
Phase 0  Observables · Tasks · Templates · Tags/TTP · Manual timeline · STIX/TheHive/IRIS export
   └─> unblocks everything; valuable standalone
Phase 1  Connector protocol + registry + health UI · TheHive push · DFIR-IRIS push · event-webhook
Phase 2  Cortex analyzers/responders · OpenCTI pull (fix feed gap) + push + lookup
Phase 3  Service-account auth + idempotency · signed triggers · Shuffle/n8n playbooks · status reconcile
```

Each phase ships behind config flags (off by default), is independently testable,
and leaves the proxy hot path untouched.

---

## 8. Open decisions (need product input)

1. **Case source of truth** once TheHive/IRIS are live: does Bulwark remain
   authoritative (push-only) or do we reconcile status inbound (bidirectional)?
   Bidirectional is more work and risks conflict loops.
2. **Observable model depth**: minimal (type/value/tlp/tags) vs richer (kill-chain
   phase, confidence, sightings count).
3. **Templates location**: YAML-in-repo only, or DB-editable per tenant via UI.
4. **Automation auth**: reuse the proxy API-key scheme vs a dedicated admin
   service-account store (recommended: dedicated, least-privilege).
5. **OpenCTI**: pull-only (safe, fills feed gap) first, or push observables/sightings
   from day one (needs TLP governance sign-off).
6. **MISP**: in scope alongside OpenCTI, or defer? (It's already half-referenced in docs.)
```
