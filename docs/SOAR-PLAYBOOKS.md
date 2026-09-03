# SOAR Playbooks — Runner-Agnostic Automation Reference

> How to wire an external SOAR/automation runner (Shuffle, n8n, Tines, a custom
> script) to Bulwark Gateway's investigation surface. Everything here is
> **runner-agnostic**: it describes the HTTP contract Bulwark exposes, not any one
> product's node graph.

Bulwark closes the loop in two directions:

```
                    ┌──────────────────────────────────────────┐
   case lifecycle   │  Bulwark Admin (:8090)                    │
   ────────────────▶│  event-webhook dispatcher (signed, OUT)   │──▶ SOAR runner
                    │                                            │      │
   scoped action    │  investigation action API (bwk_sa_, IN)   │◀─────┘
   ◀────────────────│  idempotent · rate-limited · audited      │
                    └──────────────────────────────────────────┘
```

1. **Trigger (outbound)** — Bulwark POSTs a signed JSON event to your runner when a
   case opens, escalates, or resolves.
2. **Act (inbound)** — your runner calls back with a scoped **service-account key**
   to open/enrich/contain, idempotently and under a per-key rate budget.

Both directions are **fail-open** on Bulwark's side: a dead webhook endpoint never
blocks case management, and the proxy hot path is never touched.

---

## 1. Prerequisites

| Step | Where | Notes |
|------|-------|-------|
| Mint a service-account key | **Govern → Service Accounts** (`/service-accounts`) or `POST /admin/service-accounts/` | Grant only the permissions the playbook needs. Copy the `bwk_sa_…` key once. |
| (GitOps) seed keys at boot | `BULWARK_SERVICE_ACCOUNTS_SEED` (+ `_FILE`) | JSON array; operator supplies the plaintext key so the SOAR side matches out-of-band. |
| Register an event webhook | **Investigate → Integrations** (`/integrations`) or `POST /admin/integrations/webhooks` | Set an HMAC secret to verify authenticity. |
| (optional) Register a case-mgmt connector | `POST /admin/integrations` (`thehive` / `dfir_iris` / `cortex` / OpenCTI) | For push, enrich, lookup, respond. |

### Least-privilege permissions

A service account may hold only these (`AUTOMATION_GRANTABLE_PERMISSIONS`):

```
investigation:read   investigation:write
integrations:read    integrations:write
correlation:read     correlation:write
iocs:read            iocs:write
automation:respond
```

`automation:manage` is **not** grantable — a playbook key can never mint or manage
service accounts (including itself). Match each playbook below to the smallest set:

| Playbook does… | Needs |
|----------------|-------|
| Create/mutate cases, notes, observables, tasks | `investigation:write` |
| Run origin-risk / notify response actions (`/respond`) | `automation:respond` |
| Promote an observable to the IOC database | `investigation:write` (+ `iocs:write` if you also call IOC APIs directly) |

> **Push to TheHive/IRIS/OpenCTI is session-only.** `POST /admin/integrations/push/case/{id}`
> requires `integrations:write` via an **operator session** — it is deliberately
> *not* wired for service-account keys. A playbook drives external ticketing via
> its own connector node (e.g. n8n's Jira node), not via Bulwark's push endpoint.

---

## 2. Inbound: calling the action API

### 2.1 Authentication

Present the key as a bearer token:

```
Authorization: Bearer bwk_sa_<hex>
```

Status codes on the service-account path:

| Code | Meaning |
|------|---------|
| `401` | Unknown, disabled, or expired key |
| `403` | Valid key, but missing the required permission |
| `429` | Per-key rate limit exceeded (see §2.3) |

### 2.2 Idempotency (retry-safe)

Retried playbook steps must not double-execute. Send an **`Idempotency-Key`** header
(any stable unique string — a UUID per logical step) on mutating calls:

```
Idempotency-Key: 5f3c…-open-case
```

Rules:

- Engages **only** for a `bwk_sa_` request, on `POST`/`PUT`/`DELETE` under
  `/admin/investigation`, carrying the header.
- Scope is **per-credential × method × path × key** (the key hash namespaces it),
  with a **24h TTL**. Only `2xx` responses are cached.
- A replayed request returns the original response body + status stamped
  `Idempotency-Replay: true`, **without re-running the handler**.
- **Fail-open**: any storage error degrades to normal execution — the action still
  runs.

**Best practice:** derive the key deterministically from the trigger, e.g.
`{event_id}:{step-name}`. That way an at-least-once webhook delivery + a runner
retry both collapse to a single action.

### 2.3 Rate limits

Every authenticated service-account call consumes one token from a **60-second
sliding window**. Over budget →

```
HTTP/1.1 429 Too Many Requests
Retry-After: 60
```

and a `service_account.rate_limited` audit record is written instead of executing.
The limit is the account's `rate_limit_rpm` override, else
`BULWARK_AUTOMATION_RATE_LIMIT_RPM` (default `120`). A per-key value of `0` opts the
key out. Honour `Retry-After` in your runner's retry policy.

### 2.4 Action endpoints

All paths are under `/admin/investigation`. `(auto)` = accepts a service-account key.

| Action | Method + Path | Permission | Key body fields |
|--------|---------------|------------|-----------------|
| Create case | `POST /cases` | `investigation:write` | `title` (req), `severity?`, `summary?`, `tenant?`, `template_id?` |
| Set case state | `POST /cases/{id}/state` | `investigation:write` | `status?`, `severity?`, `assignee?` (≥1 required) |
| Add note | `POST /cases/{id}/note` | `investigation:write` | `text` (req) |
| Link subject | `POST /cases/{id}/subject` | `investigation:write` | `subject_type` (incident/origin/session), `subject_key` |
| Set tags | `POST /cases/{id}/tags` | `investigation:write` | `tags[]` |
| Add timeline entry | `POST /cases/{id}/timeline` | `investigation:write` | `text`, `event_ts?` |
| Add observable | `POST /cases/{id}/observables` | `investigation:write` | `type` (ip/domain/url/hash/email/filename/user/other), `value`, `is_ioc?`, `tlp?`, `pap?`, `tags?`, `source?` |
| Promote observable → IOC | `POST /cases/{id}/observables/{obs}/promote-ioc` | `investigation:write` | — |
| Enrich observable (Cortex) | `POST /cases/{id}/observables/{obs}/enrich` | `investigation:write` | `integration_id`, `analyzer_ids[]`, `tlp?` |
| Lookup observable (OpenCTI) | `POST /cases/{id}/observables/{obs}/lookup` | `investigation:write` | `integration_id` |
| Run responder (Cortex) | `POST /cases/{id}/observables/{obs}/respond` | `investigation:write` | `integration_id`, `responder_id`, `tlp?` |
| Add task | `POST /cases/{id}/tasks` | `investigation:write` | `title`, `assignee?`, `due_at?` |
| Set task state | `POST /cases/{id}/tasks/{task}/state` | `investigation:write` | `status?` (todo/in_progress/done/cancelled), `assignee?`, `due_at?` |
| **Respond (risk/notify)** | `POST /respond` | **`automation:respond`** | `action` (raise_risk/clear_risk/notify), `scope_type?`, `digest?`, `amount?` (0–10), `severity?`, `note?`, `case_id?` |

Enums: severity = `low|medium|high|critical`; case status =
`open|investigating|contained|resolved|closed`; TLP/PAP = `red|amber|green|white`.
All case access is tenant-scoped (a cross-tenant id returns `404`, never leaking
existence).

---

## 3. Outbound: consuming event webhooks

### 3.1 Envelope

Bulwark POSTs this JSON on case lifecycle transitions:

```json
{
  "schema_version": "1.0",
  "event": "case.severity_raised",
  "event_id": "evt_1a2b3c4d5e6f7a8b",
  "timestamp": "2026-01-01T12:00:00+00:00",
  "tenant": "default-corp",
  "data": {
    "case_id": "case_…",
    "title": "Repeated exfiltration from origin …",
    "severity": "high",
    "status": "investigating",
    "from_severity": "medium",
    "to_severity": "high"
  }
}
```

Event types and their extra `data` fields:

| `event` | Fires when | Extra `data` |
|---------|-----------|--------------|
| `case.opened` | A case is created | — (base fields only) |
| `case.severity_raised` | Severity **escalates** only | `from_severity`, `to_severity` |
| `case.resolved` | Status transitions **into** `resolved` only | `from_status` |
| `test.ping` | You click "Test" | `message` (tenant is `null`) |

Base `data` on every case event: `case_id`, `title`, `severity`, `status`.

### 3.2 Delivery headers

```
Content-Type:        application/json
X-Bulwark-Event:     case.severity_raised
X-Bulwark-Delivery:  evt_1a2b3c4d5e6f7a8b
X-Bulwark-Signature: sha256=<hex>        # only when a signing secret is set
```

Deliveries are best-effort, fan out concurrently, and time out at **5s** each — a
slow endpoint never delays case management. Treat delivery as **at-least-once** and
dedupe on `event_id` (or use it in your `Idempotency-Key`).

### 3.3 Verifying the signature

The signature is `HMAC-SHA256(secret, raw_request_body)` in lowercase hex, prefixed
`sha256=`, computed over the **exact bytes** Bulwark POSTed. Verify against the raw
body (do not re-serialize):

```python
import hashlib
import hmac

def verify(raw_body: bytes, header: str, secret: str) -> bool:
    if not header or not header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header[len("sha256="):])
```

The secret is resolved from `BULWARK_INTEGRATION_WEBHOOK_<ID>_SECRET` (or its
`_FILE` variant) in preference to the inline value, and is write-only — the API
never echoes it back (only a `has_secret` flag).

---

## 4. Reference playbooks

Each is a runner-agnostic recipe: **trigger → steps → Bulwark calls**. Wire the
steps into your runner of choice. Use a deterministic `Idempotency-Key` derived from
the trigger's `event_id` on every mutating call.

### 4.1 Auto-open case
**Trigger:** an out-of-band alert (e.g. correlation crosses BLOCK, or your own
threshold on the Prometheus `bulwark_correlation_*` counters).
**Steps:**
1. `POST /cases` with `title`, `severity`, `summary`, `tenant` (optionally a
   `template_id` to seed tasks/tags).
2. `POST /cases/{id}/subject` linking the offending `origin` or `session`.
3. `POST /cases/{id}/note` recording the triggering signal.

`Idempotency-Key: {event_id}:open` makes a duplicate alert collapse to one case.

### 4.2 Auto-enrich
**Trigger:** `case.opened` webhook.
**Steps:**
1. For each indicator, `POST /cases/{id}/observables` (`type`, `value`).
2. `POST …/observables/{obs}/enrich` (Cortex `integration_id` + `analyzer_ids`)
   and/or `POST …/observables/{obs}/lookup` (OpenCTI `integration_id`).
3. If a verdict is malicious, `POST …/observables/{obs}/promote-ioc` and let the
   auto origin-risk raise fire (enrich/lookup already bump linked origins on
   malicious). Optionally `POST /cases/{id}/state` to raise severity.

### 4.3 Auto-contain (repeated exfil origin)
**Trigger:** `case.severity_raised` to `high`/`critical` on an exfiltration case.
**Steps:**
1. `POST /respond` with `action=raise_risk`, `scope_type`/`digest` of the origin,
   `amount` (0–10), `case_id` — hardening it toward BLOCK on the proxy.
   *(requires `automation:respond`)*
2. `POST /respond` with `action=notify`, `severity`, `note` to page the war-room.
3. `POST /cases/{id}/state` → `status=contained`.

### 4.4 Ticketing
**Trigger:** `case.opened` (or `case.severity_raised`) at high severity.
**Steps:** create a Jira/ServiceNow ticket **in your runner** (native node), then
`POST /cases/{id}/note` back into Bulwark with the ticket URL for traceability.
*(Bulwark's own case push to TheHive/IRIS is operator-driven, not automated — see §1.)*

### 4.5 CTI sync
**Trigger:** a new OpenCTI indicator (polled by your runner) **or** an enrich/lookup
verdict inside a case.
**Steps:** `POST …/observables/{obs}/promote-ioc` (or your `iocs:write` integration)
so the indicator becomes live-blocking in the proxy IOC scanner.

### 4.6 FP feedback loop
**Trigger:** an analyst dismisses a case as a false positive (your runner watches a
`case.resolved` webhook where the resolution note tags it FP).
**Steps:** `POST /cases/{id}/note` recording the disposition, then feed your tuning
process (e.g. disable a pattern via `/admin/guardrails` or lower a correlation
threshold via `/admin/correlation/config`) — both operator-gated, so route through a
human-approval node.

### 4.7 Daily digest
**Trigger:** a scheduler in your runner (cron).
**Steps:** `GET /admin/investigation/cases/stats` and
`GET /admin/investigation/cases/analytics` (MTTR, opened-vs-resolved), format, and
post to Slack/Teams/email. *(reads need `investigation:read`)*

---

## 5. Operational notes

- **Audit trail.** Every service-account action is audited (actor
  `service-account:<id>`), as are rate-limit rejections
  (`service_account.rate_limited`). Review under **Govern → Audit Log**.
- **Revocation.** Disable a key instantly from **Govern → Service Accounts**
  (toggle) — the next call gets `401`. Delete removes it permanently.
- **Rotation.** Mint a new key, update the runner, then disable the old one. Seeded
  keys rotate by changing the `key` in `BULWARK_SERVICE_ACCOUNTS_SEED` (a new hash =
  a new account; retire the old one).
- **Testing.** Use **Test** on a webhook subscription to fire a synthetic
  `test.ping` (ignores filters/enabled). It carries a real signature, so it doubles
  as a signature-verification check for your receiver.
