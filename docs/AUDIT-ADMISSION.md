# Pre-Upstream Audit Admission

Opt-in corporate fail-closed admission to the existing durable telemetry queue.
The helper in `src/telemetry/admission.py` is wired into the chat proxy before
every upstream attempt, including streaming and fallbacks. Enforcement remains
opt-in; no deployed configuration has been changed.

## Configuration Contract

| Setting | Default | Meaning |
|---|---|---|
| `BULWARK_AUDIT_ADMISSION_REQUIRED` | `false` | Deny forwarding unless pre-upstream evidence is durably accepted |
| `BULWARK_AUDIT_ADMISSION_TIMEOUT_MS` | `250` | Admission decision budget; integer, 1..10000 ms |

Settings validates the timeout at load time. Helm exposes these under
`telemetry.auditAdmission.required` and `timeoutMs`, rejecting required admission
with disabled telemetry or legacy storage.
When required, enable telemetry and either `BULWARK_TELEMETRY_DURABLE=true`
(local single-worker persistent SQLite) or `BULWARK_TELEMETRY_SHARED_OUTBOX=true`
(shared outbox, PostgreSQL for multi-node deployments). A configured destination
must cover the authenticated tenant. The app-state exporter must have completed
startup and remain active. Do not lazily create an exporter on the request path.

This gate is independent of `BULWARK_FAIL_MODE`, `BULWARK_LOG_ALLOWED`, and
`BULWARK_SIEM_REQUEST_AUDIT_ENABLED`. General fail-open settings must not bypass it.
The existing completion-audit middleware remains best effort and is not a
substitute for pre-upstream evidence.

## Exact Wiring

```python
async def admit_before_upstream(
    *,
    required: bool,
    exporter: TelemetryExporter | None,
    authenticated: bool,
    tenant_id: str,
    agent_id: str | None,
    request_id: str,
    timeout_ms: int = 250,
) -> AdmissionFailure | None:
    ...
```

`None` means this gate permits continuing (disabled OR durably admitted), not
that security evaluation returned ALLOW. Any returned reason denies forwarding.
Use authenticated middleware state, never client tenant headers. Request IDs
must be server-generated identifiers, not arbitrary client header values.
Identity fields are bounded ASCII identifiers (1..128 characters, letters,
digits, `_`, `.`, `:`, `-`); an absent agent ID is allowed. The subject itself
is neither passed nor persisted, only its authentication-presence boolean.

The proxy generates `admission_id` independently of client tracing headers and
retains it across fallback attempts. Simplified wiring:

```python
if settings.audit_admission_required:
    reason = await admit_before_upstream(
        required=True,
        timeout_ms=settings.audit_admission_timeout_ms,
        exporter=getattr(request.app.state, "telemetry_exporter", None),
        authenticated=bool(getattr(request.state, "subject_id", None)),
        tenant_id=request.state.tenant_id,
        agent_id=request.state.agent_id,
        request_id=admission_id,
    )
    if reason is not None:
        return JSONResponse(status_code=503, content={"error": {
            "message": "Required audit evidence unavailable",
            "type": "service_unavailable",
            "code": "audit_admission_failed",
        }})
```

Keep the outer flag check so disabled requests do not even inspect exporter or
authentication state. The helper also returns immediately when `required=False`.
Import `admit_before_upstream` from `src.telemetry.admission`.

The gate runs once per outbound attempt after input guards, credentials and SSRF
validation, before the streaming/non-streaming branch (`if is_streaming`) in the
backend-attempt loop. This covers `client.post` and `_handle_streaming`'s eventual
`client.stream`, including every fallback attempt. Never retry another backend
when audit admission rejects. Cached responses that never contact upstream need
no admission. Earlier input blocks remain the responsibility of detection and
completion telemetry. This is not an audit of every inbound HTTP request.

Do not catch `CancelledError` and continue forwarding. Do not dispatch admission
as fire-and-forget, put it after `client.post`, or place it solely inside the
stream generator after HTTP response headers have been sent. Add route-level
tests assert zero upstream calls on rejection for both response modes and
fallbacks, and assert an internal ID distinct from external trace IDs.

## Evidence And Failures

The fixed record uses `event.kind=event`, `event.category=web`,
`event.action=upstream_admission`, `event.outcome=unknown`, and
`bulwark.verdict=not_evaluated`. It carries only authenticated tenant/agent IDs,
a server-generated request ID and generated event ID/timestamps. No body, tool
arguments, model name, source IP, subject, URL/path/query, credentials, or body
hash are accepted as inputs or recorded. Each call creates a distinct event;
request ID correlates fallback attempts, not deduplication of separate admissions.

Stable failure reasons:

| Reason | Meaning |
|---|---|
| `audit_admission_invalid_config` | Invalid timeout budget |
| `audit_admission_invalid_context` | Missing authentication or invalid bounded identifiers |
| `audit_admission_unavailable` | Missing/inactive/uninitialized exporter or unexpected queue error |
| `audit_admission_not_durable` | Memory/legacy best-effort queue cannot prove persistence |
| `audit_admission_no_route` | No applicable registered tenant destination |
| `audit_admission_rejected` | Queue did not explicitly return True, including full/busy/unavailable storage |
| `audit_admission_timeout` | Admission did not confirm within the decision budget |

The helper does not log exception details or emit a second rejection event into
the failing queue. Callers may count or log the fixed reason, never exception
text, credentials, request data, or backend URLs. Existing queue/outbox counters
remain authoritative for their respective scopes; this helper adds no global
mutable state. It uses the injected exporter's existing lifecycle/queue/route
state directly, avoiding changes to shared exporter and queue code.

## Timeout And Durability

Only queue admission is awaited, never transport delivery, remote health, or SIEM
indexing. An open remote circuit does not prevent admission while the durable
store has capacity. No remote service is probed and no DB is initialized here.

`asyncio.wait_for` cancels the admission on expiry. Existing queue/outbox code
retains its bounded writer lock until an in-flight SQLite thread/DB operation
finishes. Consequently the timeout is a decision budget, **not a hard HTTP
response-time bound**. Cancellation cleanup can exceed it; this avoids releasing
the lock early and accumulating unbounded background writes. The helper also
rejects late success if a queue implementation suppresses cancellation.

A timeout, disconnect or cancellation may leave committed evidence even though
no request was forwarded. This is safe and intentional. Do not delete this row
or reinterpret it as an ALLOW or as proof of upstream execution. Cancellation
propagates without a success result. There is no atomic transaction spanning
the DB commit and an HTTP backend call, nor an exactly-once forwarding guarantee.

Persistence is only as durable as the configured volume/database WAL policy.
This does not guarantee retention after exporter acknowledgement, SIEM indexing,
power-loss survival on unsuitable storage, HA from a local SQLite file, or
unlimited availability during an outage. Size count/byte budgets with room for
WAL/index overhead; provision retention at the eventual audit destination.
See `DURABLE-TELEMETRY.md` and `SHARED-OUTBOX.md` for storage limits.

## Verification

`tests/test_audit_admission.py` exercises real temporary local/shared SQLite,
counts, restart identity, full/busy/closed/uninitialized storage, scoped routes,
shared-outbox mocks, off-mode inertness, invalid/adversarial identities, sanitized
failures, remote-circuit independence, timeouts and repeated cancellation during
a real threaded SQLite append. It never opens the operator database or calls a
remote transport. Live PostgreSQL, power loss, SIEM indexing and actual proxy
wiring are outside these helper tests.
