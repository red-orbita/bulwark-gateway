# Attachment API

The router in `src/routes/attachments.py` admits bounded binary uploads for the
existing asynchronous attachment service. It never parses documents in an HTTP
handler, retrieves external URLs, returns raw files, or forwards file IDs upstream.
No multipart dependency, new configuration singleton, or content cache is added.

## Primary Integration

The proxy now registers this router, owns its opt-in lifecycle and resolves local
references before inline attachment/input inspection. Configuration and remaining
deployment limits are documented in [Async Attachments](ASYNC-ATTACHMENTS.md).
The integration uses:

```python
from src.routes.attachments import router as attachment_router
from src.routes.attachments import resolve_chat_attachments

app.include_router(attachment_router)  # Already prefixed /v1/attachments
# During enabled-service startup, after successful initialization:
app.state.attachment_service = attachment_service
# The lifespan owner starts/stops the service and owns its store lifecycle.
```

Exact helper signature:

```python
async def resolve_chat_attachments(body: dict, request: Request) -> dict:
    ...
```

In the chat handler, after bounded (10 MiB maximum) JSON parsing/shape validation
and authentication, but BEFORE the existing inline/native attachment helper,
input DLP, input scanning, and upstream body construction:

```python
body = await resolve_chat_attachments(body, request)
```

Propagate its `HTTPException` as a rejection, never catch it and forward the
original body. Keep the existing strict attachment guard: this helper does not
authorize provider file IDs, inline/native files, alternate attachment fields, or
malformed chat envelopes. Ordinary strings containing `att_` are not references.

All routes must remain behind the proxy's auth and rate-limit middleware. Auth
must populate nonempty, bounded strings in `request.state.tenant_id`, `agent_id`,
and `attachment_owner`. Strict authentication computes ownership as `jwt:` plus
the full SHA-256 of the verified subject, or `api:` plus the full API-key SHA-256.
It does not reuse the correlation subject's truncated prefix. This prevents
cross-owner access for JWT subjects sharing a prefix or colliding with API-key
identifiers. Development/auth-disabled mode does not establish ownership.
The owner is NOT `body.user`, browser claims, or a subject header. Clients
sharing one credential share its attachment ownership; use separate credentials
for separate ownership. A fast local `service.current_policy(tenant, agent)` must
return a current policy tuple for a known, authorized agent or `None`.

When the service is enabled, CORS extends the explicit method allowlist from
`["POST"]` to `["POST", "GET", "DELETE"]` for upload, polling, and deletion;
retain the configured origin allowlist and existing `Authorization`,
`Content-Type`, `X-Tenant-ID`, and `X-Agent-ID` headers. Browser preflight must be
handled without requiring an actual request credential, while the subsequent
request still requires auth. Do not introduce a browser identity/owner header.
`Content-Length` is browser-controlled; no JavaScript header is needed for it.
CORS executes before authentication so permitted preflights succeed without
credentials, while actual requests and their errors remain authenticated and
carry the configured CORS headers. Tenant request-byte quotas reach the bounded
upload reader; model/token quotas do not parse binary uploads or prevent deletion.
Rate and concurrency quotas still apply.

Previously created development attachment rows using the old truncated owner
are intentionally not aliased: re-upload under the new identity. Such aliasing
would recreate the ownership vulnerability. Old rows expire under their TTL.

Absent `app.state.attachment_service` (or `None`) means routes and local reference
resolution return `404 not_found`. No references means the helper remains inert
without needing a service or identity lookup.

## Upload And Status

`POST /v1/attachments` takes **raw request bytes**, not JSON/base64 or multipart.
Supply one `Content-Type` header. Supported media types:

- `text/plain`, `text/markdown`, `text/csv`, `application/json`
- `image/png`, `image/jpeg`, `application/pdf`
- `application/vnd.openxmlformats-officedocument.wordprocessingml.document`

Media types are case-insensitive and parameters such as `charset=utf-8` are
ignored for MIME selection; the worker's text decoder still requires UTF-8.
Compressed HTTP content encodings are not supported. MIME is an admission hint,
not evidence that the bytes are valid or safe; the worker validates/extracts them.

`Content-Length` is optional for chunked requests, otherwise must be a single
decimal value matching received bytes. Duplicate/ambiguous lengths, simultaneous
Content-Length and Transfer-Encoding, empty uploads, and truncated uploads are
rejected. The stream has a 10-second receive deadline and a hard 2 MiB byte cap,
checked before extending the buffer, including when the length is absent or false.
Effective global/agent text and document limits can lower that cap and are checked
again after receipt. The worker also checks limits before extraction.
The handler stops consuming on rejection. Database operations retain the store's
own bounded operation deadlines; 10 seconds is the receive budget, not a total
upload-plus-database latency guarantee.

Success is `202 Accepted` with the store's public metadata, including:

```json
{
  "id": "att_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "state": "queued",
  "mime": "text/plain",
  "policy_revision": "runtime-computed-policy-and-code-fingerprint"
}
```

The example abbreviates metadata. The complete field set is `id`, `state`,
`mime`, `size_bytes`, `sha256`, `text_sha256`, `policy_revision`, `created_at`,
`expires_at`, and `reason`. Creation uses a fresh service policy revision after
receiving the bytes. A queued response is not an approval.

`GET /v1/attachments/{id}` returns only this public metadata. Poll `state`; only
`approved` is resolvable. `review_required` is NOT permission to release content
and this API offers no manual approval bypass. Public `reason` is the store's
fixed-code projection, not arbitrary internal diagnostics.

`DELETE /v1/attachments/{id}` returns an empty `204` after scoped deletion.
Unknown, expired, malformed, or differently owned IDs return `404` (including
repeat deletion). Successful upload/status/delete responses use
`Cache-Control: no-store`. There is no list, download, or `/content` endpoint.

## Chat References

Only this exact block is resolved, in every message role:

```json
{
  "type": "file",
  "file": {
    "file_id": "att_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  }
}
```

No `filename`, `file_data`, body identity, or extra block/file keys are allowed on
a local reference. IDs require `att_` plus exactly 64 lowercase hexadecimal
characters. Malformed local references are rejected rather than passed through.
Other provider IDs and inline/native formats remain unchanged for the existing
strict helper to accept or deny; they are not silently authorized here.

At most five references are allowed across all messages, counting repetitions.
The total extracted UTF-8 text is capped at 65,536 bytes, also counting repeated
references. Effective global/agent count and total-text limits can lower these
caps. Every resolution calls `store.resolve` with authenticated
tenant/agent/owner and a fresh policy revision. That store checks scope, TTL,
`approved` state, revision, and extracted-text SHA-256 before returning text.
Policy changes during the resolution batch reject the batch.

The helper substitutes `{"type": "text", "text": "...approved text..."}` in a
deep copy. The input body is never mutated, including on partial failure. No
cross-request or cross-tenant resolution cache exists. Resolved text still passes
through the regular chat guardrails; approval is not a bypass for later policy
checks or a guarantee about an LLM's response.

## Errors

Responses contain a fixed safe `detail` code, never raw bytes, extracted text,
database paths, provider diagnostics, or credentials.

| Status | Detail / Meaning |
| --- | --- |
| 400 | `invalid_length`, `empty_body`, `incomplete_body`, `invalid_body`, `invalid_attachment_reference` |
| 401 | `unauthorized`: required server-derived identity missing or invalid |
| 404 | `not_found`: absent service/agent, invalid ID, missing/expired/cross-scope document |
| 408 | `upload_timeout`: receive deadline exceeded |
| 409 | `not_ready` or `policy_changed` |
| 413 | `too_large`: raw bytes, reference count, or aggregate text cap exceeded |
| 415 | `unsupported_media_type`: missing/duplicate/unsupported MIME or content encoding |
| 429 | `capacity` or `busy` |
| 503 | `unavailable`: storage/provider failure, configuration error, or integrity failure |

## Offline Validation

```bash
python3 -m pytest tests/test_attachment_api.py tests/test_attachment_store.py tests/test_attachment_service.py -q
python3 -m ruff check src/routes/attachments.py tests/test_attachment_api.py
```

API tests inject trusted identity state in a small FastAPI ASGI app and use the
real SQLite store and `AttachmentService.process_once()` for synthetic TXT/DOCX.
They cover ownership isolation, strict shapes, bounded streaming, policy changes,
non-approved states, persisted tampering, and no partial mutation. They perform
no downloads, live-service calls, or native OCR/PDF parsing. Full proxy lifecycle,
auth middleware, CORS preflight, and upstream integration remain primary-owned
integration checks rather than claims of this isolated API suite.
