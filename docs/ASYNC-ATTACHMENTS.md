# Async Attachment Worker

`src/attachments/service.py` supplies a worker over the existing attachment
store. It does not register routes, change configuration, start native services,
call an LLM, download models, export telemetry, or perform upstream requests.
Application/API integration owns authentication, tenant/agent/owner derivation,
upload admission, allowed roles, and resolution into untrusted message content.

## Application Wiring

The proxy now registers the router and starts/stops the service through
`src/attachments/runtime.py`. It remains disabled by default. Enable with
`BULWARK_ATTACHMENT_SERVICE_ENABLED=true`, `BULWARK_WORKERS=1`, and an explicit
`BULWARK_ATTACHMENT_SERVICE_DB_URL_FILE` containing a dedicated SQLite or PostgreSQL
URL. Missing/invalid configuration fails startup without a fallback database.
SQLCipher URLs are rejected: this storage engine does not implement encryption.
Storage encryption, backup retention and access controls are operator obligations.

Each authorized agent additionally needs `attachments.async_enabled: true` in its
policy. Text formats are then available; DOCX additionally requires
`attachments.extract_documents: true`. PNG/JPEG/PDF require that agent flag plus
global `BULWARK_ATTACHMENT_EXTRACT_DOCUMENTS=true`, confirmed parser isolation and
the preprovisioned native tools/work directory described below. No downloads occur.

Runtime approvals bind to effective DLP, allowed formats, attachment limits,
OCR languages and a startup fingerprint of attachment/guardrail Python sources.
The offline scanner does not use dynamic Redis patterns. Native tool/language-data
versions are not fingerprinted; deploy immutable parser assets and do not replace
them in place while retaining approvals. This is not an artifact attestation.

Runtime limits take the stricter global/agent value: `max_file_bytes` for text
uploads, `max_document_bytes` for binary uploads, `max_total_bytes` for extracted
text and each reference batch, and `max_attachments` for reference count. Limits
are checked before buffering, after receipt, before worker extraction and during
resolution. Existing inline-attachment limits remain separate for mixed requests.
The store additionally caps raw bytes at 2 MiB and approved text at 32 KiB.

| Environment Suffix (`BULWARK_`) | Default | Purpose |
| --- | --- | --- |
| `ATTACHMENT_SERVICE_MAX_DOCUMENTS` | 100 | Retained document count |
| `ATTACHMENT_SERVICE_MAX_BYTES` | 33554432 | Accounted storage, including base64 and metadata overhead |
| `ATTACHMENT_SERVICE_MAX_PER_TENANT` | 20 | Retained documents per tenant |
| `ATTACHMENT_SERVICE_TTL_SECONDS` | 3600 | Database-clock expiration |

The current application profile requires one worker and operationally one replica;
it does not claim multi-node availability. Helm wiring now supports a dedicated
SQLite PVC or the validated shared PostgreSQL outbox TLS snapshot, with one
worker/replica, Recreate rollout and readiness gating. Live PostgreSQL validation
remains pending. See `CHATBOT-HELM.md`. `tests/test_attachment_runtime.py`
exercises local SQLite lifecycle, upload/processing/chat boundaries, policy
invalidation, scope isolation, deletion, expiry and size limits. Its upstream and
identity middleware are test doubles. `tests/test_attachment_auth.py` additionally
uses actual application middleware and JWT/API-key verification (only JWT
revocation storage is mocked). The native HTTP lab uses actual API-key auth and
parsers, but still a deterministic simulated LLM backend.

## Public Contract

```python
AttachmentService(
    store: AttachmentStore,
    *,
    policy_provider: Callable[[str, str], tuple[str, InputDlpPolicy] | None],
    work_dir: Path | None = None,
    parser_isolation_confirmed: bool = False,
    languages: str = "eng",
    poll_seconds: float = 0.2,
    allowed_mimes_provider: Callable[[str, str], frozenset[str]] | None = None,
    attachment_policy_provider: Callable[[str, str], AttachmentPolicy] | None = None,
)
async start() -> None
async stop() -> None
async process_once() -> bool
current_policy(tenant: str, agent: str) -> tuple[str, InputDlpPolicy] | None
accepts_mime(tenant: str, agent: str, mime: str) -> bool
attachment_policy(tenant: str, agent: str) -> AttachmentPolicy
upload_limit(tenant: str, agent: str, mime: str) -> int
```

`start()` initializes the store before starting exactly one worker task; repeated
starts while running are idempotent. `stop()` cancels and awaits that task,
drains parsing/scanning, then calls the store's public `close()`. The application
must drain API callers before closing the shared store. A closed store/service is
not restartable; create new instances. For manual `process_once()` use, initialize
the store first. A concurrent call returns `False` instead of queuing more work.
`ready` starts false, becomes true only after successful startup, and is false
throughout shutdown, on startup failure, or when the worker exits.
Storage failures clear readiness until a successful worker iteration; ordinary
store contention does not flap it. Unexpected worker failures are logged as a
fixed code and observed, not left as unhandled task exceptions. The public
`/ready/attachments` probe returns 503 when the worker is unavailable, without
tenant/document details. This readiness signal is not a per-request delivery SLA.

`process_once()` claims with `lease_seconds=300`. `True` means it claimed a job,
not that approval or terminal persistence succeeded. `False` means no claim,
already processing, or stopping. Store errors may propagate as safe `StoreError`
codes; the background loop backs off rather than losing its worker. No public
upload/resolve API is called during processing.

The synchronous policy provider must be a fast, local lookup with no I/O. It
returns the current revision and effective DLP policy for the exact tenant/agent,
or `None` when unavailable/removed. No policy or content-result cache is used.
`current_policy()` validates the result and masks exceptions as `unavailable`.
It has no global `policy_revision` property: revisions are scoped provider values.

Before upload, call `current_policy()` and pin its revision in `store.create()`.
Also call `accepts_mime(tenant, agent, mime)` before `store.create()`. Its optional
synchronous local provider returns the current allowed MIME frozenset for that
scope. The default `None` allows all formats supported by this worker; a provider
cannot enable unsupported formats. Invalid results/exceptions become safe
`StoreError("unavailable")`. There is no cache. The worker rechecks format policy
before extraction and before approval; disabled formats require review with
`unsupported_format` and are never passed to a parser.
The worker checks it before extraction, after scanning, and before every finish
attempt. A missing or changed revision produces `review_required` with public
reason `policy_changed`. Immediately before resolving, the API must call the
helper again and pass that revision to the store:

```python
current = service.current_policy(tenant, agent)
if current is None:
    raise StoreError("policy_changed")
text = await store.resolve(
    attachment_id, tenant=tenant, agent=agent, owner=owner,
    policy_revision=current[0],
)
```

Never accept a revision from the client or reuse an upload-time snapshot for
resolution. The integration-owned revision fingerprint must include effective
DLP, allowed-format/extraction flags, scanner rules, conversion changes, and
relevant service-version changes; do not reuse revision
identifiers. Policy reads and database writes are not one atomic transaction:
the fresh resolve check is essential. `store.resolve()` also enforces scope,
TTL, approved state, and text integrity. Identical uploads remain independent
across tenants, agents and owners.

## Processing

The store owns `queued -> processing` claims, integrity verification of raw bytes,
lease fencing, attempt limits, TTL expiry and terminal raw-payload removal.
The worker can finish as `approved`, `blocked`, `review_required`, or `failed`.
Only approved results retain extracted text, at most **32 KiB UTF-8**. Oversized,
empty, invalid UTF-8 or NUL-containing text is not truncated into approval.

Supported inputs:

| MIME | Conversion |
| --- | --- |
| `text/plain`, `text/markdown`, `application/json`, `text/csv` | Strict UTF-8 text, optional UTF-8 BOM removed; no JSON/CSV execution or interpretation |
| DOCX OOXML document MIME | Bounded `extract_docx()` in `asyncio.to_thread` |
| `application/pdf`, `image/png`, `image/jpeg` | Existing native `extract_document()` with `sandbox=True` |

Native parsing requires both `parser_isolation_confirmed=True` and an existing,
absolute operator-controlled `work_dir`. No system-temp fallback is used. The
flag is operator attestation, not proof of deployment isolation; the extractor
still requires Bubblewrap and locally provisioned Poppler/Tesseract/languages.
See [Document Extraction](DOCUMENT-EXTRACTION.md) for isolation requirements.
Unsupported formats and extraction failures require review, not silent approval.

DOCX blocks are flattened as `[DOCX <kind> <index>]` followed by block text,
preserving paragraph/table/header/footer labels. The entire flattened string is
scanned and subject to the output cap, including labels. The store currently
accepts **text only**, not `DocumentText` or structured provenance: hyperlink
counts, skipped-metadata counts, original metadata and structured blocks are not
persisted or exposed. Labels are not authenticated delimiters or trusted roles;
uploaded text can imitate them. Original document bytes are never forwarded.
See [DOCX Extraction](DOCX-EXTRACTION.md) for the conservative supported subset.

Every result passes `input_dlp.inspect_request()`; known secrets block even if
`InputDlpPolicy.enabled` is false. Effective tenant email/phone and blocked-term
settings are additive. No redaction is implemented. DLP detections block with
`input_dlp`; DLP `input_dlp_incomplete` metadata or guardrail
`input_guardrail_budget` events require review with `incomplete`, not an attack
classification. Guardrail detections block with `input_detection`; WARN/REDACT
requires review. Unexpected processor exceptions produce `failed` with
`processor_failed`, never approved text.

`InputGuardrail(offline=True)` scans all text in windows of at most 4096 characters
with 1024-character overlap, capped at 128 windows. Fixed window settings avoid
environment-dependent truncation; the offline registry performs no Redis lookup
and does not use runtime custom patterns or disable/exception overrides. The DLP
engine retains its own bounded full-text/overlapping inspection. Approved text is
never a partially scanned prefix. Overlap is finite and is not a guarantee of
detection of arbitrary cross-window instructions or semantic attacks.

## Budgets And Recovery

- Overall extraction/scanning budget: 240 seconds, shorter than the 300-second lease.
- Native extraction budget: 90 seconds, with the extractor's own child-process limits.
- Terminal persistence: at most five attempts, bounded by 30 seconds, backoff starting at 50 ms.
- Busy/unavailable finishes reuse the scan result without rerunning extraction; each retry rechecks policy.
- Approval capacity failure falls back to review without retaining text.
- Cancellation or exhausted finish retries leave the lease intact. The store may reclaim it after expiry, or require review after its attempt ceiling. No immediate requeue occurs during shutdown.
- Deleted/expired/stolen leases cannot be completed by the old worker; `finish(False)` is not retried.

Python threads cannot be forcibly cancelled. DOCX and scanning run off the event
loop; timeout/cancellation retains the service's single processing slot until the
thread finishes, even on repeated cancellation. Native extraction owns and reaps
its children on cancellation. Thread deadlines are cooperative: an individual
parser/regex call can overrun the budget and delay shutdown, but its late result
cannot be approved. The store fences expired leases; separate replicas can reclaim
an expired job while a stuck old thread drains. This is bounded concurrency per
service instance, not a distributed CPU admission limit or hard thread-kill SLA.

The worker emits no document bodies, scanner matches, parser diagnostics, DSNs,
or exception strings to logs. Every terminal reason uses the store's fixed public
code allowlist, exposed as `reason` in status. Success uses `approved`; extraction
maps to `no_text`, `incomplete`, `extraction_unavailable`, `unsupported_format`,
or `unsafe_document`. Time/window/size exhaustion and approval-capacity failure
use `incomplete`. Structured provenance is not implemented here.

## Validation

Validate middleware ownership/CORS/quota behavior, Helm storage/probes and actual
authenticated HTTP upload/processing/chat using synthetic data in an isolated
environment. A pre-forward `429 busy` is not approval. Bound retries to explicitly
retryable outcomes; never blindly repeat an ambiguously successful upload.
Native extraction, database parity and deployment behavior require separate tests.

`tests/test_attachment_service.py` uses real SQLite via the shared database
abstraction, synthetic in-memory DOCX and mocked native extraction. Run with an
explicit new pytest base directory on the data disk; no network, parser download,
running SIEM, deployment, or container build is required. Native runtime isolation
and PostgreSQL deployment behavior are not established by these worker tests.
