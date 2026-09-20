# Attachment Storage

`src.attachments.store` is an async persistence component only. It starts no
workers, routes, services, parsers, or external side effects. All SQL passes through
`src/storage/database.py`; attachment migrations have their own versioned state
row, independent of admin and telemetry migrations.

## API Contract

```python
AttachmentStore(db, max_documents=100, max_bytes=32*1024*1024,
                max_per_tenant=20, ttl_seconds=3600)
get_attachment_store(url: str) -> AttachmentStore  # synchronous, create_engine(url)

async initialize() -> None
async close() -> None
async create(*, tenant: str, agent: str, owner: str, mime: str,
             raw: bytes, policy_revision: str) -> dict
async get(id: str, *, tenant: str, agent: str, owner: str) -> dict | None
async delete(id: str, *, tenant: str, agent: str, owner: str) -> bool
async claim(*, lease_seconds=120) -> dict | None
async finish(id: str, token: str, *, state: str, text: str | None = None,
             reason: str = '') -> bool
async resolve(id: str, *, tenant: str, agent: str, owner: str,
              policy_revision: str) -> str
async expire(*, limit=100) -> int
```

Initialize before use. Supply a dedicated engine per store instance; the store
owns its engine. Call `await store.close()` after stopping workers and draining
operations, without accessing private engine attributes. Close is repeatable,
including before initialization or after failed initialization. It rejects a busy
instance with `busy`; once close starts, readiness is cleared even if shutdown
fails or the caller is cancelled. Cancellation waits for shutdown completion (or
its bounded timeout) before propagating. A closed instance cannot be initialized
again; construct a new store instead. A failed close can be retried. The factory
creates an uninitialized store with the default limits.

The factory explicitly accepts only `sqlite:///`, `postgresql://`,
`postgresql+asyncpg://`, and `postgres://` URL prefixes. It rejects
`sqlite+cipher://` and all unsupported schemes with `configuration_error` before
engine creation. The shared SQLite engine does not implement SQLCipher; accepting
its cipher URL would silently drop the key and write plaintext. Directly supplied
engines must also provide the storage protections their caller requires; the
attachment store itself does not add database encryption.

`create` and `get` return exactly `id`, `state`, `sha256`, `created_at`,
`expires_at`, `mime`, `size_bytes`, `policy_revision`, `text_sha256`, and `reason`.
Times are database-clock Unix epoch seconds. Public `size_bytes` is original raw
length. Metadata contains no owner, raw data, extracted text, free-form diagnostic, or lease
token. `get` is the status API; there is no unscoped lookup or hash lookup API.

`claim` is trusted-worker-only and returns exactly `id`, `tenant`, `agent`,
`owner`, `mime`, `raw` (bytes), `policy_revision`, `lease_token`, and `sha256`.
Do not expose or log this dictionary. `finish` accepts terminal states only:
`approved`, `blocked`, `review_required`, `failed`. `approved` requires text
(an empty string is valid); all other terminal states discard supplied text.
Reasons remain bounded internal diagnostics. Public `reason` exposes only exact
allowlisted codes: `policy_changed`, `unsupported_format`, `extraction_unavailable`,
`no_text`, `incomplete`, `unsafe_document`, `input_detection`, `input_dlp`,
`processor_failed`, `attempts_exhausted`, `integrity_error`, and `approved`.
Unknown, empty or malformed persisted reasons produce `""`, never raw diagnostics.
The whitelist is enforced on public reads, so even a persisted arbitrary reason
cannot leak through status. Existing bounded free-form `finish(reason=...)`
values remain internal; callers should supply fixed codes, not exception text.

`resolve` returns text only for a currently approved, unexpired document in the
exact tenant/agent/owner scope, with an unchanged policy revision and valid text
SHA-256. Policy revision is an opaque, nonempty fingerprint from the trusted
primary policy layer, not a client assertion. Authentication and revision
computation are responsibilities of the calling service.

## Bounds And Concurrency

- Raw bytes must be nonempty (`invalid_input` otherwise) and are capped at 2 MiB
  before Base64 encoding into a portable TEXT column.
- Approved text is capped at 32 KiB of UTF-8, without truncation. JSON framing
  preserves datetime-looking strings through the shared PostgreSQL translator.
- Tenant, agent, owner, MIME, revision and reason are capped at 256 characters.
- Global count, global bytes, and per-tenant count are transactional. All replicas
  must use identical limits and TTL; mismatched initialization is rejected.
- The byte budget includes Base64/JSON expansion, identity metadata, a 4096-byte
  per-document allowance (including reserved terminal diagnostics), and retained
  text. Even at full capacity, a failed/review-required transition without text
  needs no extra space, including for one-byte uploads. It is a logical
  live-record budget, not a bound on physical database/WAL/index/backup size.
- Terminal transitions clear raw data and adjust byte counters; document-count
  capacity is released only on deletion or expiry cleanup. Text expansion can
  cause `finish` to raise `capacity`, leaving the lease/result unchanged. The
  worker can then finish as `failed` without text.
- Scope quotas count every retained state, across agents/owners within a tenant.
  Creates always receive independent random IDs, even for identical content.
  There is no cross-tenant cache or deduplication side channel.
- A state-row write serializes transactions across SQLite engines and PostgreSQL
  replicas, before reading capacity, leases or database time. No application
  wall clock governs expiry. SQLite requires a suitable local shared file;
  PostgreSQL is the multi-host option.
- One operation may run per instance. Concurrent callers receive a retryable
  `StoreError('busy')`, rather than building an unbounded waiter queue.
- Caller cancellation is observed after the in-flight operation finishes or
  rolls back; the instance remains locked until then. Cancellation does not
  imply that a create failed to commit. There is no create idempotency key.

## Leases And Retention

States are `queued`, `processing`, `approved`, `blocked`, `review_required`, and
`failed`. A claim transitions queued work to processing and issues a random
fencing token. A crashed worker's expired lease can be reclaimed. At most three
claims occur; after the third lease expires, a subsequent claim sweep moves the
document to `review_required` and clears raw data. Recovery is parsing-only;
this store must not be used to retry external actions.

Only a matching, still-live lease token can finish an unexpired processing row.
Replays, stale workers, expired documents and deletion during processing return
`False` from `finish`. A successfully deleted row cannot be resurrected.

TTL is checked by reads, resolution, claim and completion regardless of cleanup
schedule. Missing, expired and incorrectly scoped documents are indistinguishable
(`None` from get, `False` from delete, `not_found` from resolve). Deleting a scoped
expired row removes it but returns `False`. A get of an expired scoped row also
cleans it up. `resolve` denies expired content without requiring cleanup.

`expire` deletes at most 100 expired rows per call and atomically releases their
count/byte reservations. Create and claim also attempt up to 100 expired-row
deletions. Create commits that batch in its own transaction before starting
admission, while retaining the `_run` instance lock across both transactions.
Each transaction independently locks the database state row and reads database
time. A later capacity rejection cannot roll cleanup back, so repeated attempts
make progress through an expired backlog larger than 100 rows. Admission still
checks and reserves all quotas atomically; other replicas may admit between the
two transactions without overshooting limits. Claim cleanup remains part of its
claim transaction and rolls back if that transaction fails. Call explicit cleanup
periodically, especially with larger configured capacities. There is no background
scheduler inside the store.

Base64 is transport encoding, **not encryption**. Use deployment-controlled
database/disk encryption and access controls for sensitive data. Raw data is
removed from live rows on terminal transition, and deletion/expiry removes live
storage. This is **not a secure-erasure guarantee**: prior values may remain in
WAL, database free pages, replicas, snapshots and backups subject to operator
retention policy. Hash checks detect accidental corruption, not a privileged
database attacker who can rewrite both content and hashes.

## Errors And Verification

`StoreError.code` and `str(error)` are safe fixed codes: `not_found`, `not_ready`,
`policy_changed`, `integrity_error`, `invalid_input`, `too_large`, `capacity`,
`busy`, `unavailable`, `configuration_error`. `retryable` is true for `busy` and
`unavailable`. Raw driver errors are never returned to callers. Storage errors
never produce approved text. No parser exception should be passed as a public
diagnostic by the calling service.

Focused tests use real temporary SQLite files with independent engines for
capacity and lease races, cancellation, replay/deletion fencing, scope isolation,
TTL, three-attempt recovery, corruption checks and public metadata contracts.
PostgreSQL DDL and translator compatibility are checked without provisioning a
server; live PostgreSQL concurrency validation remains a deployment test.

```bash
python -m pytest tests/test_attachment_store.py -q
python -m pytest --noconftest tests/test_attachment_store.py -q
```
