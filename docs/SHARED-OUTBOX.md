# Shared Telemetry Outbox (P8)

Opt-in shared SQLite/PostgreSQL persistence with immutable destination and tenant
snapshots, atomic leases, and per-destination acknowledgements. Legacy memory/disk
and acknowledged local queues remain unchanged when the switch is off.

## Configuration

| Environment variable | Default | Meaning |
|---|---|---|
| `BULWARK_TELEMETRY_SHARED_OUTBOX` | `false` | Exact `true` enables shared mode, taking precedence over local durable mode |
| `BULWARK_TELEMETRY_ENABLED` | `false` | Existing exporter switch, also required for startup/delivery |
| `BULWARK_ADMIN_DB_URL` | `sqlite:///data/admin.db` | Existing shared engine configuration; all replicas must select the same database |
| `BULWARK_ADMIN_DB_URL_FILE` | unset | Mandatory readable, nonempty mounted URL secret when configured; invalid/missing file fails startup, never falls back to env/SQLite |
| `BULWARK_ADMIN_DB_POOL_MIN` / `BULWARK_ADMIN_DB_POOL_MAX` | `2` / `20` | Existing PostgreSQL pool bounds |
| `BULWARK_ADMIN_DB_SSL` / `BULWARK_ADMIN_DB_SSL_MODE` | `false` / `require` | Existing engine TLS settings; use `true` / `verify-full` for production |
| `BULWARK_SHARED_OUTBOX_MAX_EVENTS` | `100000` | Shared accepted pending-event budget, 1..10000000 |
| `BULWARK_SHARED_OUTBOX_MAX_BYTES` | `52428800` | UTF-8 payload plus destination-snapshot budget, 1..1099511627776 |
| `BULWARK_TELEMETRY_BATCH_SIZE` | `100` | Shared claims capped at 1000 rows and 4 MiB per destination |
| `BULWARK_TELEMETRY_FLUSH_INTERVAL` | `1.0` | Poll interval |

No dependencies are added. PostgreSQL requires the already-defined optional
`asyncpg` dependency to be provisioned in the runtime image. SQLite uses the
existing engine's aiosqlite or executor fallback. The shared engine is now in
`src/storage/database.py`; `admin/services/database.py` reexports the same classes
and preserves admin singleton/migration lifecycle. Proxy never imports admin.

## Lifecycle And Integration

Existing `await queue.enqueue(event)` callsites remain valid. With shared mode:

- `TelemetryExporter.start()` awaits `queue.initialize()` before starting workers.
  A disabled, never-started or unsuccessfully initialized shared exporter skips
  its shutdown flush while still closing transports and database resources.
- The config loader registers transport IDs, effective config fingerprints and
  tenant scopes. Config `tenant_scope` accepts `global`, a single tenant string,
  or a JSON list. Omitted scope preserves the existing admin/global convention.
- `queue.set_destinations(tuple[DestinationSnapshot, ...])` replaces admission
  routes only. It cannot retarget pending rows. A separate producer may use this
  with `await queue.initialize()` without starting an exporter.
- `enqueue_nowait` rejects and counts a drop in shared mode. It never pretends a
  background commit has completed. Missing routes/uninitialized DB also reject.
- Shared workers use `outbox.claim(snapshot)` and
  `outbox.finish(leases, success=..., retry_seconds=...)`. Calling legacy
  `dequeue_batch`/`acknowledge_batch` in shared mode raises, preventing unsafe drains.
- `await queue.aclose()` closes owned DB resources. Exporter stop calls it; the
  synchronous `queue.close()` only closes legacy storage.
- `await outbox.status()` returns authoritative persisted accepted/rejected,
  acked/failures/corrupt, pending events and byte counts. `queue.disk_depth` is the
  last cached shared count, refreshed by the exporter, not a synchronous DB query.

**Primary integration still required outside this ownership:** expose/validate
these settings in config/deployment manifests, provision persistent storage/PG
and TLS, mount DB URL secrets, and verify lifespan ordering initializes telemetry
before accepting requests. Use `aclose()` for shutdown paths that bypass the
exporter. Add operational monitoring of `await outbox.status()`; queue-local
rejections/errors are not a shared aggregate. Define whether an admission failure
must fail the HTTP request: current callers retain the existing best-effort policy.
No main/config/proxy/workflow/dependency manifests were changed here.

Custom programmatic transports must pass a stable `destination_id` and SHA-256
`revision` to `add_transport`, and keep the transport immutable while registered.
Built-ins fingerprint their complete effective dataclass config automatically and
check it again before delivery. Registration is bounded to 64 destinations.

For built-in file-configured TLS, fingerprints include the **contents** of the CA,
client certificate and private key, not just their paths. Registration captures
those exact bytes in Linux sealed memfds and constructs a separate transport using
`/proc/self/fd/` paths. The source files are revalidated off-loop before claiming;
replaced, missing or unreadable material prevents delivery. A replacement racing
after validation cannot change the bytes consumed by TLS. Private material stays
in memory, is never written to the outbox or logged, and descriptors close at
exporter shutdown. A material change requires explicit re-registration/restart.

The shared TLS path requires Linux `memfd_create` with sealing and `/proc/self/fd`
access. Unsupported runtimes fail registration rather than silently reverting to
mutable credential files. Custom TLS transports are not pinnable through this
adapter and are refused when file-based TLS fields are present. Provision matching
material on all replicas; identical pathnames alone no longer imply a shared
destination identity. TLS-free destination fingerprints remain unchanged.

## Durable Contract

Admission reserves capacity and stores the serialized event, tenant and complete
set of applicable destination identities in one transaction. SQLite sets
`synchronous=FULL`; PostgreSQL transactions set `synchronous_commit=on` but still
depend on server WAL, replication and storage configuration. Acceptance means
the transaction completed, not the SIEM indexed
the record. Events larger than 1 MiB, invalid routes, full storage or unavailable
DB are rejected; no pending row is evicted to admit another. There is no automatic
PostgreSQL-to-SQLite fallback or migration from the old local spool.

Schema version 1 has explicit SQL for both dialects in
`src/storage/outbox_migrations.py`, separate from admin migrations. Migration and
budget initialization are transactional. PostgreSQL migration advisory locks are
transaction-scoped on the same pooled connection. Every outbox write first locks
the singleton state row, serializing capacity, claim and completion across workers.
SQLite takes its writer lock before reads. Capacity settings must agree across
replicas; mismatches and unknown schema versions fail initialization.

Leases use DB time, a random 256-bit fencing token and expiry (exporter default
60 seconds, exceeding its 30-second send timeout). Another worker cannot claim an
unexpired lease. Ack/retry requires the exact event, destination, tenant, token and
an unexpired lease. Expired or stale workers cannot remove/release another claim.
Claims only scan matching configured destinations, so a removed route cannot
starve healthy routes. Failed sends get persisted backoff (up to 30 seconds in the
exporter). Poison records are retained, counted and deferred 60 seconds for repair.

One destination's success deletes only its delivery row. Event payload/budget are
released after the last destination succeeds. A committed partial fan-out does
not resend to already acknowledged destinations after restart. Retried admission
of the same tenant/event ID while pending cannot add destinations, and rejects a
changed payload. Different tenants never share this identity. Once fully delivered,
there is no permanent deduplication tombstone.

No credentials or raw endpoints are stored in destination snapshots, only config
fingerprints, destination IDs and admission tenant scopes. Fingerprints include
credentials as well as endpoint/format/TLS settings; they are not reversible
encryption. Restrict DB access (hashes permit offline guesses against weak secrets).
Payloads retain the existing telemetry schema and are not additionally encrypted
or scrubbed by this outbox. Use encrypted volumes/PG storage and least privilege.

Changing endpoint, credentials, format or tenant scope creates a different
destination key. New destinations NEVER receive old pending events. Old records
remain pending until that exact configuration is registered again. There is no
automatic credential rotation/rebinding/replay-to-new-endpoint API; deliberate
operator recovery is required. This conservative rule favors isolation over drain
availability. Do not mutate custom transports behind a registered revision.

Caller cancellation is shielded until its single outstanding DB operation finishes;
the bounded admission lock remains held even under repeated cancellation. A killed
worker's committed claims recover after lease expiry. A crash after remote success
but before ack can duplicate delivery. Ack failure retains the lease and evidence.
There is **no exactly-once claim**; deduplicate stable event IDs at receivers. UDP
and file transport success are only local transport acknowledgements.

## Limits And Verification

- A single state-row serialization point deliberately trades throughput for
  simple correct capacity/fencing; PostgreSQL `SKIP LOCKED` scaling is not claimed.
- Each instance permits one outstanding DB operation. Busy admissions reject
  rather than queue unbounded tasks. Rejections/errors before a DB transaction are
  process-local; capacity rejections and delivery outcomes are durable counters.
  A caller cancelled during commit may not update queue-local acceptance metrics;
  the persisted `accepted` counter remains authoritative.
- Byte limits exclude indexes/WAL/row overhead and fixed lease metadata. Plan
  additional disk reserve. For 30 minutes offline, size at least
  `events_per_second * 1800` events and that count times average payload plus
  snapshots, with burst margin. Sustained-rate sizing was not benchmarked here.
- SQLite sharing is same-host/local-filesystem development only, not NFS/multi-node
  HA. PostgreSQL HA also depends on deployment, replication and WAL policy.
- Tests exercise real temporary SQLite, concurrent engines, rollback on simulated
  disk failure, cancelled commits/claims, restart, lease expiry/stale ack, scope
  changes, corrupt records, independent fan-out and config mutations. PostgreSQL
  tests use the real translator/transaction wrapper with mocked driver responses.
- Live PostgreSQL/HA failover, actual disk exhaustion, power-loss/fsync durability,
  30-minute sustained-load sizing and real SIEM transport delivery remain untested.
  No services, downloads, containers, credentials or network tests are required.
