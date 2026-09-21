# Acknowledged Local Telemetry

`BULWARK_TELEMETRY_DURABLE=true` opts into acknowledged delivery using the existing
SQLite fallback store. No new schema or database backend is introduced. This is
local restart safety, not completion of P8's shared PostgreSQL/HA requirement.

## Contract

- Accepted events commit with SQLite `synchronous=FULL` before enqueue returns.
  Async request paths run the commit in a worker thread and await acceptance.
- A busy writer rejects additional asynchronous admissions rather than creating
  an unbounded executor backlog. Rejections increment `dropped`; durable admission
  therefore trades latency/throughput for persistence and bounded resources.
- The exporter peeks rows, sends to every applicable configured destination, then
  acknowledges individually completed rows. Failure, timeout, open circuit or
  missing tenant route retains affected rows. A bounded rotating read cursor
  prevents an unroutable tenant from starving later healthy-tenant events.
- Partial fan-out may resend to destinations that already succeeded. Deduplicate
  using stable event IDs. Transport success is not proof the SIEM indexed the event;
  in particular UDP cannot provide delivery acknowledgement.
- No old pending event is deleted to admit a new one in durable mode. Count/UTF-8
  payload budgets reject admission, preserving earlier evidence. Defaults are
  100000 rows and 50 MiB payload; SQLite/WAL/index overhead needs extra disk reserve.
- Corrupt rows stop draining at that row and increment a visible counter; operator
  repair is required. Corrupt evidence is not silently discarded.

Use one exporter/worker per local path, one persistent path per replica. Do not
share the path with legacy non-durable drainers or across differently configured
destinations. Configuration changes during an outage can change replay targets;
destination snapshots and per-destination acknowledgements remain future work.
Local files do not provide shared multi-node durability or encryption at rest.

The gateway continues security processing when event admission fails, while
recording rejection counters. This is not a guarantee that every HTTP request has
a durable audit record; deployments needing that must define an audit-admission
fail-closed policy and size/provision their store accordingly.

## Transport Restrictions

Both local durable mode (`BULWARK_TELEMETRY_DURABLE=true`) and shared outbox mode
(`BULWARK_TELEMETRY_SHARED_OUTBOX=true`, which implies durable mode) reject
`FileShipperTransport` at registration, before adding a destination snapshot.
Its `flush()` is not an `fsync()` and its rotation is not coordinated between
exporters. A successful file write therefore cannot safely authorize deletion
from the outbox: a crash or competing writers/rotation can lose that evidence.
Using a shared PostgreSQL outbox does not make the file destination durable.

This is an intentional compatibility change for durable deployments:

- Configure a supported destination explicitly, for example HTTP/REST. Remove
  enabled file destinations, including any previously generated `auto-default`.
- Durable mode never auto-seeds a file transport or writes a default
  `siem_transports.json` when the transport configuration is absent.
- With telemetry enabled, startup fails explicitly if no transport is registered
  (including missing, empty or all-disabled configurations). Invalid configuration
  or registration errors propagate instead of silently dropping a destination.
- Legacy non-durable mode retains file transport support, automatic default
  configuration and its existing no-transports startup behavior.

These restrictions do **not** certify remote durable acknowledgement for all
remaining transports. UDP has no delivery acknowledgement; TCP/TLS write success
is not an application-level persistence receipt. HTTP success follows the
endpoint/transport response contract, not proof of durable SIEM storage or
indexing. End-to-end guarantees require destination-specific acknowledgement
semantics and verification beyond this registration guard.

## Verification

`tests/telemetry/test_durable_delivery.py` covers restart before acknowledgement,
failure/timeout/open circuit/unrouted tenant, partial fan-out, stable IDs, retry
recovery and queue-full rejection. Existing legacy queue tests are retained.
No live SIEM or shared-store failover was executed by these tests.

`tests/telemetry/test_durable_transport_contract.py` covers real FileShipper
rejection for local and shared queues (SQLite and unconnected PostgreSQL),
explicit startup failure without destinations, no durable default-file creation,
HTTP acceptance, configuration error propagation and unchanged legacy defaults.
It uses temporary local files and performs no external network I/O.

P8 still requires: dual-backend outbox through a shared data abstraction (without
coupling proxy imports to admin), migrations, per-destination lease/ack state,
30-minute outage sizing, power-loss/storage-full tests, and multi-node recovery.
