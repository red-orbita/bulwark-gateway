# Helm Outbox (P8)

## Modes

`telemetry.outbox.mode` selects exactly one runtime mode. No automatic migration
or fallback is configured by the chart.

| Mode | Flags | Storage and constraints |
| --- | --- | --- |
| `legacy` (default) | DURABLE=false, SHARED_OUTBOX=false | Existing ephemeral proxy queue; existing worker/replica/HPA defaults unchanged |
| `local-durable` | DURABLE=true, SHARED_OUTBOX=false | Dedicated persistent proxy PVC, one worker, one replica, HPA disabled, Recreate rollout |
| `shared-postgresql` | DURABLE=false, SHARED_OUTBOX=true | Operator-managed PostgreSQL, required mounted URL Secret, TLS and scoped NetworkPolicy; workers/replicas/HPA supported |

Both durable modes require `telemetry.enabled=true` and reject dedicated tenant
deployments, whose templates do not carry these mounts. They also require
`persistence.accessMode=ReadWriteMany`: policies, SIEM state, notifications and
admin data still cross the proxy/admin pod boundary. PostgreSQL does not remove
that storage dependency. Legacy deployments retain their existing RWO behavior
and its multi-node limitations. No changes to executor resources are included.

## Audit Admission

`telemetry.auditAdmission.required` defaults to `false`; `timeoutMs` defaults to
`250` and must be an integer in `1..10000`, even when admission is disabled.
The proxy ConfigMap always emits `BULWARK_AUDIT_ADMISSION_REQUIRED` and
`BULWARK_AUDIT_ADMISSION_TIMEOUT_MS`. Enabling the gate requires
`telemetry.enabled=true` and either `local-durable` or `shared-postgresql` outbox
mode; incompatible configurations fail rendering rather than silently weakening
the gate. All existing durable-mode storage and topology constraints still apply.

With the primary integrator's runtime wiring, this requires durable evidence
before each upstream attempt. A running exporter and a destination covering the
authenticated tenant are runtime prerequisites, not verified by Helm. The timeout
is an admission decision budget, not a hard HTTP latency bound or a wait for SIEM
delivery. See [AUDIT-ADMISSION.md](AUDIT-ADMISSION.md) for the runtime contract.

## Local Durability

Example overlay (also configure the backend normally):

```yaml
proxy:
  workers: 1
  replicas: 1
  autoscaling:
    enabled: false
  enrichment:
    enabled: false
persistence:
  accessMode: ReadWriteMany
  storageClass: corporate-rwx
telemetry:
  outbox:
    mode: local-durable
    local:
      storageClass: corporate-block
      accessMode: ReadWriteOnce
      size: 2Gi
```

The chart creates `proxy-outbox`, mounts it at `/app/data`, and sets
`BULWARK_TELEMETRY_DISK_PATH=/app/data/telemetry_queue.db`. It never reuses the
admin's `telemetry-data` PVC. `local.existingClaim` selects an operator-owned,
proxy-only PVC instead; `ReadWriteOncePod` is also accepted. The local storage
class deliberately does not inherit the shared RWX class. Use a local/block
filesystem with SQLite locking/fsync support, not NFS even if advertised as RWO.
The chart cannot inspect an existing claim's real driver, access mode or consumers.

`Recreate` prevents overlapping exporters during upgrades, at the cost of downtime.
The default PDB (`minAvailable: 1`) still blocks voluntary node drains for this
single replica; plan maintenance explicitly. Never manually scale this Deployment
or attach its claim to another exporter. Created outbox PVCs have Helm's `keep`
annotation: switching modes/uninstalling must not silently delete pending evidence.
Drain and back up before mode changes; recovery and eventual PVC deletion are
operator decisions. Existing legacy emptyDir events are not migrated.

## Shared PostgreSQL

The outbox uses independent configuration under `telemetry.outbox.postgresql`.
It does not enable `admin.database`, create a database, generate credentials or
reuse a password-only Secret. Preprovision the database and a Secret in the proxy
namespace, with a full URL under `urlKey` and optionally a PEM CA bundle under
`caKey`. Keep credentials out of Helm values and CLI arguments.

```yaml
proxy:
  enrichment:
    enabled: false
persistence:
  accessMode: ReadWriteMany
  storageClass: corporate-rwx
telemetry:
  outbox:
    mode: shared-postgresql
    postgresql:
      existingSecret: corporate-outbox
      urlKey: postgresql-url
      host: pg.corporate.example
      port: 5432
      ssl: true
      sslMode: verify-full
      caKey: ca.crt
      poolMin: 2
      poolMax: 20
      maxEvents: 100000
      maxBytes: 52428800
      egress:
        cidr: 10.20.30.40/32
```

The host/CIDR above are illustrative, not provisioned corporate inputs. A URL must
have a PostgreSQL scheme, matching host/port, username/password and database.
Percent-encode special characters in credentials. URL queries/fragments are
rejected to prevent DSN options overriding host or TLS settings. The init container
uses Python in the same proxy image to validate the mounted URL, CA and presence
of `asyncpg`, then copies the validated bytes into a small memory-backed volume.
Only that fixed, read-only snapshot is mounted by the proxy. Missing/invalid
secrets, SQLite URLs or missing driver prevent startup; no SQLite/local fallback
is configured. The snapshot contains credentials, not outbox data; PostgreSQL is
the only shared event store. Secret rotation requires pod replacement.

Both `BULWARK_ADMIN_DB_SSL=true` and `BULWARK_ADMIN_DB_SSL_MODE` are emitted;
the existing DB engine ignores the mode alone when its SSL flag is false.
`verify-full` is the default. `verify-ca` omits hostname checking; `require`
encrypts without authenticating the server and is not recommended for production.
Shared mode rejects `ssl=false`, `disable`, `allow` and `prefer`. A configured CA
sets `SSL_CERT_FILE` to the frozen CA bundle; include all trust roots needed by
other Python default-context TLS consumers, since this is process-wide.

Admin PostgreSQL now also gets an SSL flag derived from its own `sslMode`.
This is separate from the outbox configuration. The existing bundled PostgreSQL
template has no TLS provisioning: do not assume its default `require` will work.
Use operator-provisioned TLS for the outbox. Existing admin external-PG mounts,
wait init and synchronous engine TLS behavior are outside this change's scope.

## Network Scope

Shared mode requires NetworkPolicies enabled and exactly one of:

- Canonical IPv4 `egress.cidr` with prefix /8 through /32; prefer exact /32 peers.
- `egress.namespace` plus nonempty `egress.podLabels`, combined in the SAME peer
  (logical AND, not independent namespace/pod allow rules).

No empty selector or allow-all PostgreSQL rule is generated. The configured TCP
port is the only port opened by the PG rule. If it is 443 or 8000, that port is
removed from the legacy public-backend rule so it cannot broaden PG egress.
Other existing explicitly scoped service rules and independently installed
NetworkPolicies remain additive; review their union with your CNI.
DNS stays scoped to kube-dns in kube-system. CIDRs do not track changing DNS IPs:
the operator must maintain them. IPv6 CIDRs are deliberately unsupported here.

For example, instead of `cidr`, an in-cluster PG peer can use:

```yaml
egress:
  namespace: corporate-database
  podLabels:
    app.kubernetes.io/name: postgresql
    app.kubernetes.io/instance: corporate-outbox
```

For same-namespace peers, the chart adds PG ingress from the proxy to the exact
labels. Cross-namespace ingress, external firewalls, routing, CNI enforcement and
database authorization remain the database operator's responsibility. Rendering
does not contact the cluster or inspect Secret contents/PVCs.

## Offline Enrichment

The unverified Hugging Face `resolve/main` download and separate Python init image
are removed. `proxy.enrichment.enabled=false` is the secure default: no model
override is needed to render a regex-only installation. Explicitly setting it to
`true` still fails rendering until verified provisioning is supplied; it is never
silently disabled. There is no model download, fake checksum or automatic
degradation in the init step. The existing backend configuration requirements
remain unchanged.

When enabled, provide `proxy.enrichment.existingModelClaim` with assets at its root
and `modelManifest`, a trusted map of relative filenames to SHA-256 digests. Include
ALL assets required by the approved SentenceTransformer model. Mandatory entries
are `config.json`, `tokenizer.json`, `modules.json`, `model.safetensors`, and
`1_Pooling/config.json`. Extra tokenizer/config/pooling assets must also be listed.
The manifest is capped at 256 files; `modelMaxBytes` bounds total copied bytes
(default and ceiling 1 GiB). No real model or hash is supplied by this chart.

The init uses the existing proxy image and Python hashlib, reads the source PVC
read-only, rejects missing assets/symlinks/nonregular files/hash mismatches/oversize
input, and copies only verified bytes into a bounded per-pod emptyDir. The proxy
sees that verified copy read-only, not the mutable source. Unlisted source files
cannot enter the runtime view. The source claim must support the configured pod
topology (normally ROX/RWX); provision node ephemeral storage for every replica's
verified copy. This model copy is not the persistent event outbox.

`BULWARK_EMBED_MODEL` points to `/app/verified-enrichment`; HF/Transformers offline
flags prevent runtime network fetches. The old enrichment `model` identifier and
`modelCachePath` no longer select/download weights; the manifest and local path
are authoritative. Legacy `initImage`/`download` overrides are rejected when
enrichment is enabled. Admin does not receive the verified model volume and is
kept offline, not advertised as an embedding inference runtime. Optional ML
classifier provisioning under `proxy.ml` is a separate preexisting path.

A SHA-256 manifest proves equality to operator-approved bytes, not provenance or
model safety. Verify provenance/signatures and review model configs before approval;
provide an approved immutable proxy image with required inference dependencies.
Neither dependencies nor models are installed by these templates.

## Verification And Limits

Offline verification uses local `helm template` through
`tests/test_helm_outbox.py`, plus execution of rendered init scripts against tiny
synthetic files. The test overrides the suite's database-writing autouse fixture;
no database, Kubernetes API, image build, model pull or service is used.

```bash
python -m pytest tests/test_helm_outbox.py -q -p no:cacheprovider
helm lint helm/bulwark-gateway --set backend.type=none
```

These checks do not establish live PostgreSQL connectivity/TLS, PVC attach/fsync,
model loadability, HA failover, CNI behavior, SIEM indexing or outage capacity.
Provision and verify those separately before production. Audit admission is opt-in;
the default remains the runtime's best-effort HTTP policy. Even with required
pre-upstream admission, this chart does not guarantee every inbound request gets
a committed completion audit record or exactly-once delivery. See
[SHARED-OUTBOX.md](SHARED-OUTBOX.md) and
[DURABLE-TELEMETRY.md](DURABLE-TELEMETRY.md) for the runtime contracts.
