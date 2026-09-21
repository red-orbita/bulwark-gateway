# Chat Attachment Guard In Helm

The chart exposes the proxy runtime's strict attachment guard independently of
`proxy.ml.enabled`. No models, sidecars, extra volumes, dependencies or OCR flags
are required or enabled by the text-only guard. Optional document extraction below
requires operator-provisioned native tools and isolation. Use a proxy image containing the
attachment runtime integration; rendering a ConfigMap alone does not prove that
an older image enforces the guard.

## Configuration

For the separate asynchronous upload service, see **Async Service** below.

| Helm value | Default | Accepted value | Proxy environment variable |
| --- | --- | --- | --- |
| `proxy.attachments.enabled` | `false` | YAML boolean | `BULWARK_ATTACHMENT_GUARD_ENABLED` |
| `proxy.attachments.maxFileBytes` | `16000` | Integer 1..65536 | `BULWARK_ATTACHMENT_MAX_FILE_BYTES` |
| `proxy.attachments.maxTotalBytes` | `65536` | Integer 1..65536 | `BULWARK_ATTACHMENT_MAX_TOTAL_BYTES` |
| `proxy.attachments.maxCount` | `5` | Integer 1..5 | `BULWARK_ATTACHMENT_MAX_COUNT` |
| `proxy.attachments.extractDocuments` | `false` | YAML boolean | `BULWARK_ATTACHMENT_EXTRACT_DOCUMENTS` |
| `proxy.attachments.maxDocumentBytes` | `2097152` | Integer 1..2097152 | `BULWARK_ATTACHMENT_MAX_DOCUMENT_BYTES` |
| `proxy.attachments.extractionWorkDir` | `/tmp` | Existing mounted `/tmp` only | `BULWARK_ATTACHMENT_EXTRACTION_WORK_DIR` |
| `proxy.attachments.extractionLanguages` | `eng` | Runtime language syntax below | `BULWARK_ATTACHMENT_EXTRACTION_LANGUAGES` |
| `proxy.attachments.parserIsolationConfirmed` | `false` | YAML boolean | `BULWARK_ATTACHMENT_PARSER_ISOLATION_CONFIRMED` |
| `proxy.attachments.extractionTmpSize` | `256Mi` | Whole Mi, 256..4096Mi | None; sizes proxy `/tmp` tmpfs |

```yaml
proxy:
  attachments:
    enabled: true
    maxFileBytes: 16000
    maxTotalBytes: 65536
    maxCount: 5
```

All nine environment variables are always emitted as strings in `proxy-config`, consumed by
the proxy's existing `envFrom`. They are not emitted in `admin-config`. Helm rejects
invalid types and ranges even when the guard is disabled. Use unquoted booleans
and numbers in YAML, or `--set`, not `--set-string`. Numeric strings, booleans in
numeric fields, fractional values, zero, negative values and overflow are rejected,
not silently coerced or replaced by defaults.

The switch enables a global enforcement floor. An operator's enabled agent policy
can impose tighter limits; disabling the global switch does not disable an
independently enabled agent attachment policy. With neither enabled, this guard
is inert: that is not evidence that an attachment was inspected.

## Text-Only Scope

With document extraction disabled (the default):

- Images, PDF, DOCX, ZIP, encrypted/binary files, remote URLs, file IDs and other
  attachment references are blocked before forwarding. Unsupported content is
  rejected for unavailable inspection, not claimed to be a detected attack.
- Only supported inline UTF-8 text attachments within the limits are eligible:
  TXT, Markdown, JSON and CSV, supplied as canonical base64 data URIs with matching
  MIME/extension pairs. Extracted text must pass the input guardrail and attachment
  DLP checks; only the inspected text replaces the file block upstream.
- Original bytes, filenames and attachment metadata are not forwarded. Exceeding
  the byte/count budget rejects the request rather than truncating an attachment.
  The effective per-file budget also respects the runtime's 16000-byte text ceiling
  and scanner limits, even if `maxFileBytes` is configured higher.
- This is not OCR, image understanding, PDF/DOCX extraction or antivirus scanning.
  Client-provided `extracted_text` or `scanned` claims do not establish inspection.
  Enabling the guard does not promise detection of every malicious text payload.

See [Strict Chat Attachments](CHATBOT-ATTACHMENTS.md) for the inline format and
inspection contract.

## Async Service

`proxy.attachments.service.enabled=true` provisions the asynchronous API/worker,
independently of the inline guard. Each agent must also explicitly allow
`attachments.async_enabled: true`; DOCX requires `extract_documents: true`.
The chart refuses unsafe partial configuration rather than scaling a local store:

- Exactly one worker/replica; HPA and dedicated tenants disabled; rollout Recreate.
- A real approved `proxy.image.digest` is required. No digest is supplied by this
  example; setting a syntactically valid value is not supply-chain verification.
- `persistence.accessMode=ReadWriteMany` for the other proxy/admin shared volumes.
- `storageProtectionConfirmed=true` only after verifying encrypted storage,
  restricted backup access and retention. This is attestation, not encryption code.
- `service.storage=local-sqlite` creates or mounts a dedicated RWO/RWOP block PVC
  at `/app/attachments`; the admin has no mount. The fixed credential-free URL is
  mounted as a file. Never use NFS/shared SQLite or reuse an application/outbox PVC.
- The local PVC defaults to 1Gi and is retained on uninstall. Size must be whole
  Gi and at least four times `maxBytes`, allowing journal and metadata headroom.
  Existing claims still require operator verification of actual capacity/type.
- `service.storage=shared-postgresql` reuses the existing validated outbox secret,
  immutable init snapshot, CA and scoped egress. It requires
  `telemetry.outbox.mode=shared-postgresql` and `sslMode=verify-full`. Attachment
  tables have separate migrations; this profile shares the database credential.
- Defaults: `maxDocuments=100`, `maxBytes=33554432`, `maxPerTenant=20`,
  `ttlSeconds=3600`. Capacities account for encoded data and metadata overhead.
- Readiness probes `/ready/attachments`; liveness remains `/health` so temporary
  database outages do not trigger a restart loop. Worker recovery restores readiness.

PNG/JPEG/PDF still require native provisioning and isolation validation below;
the default distroless image is not claimed to contain those tools. Helm rendering
tests do not demonstrate deployed PVC encryption, CNI enforcement, TLS connectivity,
backup restoration, native parser compatibility or HA. Recreate implies downtime.
See [Async Attachments](ASYNC-ATTACHMENTS.md) and [Attachment API](ATTACHMENT-API.md).

## Native Extraction

The runtime in `src/guardrails/document_extraction.py` supports bounded PNG, JPEG
and PDF extraction; DOCX, archives and remote references remain unsupported.
Its sandbox defaults to **true**: native parsers run through Bubblewrap, with no
automatic unsandboxed fallback. Helm exposes no sandbox-disabling switch.

The effective permission follows `src/routes/proxy.py`:

- With `attachments.enabled: false`, an enabled agent attachment policy can opt
  into `extract_documents: true` independently of the global extraction flag.
- With `attachments.enabled: true`, `extractDocuments` is the global permission.
  If the agent attachment policy is also enabled, its `extract_documents` must
  **also** be true (logical AND); the policy cannot override a global denial.
- `extractDocuments` never enables the attachment guard, ML, vision or another
  global flag. With neither global nor agent attachment guard enabled, it is inert.

Before either rollout, explicitly set `parserIsolationConfirmed: true` only after
validating the actual image and deployment sandbox. The chart requires this strict
YAML boolean whenever `extractDocuments: true`; quoted booleans and truthy numbers
are rejected. Work directory, languages, limits and confirmation render even with
both global switches false, so agent-policy-only extraction can be provisioned.

The operator must supply a digest-pinned proxy image with `/usr/bin/bwrap`,
`/usr/bin/python3`, `tesseract`, `pdfinfo`, `pdftoppm`, `pdftotext`, their native
libraries, fonts and selected Tesseract language data. `extractionLanguages`
matches the runtime: one to three names separated by `+`, each 2..32 lowercase
ASCII letters/digits/underscores starting with a letter (for example `eng+spa`).
The default distroless image is not proof these tools are present.

The chart installs nothing and adds no host mounts, privileged containers,
capabilities or security-context exceptions. Nested user namespaces may be denied
by seccomp, the kernel or the container runtime. Such a deployment is unsupported
for extraction until operator validation succeeds under the unchanged controls.
Missing tools, failed sandbox startup or missing/unwritable work directory fail
closed with HTTP **503**; documents are not forwarded uninspected. A successful
synthetic sandbox test on one host does not establish support in another cluster.
Helm rendering cannot attest parser readiness or namespace availability.

### Scratch And Memory

The runtime default for `attachment_extraction_work_dir` is `None`; this chart
explicitly supplies the already-existing absolute `/tmp` memory-backed `emptyDir`.
It does not bootstrap `/tmp/document-extraction`, add an init container, or use
durable `/app/data` storage for documents. Request-private temporary subdirectories
are created and cleaned by the extractor; the parent must already exist.

Decoded input is capped at **2 MiB**, but temporary output can approach **100 MiB
per active extraction**, with **two active extractions per Python process**.
The ordinary **50Mi** tmpfs cannot support that workload, let alone five concurrent
PDFs. Five attachments per request and five pages per PDF are not concurrency
allowances: the extractor rejects excess concurrent work as `busy`, without a queue.

When extraction or isolation confirmation is enabled, `extractionTmpSize` applies
to the shared proxy tmpfs, with at least **256Mi per worker**, capped at **4096Mi**.
It never reduces enrichment's existing 500Mi minimum. With both flags false the
existing 50Mi/500Mi sizing is unchanged. Confirmation alone reserves this scratch
budget for agent-policy-only use without turning on any global guard.
Dedicated-tenant proxies have separate 50Mi scratch volumes; extraction provisioning
with `dedicatedTenants.enabled` is rejected rather than silently undersizing them.

**Operator resource validation is required:** tmpfs pages count against container
memory; a `sizeLimit` is not a reservation. Budget CPU/memory requests and limits
for scratch plus parser processes, proxy workers, other `/tmp` consumers and ML
or enrichment. When ML is enabled, `proxy.ml.resources` overrides `proxy.resources`.
Check node headroom, ResourceQuota/LimitRange, PID limits, replicas and HPA maximum.
The default 512Mi memory limit is not a guarantee that all extraction workloads fit;
Helm validates scratch bounds, not real resource availability.

After validating the operator image, isolation and resource budgets, the following
fragment provisions extraction for agent policies while keeping global defaults off:

```yaml
proxy:
  workers: 1
  attachments:
    enabled: false
    extractDocuments: false
    maxDocumentBytes: 2097152
    extractionWorkDir: /tmp
    extractionLanguages: eng
    parserIsolationConfirmed: true  # Attest only after actual deployment validation.
    extractionTmpSize: 256Mi
```

For global enforcement with document extraction permitted, explicitly set both
`enabled: true` and `extractDocuments: true`; enabled agent policies must also
permit extraction. Supply the validated image digest and measured resource
requests/limits in the operator's deployment values, not by weakening isolation.

## Offline Validation

From the repository root, render only configuration without contacting a cluster:

```bash
helm template chatbot ./helm/bulwark-gateway \
  --set backend.type=none --set secrets.create=false \
  --set proxy.attachments.enabled=true \
  --show-only templates/configmap.yaml
pytest tests/test_helm_attachments.py -q
```

`backend.type=none` is an offline-render convenience, not chatbot backend routing
configuration. The tests exercise defaults, opt-in without ML, proxy wiring,
numeric boundaries and rejection of invalid YAML/CLI values. They require an
already installed Helm CLI and do not deploy, pull images, install packages or
validate live request enforcement.
