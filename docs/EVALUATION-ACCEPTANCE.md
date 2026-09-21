# Evaluation Acceptance

These offline tools support evidence collection, profile evaluation and bounded
load measurements, not automatic production acceptance.
No independent corpus, real-model efficacy, production capacity, SIEM indexing,
80% recall achievement, or p95 below 40 ms is asserted here.

## Evidence Review Corrections

Independent review found two invalid evidence paths in the initial tooling:
normal budget-fallback BLOCK results were scored as detections, and profile p95
used the runner's malicious-only aggregate (zero for a benign-only corpus).
Reports from that version must not be reused for efficacy or profile latency
acceptance without rerunning. The earlier smoke record below remains a historical
tool observation, not revalidated acceptance evidence.

All three tools now treat event source `input_guardrail_budget`,
`metadata.reason=scan_incomplete` (the existing MCP/long-context convention), or
`metadata.scan_incomplete=true` as incomplete evaluation regardless of verdict.
These are normal `GuardrailResult` events; no scanner exception is needed.
They are never credited as TP, FP, or successful detections/flags.

- Sequential evidence retains diagnostic class counts, records incomplete samples
  separately, suppresses efficacy intervals, sets `evidence_valid=false` and exits 2.
- Profile validation stops on the first incomplete sample, returns
  `status=scan_incomplete` with no confusion matrices, quality target or p95 claim.
- Load stops new admission, counts affected requests in both `incomplete_scans`
  and `request_errors` (not as BLOCK verdicts or successful throughput), and
  invalidates the run. `completed` includes terminated error attempts; `unfinished`
  counts requests without a completed attempt. Warmup incompleteness prevents
  measurement entirely. Neither case forwards the incomplete sample to the mock.

Profile p95 now uses observed per-sample wrapper wall times from the first complete
corpus pass, malicious AND benign, once each. The injection-specific recheck is
excluded; `latency_samples` and `latency_population` state this denominator.
Nearest-rank p95 is null if no observations exist, never a fabricated zero.
Timing and quality remain invalid when evaluation does not complete.

Post-review focused regression run: 72 passed, with the existing missing
`/run/secrets` warning. Targeted mypy passed for the three evaluation modules,
including `EvidenceScan`'s inherited abstract `InputScanner.scan` contract.
Ruff passed for the six owned Python files. Full `mypy src admin
--ignore-missing-imports` checked 247 files and reported only the unrelated
`src/telemetry/exporter.py:92` error: too many arguments for `TransportProtocol`.
That file belongs to another workstream and was not modified.
No runner, protocol, detector or deployed service was changed. The full-suite
3986 passed / 21 skipped result was supplied by the reviewer before these fixes;
it was not rerun or represented as post-fix validation here.

## Local Tool Smoke Record

Executed 2026-09-10 using the documented load command and shipped smoke configs,
on HEAD `c2f0f1cd518c5f47b94498538816843aaf029e9e` plus uncommitted work.
This is a sanitized development observation, NOT a frozen release benchmark.
The three-row corpus is synthetic `previously known baseline`, not a holdout.
No services were contacted. The later addition of canonical config-hash report
fields did not change the measured workload; rerun on a frozen tree for acceptance.

| Observed field | Value |
|---|---|
| Python / OS | 3.13.5 / Linux x86_64, kernel 6.12.107+deb13-amd64 |
| Logical / affinity CPUs | 12 / 12; CPU model/quotas/contention not measured |
| Host RAM | 16,593,096,704 bytes |
| Workload | 24 requests, concurrency 2, warmup 2, seed 42, mock delay 1 ms |
| Scheduled mix | 15 benign, 9 malicious (repeated synthetic rows) |
| Completion/errors | 24 completed, 0 unfinished, 0 request/scanner errors |
| Wall / process CPU | 0.525412 s / 0.529556 s (100.79% of one core) |
| Throughput | 45.6785 completed requests/s, not sustainable RPS |
| Admitted-request p95 | 59.2011 ms, including tracing/ASGI/input scan/mock delay |
| Python traced allocation peak | 219,443 bytes; not full process memory |
| Process-lifetime RSS high-water | 927,182,848 bytes; includes imports/warmup/native allocations |
| Verdicts / mock calls | 15 benign ALLOW, 9 malicious BLOCK, 15 backend calls |
| Corpus SHA-256 | `9705e84049457397b2d2c73aa352b06a6411f54730c8c80af486c1ff20a3ed8b` |
| Manifest SHA-256 | `4f4a92fa59ae92ed7089fc98b12920d4e3cd5c96b664042923c21239f75875a9` |
| Schedule SHA-256 | `3d5ce8d87dd5a9ec8db04bad5d131d4baa86704877ad180391a3f7c81f65ef28` |
| Regex config SHA-256 | `d9934458337495f2795e9b2d7b6e500d9e0d5c760c4e41ea31f6ec0fc36c71c6` |
| Pattern-set SHA-256 | `39101256637feb6b38f108205f8680fdacb28da9e6b6828daeb7b557d68495a4` |

Actual hybrid invocation using `evaluation-hybrid.json --model-dir models`
returned `status=not_ready`, `ready=false`, `evidence_valid=false`, exit 2,
`model.status=missing_artifacts_or_trust_manifest`. Directory inspection found
only `models/injection-classifier/config.json`, no ONNX weights or tokenizer.
No real-model inference was executed; the verified-model success path is tested
with explicitly mocked inference only. No model was downloaded.

Root free space after the checks was 19,328,057,344 bytes, above 5 GiB. The shared
host was not isolated, so these timings are illustrative tool output only.
Focused tests forbid DNS/socket connections and override the repository's global
admin-DB-mutating fixture. The environment lacks `pytest-cov`; coverage percentages
were not measured and no dependency was installed to obtain them.
Final focused run: 55 passed (1.98 s), one existing `/run/secrets`-absent warning.
Ruff passed for the six assigned Python files. No full-suite or real-model
success-path validation is claimed. Temporary pytest files remain only under
the workspace's `.evaluation-tmp/`; they are not evidence artifacts for release.

## Tools And Trust

| Module | Actually exercises | Does not establish |
|---|---|---|
| `src.evaluation.evidence` | Existing offline `InputGuardrail.inspect`, per-source/language/channel counts, Wilson 95% intervals | Full proxy, model efficacy, corpus independence |
| `src.evaluation.profile_validation` | Existing `EvaluationRunner`, `split_samples`, scanner pipeline, regex and optionally local ONNX injection classifier | Deployed profile parity, LLM attack success, automatic acceptance |
| `src.evaluation.load_harness` | Seeded closed-loop workers, two in-process ASGI apps, same candidate input pipeline, mock backend | Production proxy, network, auth, tenant policies, SSE, tool/output filters, telemetry or sustainable capacity |

Regex in the candidate profile is dispatched to worker threads, unlike the
production regex scanner. ML uses the existing classifier but an explicit local
manager, without changing global settings/singletons. Its `safe_scan` override
invalidates evidence on errors instead of scoring fail-closed errors as correct
BLOCK detections. Invalid/absent/NaN model scores cannot silently become ALLOW.
This difference is deliberate and must be reconciled before deployment claims.

No downloads, installation, listener, service lifespan, Redis or remote backend
is used. ASGI clients have fixed `.invalid` hosts, explicit transports, timeouts,
no redirects and no environment proxy inheritance. They never resolve DNS.
Run in a dedicated process; tools do not mutate deployed configuration.

## Corpus Contract

JSONL rows require `text`, `label` (`benign`/`malicious`), `source`, `language`,
`channel`. Optional `category` is `prompt_injection`, `jailbreak`, or `other`
(default). Declare non-injection harmful behavior as `other`, not injection to
inflate injection recall. Channel labels describe data, not protocol coverage.
Limits: 8 MiB/file, 2,000 samples, 16,384 UTF-8 bytes/text, 128 characters/tag.
Unknown fields, duplicates, invalid rows and oversize files abort, never skip.

The manifest requires schema version 1, exact file SHA-256, classification,
owner, provenance/label-review/rights-review references, collection date,
`used_for_tuning`, and optional tuning SHA-256. References are bounded opaque
operator references, not URLs fetched by the tool. Only use sanitized references,
revision descriptions and hardware descriptions; these are published verbatim.
The CLI reports generic input failures rather than echoing invalid data.

`operator_attested_independent` requires a separate nonempty tuning inventory
with matching hash, `used_for_tuning=false`, and no normalized text overlap
(NFKC, casefold, whitespace) with that inventory, bundled corpus shards or known
evaluation examples. Supply the complete tuning inventory within limits; do not
truncate it to pass. Larger inventories require a reviewed bounded extension.
This detects trivial reuse, NOT paraphrases, hidden training contamination,
false ownership declarations or incomplete inventories. A hash authenticates
bytes relative to the supplied manifest, not the source's honesty. Owner and
peer review remain mandatory; `independence_certified` is always false.

`previously known baseline` is required for bundled data, regression data, or
generated smoke fixtures. The shipped three-row example is explicitly synthetic,
authored to test the tools, used in regression work, and is NOT an independent
holdout. No holdout is shipped. Bundled datasets use a different schema: an
operator can prepare a reviewed strict-schema derivative with original shard
hashes and transformation recorded in their provenance record. Keep category and
labels honest; do not describe the derivative as unseen.

## Reproduce Locally

Commands below run only small hermetic smoke checks from the workspace root.
Use an existing Python environment. Direct all temporary files and any captured
reports to a private directory on an approved data filesystem. Check actual root,
container storage and evidence filesystem headroom before and after execution;
preserve at least 5 GiB root reserve. Do not install a model to make readiness pass.

```bash
export PYTHONDONTWRITEBYTECODE=1
PY=python

$PY -m src.evaluation.evidence config/examples/evaluation-smoke.jsonl \
  --manifest config/examples/evaluation-smoke-manifest.json \
  --revision '<actual HEAD plus dirty-worktree disclosure>' --hardware '<sanitized operator description>'

$PY -m src.evaluation.profile_validation config/examples/evaluation-smoke.jsonl \
  --manifest config/examples/evaluation-smoke-manifest.json \
  --config config/examples/evaluation-regex.json \
  --revision '<actual revision>' --hardware '<sanitized description>'

$PY -m src.evaluation.profile_validation config/examples/evaluation-smoke.jsonl \
  --manifest config/examples/evaluation-smoke-manifest.json \
  --config config/examples/evaluation-hybrid.json --model-dir models \
  --revision '<actual revision>' --hardware '<sanitized description>'

$PY -m src.evaluation.load_harness config/examples/evaluation-smoke.jsonl \
  --manifest config/examples/evaluation-smoke-manifest.json \
  --config config/examples/evaluation-load-smoke.json \
  --profile-config config/examples/evaluation-regex.json \
  --revision '<actual revision>' --hardware '<sanitized description>'
```

Successful measurements exit 0, invalid inputs/readiness/run errors exit 2.
Exit 0 means the measurement ran, NOT that acceptance thresholds were achieved.
The original evidence CLI permits manifest-free input but labels it
`unverified_operator_corpus`; the profile/load CLIs require a manifest.

## Hybrid Profile Gate

The hybrid requires already provisioned `injection-classifier/model.onnx`,
`tokenizer.json`, and `config.json`, all pinned in the EXISTING trusted
`config/model_manifest.json`. No manifest regeneration or integrity bypass.
The preflight caps ONNX at 256 MiB, tokenizer at 8 MiB, config at 64 KiB;
larger models are unsupported by this bounded tool, not silently accepted.
Exact relative keys are required. Both binary labels `SAFE` and `INJECTION`
must be declared in verified config, in model output order. Existing manager
verification and CPU provider loading remain in use. Warmup must return finite,
normalized probabilities; missing artifacts/dependencies/invalid hashes fail
offline readiness instead of falling back to regex.

Use a trusted read-only model directory and manifest throughout the run.
Preflight and existing manager load are separate reads: this tool is not an
atomic snapshot defense against a concurrent writer. Native inference and file
I/O threads cannot be forcibly killed by asyncio deadlines; operator process
supervision/resource limits remain necessary for untrusted or hanging runtimes.
Tokenization truncates at 512 tokens. Readiness is not a safety/accuracy guarantee.

Evaluation reports preserve block/flag confusion matrices, injection-only recall,
benign FPR, sample counts and Wilson intervals. Empty classes have null headline
rates/intervals (legacy confusion-matrix zero-denominator fields remain zero).
`statistical_target_met` requires recall lower 95% bound >=0.80 and FPR upper
95% bound <=0.02. It is an intentionally conservative statistical flag, not
release approval. No sample size is fabricated to satisfy it.

Owners must pre-register sources/languages/indirect channels, target sample sizes,
label adjudication and latency budget before using a frozen holdout. Require
independent provenance review plus confidence bounds, subgroup analysis,
false-positive triage and actual deploy-path validation before changing BETA.
The profile runner never sets acceptance to achieved.

## Performance Gate

Load config bounds: 10,000 measured requests, 32 workers, 100 warmups, 100 ms mock
delay, 10 seconds/request and 300 seconds/run. Warmup has a separate run deadline.
Workload samples with replacement from validated data using a fixed seed.
Report includes schedule hash and actual scheduled class mix. Preserve both
corpus and config hashes when comparing runs; random seeds are not credentials.
Admission stops on the first request error/timeout, preventing a growing queue
of native/thread work that asyncio cancellation cannot terminate.

Measured fields include admitted-request p95 (nearest rank), total and successful
completion throughput, wall time, process CPU seconds/% of one core, traced Python
allocation peak, Linux process-lifetime RSS high-water, errors, unfinished requests,
verdict distribution by true label, and backend calls. A failed run is marked
invalid; partial metrics are diagnostic, never passing performance evidence.
Cold imports/model loading/warmup are excluded from timed load. Tracemalloc
overhead IS included; RSS includes earlier process activity and native allocations.
Closed-loop scheduling omits pre-admission queue delay (coordinated omission).
Thus the number is neither production endpoint p95 nor sustainable RPS.

Environment evidence allowlists Python/kernel/architecture, host RAM, CPU count,
affinity count, effective regex budgets, engine-config hash and pattern-set hash.
It never dumps environment secrets or hostname. CPU model, frequency, cgroup
quotas, NUMA, host contention, disk, exact worktree diff/artifact identity and model
approval must be supplied/reviewed separately. Revision/hardware strings are
operator claims, not attestation of a clean checkout.

For real acceptance, the performance owner must freeze quality and workload,
run repeated before/after samples on the same approved hardware/deployment,
include allow/block/WARN, long inputs, streaming, concurrency and target arrival
rates, and inspect saturation/errors/CPU/memory. Halving p95 requires a comparable
before baseline at unchanged quality, not comparison of unrelated smoke runs.
No production experiment is authorized by this document.

## Evidence Handoff

Store sanitized reports with exact corpus/config/model hashes, immutable code
identity plus dirty diff if applicable, command, date, operator and review outcome.
Prompts, credentials and raw model files are not in reports. Source references
and supplied descriptions can still contain sensitive data: review before sharing.
The separate signing owner can place these reports in the release evidence
manifest; these modules do not sign, publish, edit ledgers or alter workflows.

SIEM tiers remain separate: serialized event, transport acceptance, indexed event,
field/rule validation, then alert/case workflow. Each tier needs its own actual
evidence and owner. These tools exercise NONE of those tiers. Keep Wazuh and its
dependencies intact; do not start another SIEM as part of evaluation.
