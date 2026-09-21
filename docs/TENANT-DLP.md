# Tenant And Agent Input DLP

`input_dlp` on an agent policy adds controls to the global pre-upstream DLP floor.
It is selected from the policy engine using authenticated request-state tenant and
agent IDs, never body/header identity claims. See `config/examples/tenant-dlp.yaml`.

| Setting | Contract |
|---|---|
| enabled | Strict boolean; default false. Global DLP cannot be disabled by this field. |
| max_bytes | Strict integer 1-262144; default 65536. When both scopes enable DLP, the smaller budget wins. |
| redact_email / redact_phone | Strict booleans enabling additional PII detection. Global enabled checks cannot be disabled. |
| blocked_terms | At most 32 literal strings of 3-128 characters, normalized with Unicode NFKC and case folding. Matches cause BLOCK, not logging of the matched term. |

Known secret/PII signatures always run when either global or agent DLP is enabled.
Classification matching is bounded substring matching, not arbitrary regex or a
semantic classifier. It includes Unicode normalization/invisible-format removal,
but does not promise arbitrary encoding, image, synonym or cross-field coverage.
Store classification markers here, not sensitive documents or credentials.

Policy-specific terms apply only when that policy enables DLP. There is no request
flag for opting out, destination exception, allow-secret bypass or remote model.
The existing DLP node/string/UTF-8 limits continue to apply. Requests exceeding
them block rather than receiving partial-coverage approval. Operator policy
validation rejects misspelled fields and ambiguous boolean/integer coercion.

## Policy Publication

Startup rejects a partially invalid policy set. Hot reload retains the entire
previous engine and file-version snapshot if any file fails parsing/validation,
or if two entries claim the same tenant/agent. A corrected file is retried; policy
I/O runs in a worker thread. File identity/size/nanosecond timestamps are captured
from the opened file and compared before publication; replacement during a read
rejects that candidate set rather than recording newer metadata for old content.
The shipped empty `agents: {}` baseline is retained as an empty set for compatibility.
This preserves protections of one tenant when a
different file is invalid. Existing all-policies-empty rejection remains active.

This does not replace an admin policy editor, destination-scoped DLP, outbound
firewall controls or corporate data classification. No runtime policies were
activated by adding the example. Evaluate false positives before rollout.

## Backend Egress

An agent can additionally specify `backend_egress.enabled: true` with 1-32
`allowed_origins`, such as `https://llm.corp.example`. Matching is exact after
scheme/hostname/port normalization; HTTPS and HTTP are different permissions.
Default ports, IDNA names and IPv6 literals are canonicalized. Wildcards,
credentials, fragments, allowlist paths and query strings are rejected.

The proxy checks each attempted primary/fallback destination before loading its
credential or contacting it, in both response modes. A disallowed fallback is
blocked, not contacted to preserve availability. This does not exempt matching
origins from SSRF validation and does not pin resolved IPs or replace a network
firewall. An allowed hostname with compromised DNS remains an infrastructure risk.
Cached responses perform no upstream egress. Policy deletion/changes require the
existing operator permissions; no client-controlled bypass is provided.

## Adapter Contract Follow-up

LangChain/LlamaIndex and CrewAI now reject input REDACT when they cannot safely
replace the argument structure; they do not send the original. Empty output
redactions are honored; missing replacements and unsupported/immutable outputs
fail rather than returning original content. CrewAI task-inspection exceptions
return a failed guardrail result without exception details. AutoGen generation
requires explicit bounded messages, scans all supplied roles and rejects changed
input rather than invoking its original history. These tests use framework doubles,
not a compatibility certification for installed third-party releases. Auxiliary
methods, framework-owned history, source-node metadata and arbitrary tool execution
still require dedicated application integration and execution-boundary validation.
