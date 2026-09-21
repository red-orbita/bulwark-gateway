# SDK Adapter Contracts

These contracts cover the AutoGen, CrewAI, LangChain and LlamaIndex adapters in
`src/sdk/integrations`. Tests use local doubles, plus focused checks with the
existing regex/output scanners. They do **not** certify any vendor release or
claim compatibility with every framework object. No vendor packages or models
are downloaded for these tests.

## Inspection Boundary

- Every string in supported eager structures is inspected, including dictionary
  keys, nested arguments, all output fields, metadata and all message roles
  (including system, developer, assistant and tool). A familiar field name no
  longer hides sibling fields.
- Supported data consists of exact built-in `str`, `dict` with string keys,
  `list`, `tuple`, `None`, `bool`, `int` (up to 256 bits) and `float`. Subclasses
  with custom behavior are not accepted as these built-ins.
- A narrow passive-record contract accepts exact `SimpleNamespace` and ordinary
  direct `object` subclasses with only instance storage and an initializer. They
  must contain a recognized field (`content`, `raw`, `response`, `text`,
  `query_str`, `result` or `output`). All stored fields are inspected, not only
  that recognized field. Clean records are reconstructed as detached instances
  of the same passive type, without invoking constructors or copy hooks. Records with
  methods, properties, slots, custom accessors, inheritance or custom metaclasses
  are rejected. Arbitrary Pydantic/dataclass/vendor objects are not guaranteed.
- Payload inspection does not call `get_response`, `model_dump`, `__str__`,
  properties, custom iterators or dynamic attribute access. Unknown objects,
  generators, async generators, lazy responses and binary payloads fail closed,
  even if another field is clean. Materialize and normalize them explicitly
  outside the adapter using a trusted application-specific contract.
- Limits per complete input/output tree are 1,024 nodes, depth 32, and 16 KiB
  input / 64 KiB output UTF-8 text (keys and joining separators included).
  Repeated references count repeatedly; cycles, invalid Unicode and excessive
  size fail closed before scanning. Redacted output is bounded too.
- Validation captures a detached snapshot of every supported container and
  passive record before any scanner call or `await`. Only this snapshot is used
  for input forwarding, output returns and redaction reconstruction. A scanner
  callback or another task mutating the caller's original cannot change the
  inspected data. Unknown/lazy values are rejected, never copied via hooks.
- Clean data preserves values and supported types, **not object identity or
  alias relationships**. Every occurrence of a shared mutable value is detached.
  Mutations made by an underlying tool to its input snapshot are not propagated
  to the caller's original containers. Explicit `None` remains `None`.

## Redaction And Errors

Input BLOCK or REDACT rejects a wrapped invocation **before execution**. Input
redaction is never ignored or forwarded as the original. AutoGen's explicit
scalar `scan_message` / `scan_message_async` methods still return the replacement
string, including an empty replacement; structured input redaction is rejected.

Inputs are scanned leaf by leaf and as combined text. Outputs are scanned leaf
by leaf and again as combined sanitized text. Scalar mapping entries also produce
contextual `key=value` candidates (including nested metadata and passive-record
fields). This preserves credential context, for example
`{"metadata": {"password": "violet-harbor"}}`, which isolated string scans would
miss. Contextual BLOCK or REDACT rejects the result: an aggregate replacement
cannot be unambiguously assigned to the original fields. Context candidates are
bounded by the same per-direction text budget, separately from the leaf budget.

Multiple output fields and metadata are all covered. Built-in containers are
rebuilt from the detached snapshot at exact string paths. An empty string
is a valid replacement; a missing/non-string replacement is an error. Findings
requiring key renaming, object mutation or cross-field reconstruction are
ambiguous and block instead of returning partially sanitized data. No fallback
response retains an uninspected original or proxies its metadata/source nodes.

Explicit `None` output remains a legitimate empty outcome, as do clean strings
and supported eager data. This is distinct from an unknown response for which no
text could be extracted. Scanner exceptions and invalid verdicts fail closed
with generic errors. CrewAI's task callback reports `(False, generic_reason)`
rather than exposing payloads or scanner diagnostics.

## Adapter Surfaces

| Adapter | Guarded surface | Important boundary |
| --- | --- | --- |
| AutoGen | `generate_reply`, `a_generate_reply`, explicit scan methods | Generation requires 1-128 explicit text messages (or one string); implicit history, missing content and non-text blocks are rejected. All roles and additional invocation kwargs are inspected. `sender` is a trusted framework routing handle, not inspected content. |
| CrewAI | `run` and `_run`, `guard_tool`, `task_guardrail` | Both synchronous tool entrypoints are wrapped when present. All positional/keyword arguments are inspected recursively, including short strings. This is content inspection, not tool authorization or coverage of unrelated/async tool entrypoints. |
| LangChain | `invoke`, `ainvoke` | Entire input and invocation kwargs are inspected; `None` input is rejected. `RunnableConfig` is trusted operator configuration, not a prompt transport. `as_callback` is bounded, best-effort monitoring only and cannot enforce blocking/redaction. |
| LlamaIndex | `query`, `aquery` | Entire query and kwargs are inspected; `None` query is rejected. Unknown methods are no longer forwarded to the underlying engine; this prevents obtaining an unguarded execution path through the wrapper. |

Framework endpoints, installed framework code and operator configuration are
trusted. Hidden framework memory, constructor-supplied prompts, retrieval steps,
tool execution and callbacks outside these invocation boundaries are not made
safe by a content adapter. Use explicit history and application-specific
normalization, and do not place prompt content in trusted configuration handles.
Scanning textual tool arguments is not equivalent to validating tool permissions
or scanning images, audio or serialized artifacts.

## Compatibility Changes

- CrewAI nested dictionaries/lists and short arguments no longer bypass scanning.
- LangChain no longer stops at the first recognized input/output field.
- Unknown/lazy outputs no longer pass unchanged; LlamaIndex no longer attempts
  implicit materialization, stringification or arbitrary method forwarding.
- Dynamic/vendor objects that previously happened to expose a text property may
  now be rejected. Use built-in eager data or a dedicated reviewed adapter.
- Object redaction and aggregate/ambiguous replacements block instead of mutating
  a selected property and potentially leaving secondary content or secrets intact.
- Contextual credentials now block even when their isolated keys and values are
  individually allowed. Clean mutable data is detached rather than returned or
  forwarded by identity; caller-side mutations during inspection cannot escape.
- Existing input-redaction prevention and legitimate `None` output are preserved.

## Local Verification

Run with the existing project virtual environment, without installing packages:

```bash
python -m pytest \
  tests/test_adapter_redaction_contracts.py \
  tests/test_sdk_agent_integrations.py \
  tests/test_adapter_structured_contracts.py -q --tb=short
```

The structured tests cover nested attacks/redactions, every role, secondary
outputs and metadata, sync/async parity, unknown/lazy objects without execution,
cycles and budgets, short arguments, immutable/ambiguous redaction, generic
scanner failures, tenant/agent context forwarding and legitimate empty outcomes.
Review regressions exercise contextual credentials with the real `OutputFilter`,
sync scanner mutations, mutations by another task while a scanner awaits,
secret/generator insertion, redaction reconstruction, detached kwargs/records
and rejection of copy hooks. They are adapter contracts, not vendor version tests.
