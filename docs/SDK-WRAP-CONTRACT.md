# Generic SDK Wrapper Contract

`Guard.wrap`, `wrap_sync` and the `protect` decorator are text-only convenience
wrappers, not substitutes for the proxy's tool policy, DLP, IOC or SSE pipeline.
This branch rejects unsupported shapes instead of returning uninspected content.

## Supported Shapes

| Input | Behavior |
|---|---|
| One positional string | Inspect and apply scalar redaction before calling backend |
| One string keyword: prompt/content/input/query/message | Inspect and apply redaction to that same keyword |
| messages list with 1-128 entries | Inspect text from all roles, not just user |
| Structured message content | Only text blocks supported, maximum 128 per message |
| Multiple prompt sources, tool definitions/history, streaming, images or unknown shape | Raise SecurityError before backend execution |

Total extracted input is capped at 16384 UTF-8 bytes including join separators.
That is a wrapper work limit, not a guarantee that every detector scans every
byte under every configuration. Detection still depends on enabled scanners and
their individual budgets. Metadata and arbitrary additional function arguments
are not covered by this text extraction contract; use explicit scan/DLP APIs or
an application-specific adapter rather than sending sensitive data through them.

Conversation redaction remains rejected: a flattened replacement cannot safely
restore role boundaries. Multi-turn model context is not reconstructed by the
wrapper; use a dedicated conversation integration for that capability.

| Output | Behavior |
|---|---|
| String, including empty | Inspect; return replacement if redacted |
| Dict with exactly one content or text selector | Inspect; shallow-copy replacement without mutating caller's response |
| Dict with exactly one choices entry containing message.content | Inspect; block on BLOCK; require explicit adapter on REDACT |
| Passive record with string content and no choices/tool payload | Inspect detached same-type record; require explicit adapter on REDACT |
| Multiple choices/selectors, tool calls, generators, unknown/non-text payload | Raise SecurityError; never return as inspected |

Selected output text is capped at 65536 UTF-8 bytes. Arbitrary response metadata
is not inspected; do not treat wrapper approval as approval of every byte of an
unknown provider envelope. Tool execution always needs explicit authorization.

Before scanning, arguments and responses are captured as bounded, detached trees
using the structured adapters' passive-record checks. Built-in dict/list/tuple
containers, scalar values, `SimpleNamespace` and supported passive records retain
their values and types, but mutable identity is intentionally not preserved.
Caller/provider mutations during scan awaits cannot change the forwarded or
returned snapshot. Dynamic objects, properties, custom containers, cycles, excessive
depth/node counts and oversized aggregate envelopes fail closed. Each snapshot is
limited to 1 MiB of UTF-8 strings (including keys and metadata), 1024 nodes and
32 levels of nesting. The smaller selected-text limits above remain unchanged.
Snapshotting metadata bounds
and detaches it; it does not add metadata threat scanning to this wrapper.

## Async And Startup

Async callable objects and awaitables returned by sync callables are awaited
before output inspection. Sync backends run through `asyncio.to_thread`, not on
the event loop. They must tolerate worker-thread invocation. Cancellation cannot
undo a synchronous backend side effect; this wrapper is not an execution sandbox.

Unknown scanner names refuse startup in fail-closed mode. Explicit fail-open mode
logs and skips them. Scanner startup/readiness failures retain the previously
documented fail-closed or explicitly degraded behavior. No global default flags
are enabled by this change.

## Evidence

`tests/test_sdk_wrap_contracts.py` tests roles, structured text, unsupported shapes,
limits, real injection blocking, real output redaction and async callable behavior.
The initial 40-case regression run had 33 failures and 7 passing cases before this
change. This measures wrapper contracts, not independent detection recall.
Existing framework adapters have separate contracts and are not implicitly fixed
or certified by these changes to the generic wrapper.
