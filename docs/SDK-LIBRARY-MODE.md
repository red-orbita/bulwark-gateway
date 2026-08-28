# Using Bulwark as a Library

Bulwark can run as an **embedded Python library** — you get the same scanner
pipeline that powers the gateway, in-process, with no proxy, no network hop, and
no FastAPI server. This is the right choice when you want to guard LLM calls
directly inside your own application or agent framework.

> **Three different SDKs ship in this repo — do not conflate them.** This guide
> documents the **in-process library** (`src/sdk`), which runs the *real*
> scanner pipeline in your process. Two other, thinner SDKs exist for
> talking to a *running* gateway over HTTP; they are summarized in
> [§7](#7-the-other-two-sdks-http-clients) so you pick the right one.

---

## 1. What the In-Process SDK Is

`src/sdk` exposes a `Guard` class that instantiates a `ScannerPipeline` and runs
your chosen scanners locally. It is part of the `bulwark-gateway` package
(v1.0.0) — the same code the proxy runs. There is **no HTTP call**: `scan_input`
and `scan_output` execute the pipeline directly.

Public surface (`src/sdk/__init__.py`):

```python
from src.sdk import Guard, ScanResult, Verdict
from src.sdk import LangChainGuard, LlamaIndexGuard   # framework adapters
```

`SecurityError` (raised when a wrapped call is blocked) lives in
`src/sdk/guard.py`:

```python
from src.sdk.guard import SecurityError
```

---

## 2. Quick Start

```python
import asyncio
from src.sdk import Guard, Verdict


async def main():
    guard = Guard(scanners=["regex_injection", "output_redaction"])
    await guard.startup()          # registers + starts the scanners

    result = await guard.scan_input("Ignore all previous instructions and...")
    if result.verdict == Verdict.BLOCK:
        print("blocked:", result.events[0].description)

    await guard.shutdown()

asyncio.run(main())
```

`Guard.startup()` must be called before any scan — it lazily imports each
scanner class and registers it in the pipeline. Skipping it raises
`RuntimeError`.

---

## 3. Constructor

```python
Guard(scanners: list[str] | None = None, config: dict | None = None)
```

**`scanners`** — a list of scanner names. If `None`, the default set is used:

```python
_DEFAULT_SCANNERS = ["regex_injection", "output_redaction"]
```

Available names (from the `_SCANNER_REGISTRY` in `src/sdk/guard.py`):

| Name | Class | Lane |
|------|-------|------|
| `regex_injection` | `RegexInputScanner` | input blocking (GA) |
| `output_redaction` | `OutputRedactionScanner` | output blocking (GA) |
| `tool_policy` | `ToolPolicyScanner` | tool-call RBAC |
| `ml_injection` | `InjectionClassifier` | ML input (needs a provisioned model) |
| `ml_toxicity` | `ToxicityScanner` | ML input (needs a provisioned model) |
| `hallucination` | `HallucinationScanner` | output async (needs NLI model) |
| `relevance` | `RelevanceScanner` | output async (needs embeddings model) |
| `grounding` | `GroundingScanner` | output async (needs NLI model) |
| `schema_validator` | `SchemaValidator` | output (model-free) |
| `language_detector` | `LanguageDetector` | multilingual |

> The ML/output-validation scanners are only useful if their models are
> provisioned (see `download-models.py` and the `BULWARK_*_ENABLED` flags in the
> project config). Without a model they may be inert — the default two scanners
> are the deterministic, always-available baseline.

**`config`** — override dict. Supported keys:

| Key | Type | Effect |
|-----|------|--------|
| `timeout_ms` | float | Per-scanner timeout (default 5000) |
| `fail_mode` | str | `"closed"` (default) raises if a scanner fails to load; `"open"` skips it |
| `block_threshold` | float | Minimum confidence to block (scanner-dependent) |
| `ml_enabled` | bool | Enable ML scanners |

If a scanner name is unknown, it is logged and skipped. If a known scanner fails
to *load* and `fail_mode="closed"`, `startup()` raises `RuntimeError` — a
fail-closed posture so you never silently run with fewer guards than you asked
for.

---

## 4. Scanning APIs

### Async

```python
result = await guard.scan_input(
    "user message",
    tenant_id="acme",         # defaults to "default"
    agent_id="support-bot",   # defaults to "default"
    metadata={"source": "web"},
)

result = await guard.scan_output(
    "LLM response text",
    input_messages=[{"role": "user", "content": "..."}],
    tenant_id="acme",
    agent_id="support-bot",
)
```

Both return a `ScanResult`:

```python
@dataclass
class ScanResult:
    verdict: Verdict                       # ALLOW / BLOCK / WARN / REDACT
    events: list[SecurityEvent]            # findings (for logging / SIEM)
    modified_content: str | None           # redacted text when verdict == REDACT
    latency_ms: float                       # measured scan time
```

`scan_input` runs the **input blocking** lane; `scan_output` runs the **output
blocking** lane.

### Sync

For non-async codebases there are synchronous wrappers — `scan_input_sync`,
`scan_output_sync`, `wrap_sync`. They safely run the coroutine even when called
from inside an existing event loop (e.g. a Jupyter notebook) by offloading to a
worker thread:

```python
result = guard.scan_input_sync("user message")
```

---

## 5. Wrapping an LLM Call

`wrap()` scans input, runs your LLM call, then scans the output — raising
`SecurityError` if either side is blocked, and substituting redacted content on
a `REDACT` verdict.

```python
from src.sdk.guard import SecurityError

async def call_llm(prompt: str) -> str:
    return await my_model.complete(prompt)

try:
    answer = await guard.wrap(call_llm, "summarize this document ...")
except SecurityError as e:
    answer = "Request blocked by security policy."
```

`wrap()` extracts the input from the first string positional argument or from a
`prompt`/`content`/`input`/`query`/`message`/`messages` kwarg, and extracts
output from a plain string, an OpenAI-style `{"choices": [...]}` dict, a
`{"content": ...}`/`{"text": ...}` dict, or any object with a `.content`
attribute.

### Decorator form

```python
@guard.protect(tenant_id="acme", agent_id="support-bot")
async def generate(prompt: str) -> str:
    return await my_model.complete(prompt)

answer = await generate("hello")   # transparently scanned in + out
```

`@guard.protect()` works on both sync and async functions (it dispatches to
`wrap` / `wrap_sync` automatically).

---

## 6. Framework Adapters

`src/sdk/integrations` provides thin, optional wrappers. They accept an existing
`Guard` (or build one with defaults) and require the target framework to be
installed:

| Adapter | Import | Wraps |
|---------|--------|-------|
| `LangChainGuard` | `from src.sdk import LangChainGuard` | a LangChain `Runnable`/chain (`.invoke`/`.ainvoke`) |
| `LlamaIndexGuard` | `from src.sdk import LlamaIndexGuard` | LlamaIndex query flow |
| `AutoGenGuard` | `from src.sdk.integrations import AutoGenGuard` | AutoGen agent messages/replies |
| `CrewAIGuard` | `from src.sdk.integrations import CrewAIGuard` | CrewAI tools / task guardrails |

LangChain example:

```python
from src.sdk import Guard, LangChainGuard

guard = Guard()
await guard.startup()

lc_guard = LangChainGuard(guard=guard)
safe_chain = lc_guard.wrap(my_chain)
response = await safe_chain.ainvoke({"input": "hello"})
```

The wrapped runnable scans input before and output after the chain, raising
`SecurityError` on a block. If `langchain-core` is not installed, `.wrap()`
raises a clear `ImportError`.

---

## 7. The Other Two SDKs (HTTP clients)

If you are **not** embedding Bulwark but instead calling a **running gateway**,
use one of these instead of `src/sdk`:

### `bulwark-gateway-sdk` (standalone Python, `sdk/`)

Package `bulwark_sdk` (`__version__ = "0.2.0"`). Two entry classes:

```python
from bulwark_sdk import BulwarkClient, BulwarkGuard

# Remote: calls a running gateway over HTTP
client = BulwarkClient(
    base_url="https://bulwark.company.com",
    api_key="sk-...",
    tenant_id="acme-corp",
    agent_id="support-bot",
)
result = await client.scan_input("user message")

# Local: offline regex-only guard (a lightweight subset, NOT the full pipeline)
guard = BulwarkGuard()
result = guard.scan("user message")
```

Note `BulwarkGuard` here is a standalone regex guard — it is **not** the
in-process `Guard` from `src/sdk` and does not run the full scanner pipeline.

### `@bulwark-gateway/sdk` (TypeScript, `sdk/typescript/`)

HTTP-only client for Node/browser. The exported class is **`SentinelClient`**
(the TypeScript SDK does not expose a `BulwarkClient`):

```ts
import { SentinelClient } from "@bulwark-gateway/sdk";

const client = new SentinelClient({ baseUrl, apiKey, tenantId, agentId });
const result = await client.scanInput("user message");
```

### Which one do I use?

| You want to… | Use |
|--------------|-----|
| Run the real scanner pipeline in-process, no server | `src/sdk` → `Guard` (this guide) |
| Call a deployed gateway from Python | `bulwark_sdk` → `BulwarkClient` |
| Do a quick offline regex check in Python, no pipeline | `bulwark_sdk` → `BulwarkGuard` |
| Call a deployed gateway from TypeScript/Node | `@bulwark-gateway/sdk` → `SentinelClient` |

> **Branding note:** these packages mix the `Bulwark` and `Sentinel` names
> (notably the TS client class). Match the exact identifier for the package you
> import — they are not interchangeable.

---

## 8. Lifecycle & Threading Notes

- Always `await guard.startup()` before scanning and `await guard.shutdown()`
  when done (releases scanner resources / models).
- `Guard` is intended to be built once and reused; do not create a new `Guard`
  per request — model loading happens in `startup()`.
- The sync wrappers detect a running event loop and offload to a worker thread,
  so they are safe to call from notebooks and mixed sync/async code.
- The same hot-path rule applies as everywhere in Bulwark: scanners must not
  make network/LLM calls during `scan()`.

---

## 9. Next Steps

- Add your own detection logic: [Writing a Custom Scanner](CUSTOM-SCANNERS.md).
- Package and distribute a scanner: [Plugins](PLUGINS.md).
- Full architecture and request flow: [Architecture](ARCHITECTURE.md).
