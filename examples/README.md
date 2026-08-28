# Bulwark Gateway — Examples

Runnable examples for using Bulwark **as a library** (SDK / library mode) — the
security guardrails run in-process, with no gateway server, no network, and no
LLM backend required.

All examples import the `Guard` class from `src.sdk` and bootstrap `sys.path`
themselves, so you can run any of them straight from the repository root:

```bash
python examples/quickstart.py
```

> The proxy validates configuration at import time, so set a JWT secret first
> (any 32+ character string works for local runs):
>
> ```bash
> export BULWARK_JWT_SECRET="local-dev-secret-at-least-32-characters"
> ```

## Contents

| File | Dependencies | What it shows |
|------|--------------|---------------|
| [`quickstart.py`](quickstart.py) | none (stdlib + Bulwark) | Scan input (block a prompt injection, allow a benign message) and scan output (redact an AWS key in an LLM response). |
| [`wrap_llm.py`](wrap_llm.py) | none | Protect an existing LLM function with `guard.wrap(...)` and the `@guard.protect()` decorator. Malicious input raises `SecurityError` before the model is called. |
| [`langchain_guard.py`](langchain_guard.py) | `langchain-core` (optional) | Wrap a LangChain `Runnable` with `LangChainGuard`. Skips gracefully (exit 0) if LangChain is not installed. |

The first two run with only the packages Bulwark already needs, so they are
safe to execute in CI as smoke tests. `langchain_guard.py` degrades to a no-op
with an install hint when its optional dependency is absent.

## The `Guard` API in one minute

```python
from src.sdk import Guard, SecurityError
from src.models import Verdict

guard = Guard()                      # defaults: regex injection + output redaction
await guard.startup()

result = await guard.scan_input("Ignore previous instructions ...")
if result.verdict == Verdict.BLOCK:
    ...                              # reject the request

safe = await guard.scan_output(llm_response)   # REDACT masks secrets/PII
answer = await guard.wrap(call_llm, prompt)    # scans input + output around the call

await guard.shutdown()
```

Pass an explicit scanner set to opt into more engines, e.g.
`Guard(scanners=["regex_injection", "output_redaction", "tool_policy"])`.
See [`docs/SDK-LIBRARY-MODE.md`](../docs/SDK-LIBRARY-MODE.md) for the full API,
available scanner names, and the LlamaIndex / AutoGen / CrewAI adapters.
