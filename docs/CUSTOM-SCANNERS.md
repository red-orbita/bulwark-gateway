# Writing a Custom Scanner

How to build, register, and ship a scanner for the Bulwark Gateway scanner
framework. Scanners are the atomic units of security checking — each one
inspects input or output content and returns a `Verdict`.

This guide covers the in-tree scanner API. If you want to distribute your
scanner as an installable package (with its own `bulwark-plugin.yaml`,
security audit, and lifecycle management), read [Plugins](PLUGINS.md) after
this — a plugin *contains* a scanner class that implements exactly the
interface described here.

---

## 1. The Scanner Contract

All scanners subclass one of two abstract base classes from
`src/scanners/protocol.py`:

- **`InputScanner`** — inspects user messages **before** they reach the LLM.
- **`OutputScanner`** — inspects LLM responses **before** they reach the user.

Both require you to implement exactly **two** members:

| Member | Kind | Purpose |
|--------|------|---------|
| `info` | `@property` returning `ScannerInfo` | Static metadata (name, type, priority, maturity) |
| `scan(content, context)` | `async` method returning `GuardrailResult` | The actual detection logic |

Three lifecycle hooks are **optional** (they have safe no-op defaults):

| Hook | Default | When it runs |
|------|---------|--------------|
| `async startup()` | no-op | Once at app startup — load models, warm caches |
| `async shutdown()` | no-op | Once at app shutdown — release resources |
| `async health()` | returns `True` | Health probe; a blocking scanner reporting `False` is fatal at boot |

> **Never override `safe_scan()`.** The base class provides it — it wraps your
> `scan()` with a timeout and exception guard so a buggy scanner can never crash
> the pipeline. The pipeline always calls `safe_scan()`, never `scan()` directly.

---

## 2. Scanner Types and the Fail Mode

`ScannerInfo.scanner_type` places your scanner in one of four lanes
(`ScannerType` enum):

| Type | Lane | Can block? | On error/timeout |
|------|------|-----------|------------------|
| `INPUT_BLOCKING` | Hot path, before forward | Yes | **Fail-closed → BLOCK** |
| `INPUT_ASYNC` | Fire-and-forget enrichment | No | Fail-open → ALLOW |
| `OUTPUT_BLOCKING` | Output path, before return | Yes (block/redact) | **Fail-closed → BLOCK** |
| `OUTPUT_ASYNC` | Output enrichment | No | Fail-open → ALLOW |

This asymmetry is deliberate and enforced in `safe_scan()`
(`src/scanners/protocol.py`): a **blocking** scanner that crashes or times out
returns `BLOCK` (the request is denied rather than passed through unscanned);
an **async/advisory** scanner that fails returns `ALLOW` (it never gates request
flow). Choose `*_BLOCKING` only if your detection is deterministic, fast, and
you are prepared for its failures to deny traffic.

The default per-scanner timeout is **5000 ms**. If your `scan()` exceeds 80% of
the timeout, the pipeline logs a `scanner_slow` warning.

---

## 3. Priority

`ScannerInfo.priority` (int, 0–100, **lower runs first**) orders scanners
within a lane. The builtin `regex_input` scanner uses `priority=10` so the
cheap, comprehensive regex check runs before anything expensive. Pick a value
that reflects your scanner's cost and how early you want it to short-circuit.

---

## 4. Maturity Tier — an Honesty Signal

`ScannerInfo.maturity` (`MaturityTier` enum) declares how much operators should
trust your verdicts. It is **not** a functional gate — it is a truthfulness
signal so the product never overstates its coverage:

| Tier | Meaning |
|------|---------|
| `GA` | Deterministic, tested, production-proven. Safe to run blocking. |
| `BETA` | Real detection logic or a provisioned model + tests, but efficacy not yet validated against an external benchmark. Prefer WARN/shadow before blocking. |
| `EXPERIMENTAL` | Incomplete, unvalidated, or not wired to a model. May be inert. |

**The default is `EXPERIMENTAL`.** Anything you do not explicitly promote is
treated as unproven — new and third-party scanners never masquerade as GA. Only
set `GA` when your scanner genuinely earns it.

---

## 5. The `scan()` Method

```python
async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
    ...
```

**Inputs**

- `content: str` — the text to scan. For input scanners this is the normalized
  user content; for output scanners it is the LLM response text.
- `context: ScanContext` — request context. Useful fields:

| Field | Type | Notes |
|-------|------|-------|
| `tenant_id` / `agent_id` | `str` | Tenant/agent isolation — stamp these on every event |
| `request_id` | `str` | Trace correlation |
| `messages` | `list[dict]` | Full message list; `context.user_content` concatenates user turns |
| `metadata` | `dict` | Free-form context threaded from the proxy |
| `language` | `str \| None` | Detected language, if the language detector ran |
| `content_type` | `str` | `"text"`, `"image"`, `"audio"`, `"multimodal"` |
| `session_id` / `source_ip` | `str \| None` | Dialog + origin context |

**Output** — a `GuardrailResult` (`src/models.py`):

- `verdict: Verdict` — `ALLOW`, `BLOCK`, `WARN`, or `REDACT`.
- `events: list[SecurityEvent]` — emit one per finding (feeds SIEM/notifications).
- `modified_content: str | None` — for `REDACT`, the sanitized content to
  forward in place of the original.

**Rules of the hot path** (from the project conventions):

- **No external/network/LLM calls inside `scan()`.** The hot path is pure
  computation. Do any model loading in `startup()`.
- Return `ALLOW` with no events for clean content — do not fabricate findings.
- Stamp `tenant_id`, `agent_id`, and `request_id` from `context` on every event.

---

## 6. Complete Example — an Input Scanner

The repository ships a real, dependency-free example at
`plugins/examples/input-dlp-scanner/scanner.py` (a DLP scanner with Luhn credit
card validation, IBAN/DNI/NIE checks, and bulk-PII detection). Here is a
minimal scanner distilled to the essentials:

```python
from __future__ import annotations

import re

from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict
from src.scanners.protocol import (
    InputScanner,
    MaturityTier,
    ScanContext,
    ScannerInfo,
    ScannerType,
)

_SECRET_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")  # AWS access key id


class Scanner(InputScanner):
    """Blocks messages that leak an AWS access key id."""

    @property
    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="aws-key-blocker",
            version="1.0.0",
            scanner_type=ScannerType.INPUT_ASYNC,   # advisory: fail-open
            description="Blocks AWS access key ids in prompts",
            author="your-org",
            priority=40,
            maturity=MaturityTier.BETA,              # be honest
        )

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        if not _SECRET_RE.search(content):
            return GuardrailResult(verdict=Verdict.ALLOW)

        event = SecurityEvent(
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            verdict=Verdict.BLOCK,
            category=ThreatCategory.CREDENTIAL_ACCESS,
            severity="critical",
            description="AWS access key id detected in user input",
            source="aws-key-blocker",
            request_id=context.request_id,
        )
        return GuardrailResult(verdict=Verdict.BLOCK, events=[event])
```

### Output scanner + redaction

An `OutputScanner` is identical except it subclasses `OutputScanner` and may set
`modified_content` for a `REDACT` verdict:

```python
class Scanner(OutputScanner):
    @property
    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="ssn-redactor",
            version="1.0.0",
            scanner_type=ScannerType.OUTPUT_BLOCKING,  # can redact/block
            maturity=MaturityTier.BETA,
        )

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        redacted, n = re.subn(r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED:SSN]", content)
        if n == 0:
            return GuardrailResult(verdict=Verdict.ALLOW)
        return GuardrailResult(verdict=Verdict.REDACT, modified_content=redacted)
```

### Loading a model

Do it in `startup()`, not in `scan()`:

```python
class Scanner(InputScanner):
    def __init__(self) -> None:
        self._model = None

    async def startup(self) -> None:
        self._model = load_my_model()   # runs once at boot

    async def health(self) -> bool:
        return self._model is not None   # blocking scanner: False ⇒ boot fails
```

If `startup()` raises, the pipeline auto-disables the scanner rather than
crashing (see §8). A blocking scanner whose `health()` returns `False` at boot
is treated as a fatal misconfiguration.

---

## 7. Registration

There are two ways to get a scanner into the pipeline.

### 7a. Programmatic (in-process)

Register directly on a `ScannerPipeline` (this is what the [SDK](SDK-LIBRARY-MODE.md)
does under the hood):

```python
from src.scanners.pipeline import ScannerPipeline

pipeline = ScannerPipeline()
pipeline.register(Scanner())          # routes to the correct lane by scanner_type
await pipeline.startup()              # calls startup() on every scanner
```

`register(scanner, priority=None, enabled=True)` reads `scanner.info`, routes it
to the lane implied by `scanner_type`, and sorts the lane by priority. You can
override priority at registration time.

### 7b. Discovery (packaged or drop-in)

`src/scanners/discovery.py` finds scanner **classes** (it does not execute them
until they are registered) from two sources:

**Python entry points** — for pip-installable packages. Declare in your
`pyproject.toml`:

```toml
[project.entry-points."bulwark.scanners"]
my_scanner = "my_package.scanner:Scanner"
```

**Drop-in directory** — any `*.py` file in a scanner directory (files starting
with `_` are skipped). Each file is imported and classes subclassing
`InputScanner`/`OutputScanner` (and defined in that module) are collected.

```python
from pathlib import Path
from src.scanners.discovery import discover_all_scanners, instantiate_scanner

classes = discover_all_scanners(scanner_dir=Path("config/scanners"))
for cls in classes:
    pipeline.register(instantiate_scanner(cls))
```

Entry-point scanners take priority over drop-in ones with the same class name
(dedup is by class name).

---

## 8. Failure Semantics You Get for Free

The pipeline is defensive by design:

- **`scan()` throws** → `safe_scan()` catches it. Blocking scanner ⇒ `BLOCK`;
  async scanner ⇒ `ALLOW`. The pipeline never propagates the exception.
- **`scan()` times out** (default 5 s) → same fail-closed/fail-open split.
- **`startup()` throws** → `pipeline.startup()` auto-disables that scanner and
  keeps booting (a broken scanner cannot take down the gateway).
- **Blocking scanner `health()` is `False` at boot** →
  `pipeline.unhealthy_blocking_scanners()` reports it; this is a fatal
  boot condition (a hot-path guard that cannot run must not be silently skipped).

You do not need to add your own try/except around detection logic for safety —
but you should still handle *expected* conditions gracefully and return a clean
`ALLOW` when there is nothing to report.

---

## 9. Testing

Every new scanner must have tests with **both** a positive (should block/flag)
and a negative (should allow legitimate traffic) case — this is a hard project
requirement. Test the scanner directly; no server needed:

```python
import pytest
from src.models import Verdict
from src.scanners.protocol import ScanContext
from my_package.scanner import Scanner


def _ctx(text: str) -> ScanContext:
    return ScanContext(
        tenant_id="t1",
        agent_id="a1",
        request_id="r1",
        messages=[{"role": "user", "content": text}],
    )


@pytest.mark.asyncio
async def test_blocks_aws_key():
    s = Scanner()
    await s.startup()
    result = await s.scan("my key is AKIAIOSFODNN7EXAMPLE", _ctx("..."))
    assert result.verdict == Verdict.BLOCK
    assert result.events


@pytest.mark.asyncio
async def test_allows_clean_text():
    s = Scanner()
    await s.startup()
    result = await s.scan("what is the weather today?", _ctx("..."))
    assert result.verdict == Verdict.ALLOW
    assert not result.events
```

Run with `pytest -q`. Existing framework tests live in
`tests/test_scanner_framework.py` and are a good reference.

---

## 10. Checklist

- [ ] Subclass `InputScanner` or `OutputScanner`.
- [ ] Implement `info` (property) and `async scan()`.
- [ ] Pick the correct `ScannerType` — only go blocking if you accept fail-closed.
- [ ] Set an honest `MaturityTier` (default `EXPERIMENTAL`; earn `GA`).
- [ ] Load models in `startup()`, not `scan()`. No network/LLM calls in the hot path.
- [ ] Stamp `tenant_id`/`agent_id`/`request_id` on every `SecurityEvent`.
- [ ] Add positive **and** negative tests.
- [ ] Register programmatically, via entry points, or via drop-in directory.

To package and distribute the scanner (spec file, security audit, install/enable
lifecycle), continue with [Plugins](PLUGINS.md).
