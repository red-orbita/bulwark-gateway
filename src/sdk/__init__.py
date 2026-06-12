"""
Sentinel SDK — Embeddable Python library for AI security guardrails.

Use Sentinel as a library without running the full gateway proxy.
Provides input/output scanning, framework integrations, and decorators
for wrapping LLM calls with security guardrails.

Usage:
    from src.sdk import Guard, ScanResult, Verdict

    guard = Guard(scanners=["regex_injection", "output_redaction"])
    await guard.startup()

    result = await guard.scan_input("user message here")
    if result.verdict == Verdict.BLOCK:
        raise SecurityError(result.events)

    # Or use as a decorator:
    @guard.protect()
    async def my_llm_call(prompt: str) -> str:
        return await call_llm(prompt)
"""

from __future__ import annotations

from src.models import Verdict
from src.sdk.guard import Guard, ScanResult
from src.sdk.integrations import LangChainGuard, LlamaIndexGuard

__all__ = [
    "Guard",
    "LangChainGuard",
    "LlamaIndexGuard",
    "ScanResult",
    "Verdict",
]
