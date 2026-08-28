"""Built-in scanners — Wrappers around existing Bulwark guardrail engines."""

from __future__ import annotations

from typing import TYPE_CHECKING

from src.scanners.builtin.output_redaction_scanner import OutputRedactionScanner
from src.scanners.builtin.regex_scanner import RegexInputScanner
from src.scanners.builtin.tool_policy_scanner import ToolPolicyScanner

if TYPE_CHECKING:
    from src.scanners.pipeline import ScannerPipeline

__all__ = [
    "RegexInputScanner",
    "OutputRedactionScanner",
    "ToolPolicyScanner",
    "register_builtin_scanners",
]


def register_builtin_scanners(
    pipeline: "ScannerPipeline",
    policy_engine=None,
) -> None:
    """Register the always-on GA built-in scanners into a pipeline.

    Single source of truth for the deterministic scanners that must always be
    present regardless of how the pipeline is bootstrapped:

      - ``RegexInputScanner``    — input prompt-injection / jailbreak detection
      - ``OutputRedactionScanner`` — secret / PII redaction on responses
      - ``ToolPolicyScanner``    — per-agent RBAC enforcement on tool calls

    Both the application lifespan (``src/main.py``) and standalone entrypoints
    (the evaluation CLI, SDK harnesses) call this helper so their scanner
    coverage never drifts. Without it, a pipeline created via
    ``get_scanner_pipeline()`` outside the app lifespan would be empty and
    silently report 0% detection.

    Args:
        pipeline: The :class:`~src.scanners.pipeline.ScannerPipeline` to
            populate.
        policy_engine: Optional tool-policy engine. When provided it is wired
            into the :class:`ToolPolicyScanner`; when ``None`` the tool-policy
            scanner degrades gracefully to ``ALLOW`` (safe for input-only
            evaluation harnesses that have no tenant policies loaded).
    """
    pipeline.register(RegexInputScanner())
    pipeline.register(OutputRedactionScanner())

    tool_policy_scanner = ToolPolicyScanner()
    if policy_engine is not None:
        tool_policy_scanner.set_policy_engine(policy_engine)
    pipeline.register(tool_policy_scanner)
