"""
Tool Policy Scanner — Wraps the existing ToolPolicy engine as a scanner plugin.

This scanner validates tool calls in LLM responses against per-agent
RBAC policies. It runs in the output pipeline but operates on tool_calls
rather than text content.

Priority: 5 (runs before output redaction since it modifies response structure)
"""

from __future__ import annotations

import json

from src.models import GuardrailResult, ToolCall, Verdict
from src.scanners.protocol import MaturityTier, OutputScanner, ScanContext, ScannerInfo, ScannerType


class ToolPolicyScanner(OutputScanner):
    """Output scanner for tool call RBAC enforcement.

    Wraps the existing ToolPolicy engine which enforces:
      - allowed_tools / denied_tools per agent
      - Argument pattern matching (regex on tool arguments)
      - denied_arguments (blocklist specific values)
      - max_tool_calls per request
      - Path traversal detection in file paths
      - Self-protection (blocks modifications to gateway config)
      - Sensitive file read blocking
      - Sandbox levels: strict (deny by default), standard (allow unless denied)

    Note: This scanner needs the policy_engine from app state, so it must
    be initialized with a reference to the policy loader.
    """

    def __init__(self, policy_engine=None) -> None:
        self._policy_engine = policy_engine

    def set_policy_engine(self, engine) -> None:
        """Set the policy engine (called after policy loader initializes)."""
        self._policy_engine = engine

    @property
    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="tool_policy",
            version="1.0.0",
            scanner_type=ScannerType.OUTPUT_BLOCKING,
            description="RBAC enforcement on agent tool calls",
            maturity=MaturityTier.GA,
            author="bulwark",
            priority=5,  # Runs before output redaction
        )

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """Evaluate tool calls from the response against policy.

        This scanner expects tool_calls data in context.metadata["tool_calls"].
        If no tool calls are present, it returns ALLOW.
        """
        tool_calls_raw = context.metadata.get("tool_calls", [])
        if not tool_calls_raw:
            return GuardrailResult(verdict=Verdict.ALLOW)
        if not self._policy_engine or not isinstance(tool_calls_raw, list) or len(tool_calls_raw) > 128:
            return GuardrailResult(verdict=Verdict.BLOCK)

        # Parse tool calls
        def unique_keys(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Duplicate tool argument key")
                result[key] = value
            return result

        tool_calls = []
        for tc in tool_calls_raw:
            try:
                raw = tc.get("function", {}).get("arguments", "{}")
                if not isinstance(raw, str) or len(raw) > 1024 * 1024 or len(raw.encode()) > 1024 * 1024:
                    return GuardrailResult(verdict=Verdict.BLOCK)
                args = json.loads(raw, object_pairs_hook=unique_keys)
                if not isinstance(args, dict):
                    return GuardrailResult(verdict=Verdict.BLOCK)
                json.dumps(args, allow_nan=False)
            except (ValueError, TypeError, AttributeError, RecursionError):
                return GuardrailResult(verdict=Verdict.BLOCK)
            tool_calls.append(
                ToolCall(
                    id=tc.get("id"),
                    name=tc.get("function", {}).get("name", ""),
                    arguments=args,
                )
            )

        if not tool_calls:
            return GuardrailResult(verdict=Verdict.ALLOW)

        return self._policy_engine.evaluate_tool_calls(
            tool_calls, context.tenant_id, context.agent_id
        )

    async def health(self) -> bool:
        """Healthy if policy engine is set."""
        return self._policy_engine is not None
