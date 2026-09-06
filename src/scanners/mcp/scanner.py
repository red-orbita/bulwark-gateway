"""
McpToolScanner — runtime enforcement of MCP tool-definition security.

MCP tool poisoning is an inbound-request threat: an attacker who controls (or has
compromised) an MCP server ships tool *definitions* — names, descriptions and
parameter-schema descriptions — laced with hidden instructions, unicode
deception, or parameter-description injection. Those definitions are read by the
LLM (not the end user), so a poisoned description can hijack the model before it
ever sees the user's prompt. Bulwark's classic input guardrail scans message
prose only; the ``tools`` array flows straight to the backend unscanned.

This scanner closes that gap. It runs in the proxy's Phase-1 input pipeline,
reads the inbound tool definitions the proxy stashes at
``context.metadata["tool_definitions"]``, and feeds them through the shared
stdlib ``mcp_poisoning`` detector (rules BWK-MCP-TP1..TP4). It is
**inert-by-default** (registered only when ``BULWARK_MCP_SCANNING_ENABLED=true``)
and, like the ML scanners, runs as ``INPUT_ASYNC`` (WARN/enrichment only) unless
``BULWARK_MCP_SCANNING_BLOCKING=true`` promotes it to ``INPUT_BLOCKING`` (a
high/critical finding then returns 403 before the request is forwarded).

Zero third-party dependencies (pure regex), so it is always available — no model
provisioning required.
"""

from __future__ import annotations

import logging
from typing import Any

from src.config import settings
from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict
from src.scanners.mcp.mcp_poisoning import analyze_manifest
from src.scanners.protocol import (
    InputScanner,
    MaturityTier,
    ScanContext,
    ScannerInfo,
    ScannerType,
)

logger = logging.getLogger(__name__)

# Bound the work + event fan-out an adversarial tool array can trigger.
_MAX_TOOLS = 128
_MAX_EVENTS = 32

# Poisoning rule → Bulwark threat category. TP1 (hidden instructions), TP2
# (unicode deception) and TP3 (parameter injection) are injection-via-tool-channel;
# TP4 (description/behavior mismatch) is deceptive tool abuse.
_RULE_CATEGORY = {
    "BWK-MCP-TP4": ThreatCategory.TOOL_ABUSE,
}
_DEFAULT_CATEGORY = ThreatCategory.PROMPT_INJECTION

# Finding severity → whether it is block-worthy (only enforced in blocking mode).
_BLOCK_SEVERITIES = frozenset({"high", "critical"})
_VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})


def _normalize_tool_defs(raw: Any) -> list[dict[str, Any]]:
    """Flatten OpenAI-style tool wrappers into the MCP-native shape.

    OpenAI/Ollama send ``{"type": "function", "function": {name, description,
    parameters}}``; native MCP manifests are flat ``{name, description,
    inputSchema}``. ``analyze_manifest`` reads the flat shape, so unwrap the
    ``function`` envelope here (leaving native defs untouched) rather than
    forking the shared detector.
    """
    tools: list[dict[str, Any]] = []
    if not isinstance(raw, list):
        return tools
    for entry in raw[:_MAX_TOOLS]:
        if not isinstance(entry, dict):
            continue
        fn = entry.get("function")
        tools.append(fn if isinstance(fn, dict) else entry)
    return tools


class McpToolScanner(InputScanner):
    """Scan inbound MCP/OpenAI tool definitions for tool-poisoning (TP1..TP4)."""

    def __init__(self, blocking: bool | None = None) -> None:
        self._blocking = blocking if blocking is not None else settings.mcp_scanning_blocking

    @property
    def info(self) -> ScannerInfo:
        scanner_type = (
            ScannerType.INPUT_BLOCKING if self._blocking else ScannerType.INPUT_ASYNC
        )
        return ScannerInfo(
            name="mcp_tool_scanner",
            version="1.0.0",
            scanner_type=scanner_type,
            description=(
                "MCP tool-definition poisoning detection "
                "(hidden instructions, unicode deception, param injection)"
            ),
            maturity=MaturityTier.BETA,
            author="bulwark",
            priority=30,
        )

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """Scan the request's tool definitions (from context.metadata).

        The proxy stashes the raw ``tools`` array at
        ``context.metadata["tool_definitions"]``. When absent (the common case —
        most chat requests carry no tools) this is a zero-cost ALLOW.
        """
        tool_defs = _normalize_tool_defs(context.metadata.get("tool_definitions"))
        if not tool_defs:
            return GuardrailResult(verdict=Verdict.ALLOW)

        try:
            findings = analyze_manifest({"tools": tool_defs}, source="request")
        except Exception as exc:  # pragma: no cover - defensive; detector is pure regex
            # Fail-open on an unexpected detector error: the regex input guardrail
            # and response-side tool-policy lanes still cover this request.
            logger.warning("mcp_tool_scanner_error", extra={"error": str(exc)})
            return GuardrailResult(verdict=Verdict.ALLOW)

        if not findings:
            return GuardrailResult(verdict=Verdict.ALLOW)

        events: list[SecurityEvent] = []
        worst_block = False
        for finding in findings[:_MAX_EVENTS]:
            severity = str(finding.get("severity", "medium")).lower()
            is_block = severity in _BLOCK_SEVERITIES
            worst_block = worst_block or is_block
            rule_id = str(finding.get("rule_id", "BWK-MCP-TP"))
            category = _RULE_CATEGORY.get(rule_id, _DEFAULT_CATEGORY)
            tool_name = finding.get("tool_name")
            message = finding.get("message", "suspicious tool definition")
            # The event verdict mirrors the *enforced* outcome: a block-worthy
            # finding only carries BLOCK when the scanner is actually blocking —
            # otherwise it is WARN so the SIEM never records a block that did not
            # happen.
            enforced_block = is_block and self._blocking
            events.append(
                SecurityEvent(
                    tenant_id=context.tenant_id,
                    agent_id=context.agent_id,
                    verdict=Verdict.BLOCK if enforced_block else Verdict.WARN,
                    category=category,
                    description=f"MCP tool poisoning [{rule_id}]: {message}",
                    source="mcp_tool_scanner",
                    severity=severity if severity in _VALID_SEVERITIES else "medium",
                    request_id=context.request_id,
                    tool_name=tool_name if isinstance(tool_name, str) else None,
                    metadata={
                        "rule_id": rule_id,
                        "confidence": finding.get("confidence"),
                        "parameter": finding.get("parameter"),
                        "location": finding.get("file"),
                    },
                )
            )

        # In blocking mode a high/critical finding hardens the whole request to
        # BLOCK (the pipeline enforces it → 403). Otherwise WARN: the events are
        # logged/alerted but the request proceeds. When the scanner is registered
        # as INPUT_ASYNC (non-blocking mode) even a BLOCK verdict is downgraded to
        # logging by the async runner — mirroring the ML injection scanner.
        if worst_block and self._blocking:
            return GuardrailResult(verdict=Verdict.BLOCK, events=events)
        return GuardrailResult(verdict=Verdict.WARN, events=events)
