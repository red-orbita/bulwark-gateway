"""
Regex Input Scanner — Wraps the existing InputGuardrail as a scanner plugin.

This is the primary blocking input scanner. It runs the full 4600+ line
regex detection engine (prompt injection, jailbreak, encoding attacks)
within the hot path.

Priority: 10 (runs first — cheapest and most comprehensive blocking check)
"""

from __future__ import annotations

from src.guardrails.input_guardrail import InputGuardrail
from src.models import GuardrailResult
from src.scanners.protocol import InputScanner, ScanContext, ScannerInfo, ScannerType


class RegexInputScanner(InputScanner):
    """Blocking input scanner using regex pattern matching.

    Wraps the existing InputGuardrail engine (4600+ patterns) as a
    pluggable scanner. This scanner is always in the hot path and
    provides the primary line of defense.

    Detection capabilities:
      - Prompt injection (instruction overrides, role hijacking)
      - Jailbreak attempts (DAN, persona injection, fictional framing)
      - Encoded payloads (base64, hex, URL, Unicode, Morse, Braille)
      - Command injection (shell, SQL, SSTI, XXE, path traversal)
      - Exfiltration attempts (data theft patterns)
      - Reverse shell payloads
      - Multi-layer encoding evasion
    """

    def __init__(self) -> None:
        self._engine = InputGuardrail()

    @property
    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="regex_input",
            version="1.0.0",
            scanner_type=ScannerType.INPUT_BLOCKING,
            description="Regex-based prompt injection and attack detection (4600+ patterns)",
            author="sentinel",
            priority=10,  # Runs first — fast, comprehensive
        )

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """Run regex detection on input content.

        Delegates to InputGuardrail.inspect_messages() which handles:
          - Unicode NFKC normalization
          - Shannon entropy detection
          - Multi-layer decoding
          - Pattern matching across all categories
        """
        # Use the full message inspection (handles message list)
        if context.messages:
            return self._engine.inspect_messages(
                context.messages, context.tenant_id, context.agent_id
            )
        # Fallback: single content string
        return self._engine.inspect(content, context.tenant_id, context.agent_id)

    async def health(self) -> bool:
        """Regex engine is always healthy (no external dependencies)."""
        return True
