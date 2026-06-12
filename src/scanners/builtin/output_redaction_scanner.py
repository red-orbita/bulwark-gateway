"""
Output Redaction Scanner — Wraps the existing OutputFilter as a scanner plugin.

This is the primary blocking output scanner. It detects and redacts
secrets, credentials, PII, and dangerous content from LLM responses.

Priority: 10 (runs first in output pipeline)
"""

from __future__ import annotations

from src.guardrails.output_filter import OutputFilter
from src.models import GuardrailResult
from src.scanners.protocol import OutputScanner, ScanContext, ScannerInfo, ScannerType


class OutputRedactionScanner(OutputScanner):
    """Blocking output scanner for secret/PII redaction.

    Wraps the existing OutputFilter engine which detects:
      - API keys (AWS, GCP, Azure, GitHub, OpenAI, Stripe, etc.)
      - Database connection strings
      - Private keys (RSA, EC, SSH, PEM blocks)
      - JWT tokens, session tokens
      - PII (SSN, credit cards, phone numbers, emails)
      - Internal paths and hostnames
      - Indirect prompt injection in tool outputs
      - Unicode smuggling in responses
      - ROT13/Base64 encoded secrets
      - Dangerous executable commands (OWASP LLM02)
    """

    def __init__(self) -> None:
        self._engine = OutputFilter()

    @property
    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="output_redaction",
            version="1.0.0",
            scanner_type=ScannerType.OUTPUT_BLOCKING,
            description="Secret/PII/credential redaction in LLM outputs",
            author="sentinel",
            priority=10,  # Runs first in output pipeline
        )

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """Run output filter on LLM response content.

        Returns REDACT verdict with modified_content if secrets found.
        Returns ALLOW if content is clean.
        """
        return self._engine.inspect_and_redact(
            content, context.tenant_id, context.agent_id
        )

    async def health(self) -> bool:
        """Output filter is always healthy (regex-only, no external deps)."""
        return True
