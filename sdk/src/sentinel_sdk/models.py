"""
Pydantic models for the Sentinel Gateway SDK.

These models represent the data structures used for communication
with the Sentinel Gateway API and for local guard operations.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    """Security verdict returned by guardrail scans.

    Values:
        ALLOW: Content is safe to proceed.
        BLOCK: Content is malicious or violates policy.
        WARN: Content is suspicious but allowed.
        REDACT: Content contains sensitive data that was masked.
    """

    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"
    REDACT = "redact"


class ThreatCategory(str, Enum):
    """Category of security threat detected."""

    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    TOOL_ABUSE = "tool_abuse"
    EXFILTRATION = "exfiltration"
    CREDENTIAL_ACCESS = "credential_access"
    REVERSE_SHELL = "reverse_shell"
    MALICIOUS_DOMAIN = "malicious_domain"
    PII_LEAK = "pii_leak"
    POLICY_VIOLATION = "policy_violation"
    RATE_LIMIT = "rate_limit"
    INSECURE_OUTPUT = "insecure_output"
    DENIAL_OF_SERVICE = "denial_of_service"
    EXCESSIVE_AGENCY = "excessive_agency"
    MODEL_THEFT = "model_theft"


class Severity(str, Enum):
    """Severity level of a security event."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEvent(BaseModel):
    """A security event detected during scanning.

    Attributes:
        category: Type of threat detected.
        severity: How severe the detection is.
        description: Human-readable description of the finding.
        pattern_id: Identifier of the pattern that matched (if applicable).
        matched_pattern: The regex/rule that triggered (if applicable).
    """

    category: Optional[ThreatCategory] = None
    severity: Severity = Severity.MEDIUM
    description: str = ""
    pattern_id: Optional[str] = None
    matched_pattern: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Result of a security scan operation.

    Returned by both remote API calls and local guard scans.

    Attributes:
        verdict: The security verdict (ALLOW, BLOCK, WARN, REDACT).
        events: List of security events detected during scanning.
        modified_content: Redacted/modified content (if verdict is REDACT).
        latency_ms: Total scanning time in milliseconds.
    """

    verdict: Verdict = Verdict.ALLOW
    events: list[SecurityEvent] = Field(default_factory=list)
    modified_content: Optional[str] = None
    latency_ms: float = 0.0

    @property
    def is_blocked(self) -> bool:
        """Whether the content was blocked."""
        return self.verdict == Verdict.BLOCK

    @property
    def is_safe(self) -> bool:
        """Whether the content passed all checks (ALLOW)."""
        return self.verdict == Verdict.ALLOW

    @property
    def reason(self) -> str:
        """Human-readable reason for the verdict."""
        if self.events:
            return self.events[0].description
        return self.verdict.value


class Message(BaseModel):
    """A chat message in OpenAI-compatible format."""

    role: str
    content: str
    name: Optional[str] = None
    tool_calls: Optional[list[dict[str, Any]]] = None
    tool_call_id: Optional[str] = None


class ChatCompletionRequest(BaseModel):
    """Request body for chat completion (OpenAI-compatible)."""

    model: str
    messages: list[Message]
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    stream: bool = False
    tools: Optional[list[dict[str, Any]]] = None
    tool_choice: Optional[Any] = None


class HealthStatus(BaseModel):
    """Health check response from Sentinel Gateway."""

    status: str = "healthy"
    version: Optional[str] = None
    uptime_seconds: Optional[float] = None
    requests_total: Optional[int] = None
    blocks_total: Optional[int] = None
