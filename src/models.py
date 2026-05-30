"""Data models for requests, responses, and security events."""
from pydantic import BaseModel, Field
from typing import Any
from enum import Enum
from datetime import datetime


# === Security Verdicts ===

class Verdict(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"
    REDACT = "redact"


class ThreatCategory(str, Enum):
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


class SecurityEvent(BaseModel):
    """Structured security event for logging/SIEM."""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    tenant_id: str
    agent_id: str
    verdict: Verdict
    category: ThreatCategory
    description: str
    source: str  # which guardrail triggered
    severity: str = "medium"  # low, medium, high, critical
    request_id: str | None = None
    tool_name: str | None = None
    matched_pattern: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


# === Tool Call Models ===

class ToolCall(BaseModel):
    """Represents a single tool call from the agent."""
    id: str | None = None
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ToolCallResult(BaseModel):
    """Result of a tool call execution."""
    tool_call_id: str | None = None
    content: str
    is_error: bool = False


# === Proxy Request/Response ===

class Message(BaseModel):
    role: str
    content: str | None = None
    tool_calls: list[dict[str, Any]] | None = None
    tool_call_id: str | None = None


class ChatRequest(BaseModel):
    """OpenAI-compatible chat completion request."""
    model: str
    messages: list[Message]
    tools: list[dict[str, Any]] | None = None
    tool_choice: str | dict | None = None
    temperature: float | None = None
    max_tokens: int | None = None
    stream: bool = False


class GuardrailResult(BaseModel):
    """Result of a guardrail check."""
    verdict: Verdict
    events: list[SecurityEvent] = Field(default_factory=list)
    modified_content: str | None = None  # For redaction
    blocked_tools: list[str] = Field(default_factory=list)
