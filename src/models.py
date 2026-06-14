"""Data models for requests, responses, and security events."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# === Strict Base Model ===


class StrictModel(BaseModel):
    """Base model with strict validation: rejects unknown fields."""

    model_config = ConfigDict(extra="forbid")


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
    # OWASP LLM Top 10 additions
    INSECURE_OUTPUT = "insecure_output"  # LLM02
    DENIAL_OF_SERVICE = "denial_of_service"  # LLM04
    EXCESSIVE_AGENCY = "excessive_agency"  # LLM08/LLM09
    MODEL_THEFT = "model_theft"  # LLM10
    # Adversarial ML
    PRIVACY_ATTACK = "privacy_attack"  # Model inversion / Membership inference
    # Agentic attacks
    PLAN_CORRUPTION = "plan_corruption"  # CoT/reasoning manipulation
    CROSS_AGENT_INJECTION = "cross_agent_injection"  # Inter-agent propagation
    MEMORY_MANIPULATION = "memory_manipulation"  # RAG/vector store poisoning


class SecurityEvent(StrictModel):
    """Structured security event for logging/SIEM."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tenant_id: str = Field(..., max_length=128)
    agent_id: str = Field(..., max_length=128)
    verdict: Verdict
    category: ThreatCategory
    description: str = Field(..., max_length=2048)
    source: str = Field(..., max_length=256)  # which guardrail triggered
    severity: str = Field(default="medium", max_length=16)  # low, medium, high, critical
    request_id: str | None = Field(default=None, max_length=128)
    tool_name: str | None = Field(default=None, max_length=256)
    matched_pattern: str | None = Field(default=None, max_length=1024)
    metadata: dict[str, Any] = Field(default_factory=dict)


# === Tool Call Models ===


class ToolCall(StrictModel):
    """Represents a single tool call from the agent."""

    id: str | None = Field(default=None, max_length=256)
    name: str = Field(..., max_length=256)
    arguments: dict[str, Any] = Field(default_factory=dict)


class ToolCallResult(StrictModel):
    """Result of a tool call execution."""

    tool_call_id: str | None = Field(default=None, max_length=256)
    content: str = Field(..., max_length=1_048_576)  # 1MB max
    is_error: bool = False


# === Proxy Request/Response ===


class Message(StrictModel):
    role: str = Field(..., max_length=32)
    content: str | None = Field(default=None, max_length=2_097_152)  # 2MB max
    tool_calls: list[dict[str, Any]] | None = None
    tool_call_id: str | None = Field(default=None, max_length=256)


class ChatRequest(StrictModel):
    """OpenAI-compatible chat completion request."""

    model: str = Field(..., max_length=256)
    messages: list[Message] = Field(..., max_length=1024)  # max 1024 messages
    tools: list[dict[str, Any]] | None = None
    tool_choice: str | dict | None = None
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    max_tokens: int | None = Field(default=None, ge=1, le=1_000_000)
    stream: bool = False


class GuardrailResult(StrictModel):
    """Result of a guardrail check."""

    verdict: Verdict
    events: list[SecurityEvent] = Field(default_factory=list)
    modified_content: str | None = None  # For redaction
    blocked_tools: list[str] = Field(default_factory=list)
