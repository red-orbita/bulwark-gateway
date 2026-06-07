"""
Telemetry Schema — Pydantic v2 models aligned to ECS + OCSF.

Base format is JSON/ECS. Converters to CEF and LEEF are provided
for legacy SIEMs (QRadar, ArcSight, FortiSIEM).
"""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class TelemetryEventCategory(str, Enum):
    """ECS event.category values relevant to Sentinel Gateway."""

    INTRUSION_DETECTION = "intrusion_detection"
    NETWORK = "network"
    AUTHENTICATION = "authentication"
    PROCESS = "process"
    WEB = "web"
    THREAT = "threat"


class TelemetrySeverity(int, Enum):
    """Severity levels (0-10 scale, ECS compatible)."""

    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 4
    HIGH = 7
    CRITICAL = 10


class ECSSource(BaseModel):
    """ECS source fields."""

    ip: Optional[str] = None
    port: Optional[int] = None
    user_agent: Optional[str] = None


class ECSEvent(BaseModel):
    """ECS event metadata."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    kind: str = "alert"
    category: TelemetryEventCategory = TelemetryEventCategory.INTRUSION_DETECTION
    action: str = "blocked"
    outcome: str = "failure"  # failure = blocked, success = allowed
    severity: TelemetrySeverity = TelemetrySeverity.MEDIUM
    created: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    duration: Optional[int] = None  # nanoseconds


class ECSObserver(BaseModel):
    """ECS observer (Sentinel Gateway instance)."""

    type: str = "sentinel-gateway"
    name: str = "sentinel-gateway"
    version: str = "0.2.0"
    hostname: Optional[str] = None


class SentinelFields(BaseModel):
    """Custom fields specific to Sentinel Gateway (nested under 'sentinel.')."""

    verdict: str  # allow, block, warn, redact
    rule_id: Optional[str] = None
    rule_description: Optional[str] = None
    threat_category: Optional[str] = None
    confidence: float = 1.0
    matched_pattern: Optional[str] = None
    guardrail_layer: str = "input"  # input, output, tool_policy
    latency_ms: float = 0.0
    input_hash: Optional[str] = None  # SHA-256, never raw payload
    session_id: Optional[str] = None
    request_id: Optional[str] = None


class TenantFields(BaseModel):
    """Multi-tenant context."""

    id: str
    agent_id: Optional[str] = None
    name: Optional[str] = None


class SecurityTelemetryEvent(BaseModel):
    """
    Root telemetry event model — ECS-aligned with Sentinel extensions.

    Compatible with: ECS 8.x, OCSF 1.1, CEF (via converter), LEEF (via converter).
    """

    # ECS root fields
    timestamp: str = Field(
        alias="@timestamp",
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    message: str = ""
    tags: list[str] = Field(default_factory=lambda: ["sentinel-gateway", "security"])
    labels: dict[str, str] = Field(default_factory=dict)

    # ECS structured fields
    event: ECSEvent = Field(default_factory=ECSEvent)
    observer: ECSObserver = Field(default_factory=ECSObserver)
    source: ECSSource = Field(default_factory=ECSSource)

    # Sentinel-specific fields
    sentinel: SentinelFields
    tenant: TenantFields

    model_config = {"populate_by_name": True}

    @field_validator("timestamp", mode="before")
    @classmethod
    def ensure_iso_timestamp(cls, v: Any) -> str:
        if isinstance(v, datetime):
            return v.isoformat()
        if isinstance(v, (int, float)):
            return datetime.fromtimestamp(v, tz=timezone.utc).isoformat()
        return str(v)

    def to_ecs_json(self) -> dict[str, Any]:
        """Export as ECS-compatible JSON dict."""
        return self.model_dump(by_alias=True, exclude_none=True)

    def to_cef(self) -> str:
        """Convert to CEF (Common Event Format) for ArcSight, FortiSIEM, etc."""
        severity = self.event.severity.value
        # CEF severity is 0-10
        name = self.sentinel.rule_description or self.sentinel.threat_category or "SecurityEvent"
        extension = (
            f"src={self.source.ip or '0.0.0.0'} "
            f"act={self.sentinel.verdict} "
            f"cat={self.event.category.value} "
            f"cs1={self.tenant.id} cs1Label=TenantID "
            f"cs2={self.sentinel.guardrail_layer} cs2Label=GuardrailLayer "
            f"cs3={self.sentinel.rule_id or 'none'} cs3Label=RuleID "
            f"cn1={int(self.sentinel.latency_ms)} cn1Label=LatencyMs "
            f"msg={self.message}"
        )
        return (
            f"CEF:0|SentinelGateway|Guardrail|{self.observer.version}|"
            f"{self.sentinel.threat_category or 'generic'}|{name}|{severity}|{extension}"
        )

    def to_leef(self) -> str:
        """Convert to LEEF 2.0 (Log Event Extended Format) for IBM QRadar."""
        return (
            f"LEEF:2.0|SentinelGateway|Guardrail|{self.observer.version}|SecurityEvent|"
            f"cat={self.event.category.value}\t"
            f"sev={self.event.severity.value}\t"
            f"src={self.source.ip or '0.0.0.0'}\t"
            f"action={self.sentinel.verdict}\t"
            f"tenantId={self.tenant.id}\t"
            f"ruleId={self.sentinel.rule_id or 'none'}\t"
            f"guardrailLayer={self.sentinel.guardrail_layer}\t"
            f"latencyMs={int(self.sentinel.latency_ms)}\t"
            f"msg={self.message}"
        )


def from_security_event(
    verdict: str,
    rule_id: Optional[str],
    rule_description: Optional[str],
    threat_category: Optional[str],
    tenant_id: str,
    agent_id: Optional[str],
    guardrail_layer: str,
    latency_ms: float,
    raw_input: Optional[str] = None,
    source_ip: Optional[str] = None,
    request_id: Optional[str] = None,
    confidence: float = 1.0,
) -> SecurityTelemetryEvent:
    """Factory: create telemetry event from guardrail SecurityEvent."""
    input_hash = hashlib.sha256(raw_input.encode()).hexdigest()[:16] if raw_input else None

    severity = TelemetrySeverity.INFORMATIONAL
    if verdict == "block":
        severity = TelemetrySeverity.HIGH
    elif verdict == "warn":
        severity = TelemetrySeverity.MEDIUM
    elif verdict == "redact":
        severity = TelemetrySeverity.LOW

    outcome = "failure" if verdict == "block" else "success"
    action = verdict

    message = f"Sentinel Gateway {verdict.upper()}: {rule_description or threat_category or 'security event'}"

    return SecurityTelemetryEvent(
        **{"@timestamp": datetime.now(timezone.utc).isoformat()},
        message=message,
        event=ECSEvent(
            category=TelemetryEventCategory.INTRUSION_DETECTION,
            action=action,
            outcome=outcome,
            severity=severity,
            duration=int(latency_ms * 1_000_000),  # ms → ns
        ),
        source=ECSSource(ip=source_ip),
        sentinel=SentinelFields(
            verdict=verdict,
            rule_id=rule_id,
            rule_description=rule_description,
            threat_category=threat_category,
            confidence=confidence,
            guardrail_layer=guardrail_layer,
            latency_ms=latency_ms,
            input_hash=input_hash,
            request_id=request_id,
        ),
        tenant=TenantFields(id=tenant_id, agent_id=agent_id),
    )
