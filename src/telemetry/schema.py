"""
Telemetry Schema — Pydantic v2 models aligned to ECS + OCSF.

Base format is JSON/ECS. Converters to CEF and LEEF are provided
for legacy SIEMs (QRadar, ArcSight, FortiSIEM).
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

from src.telemetry.compliance import OWASP_LLM_VERSION, compliance_for

# Placeholder used in CEF/LEEF `src` fields when the originating IP is unknown.
# These formats require a syntactically valid IP; "0.0.0.0" is the conventional
# "unspecified address" sentinel. This is a log-record value, NOT a socket bind.
_UNKNOWN_SRC_IP = "0.0.0.0"  # noqa: S104 — log-record sentinel value, not a socket bind  # nosec B104


class TelemetryEventCategory(str, Enum):
    """ECS event.category values relevant to Bulwark Gateway."""

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
    """ECS observer (Bulwark Gateway instance)."""

    type: str = "bulwark-gateway"
    name: str = "bulwark-gateway"
    version: str = "1.0.0"
    hostname: Optional[str] = None


class ComplianceFields(BaseModel):
    """Regulatory / standards references for a detection (``bulwark.compliance.*``).

    Every axis is optional; empty axes are dropped from the ECS export. Mirrors
    src/telemetry/compliance.ComplianceMapping so a SIEM can pivot a detection to
    OWASP LLM / MITRE ATLAS / MITRE ATT&CK / NIST AI RMF / EU AI Act without a
    lookup table.
    """

    owasp_llm: Optional[list[str]] = None
    owasp_llm_version: Optional[str] = None
    mitre_atlas: Optional[list[str]] = None
    mitre_attack: Optional[list[str]] = None
    nist_ai_rmf: Optional[list[str]] = None
    eu_ai_act: Optional[list[str]] = None


class BulwarkFields(BaseModel):
    """Custom fields specific to Bulwark Gateway (nested under 'bulwark.')."""

    verdict: str  # allow, block, warn, redact
    event_id: Optional[str] = None  # Canonical detection id — correlates across all sinks
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
    # F3 (allow-exception): when an allowlist exception degrades a would-be BLOCK
    # to WARN, the request is still adversarial and is exported to the SIEM tagged
    # so an analyst can distinguish "let through by policy exception" from a
    # generic warn. `exception_scope` is the tenant:agent the exception applied to.
    allowed_by_exception: bool = False
    exception_scope: Optional[str] = None
    # Declarative regulatory/standards references for the threat category
    # (nested under `bulwark.compliance.*`). Populated from the central mapping in
    # src/telemetry/compliance.py; omitted when the category has no mapping.
    compliance: Optional[ComplianceFields] = None


class TenantFields(BaseModel):
    """Multi-tenant context."""

    id: str
    agent_id: Optional[str] = None
    name: Optional[str] = None


class SecurityTelemetryEvent(BaseModel):
    """
    Root telemetry event model — ECS-aligned with Bulwark extensions.

    Compatible with: ECS 8.x, OCSF 1.1, CEF (via converter), LEEF (via converter).
    """

    # ECS root fields
    timestamp: str = Field(
        alias="@timestamp",
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    message: str = ""
    tags: list[str] = Field(default_factory=lambda: ["bulwark-gateway", "security"])
    labels: dict[str, str] = Field(default_factory=dict)

    # ECS structured fields
    event: ECSEvent = Field(default_factory=ECSEvent)
    observer: ECSObserver = Field(default_factory=ECSObserver)
    source: ECSSource = Field(default_factory=ECSSource)

    # Bulwark-specific fields
    bulwark: BulwarkFields
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
        name = self.bulwark.rule_description or self.bulwark.threat_category or "SecurityEvent"
        comp = self.bulwark.compliance
        # Compact, legacy-SIEM-friendly compliance summary (CEF has no arrays):
        # OWASP + EU AI Act are the two axes analysts most often pivot on.
        compliance_summary = "none"
        if comp is not None:
            parts = list(comp.owasp_llm or []) + list(comp.eu_ai_act or [])
            if parts:
                compliance_summary = ",".join(parts)
        extension = (
            f"src={self.source.ip or _UNKNOWN_SRC_IP} "
            f"act={self.bulwark.verdict} "
            f"cat={self.event.category.value} "
            f"cs1={self.tenant.id} cs1Label=TenantID "
            f"cs2={self.bulwark.guardrail_layer} cs2Label=GuardrailLayer "
            f"cs3={self.bulwark.rule_id or 'none'} cs3Label=RuleID "
            f"cn1={int(self.bulwark.latency_ms)} cn1Label=LatencyMs "
            f"cs4={str(self.bulwark.allowed_by_exception).lower()} cs4Label=AllowedByException "
            f"cs5={self.bulwark.exception_scope or 'none'} cs5Label=ExceptionScope "
            f"cs6={compliance_summary} cs6Label=Compliance "
            f"msg={self.message}"
        )
        return (
            f"CEF:0|BulwarkGateway|Guardrail|{self.observer.version}|"
            f"{self.bulwark.threat_category or 'generic'}|{name}|{severity}|{extension}"
        )

    def to_leef(self) -> str:
        """Convert to LEEF 2.0 (Log Event Extended Format) for IBM QRadar."""
        comp = self.bulwark.compliance
        owasp = ",".join(comp.owasp_llm) if comp and comp.owasp_llm else "none"
        atlas = ",".join(comp.mitre_atlas) if comp and comp.mitre_atlas else "none"
        mitre = ",".join(comp.mitre_attack) if comp and comp.mitre_attack else "none"
        eu_ai_act = ",".join(comp.eu_ai_act) if comp and comp.eu_ai_act else "none"
        return (
            f"LEEF:2.0|BulwarkGateway|Guardrail|{self.observer.version}|SecurityEvent|"
            f"cat={self.event.category.value}\t"
            f"sev={self.event.severity.value}\t"
            f"src={self.source.ip or _UNKNOWN_SRC_IP}\t"
            f"action={self.bulwark.verdict}\t"
            f"tenantId={self.tenant.id}\t"
            f"ruleId={self.bulwark.rule_id or 'none'}\t"
            f"guardrailLayer={self.bulwark.guardrail_layer}\t"
            f"latencyMs={int(self.bulwark.latency_ms)}\t"
            f"allowedByException={str(self.bulwark.allowed_by_exception).lower()}\t"
            f"exceptionScope={self.bulwark.exception_scope or 'none'}\t"
            f"owaspLlm={owasp}\t"
            f"mitreAtlas={atlas}\t"
            f"mitreAttack={mitre}\t"
            f"euAiAct={eu_ai_act}\t"
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
    allowed_by_exception: bool = False,
    exception_scope: Optional[str] = None,
    event_id: Optional[str] = None,
) -> SecurityTelemetryEvent:
    """Factory: create telemetry event from guardrail SecurityEvent.

    ``event_id`` is the canonical detection id (SecurityEvent.event_id). When
    provided it becomes the ECS ``event.id`` AND ``bulwark.event_id`` so the SIEM
    record shares the SAME identifier as the notification/webhook/log for the same
    detection. When omitted (e.g. legacy callers), ECSEvent mints a uuid4 as before.
    """
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

    message = f"Bulwark Gateway {verdict.upper()}: {rule_description or threat_category or 'security event'}"

    # An allow-exception is a distinct, auditable signal — tag it so SIEM
    # searches/correlations can isolate "adversarial but allowed by exception".
    tags = ["bulwark-gateway", "security"]
    if allowed_by_exception:
        tags.append("allowed-by-exception")

    # Attach declarative compliance references for the threat category (OWASP LLM /
    # MITRE ATT&CK / NIST AI RMF / EU AI Act). None for unmapped/ad-hoc categories.
    compliance_fields: Optional[ComplianceFields] = None
    mapping = compliance_for(threat_category)
    if mapping is not None and not mapping.is_empty():
        compliance_fields = ComplianceFields(
            owasp_llm=list(mapping.owasp_llm) or None,
            owasp_llm_version=OWASP_LLM_VERSION if mapping.owasp_llm else None,
            mitre_atlas=list(mapping.mitre_atlas) or None,
            mitre_attack=list(mapping.mitre_attack) or None,
            nist_ai_rmf=list(mapping.nist_ai_rmf) or None,
            eu_ai_act=list(mapping.eu_ai_act) or None,
        )

    return SecurityTelemetryEvent(
        **{"@timestamp": datetime.now(timezone.utc).isoformat()},  # type: ignore[arg-type]
        message=message,
        tags=tags,
        event=ECSEvent(
            **({"id": event_id} if event_id else {}),
            category=TelemetryEventCategory.INTRUSION_DETECTION,
            action=action,
            outcome=outcome,
            severity=severity,
            duration=int(latency_ms * 1_000_000),  # ms → ns
        ),
        source=ECSSource(ip=source_ip),
        bulwark=BulwarkFields(
            verdict=verdict,
            event_id=event_id,
            rule_id=rule_id,
            rule_description=rule_description,
            threat_category=threat_category,
            confidence=confidence,
            guardrail_layer=guardrail_layer,
            latency_ms=latency_ms,
            input_hash=input_hash,
            request_id=request_id,
            allowed_by_exception=allowed_by_exception,
            exception_scope=exception_scope,
            compliance=compliance_fields,
        ),
        tenant=TenantFields(id=tenant_id, agent_id=agent_id),
    )
