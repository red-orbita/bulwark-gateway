"""Configuration & Policy models."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel


class PolicySummary(BaseModel):
    name: str
    tenant: str
    version: int = 1
    active: bool = True
    agents: list[str] = []
    last_modified: Optional[datetime] = None
    modified_by: Optional[str] = None


class PolicyDetail(BaseModel):
    name: str
    tenant: str
    version: int = 1
    active: bool = True
    content: str  # Raw YAML content
    agents: list[str] = []
    created_at: datetime
    last_modified: datetime
    modified_by: str
    checksum: str  # SHA-256 of content


class PolicyCreateRequest(BaseModel):
    name: str
    tenant: str
    content: str  # YAML content
    active: bool = True


class PolicyUpdateRequest(BaseModel):
    content: str
    active: Optional[bool] = None
    comment: str = ""  # Change reason


class PolicyValidationResult(BaseModel):
    valid: bool
    errors: list[str] = []
    warnings: list[str] = []
    affected_agents: list[str] = []
    dry_run_verdict: Optional[str] = None


class PolicyDiff(BaseModel):
    version_from: int
    version_to: int
    diff_text: str  # Unified diff
    changed_by: str
    changed_at: datetime


class ConfigApplyRequest(BaseModel):
    policy_name: str
    version: Optional[int] = None  # None = latest
    dry_run: bool = True


class ConfigApplyResult(BaseModel):
    success: bool
    policy_name: str
    version: int
    applied_at: Optional[datetime] = None
    dry_run: bool
    validation: PolicyValidationResult
    rollback_version: Optional[int] = None


class GuardrailPattern(BaseModel):
    id: str
    pattern: str  # Regex
    category: str
    severity: str  # critical, high, medium, low
    description: str
    layer: str  # input, output, tool_policy
    enabled: bool = True
    false_positive_count: int = 0
    true_positive_count: int = 0
    last_triggered: Optional[datetime] = None


class GuardrailTestRequest(BaseModel):
    payload: str
    tenant_id: str = "test-tenant"
    agent_id: str = "test-agent"
    layer: str = "input"  # input, output


class GuardrailTestResult(BaseModel):
    verdict: str
    events: list[dict[str, Any]] = []
    latency_ms: float
    matched_patterns: list[dict[str, Any]] = []


class SIEMConfig(BaseModel):
    platform: str
    transport: str  # syslog, http_rest, tcp_tls, file_shipper
    enabled: bool = False
    connection: dict[str, Any] = {}
    batching: dict[str, Any] = {}
    circuit_breaker_state: str = "closed"
    last_export_at: Optional[datetime] = None
    events_exported: int = 0
    export_errors: int = 0
    queue_depth: int = 0


class SIEMTestResult(BaseModel):
    success: bool
    platform: str
    transport: str
    latency_ms: float
    error: Optional[str] = None
