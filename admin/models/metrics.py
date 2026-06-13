"""Audit & Metrics models."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class AuditEntry(BaseModel):
    id: str
    timestamp: datetime
    actor: str  # username
    action: str  # create, update, delete, apply, rollback, test
    resource_type: str  # policy, guardrail, siem, auth
    resource_id: str
    payload_hash: str  # SHA-256 of change payload (never raw)
    result: str  # success, failure, dry_run_pass, dry_run_fail
    details: Optional[str] = None
    ip_address: Optional[str] = None
    rollback_ref: Optional[str] = None  # ID of entry this rolled back


class AuditQuery(BaseModel):
    actor: Optional[str] = None
    action: Optional[str] = None
    resource_type: Optional[str] = None
    tenant_id: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    limit: int = 100
    offset: int = 0


class AuditExportRequest(BaseModel):
    format: str = "json"  # json, csv
    query: AuditQuery = Field(default_factory=AuditQuery)


class MetricsSnapshot(BaseModel):
    """Real-time metrics for dashboard."""
    timestamp: datetime
    # Hot path
    latency_p50_ms: float = 0.0
    latency_p95_ms: float = 0.0
    latency_p99_ms: float = 0.0
    requests_total: int = 0
    requests_per_second: float = 0.0
    # Security
    events_blocked: int = 0
    events_warned: int = 0
    events_allowed: int = 0
    bypass_rate: float = 0.0
    false_positive_rate: float = 0.0
    # Telemetry/SIEM
    queue_depth_memory: int = 0
    queue_depth_disk: int = 0
    siem_export_rate: float = 0.0
    siem_export_errors: int = 0
    circuit_breaker_state: str = "closed"
    # System
    active_tenants: int = 0
    active_policies: int = 0
    policy_version: str = "unknown"
    uptime_seconds: float = 0.0


class AlertDefinition(BaseModel):
    id: str
    name: str
    metric: str
    condition: str  # gt, lt, eq
    threshold: float
    severity: str  # critical, warning, info
    enabled: bool = True
    cooldown_seconds: int = 300


class AlertEvent(BaseModel):
    alert_id: str
    triggered_at: datetime
    metric_value: float
    threshold: float
    message: str
    acknowledged: bool = False
