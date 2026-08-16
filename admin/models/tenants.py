"""Pydantic models for tenant and agent management."""
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class TenantStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    DISABLED = "disabled"


class AgentStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    DISABLED = "disabled"


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


# --- Tenant models ---


class TenantInfo(BaseModel):
    id: str
    name: str
    status: TenantStatus = TenantStatus.ACTIVE
    agent_count: int = 0
    contact_email: Optional[str] = None
    created_at: Optional[datetime] = None


class TenantCreate(BaseModel):
    id: str = Field(..., pattern=r"^[a-z0-9][a-z0-9\-]{1,62}[a-z0-9]$")
    name: str = Field(..., min_length=1, max_length=128)
    contact_email: Optional[str] = None


class TenantUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    status: Optional[TenantStatus] = None
    contact_email: Optional[str] = None


# --- Agent models ---


class AgentInfo(BaseModel):
    agent_id: str
    tenant_id: str
    backend_url: str
    model: Optional[str] = None
    timeout: float = 120.0
    status: AgentStatus = AgentStatus.ACTIVE
    health_endpoint: str = "/health"
    path_prefix: str = "/v1"
    auth_header: Optional[str] = None
    allowed_tools: Optional[list[str]] = None
    denied_tools: Optional[list[str]] = None
    description: Optional[str] = None


class AgentCreate(BaseModel):
    agent_id: str = Field(..., pattern=r"^[a-z0-9][a-z0-9\-]{1,62}[a-z0-9]$")
    tenant_id: str
    backend_url: str
    model: Optional[str] = None
    timeout: float = 120.0
    health_endpoint: str = "/health"
    path_prefix: str = "/v1"
    auth_header: Optional[str] = None
    description: Optional[str] = None


class AgentUpdate(BaseModel):
    backend_url: Optional[str] = None
    model: Optional[str] = None
    timeout: Optional[float] = None
    status: Optional[AgentStatus] = None
    health_endpoint: Optional[str] = None
    path_prefix: Optional[str] = None
    auth_header: Optional[str] = None
    description: Optional[str] = None


class HealthCheckResponse(BaseModel):
    agent_id: str
    status: HealthStatus
    latency_ms: Optional[float] = None
    last_checked: datetime


# --- Quota models ---
#
# Per-tenant resource quotas enforced by src/middleware/quotas.py. Stored in
# agents.yaml under `tenants.<id>.quotas` (sibling of `agents`/`_meta`).
#
# NOTE: `rate_limit_rpm` is deliberately excluded from this admin surface. It is
# parsed by the proxy but NOT enforced by QuotaMiddleware — effective RPM limits
# are managed by the dedicated Rate Limits page (Redis `bulwark:rate_limits:config`).
# Exposing it here would create two conflicting sources of truth.


class TenantQuotaInfo(BaseModel):
    """Effective per-tenant quota configuration (0 = unlimited)."""

    tenant_id: str
    configured: bool = False  # False if tenant has no `quotas:` block yet
    max_concurrent_requests: int = 0
    max_tokens_per_day: int = 0
    max_request_size_bytes: int = 0
    allowed_models: Optional[list[str]] = None  # None = all models allowed
    priority_weight: float = 1.0
    tokens_used_today: int = 0  # Live counter from Redis (0 if unavailable)


class TenantQuotaUpdate(BaseModel):
    """Partial update for a tenant's quota block. Omitted fields are unchanged."""

    max_concurrent_requests: Optional[int] = Field(None, ge=0, le=100_000)
    max_tokens_per_day: Optional[int] = Field(None, ge=0, le=1_000_000_000)
    max_request_size_bytes: Optional[int] = Field(None, ge=0, le=1_073_741_824)
    allowed_models: Optional[list[str]] = None
    priority_weight: Optional[float] = Field(None, ge=0.0, le=1000.0)


# --- Defaults models ---


class DefaultsInfo(BaseModel):
    backend_url: str = "http://ollama:11434"
    timeout: float = 120.0
    auth_header: Optional[str] = None
    health_endpoint: str = "/health"


class DefaultsUpdate(BaseModel):
    backend_url: Optional[str] = None
    timeout: Optional[float] = None
    auth_header: Optional[str] = None
    health_endpoint: Optional[str] = None
