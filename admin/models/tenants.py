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
