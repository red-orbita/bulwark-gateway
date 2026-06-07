"""Auth & RBAC models."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class UserRole(str, Enum):
    ADMIN = "admin"          # Full access
    SECURITY = "security"    # Manage guardrails, policies, SIEM
    AUDITOR = "auditor"      # Read-only + audit logs
    VIEWER = "viewer"        # Read-only dashboard


class TokenPayload(BaseModel):
    sub: str  # username/user_id
    role: UserRole
    tenant: Optional[str] = None
    exp: datetime
    iat: datetime


class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: Optional[str] = None


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 3600
    role: UserRole
    username: str
    mfa_required: bool = False
    force_password_change: bool = False


class UserInfo(BaseModel):
    username: str
    role: UserRole
    tenant: Optional[str] = None
    last_login: Optional[datetime] = None


# --- User management models ---

class UserCreate(BaseModel):
    username: str
    password: str
    role: str
    tenant_scope: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None


class UserUpdate(BaseModel):
    role: Optional[str] = None
    tenant_scope: Optional[str] = None
    active: Optional[bool] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None


class ProfileUpdate(BaseModel):
    """Model for users updating their own profile (non-privileged fields)."""
    email: Optional[str] = None
    phone: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None


class UserResponse(BaseModel):
    id: str
    username: str
    role: str
    tenant_scope: Optional[str] = None
    active: bool
    mfa_enabled: bool = False
    email: Optional[str] = None
    phone: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    created_at: str
    last_login: Optional[str] = None


class SessionResponse(BaseModel):
    id: str
    created_at: str
    expires_at: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


class MFASetupResponse(BaseModel):
    secret: str
    provisioning_uri: str
    qr_code_url: str


class ChangePasswordRequest(BaseModel):
    current_password: Optional[str] = None
    new_password: str


# RBAC permission matrix
ROLE_PERMISSIONS: dict[UserRole, set[str]] = {
    UserRole.ADMIN: {
        "policies:read", "policies:write", "policies:delete", "policies:apply",
        "guardrails:read", "guardrails:write", "guardrails:test",
        "iocs:read", "iocs:write",
        "siem:read", "siem:write", "siem:test",
        "notifications:read", "notifications:write",
        "audit:read", "audit:export",
        "users:manage", "orchestrator:trigger",
        "config:validate", "config:rollback",
        "admin:read",
    },
    UserRole.SECURITY: {
        "policies:read", "policies:write", "policies:apply",
        "guardrails:read", "guardrails:write", "guardrails:test",
        "iocs:read", "iocs:write",
        "siem:read", "siem:write", "siem:test",
        "notifications:read", "notifications:write",
        "audit:read",
        "config:validate",
        "admin:read",
    },
    UserRole.AUDITOR: {
        "policies:read",
        "guardrails:read",
        "iocs:read",
        "siem:read",
        "notifications:read",
        "audit:read", "audit:export",
        "admin:read",
    },
    UserRole.VIEWER: {
        "policies:read",
        "siem:read",
        "notifications:read",
        "admin:read",
    },
}
