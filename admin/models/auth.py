"""Auth & RBAC models."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, field_validator


def _iso_if_datetime(value):
    """Coerce a datetime to an ISO-8601 string, passing through str/None.

    The admin store has two backends: SQLite persists timestamps as ISO
    strings, while the PostgreSQL backend (used in HA deployments) returns
    native ``datetime`` objects. Response models below declare these fields
    as ``str``; without this coercion, Pydantic raises ``string_type`` and
    the endpoint 500s on Postgres only. Normalising here keeps the API shape
    identical across backends.
    """
    if isinstance(value, datetime):
        return value.isoformat()
    return value


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
    token_type: str = "bearer"  # noqa: S105 - OAuth2 token_type literal, not a credential  # nosemgrep: bulwark-no-hardcoded-jwt-secret
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

    @field_validator("created_at", "last_login", mode="before")
    @classmethod
    def _coerce_timestamps(cls, value):
        return _iso_if_datetime(value)


class SessionResponse(BaseModel):
    id: str
    created_at: str
    expires_at: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

    @field_validator("created_at", "expires_at", mode="before")
    @classmethod
    def _coerce_timestamps(cls, value):
        return _iso_if_datetime(value)


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
        "plugins:read", "plugins:write",
        "evaluation:read", "evaluation:run",
        "discovery:read", "discovery:scan",
        "gdpr:read", "gdpr:write", "gdpr:pseudonymize", "gdpr:export",
        "vkeys:read", "vkeys:write",
        "quotas:read", "quotas:write",
        "cost:read", "cost:write",
        "cache:read", "cache:write",
        "sessions:read", "sessions:write",
        "correlation:read", "correlation:write",
        "investigation:read", "investigation:write",
        "integrations:read", "integrations:write",
        "automation:manage", "automation:respond",
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
        "plugins:read", "plugins:write",
        "evaluation:read", "evaluation:run",
        "discovery:read", "discovery:scan",
        "vkeys:read",
        "quotas:read", "quotas:write",
        "cost:read", "cost:write",
        "cache:read", "cache:write",
        "sessions:read", "sessions:write",
        "correlation:read", "correlation:write",
        "investigation:read", "investigation:write",
        "integrations:read", "integrations:write",
        "automation:manage", "automation:respond",
    },
    UserRole.AUDITOR: {
        "policies:read",
        "guardrails:read",
        "iocs:read",
        "siem:read",
        "notifications:read",
        "audit:read", "audit:export",
        "admin:read",
        "plugins:read",
        "evaluation:read",
        "discovery:read",
        "gdpr:read",
        "vkeys:read",
        "quotas:read",
        "cost:read",
        "cache:read",
        "sessions:read",
        "correlation:read",
        "investigation:read",
    },
    UserRole.VIEWER: {
        "policies:read",
        "siem:read",
        "notifications:read",
        "admin:read",
        "plugins:read",
        "evaluation:read",
        "discovery:read",
        "quotas:read",
        "cost:read",
        "cache:read",
        "sessions:read",
        "correlation:read",
        "investigation:read",
    },
}


# ─── Automation service-account permission whitelist ──────────────────────────
#
# The subset of RBAC permissions a *service account* (a scoped, non-interactive
# automation credential — see ``service_account_store``) may be granted. It is
# deliberately narrow and least-privilege: a playbook token can act on the
# investigation / integrations / correlation / IOC surfaces and invoke the
# dedicated ``automation:respond`` verb, but can NEVER manage users, rotate
# secrets, edit guardrails/policies, or manage service accounts themselves
# (``automation:manage`` is human-operator-only and is intentionally absent
# here). Minting rejects any permission outside this set, so a service account
# can never be escalated beyond what an automation playbook legitimately needs.
AUTOMATION_GRANTABLE_PERMISSIONS: set[str] = {
    "investigation:read", "investigation:write",
    "integrations:read", "integrations:write",
    "correlation:read", "correlation:write",
    "iocs:read", "iocs:write",
    "automation:respond",
}
