"""User management API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..models.auth import (
    UserRole, TokenPayload,
    UserCreate, UserUpdate, UserResponse, SessionResponse,
    MFASetupResponse, ChangePasswordRequest, ProfileUpdate,
)
from ..services.auth_service import require_role, get_current_user
from ..services.audit_logger import get_audit_logger
from ..services.user_store import get_user_store

router = APIRouter()


def _resolve_username(user_id: str) -> str | None:
    """Resolve user_id to username for ownership checks."""
    store = get_user_store()
    u = store.get_user_by_id(user_id)
    return u["username"] if u else None


def _user_to_response(u: dict) -> UserResponse:
    return UserResponse(
        id=u["id"],
        username=u["username"],
        role=u["role"],
        tenant_scope=u.get("tenant_scope"),
        active=bool(u["active"]),
        mfa_enabled=bool(u.get("mfa_secret")),
        email=u.get("email"),
        phone=u.get("phone"),
        first_name=u.get("first_name"),
        last_name=u.get("last_name"),
        created_at=u["created_at"],
        last_login=u.get("last_login"),
    )


@router.get("/users", response_model=list[UserResponse])
async def list_users(user: TokenPayload = Depends(require_role(UserRole.ADMIN))):
    """List all users."""
    store = get_user_store()
    return [_user_to_response(u) for u in store.list_users()]


@router.post("/users", response_model=UserResponse, status_code=201)
async def create_user(req: UserCreate, user: TokenPayload = Depends(require_role(UserRole.ADMIN))):
    """Create a new user."""
    store = get_user_store()
    try:
        new_user = store.create_user(
            req.username, req.password, req.role, req.tenant_scope,
            email=req.email, phone=req.phone,
            first_name=req.first_name, last_name=req.last_name,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        if "UNIQUE" in str(e):
            raise HTTPException(status_code=409, detail="Username already exists")
        raise
    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="user.create", resource_type="user", resource_id=new_user["id"], details=f"username={req.username} role={req.role}")
    return _user_to_response(new_user)


@router.put("/users/{user_id}", response_model=UserResponse)
async def update_user(user_id: str, req: UserUpdate, user: TokenPayload = Depends(require_role(UserRole.ADMIN))):
    """Update user fields."""
    store = get_user_store()
    existing = store.get_user_by_id(user_id)
    if not existing:
        raise HTTPException(status_code=404, detail="User not found")
    updated = store.update_user(user_id, **req.model_dump(exclude_none=True))
    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="user.update", resource_type="user", resource_id=user_id, details=str(req.model_dump(exclude_none=True)))
    return _user_to_response(updated)


@router.delete("/users/{user_id}")
async def delete_user(user_id: str, user: TokenPayload = Depends(require_role(UserRole.ADMIN))):
    """Soft-delete user."""
    store = get_user_store()
    if not store.delete_user(user_id):
        raise HTTPException(status_code=404, detail="User not found")
    store.revoke_all_sessions(user_id)
    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="user.delete", resource_type="user", resource_id=user_id)
    return {"status": "deleted"}


@router.post("/users/{user_id}/reset-password")
async def reset_password(user_id: str, req: ChangePasswordRequest, user: TokenPayload = Depends(require_role(UserRole.ADMIN))):
    """Reset user password (admin only)."""
    store = get_user_store()
    if not store.get_user_by_id(user_id):
        raise HTTPException(status_code=404, detail="User not found")
    try:
        store.change_password(user_id, req.new_password)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    store.revoke_all_sessions(user_id)
    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="user.reset_password", resource_type="user", resource_id=user_id)
    return {"status": "password_reset"}


@router.get("/users/{user_id}/sessions", response_model=list[SessionResponse])
async def list_sessions(user_id: str, user: TokenPayload = Depends(get_current_user)):
    """List active sessions for a user. Users can only view their own sessions; admins can view any."""
    if user.role != UserRole.ADMIN and user.sub != _resolve_username(user_id):
        raise HTTPException(status_code=403, detail="Cannot access other user's sessions")
    store = get_user_store()
    sessions = store.get_active_sessions(user_id)
    return [SessionResponse(**s) for s in sessions]


@router.delete("/users/{user_id}/sessions/{session_id}")
async def revoke_session(user_id: str, session_id: str, user: TokenPayload = Depends(get_current_user)):
    """Revoke a specific session. Users can only revoke their own; admins can revoke any."""
    if user.role != UserRole.ADMIN and user.sub != _resolve_username(user_id):
        raise HTTPException(status_code=403, detail="Cannot revoke other user's sessions")
    store = get_user_store()
    if not store.revoke_session(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="session.revoke", resource_type="session", resource_id=session_id)
    return {"status": "revoked"}


@router.post("/users/{user_id}/mfa/setup", response_model=MFASetupResponse)
async def mfa_setup(user_id: str, user: TokenPayload = Depends(get_current_user)):
    """Generate TOTP secret. Users can only setup their own MFA; admins can setup any."""
    if user.role != UserRole.ADMIN and user.sub != _resolve_username(user_id):
        raise HTTPException(status_code=403, detail="Cannot setup MFA for other users")
    store = get_user_store()
    try:
        result = store.setup_mfa(user_id)
    except RuntimeError as e:
        raise HTTPException(status_code=501, detail=str(e))
    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="mfa.setup", resource_type="user", resource_id=user_id)
    return MFASetupResponse(
        secret=result["secret"],
        provisioning_uri=result["provisioning_uri"],
        qr_code_url=result["provisioning_uri"],
    )


@router.post("/users/{user_id}/mfa/verify")
async def mfa_verify(user_id: str, code: str, user: TokenPayload = Depends(get_current_user)):
    """Verify TOTP code. Users can only verify their own MFA; admins can verify any."""
    if user.role != UserRole.ADMIN and user.sub != _resolve_username(user_id):
        raise HTTPException(status_code=403, detail="Cannot verify MFA for other users")
    store = get_user_store()
    if not store.verify_mfa(user_id, code):
        raise HTTPException(status_code=400, detail="Invalid MFA code")
    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="mfa.verified", resource_type="user", resource_id=user_id)
    return {"status": "mfa_enabled"}


@router.delete("/users/{user_id}/mfa")
async def mfa_disable(user_id: str, user: TokenPayload = Depends(require_role(UserRole.ADMIN))):
    """Disable MFA for a user."""
    store = get_user_store()
    store.disable_mfa(user_id)
    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="mfa.disabled", resource_type="user", resource_id=user_id)
    return {"status": "mfa_disabled"}


@router.get("/profile", response_model=UserResponse)
async def get_profile(user: TokenPayload = Depends(get_current_user)):
    """Get current user's profile."""
    store = get_user_store()
    u = store.get_user(user.sub)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_to_response(u)


@router.put("/profile", response_model=UserResponse)
async def update_profile(req: ProfileUpdate, user: TokenPayload = Depends(get_current_user)):
    """Update current user's own profile (non-privileged fields only)."""
    store = get_user_store()
    u = store.get_user(user.sub)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    updated = store.update_user(u["id"], **req.model_dump(exclude_none=True))
    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="profile.update", resource_type="user", resource_id=u["id"], details=str(req.model_dump(exclude_none=True)))
    return _user_to_response(updated)
