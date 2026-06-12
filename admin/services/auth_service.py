"""Auth service — JWT-based authentication + RBAC enforcement.

Uses PyJWT for token creation and verification.
Addresses HIGH-05: replaces custom HMAC JWT implementation with PyJWT.
"""

from __future__ import annotations

import hashlib
import os
import sys
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..models.auth import UserRole, TokenPayload, ROLE_PERMISSIONS

# ─── Session validation cache ─────────────────────────────────────────
# SQLCipher is slow (50-800ms per operation). Cache session validity
# in memory with a 30s TTL to avoid hitting the encrypted DB on every request.
_session_cache: dict[str, float] = {}  # token_hash -> last_validated_at (monotonic)
_SESSION_CACHE_TTL = 30.0  # seconds
from .secrets import read_secret

# Read JWT secret from Docker secret file or env var
JWT_SECRET = read_secret("ADMIN_JWT_SECRET", default="sentinel-admin-change-me-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = int(os.getenv("ADMIN_JWT_EXPIRY_HOURS", "8"))
SESSION_IDLE_TIMEOUT_MINUTES = int(os.getenv("ADMIN_SESSION_IDLE_TIMEOUT", "30"))
JWT_ISSUER = "sentinel-admin"
JWT_AUDIENCE = "sentinel-admin"

# Validate JWT secret at import time (skip in tests)
_INSECURE_SECRETS = {"sentinel-admin-change-me-in-production", "", "secret", "test", "dev", "change-me"}
if JWT_SECRET.lower().strip() in _INSECURE_SECRETS:
    _debug = os.getenv("ADMIN_DEBUG", "false").lower() in ("true", "1")
    _testing = "pytest" in sys.modules or "unittest" in sys.modules
    if not _debug and not _testing:
        raise SystemExit(
            "FATAL: ADMIN_JWT_SECRET is insecure. "
            "Set a strong secret (32+ chars) via environment variable or Docker secret."
        )
    import logging
    logging.getLogger(__name__).warning("INSECURE ADMIN_JWT_SECRET — only acceptable in debug/test mode")

security_scheme = HTTPBearer(auto_error=False)


class AuthService:
    """JWT token management and validation using PyJWT."""

    @staticmethod
    def create_token(username: str, role: UserRole, user_id: Optional[str] = None,
                     ip: Optional[str] = None, user_agent: Optional[str] = None) -> str:
        """Create a JWT token (HS256) with standard claims."""
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=JWT_EXPIRY_HOURS)
        payload = {
            "sub": username,
            "role": role.value,
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
            "iat": now,
            "exp": expires_at,
            "jti": str(uuid.uuid4()),
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

        # Record session
        if user_id:
            try:
                from .user_store import get_user_store
                store = get_user_store()
                store.create_session(user_id, token, ip, user_agent, expires_at.isoformat())
            except Exception:
                pass  # Don't fail auth if session recording fails

        return token

    @staticmethod
    def create_sse_token(username: str, role: UserRole) -> str:
        """Create a short-lived JWT (60s) for SSE connections.

        This avoids exposing long-lived session tokens in URL query params.
        """
        now = datetime.now(timezone.utc)
        payload = {
            "sub": username,
            "role": role.value,
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
            "iat": now,
            "exp": now + timedelta(seconds=60),
            "jti": str(uuid.uuid4()),
            "purpose": "sse",
        }
        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    @staticmethod
    def verify_token(token: str) -> Optional[TokenPayload]:
        """Verify and decode JWT token.

        Validates: signature (HS256 only), expiry, issuer, audience.
        Pins algorithms=["HS256"] to block alg:none attacks.
        """
        try:
            payload = jwt.decode(
                token,
                JWT_SECRET,
                algorithms=[JWT_ALGORITHM],
                audience=JWT_AUDIENCE,
                issuer=JWT_ISSUER,
                options={
                    "require": ["exp", "iat", "sub"],
                },
            )
            return TokenPayload(
                sub=payload["sub"],
                role=UserRole(payload["role"]),
                exp=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
                iat=datetime.fromtimestamp(payload["iat"], tz=timezone.utc),
            )
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        except (KeyError, ValueError):
            return None

    @staticmethod
    def authenticate(username: str, password: str, mfa_code: Optional[str] = None) -> dict:
        """Verify username/password + MFA.

        Returns:
            {"success": True, "username": str, "role": UserRole, "user_id": str}
            {"success": False, "error": str}
            {"success": False, "mfa_required": True}
        """
        from .user_store import get_user_store
        store = get_user_store()

        user = store.verify_password(username, password)
        if not user:
            return {"success": False, "error": "Invalid credentials"}

        role = UserRole(user["role"])

        # Check MFA
        if user.get("mfa_secret"):
            if not mfa_code:
                return {"success": False, "mfa_required": True}
            if not store.verify_mfa(user["id"], mfa_code):
                return {"success": False, "error": "Invalid MFA code"}

        return {"success": True, "username": username, "role": role, "user_id": user["id"]}


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
) -> TokenPayload:
    """FastAPI dependency: extract and validate JWT from Authorization header."""
    if credentials is None:
        token = request.cookies.get("admin_token")
        if not token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    else:
        token = credentials.credentials

    payload = AuthService.verify_token(token)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    # HIGH-04: Check token revocation + idle timeout
    # Use in-memory cache to avoid SQLCipher overhead on every request
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = time.monotonic()
    last_checked = _session_cache.get(token_hash, 0.0)

    if (now - last_checked) < _SESSION_CACHE_TTL:
        # Cache hit — session was valid recently, skip DB check
        return payload

    # Cache miss — validate against DB (in executor to avoid blocking event loop)
    import asyncio

    def _validate_session() -> bool:
        try:
            from .user_store import get_user_store
            store = get_user_store()
            if not store.is_session_valid(token_hash):
                return False
            if not store.check_and_update_activity(token_hash, SESSION_IDLE_TIMEOUT_MINUTES):
                return False
        except (ImportError, AttributeError):
            pass
        return True

    is_valid = await asyncio.get_event_loop().run_in_executor(None, _validate_session)
    if not is_valid:
        _session_cache.pop(token_hash, None)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session has been revoked or expired")

    # Update cache
    _session_cache[token_hash] = now
    return payload


def require_role(*roles: UserRole):
    """FastAPI dependency factory: require specific role(s)."""
    async def _check(user: TokenPayload = Depends(get_current_user)) -> TokenPayload:
        if user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Requires role: {[r.value for r in roles]}")
        return user
    return _check


def require_permission(permission: str):
    """FastAPI dependency factory: require specific permission."""
    async def _check(user: TokenPayload = Depends(get_current_user)) -> TokenPayload:
        user_perms = ROLE_PERMISSIONS.get(user.role, set())
        if permission not in user_perms:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Missing permission: {permission}")
        return user
    return _check
