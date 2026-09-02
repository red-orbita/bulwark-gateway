"""Auth service — JWT-based authentication + RBAC enforcement.

Uses PyJWT for token creation and verification.
Addresses HIGH-05: replaces custom HMAC JWT implementation with PyJWT.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..models.auth import ROLE_PERMISSIONS, TokenPayload, UserRole
from .secrets import read_secret

# ─── Session validation cache ─────────────────────────────────────────
# SQLCipher is slow (50-800ms per operation). Cache session validity
# in memory with a short TTL to avoid hitting the encrypted DB on every request.
# SECURITY FIX (APT-16): Reduced from 5s to 2s to further minimize the revocation window.
# Previous 5s window allowed stolen sessions to remain valid after logout.
# Tradeoff: ~15x more DB lookups vs 30s original; mitigated by SQLCipher connection pooling.
# For zero-delay revocation, deploy with Redis and set ADMIN_SESSION_CACHE_TTL=0.
_session_cache: dict[str, float] = {}  # token_hash -> last_validated_at (monotonic)
_SESSION_CACHE_TTL = float(os.getenv("ADMIN_SESSION_CACHE_TTL", "2.0"))  # seconds (was 5s, was 30s)

# Read JWT secret from Docker secret file or env var
JWT_SECRET = read_secret("ADMIN_JWT_SECRET", default="bulwark-admin-change-me-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = int(os.getenv("ADMIN_JWT_EXPIRY_HOURS", "8"))
SESSION_IDLE_TIMEOUT_MINUTES = int(os.getenv("ADMIN_SESSION_IDLE_TIMEOUT", "30"))
JWT_ISSUER = "bulwark-admin"
JWT_AUDIENCE = "bulwark-admin"

# Optional static bearer token that lets Prometheus scrape the metrics endpoint
# (/admin/health/metrics) without a user session. Read from a Docker/K8s secret
# file (BULWARK_METRICS_SCRAPE_TOKEN_FILE) or env var. Empty by default, which
# DISABLES the scrape-token path entirely — there is no insecure default, and
# the metrics endpoint then requires an admin:read JWT like any other endpoint.
METRICS_SCRAPE_TOKEN = read_secret("BULWARK_METRICS_SCRAPE_TOKEN", default="")

# Validate JWT secret at import time (skip in tests)
_INSECURE_SECRETS = {"bulwark-admin-change-me-in-production", "", "secret", "test", "dev", "change-me"}
if JWT_SECRET.lower().strip() in _INSECURE_SECRETS or len(JWT_SECRET) < 32:
    _debug = os.getenv("ADMIN_DEBUG", "false").lower() in ("true", "1")
    _testing = "pytest" in sys.modules or "unittest" in sys.modules
    if not _debug and not _testing:
        raise SystemExit(
            "FATAL: ADMIN_JWT_SECRET is insecure (must be 32+ chars and not a known default). "
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
            except Exception:  # noqa: S110 - session recording is best-effort; must not fail auth
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
            {"success": True, "username": str, "role": UserRole, "user_id": str, "force_password_change": bool}
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

        return {
            "success": True,
            "username": username,
            "role": role,
            "user_id": user["id"],
            "force_password_change": bool(user.get("force_password_change")),
        }


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
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role: {[r.value for r in roles]}",
            )
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


async def _audit_rate_limited(account_id: str, limit: int) -> None:
    """Record a service-account rate-limit rejection (best-effort, never raises).

    A throttled request already returns 429; a failure to write the audit trail
    must not mask that or crash the request path, so any error is swallowed.
    """
    try:
        import json

        from .audit_logger import get_audit_logger

        await get_audit_logger().log(
            actor=f"service-account:{account_id}",
            action="service_account.rate_limited",
            resource_type="service_account",
            resource_id=account_id,
            details=json.dumps({"limit_rpm": limit, "window_seconds": 60}),
        )
    except Exception:  # noqa: S110,BLE001 - audit is advisory; never break the 429 path
        pass


def require_permission_automation(permission: str):
    """Dependency factory for automation-enabled endpoints (Phase 3.2a).

    Accepts EITHER:
      * a valid operator session/JWT whose role carries ``permission`` (normal
        interactive admin auth, via ``get_current_user`` + ``ROLE_PERMISSIONS``), OR
      * a **service-account key** (``bwk_sa_…``) presented as
        ``Authorization: Bearer <key>`` whose explicit, least-privilege permission
        set contains ``permission`` (see ``service_account_store``).

    This is wired ONLY onto endpoints explicitly opened to automation, so the
    service-account credential path has minimal blast radius — every other admin
    endpoint keeps using ``require_permission`` (session-only). A presented token
    that begins with the service-account prefix is resolved EXCLUSIVELY on the
    service-account path (an unknown/disabled/expired key is rejected outright,
    never silently retried as a session token), which keeps failure modes
    unambiguous. The returned ``TokenPayload`` identifies the service account
    (``sub='service-account:<id>'``) with the lowest role so no downstream
    role-based check can widen its access beyond the explicit permission grant.
    """
    async def _check(
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    ) -> TokenPayload:
        presented = credentials.credentials if credentials is not None else None
        if presented:
            from .service_account_store import KEY_PREFIX, ServiceAccountStore
            if presented.startswith(KEY_PREFIX):
                account = await ServiceAccountStore().verify(presented)
                if account is None:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid, disabled or expired service-account key",
                    )
                if permission not in set(account.get("permissions", [])):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Service account missing permission: {permission}",
                    )
                # Per-key rate limit (Phase 3.2c). A per-account override wins,
                # else the environment default; a resolved limit <= 0 is unbounded.
                from .automation_rate_limit import (
                    default_rate_limit_rpm,
                    get_automation_rate_limiter,
                )
                override = account.get("rate_limit_rpm")
                limit = override if isinstance(override, int) else default_rate_limit_rpm()
                if not get_automation_rate_limiter().consume(account["account_id"], limit):
                    await _audit_rate_limited(account["account_id"], limit)
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail="Service account rate limit exceeded",
                        headers={"Retry-After": "60"},
                    )
                now = datetime.now(timezone.utc)
                return TokenPayload(
                    sub=f"service-account:{account['account_id']}",
                    role=UserRole.VIEWER,
                    exp=now + timedelta(minutes=1),
                    iat=now,
                )

        # Fall back to the standard operator JWT/session validation + RBAC check.
        user = await get_current_user(request, credentials)
        user_perms = ROLE_PERMISSIONS.get(user.role, set())
        if permission not in user_perms:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission: {permission}",
            )
        return user
    return _check


def require_permission_or_scrape_token(permission: str):
    """Dependency factory for the Prometheus metrics endpoint.

    Accepts EITHER:
      * a valid session/JWT that carries ``permission`` (normal admin auth), OR
      * the dedicated static scrape token in ``METRICS_SCRAPE_TOKEN`` presented
        as ``Authorization: Bearer <token>``.

    The scrape-token branch is inert when no token is configured (empty), so
    there is no insecure default — the endpoint then behaves exactly like
    ``require_permission(permission)``. The token is compared in constant time
    (``hmac.compare_digest``) and grants access to the metrics endpoint ONLY
    (this dependency is not wired anywhere else).
    """
    async def _check(
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    ) -> TokenPayload:
        token = METRICS_SCRAPE_TOKEN
        if token and credentials is not None:
            presented = credentials.credentials or ""
            if hmac.compare_digest(presented.encode("utf-8"), token.encode("utf-8")):
                now = datetime.now(timezone.utc)
                return TokenPayload(
                    sub="prometheus-scraper",
                    role=UserRole.VIEWER,
                    exp=now + timedelta(minutes=1),
                    iat=now,
                )
        # Fall back to the standard JWT/session validation + permission check.
        user = await get_current_user(request, credentials)
        user_perms = ROLE_PERMISSIONS.get(user.role, set())
        if permission not in user_perms:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission: {permission}",
            )
        return user
    return _check
