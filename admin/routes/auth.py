"""Auth routes — Login, token refresh, user info, password change."""

from __future__ import annotations

import hashlib
import os
import time
from fastapi import APIRouter, Depends, HTTPException, Request, Response

from ..models.auth import LoginRequest, LoginResponse, UserInfo, TokenPayload, ChangePasswordRequest
from ..services.auth_service import AuthService, get_current_user
from ..services.audit_logger import get_audit_logger
from ..services.user_store import get_user_store

router = APIRouter()

# Login rate limiting constants
_MAX_ATTEMPTS = 5
_MAX_USERNAME_ATTEMPTS = 3  # stricter per-username limit
_WINDOW_SECONDS = 300  # 5 minutes
_LOCKOUT_SECONDS = 900  # 15 minutes after max attempts

# Uses TTLCache to auto-evict entries after lockout period (prevents memory leak)
from cachetools import TTLCache

_LOGIN_ATTEMPTS: TTLCache = TTLCache(maxsize=5000, ttl=_LOCKOUT_SECONDS)
_USERNAME_ATTEMPTS: TTLCache = TTLCache(maxsize=5000, ttl=_LOCKOUT_SECONDS)


def _should_set_secure_cookie(request: Request) -> bool:
    """Determine if the session cookie should have the Secure flag.

    Logic (priority order):
    1. Explicit BULWARK_HTTPS env var overrides everything
    2. If behind a reverse proxy with X-Forwarded-Proto: https → secure
    3. If request URL scheme is https → secure
    4. Otherwise (plain HTTP, localhost dev) → not secure
    """
    explicit = os.environ.get("BULWARK_HTTPS", "").lower().strip()
    if explicit in ("true", "1", "yes"):
        return True
    if explicit in ("false", "0", "no"):
        return False
    # Auto-detect from request
    forwarded_proto = request.headers.get("x-forwarded-proto", "")
    if forwarded_proto == "https":
        return True
    if request.url.scheme == "https":
        return True
    return False

# SECURITY FIX (APT-08): Distributed rate limiting via Redis.
# In-memory rate limiting is per-process — with 4 workers * 2 replicas,
# an attacker gets 40 attempts instead of 5. Redis provides a single
# authoritative counter shared across all processes/pods.
_rate_limit_redis = None
_rate_limit_redis_init = False


def _get_rate_limit_redis():
    """Lazy-initialize Redis client for distributed rate limiting."""
    global _rate_limit_redis, _rate_limit_redis_init
    if _rate_limit_redis_init:
        return _rate_limit_redis
    _rate_limit_redis_init = True
    try:
        redis_url = os.getenv("BULWARK_REDIS_URL")
        if redis_url:
            import redis
            from admin.services.redis_sync import get_redis_client
            _rate_limit_redis = get_redis_client()
    except Exception:
        _rate_limit_redis = None
    return _rate_limit_redis


def _check_login_rate_limit(ip: str, username: str | None = None) -> None:
    """Block login if IP or username has exceeded max attempts in window.

    SECURITY FIX (APT-08): Uses Redis for distributed counting when available.
    Falls back to in-memory TTLCache when Redis is unavailable (degraded but functional).
    """
    # Try distributed (Redis) rate limiting first
    r = _get_rate_limit_redis()
    if r:
        try:
            return _check_rate_limit_redis(r, ip, username)
        except Exception:
            pass  # Fall through to local rate limiting

    # Fallback: local in-memory rate limiting (per-process)
    _check_rate_limit_local(ip, username)


def _check_rate_limit_redis(r, ip: str, username: str | None) -> None:
    """Redis-based distributed rate limiting using sliding window."""
    now = time.time()
    pipe = r.pipeline(transaction=True)

    # Check IP-based rate limit
    ip_key = f"bulwark:admin:login_attempts:ip:{ip}"
    pipe.zremrangebyscore(ip_key, 0, now - _LOCKOUT_SECONDS)
    pipe.zcard(ip_key)
    results = pipe.execute()
    ip_count = results[1]

    if ip_count >= _MAX_ATTEMPTS:
        raise HTTPException(
            status_code=429,
            detail=f"Too many login attempts. Try again in {_LOCKOUT_SECONDS // 60} minutes.",
        )

    # Check per-username rate limit
    if username:
        user_key = f"bulwark:admin:login_attempts:user:{username}"
        pipe.zremrangebyscore(user_key, 0, now - _LOCKOUT_SECONDS)
        pipe.zcard(user_key)
        results = pipe.execute()
        user_count = results[1]

        if user_count >= _MAX_USERNAME_ATTEMPTS:
            raise HTTPException(
                status_code=429,
                detail=f"Account temporarily locked. Try again in {_LOCKOUT_SECONDS // 60} minutes.",
            )


def _check_rate_limit_local(ip: str, username: str | None) -> None:
    """In-memory rate limiting fallback (per-process, not distributed)."""
    now = time.time()
    # Clean old entries and check IP
    attempts = _LOGIN_ATTEMPTS.get(ip, [])
    attempts = [t for t in attempts if now - t < _LOCKOUT_SECONDS]
    _LOGIN_ATTEMPTS[ip] = attempts

    recent = [t for t in attempts if now - t < _WINDOW_SECONDS]
    if len(recent) >= _MAX_ATTEMPTS:
        raise HTTPException(
            status_code=429,
            detail=f"Too many login attempts. Try again in {_LOCKOUT_SECONDS // 60} minutes.",
        )

    # Also check per-username rate limit (prevents distributed brute-force)
    if username:
        user_attempts = _USERNAME_ATTEMPTS.get(username, [])
        user_attempts = [t for t in user_attempts if now - t < _LOCKOUT_SECONDS]
        _USERNAME_ATTEMPTS[username] = user_attempts
        recent_user = [t for t in user_attempts if now - t < _WINDOW_SECONDS]
        if len(recent_user) >= _MAX_USERNAME_ATTEMPTS:
            raise HTTPException(
                status_code=429,
                detail=f"Account temporarily locked. Try again in {_LOCKOUT_SECONDS // 60} minutes.",
            )


def _record_login_attempt(ip: str, username: str | None = None) -> None:
    """Record a failed login attempt (distributed via Redis when available)."""
    # Try Redis first for distributed counting
    r = _get_rate_limit_redis()
    if r:
        try:
            now = time.time()
            pipe = r.pipeline(transaction=True)
            ip_key = f"bulwark:admin:login_attempts:ip:{ip}"
            pipe.zadd(ip_key, {f"{now}": now})
            pipe.expire(ip_key, _LOCKOUT_SECONDS)
            if username:
                user_key = f"bulwark:admin:login_attempts:user:{username}"
                pipe.zadd(user_key, {f"{now}": now})
                pipe.expire(user_key, _LOCKOUT_SECONDS)
            pipe.execute()
            return
        except Exception:
            pass  # Fall through to local

    # Fallback: local in-memory
    attempts = _LOGIN_ATTEMPTS.get(ip, [])
    attempts.append(time.time())
    _LOGIN_ATTEMPTS[ip] = attempts
    if username:
        user_attempts = _USERNAME_ATTEMPTS.get(username, [])
        user_attempts.append(time.time())
        _USERNAME_ATTEMPTS[username] = user_attempts


@router.post("/login", response_model=LoginResponse)
async def login(req: LoginRequest, request: Request, response: Response):
    """Authenticate and return JWT token."""
    ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent")

    # Rate limiting
    _check_login_rate_limit(ip, req.username)

    # Run bcrypt-heavy auth in thread pool to avoid blocking event loop
    import asyncio
    result = await asyncio.get_event_loop().run_in_executor(
        None, AuthService.authenticate, req.username, req.password, req.mfa_code
    )

    if not result.get("success"):
        _record_login_attempt(ip, req.username)
        if result.get("mfa_required"):
            return LoginResponse(
                access_token="",
                role="admin",
                username=req.username,
                mfa_required=True,
                expires_in=0,
            )
        raise HTTPException(status_code=401, detail=result.get("error", "Invalid credentials"))

    username = result["username"]
    role = result["role"]
    user_id = result["user_id"]

    # Check if user must change password before getting full access
    if result.get("force_password_change"):
        return LoginResponse(
            access_token="",
            role=role,
            username=username,
            mfa_required=False,
            force_password_change=True,
            expires_in=0,
        )

    token = AuthService.create_token(username, role, user_id=user_id, ip=ip, user_agent=user_agent)

    audit = get_audit_logger()
    await audit.log(actor=username, action="auth.login", resource_type="user", resource_id=user_id, details=str({"ip": ip}))

    response = Response(
        content=LoginResponse(
            access_token=token,
            role=role,
            username=username,
        ).model_dump_json(),
        media_type="application/json",
    )
    # Set HttpOnly cookie for browser-based auth
    is_secure = _should_set_secure_cookie(request)
    response.set_cookie(
        key="admin_token",
        value=token,
        httponly=True,
        secure=is_secure,
        samesite="strict" if is_secure else "lax",
        max_age=28800,  # 8h — aligned with JWT expiry
        path="/",
    )
    return response


@router.get("/me", response_model=UserInfo)
async def get_me(user: TokenPayload = Depends(get_current_user)):
    """Get current user info from token."""
    return UserInfo(username=user.sub, role=user.role)


@router.post("/logout")
async def logout(request: Request, response: Response, user: TokenPayload = Depends(get_current_user)):
    """Revoke current session and clear cookie."""
    response.delete_cookie("admin_token", path="/", samesite="strict", secure=True, httponly=True)

    # Try to revoke the session by token hash
    token = None
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:]
    else:
        token = request.cookies.get("admin_token")

    if token:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        store = get_user_store()
        # Revoke session by token hash — works for both SQLite and PostgreSQL
        if hasattr(store, '_conn') and store._conn:
            store._conn.execute("UPDATE sessions SET revoked = 1 WHERE token_hash = ?", (token_hash,))
            store._conn.commit()
        elif hasattr(store, '_get_db'):
            db = store._get_db()
            if hasattr(db, 'sync_execute'):
                db.sync_execute("UPDATE sessions SET revoked = 1 WHERE token_hash = ?", (token_hash,))

    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="auth.logout", resource_type="user", resource_id=user.sub)

    return {"status": "logged_out"}


@router.post("/change-password")
async def change_password(req: ChangePasswordRequest, request: Request, user: TokenPayload = Depends(get_current_user)):
    """Change own password only (authenticated user). Cannot change other users' passwords."""
    ip = request.client.host if request.client else "unknown"
    _check_login_rate_limit(ip, user.sub)

    import asyncio
    loop = asyncio.get_running_loop()
    store = get_user_store()

    db_user = await loop.run_in_executor(None, store.get_user, user.sub)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Verify current password (MANDATORY)
    if not req.current_password:
        raise HTTPException(status_code=400, detail="current_password is required")
    verified = await loop.run_in_executor(None, store.verify_password, user.sub, req.current_password)
    if not verified:
        _record_login_attempt(ip, user.sub)
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    try:
        await loop.run_in_executor(None, store.change_password, db_user["id"], req.new_password)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="auth.change_password", resource_type="user", resource_id=db_user["id"])

    return {"status": "password_changed"}


@router.post("/force-change-password")
async def force_change_password(request: Request):
    """Change password without token — only for users with force_password_change=true.
    
    Requires username + current_password verification (rate-limited).
    On success, returns a full login token so the client doesn't need a second login.
    """
    ip = request.client.host if request.client else "unknown"

    body = await request.json()
    username = body.get("username", "")
    current_password = body.get("current_password", "")
    new_password = body.get("new_password", "")

    if not username or not current_password or not new_password:
        raise HTTPException(status_code=400, detail="username, current_password, and new_password required")

    # Rate limit by both IP and target username
    _check_login_rate_limit(ip, username)

    if len(new_password) < 12:
        raise HTTPException(status_code=400, detail="New password must be at least 12 characters")

    import asyncio
    loop = asyncio.get_running_loop()
    store = get_user_store()

    # Verify credentials
    verified = await loop.run_in_executor(None, store.verify_password, username, current_password)
    if not verified:
        _record_login_attempt(ip, username)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Only allow if force_password_change is set
    db_user = await loop.run_in_executor(None, store.get_user, username)
    if not db_user or not db_user.get("force_password_change"):
        raise HTTPException(status_code=403, detail="Password change not required")

    # Prevent reusing same password
    if current_password == new_password:
        raise HTTPException(status_code=400, detail="New password must be different from current password")

    try:
        await loop.run_in_executor(None, store.change_password, db_user["id"], new_password)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    audit = get_audit_logger()
    await audit.log(actor=username, action="auth.force_change_password", resource_type="user", resource_id=db_user["id"])

    # Issue token immediately (no need for second login round-trip)
    from ..models.auth import UserRole
    role = UserRole(db_user["role"])
    user_agent = request.headers.get("user-agent")
    token = AuthService.create_token(username, role, user_id=db_user["id"], ip=ip, user_agent=user_agent)

    response = Response(
        content=LoginResponse(
            access_token=token,
            role=role,
            username=username,
        ).model_dump_json(),
        media_type="application/json",
    )
    is_secure = _should_set_secure_cookie(request)
    response.set_cookie(
        key="admin_token",
        value=token,
        httponly=True,
        secure=is_secure,
        samesite="strict" if is_secure else "lax",
        max_age=28800,
        path="/",
    )
    return response
