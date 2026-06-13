"""
Authentication middleware — validates JWT tokens or API keys.

Security model: fail-closed. If auth is enabled and no valid credential
is presented, the request is rejected with 401.

Supports:
  - HS256 (symmetric): shared secret verification (backward compatible)
  - RS256/ES256 (asymmetric): public key verification (enterprise mode)
  - JWKS endpoint integration for external IdP (key rotation via 'kid')
"""

import hashlib
import hmac
import logging
import re
from typing import Optional, Set

from fastapi import Request
import jwt
from jwt import InvalidTokenError as JWTError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from src.config import settings
from src.middleware.jwt_keys import is_asymmetric, get_verification_key, JWTKeyError

logger = logging.getLogger(__name__)

# Regex for valid tenant/agent IDs (alphanumeric, hyphens, underscores, 1-64 chars)
_SAFE_ID = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")


# Token revocation check via Redis (best-effort, non-blocking)
_revocation_redis = None
_revocation_redis_init = False


def _is_token_revoked(jti: str) -> bool:
    """Check if a JWT ID is in the revocation set (Redis).

    Fail-CLOSED: returns True (revoked/blocked) if Redis is unavailable,
    rejecting the request. This prevents use of revoked tokens during
    Redis outages. Short-lived tokens (1h) limit the impact window.
    """
    global _revocation_redis, _revocation_redis_init
    if not _revocation_redis_init:
        _revocation_redis_init = True
        try:
            import redis as _redis
            url = getattr(settings, "redis_url", None)
            if url:
                _revocation_redis = _redis.from_url(url, decode_responses=True, socket_timeout=0.1)
                _revocation_redis.ping()
        except Exception:
            _revocation_redis = None

    if not _revocation_redis:
        # Fail-closed: cannot verify revocation → reject token (C-04)
        return True
    try:
        return _revocation_redis.sismember("sentinel:revoked_tokens", jti)
    except Exception:
        # Fail-closed on Redis error (C-04)
        return True

# Paths that don't require auth (H-13: removed /health/stats, /health/telemetry)
# /internal/* paths are cluster-internal only (NetworkPolicy enforced)
PUBLIC_PATHS = {"/health", "/ready", "/health/live", "/docs", "/openapi.json", "/internal/scanners/status"}

# Pre-compute valid API key hashes at startup (constant-time comparison)
_API_KEY_HASHES: Set[str] = set()


def _init_api_keys() -> Set[str]:
    """Load API keys from config, store as SHA-256 hashes."""
    keys = set()
    if settings.api_keys:
        for key in settings.api_keys.split(","):
            key = key.strip()
            if len(key) >= 16:
                keys.add(hashlib.sha256(key.encode()).hexdigest())
    return keys


# Initialize on module load
_API_KEY_HASHES = _init_api_keys()


def _get_jwt_verification_key(token: str):
    """Select the appropriate verification key based on JWT algorithm and headers.

    For HS256 (symmetric): returns the shared secret string.
    For RS256/ES256 (asymmetric): extracts 'kid' from JWT header and
    resolves the public key via static file or JWKS endpoint.

    Fail-closed: if asymmetric key resolution fails, raises JWTKeyError
    which causes the caller to reject the request.

    Args:
        token: Raw JWT string (used to extract unverified headers).

    Returns:
        Verification key (str for HS256, public key object for RS256/ES256).

    Raises:
        JWTKeyError: If asymmetric key cannot be resolved.
    """
    algorithm = settings.jwt_algorithm

    if not is_asymmetric(algorithm):
        # HS256 — use shared secret (backward compatible)
        return settings.jwt_secret

    # RS256/ES256 — resolve public key
    # Extract 'kid' from JWT header (unverified) for key rotation support
    try:
        unverified_header = jwt.get_unverified_header(token)
    except Exception:
        # Malformed token — let jwt.decode() handle the error
        # Return a key anyway so decode() produces a proper JWTError
        return get_verification_key(algorithm, kid=None)

    kid = unverified_header.get("kid") or getattr(settings, "jwt_key_id", None) or None
    return get_verification_key(algorithm, kid=kid)


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip auth for health checks and public paths
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        # Extract tenant and agent from headers (defaults used if JWT doesn't override)
        tenant_id = request.headers.get("X-Tenant-ID", "default")
        agent_id = request.headers.get("X-Agent-ID", "default")
        auth_header = request.headers.get("Authorization", "")

        # Validate auth
        if settings.api_keys_enabled:
            if not auth_header:
                return JSONResponse(
                    status_code=401,
                    content={"error": "Missing Authorization header"},
                )

            if auth_header.startswith("Bearer "):
                token = auth_header[7:]
                # Try JWT first
                try:
                    # H-03: Validate audience/issuer to prevent cross-service token reuse
                    # SECURITY FIX (VULN 1.3+1.4): Require both exp AND jti claims.
                    # Tokens without jti cannot be revoked. Tokens without exp never expire.
                    decode_options = {"require": ["exp", "jti"]}
                    decode_kwargs = {
                        "algorithms": [settings.jwt_algorithm],
                    }
                    # SECURITY FIX (VULN 1.10): Always enforce audience/issuer
                    # when configured, removing the empty-string bypass
                    jwt_audience = getattr(settings, "jwt_audience", None)
                    jwt_issuer = getattr(settings, "jwt_issuer", None)
                    if jwt_audience:
                        decode_kwargs["audience"] = jwt_audience
                    if jwt_issuer:
                        decode_kwargs["issuer"] = jwt_issuer

                    # Select verification key based on algorithm
                    verification_key = _get_jwt_verification_key(token)

                    payload = jwt.decode(
                        token,
                        verification_key,
                        options=decode_options,
                        **decode_kwargs,
                    )
                    # SECURITY FIX (VULN 1.3): jti is now mandatory (required above),
                    # so this check always runs. No more skip-if-absent bypass.
                    jti = payload["jti"]
                    if _is_token_revoked(jti):
                        return JSONResponse(
                            status_code=401,
                            content={"error": "Token has been revoked"},
                        )
                    # Use authenticated tenant/agent from JWT (H-04: prevents header spoofing)
                    tenant_id = payload.get("tenant_id", tenant_id)
                    agent_id = payload.get("agent_id", agent_id)
                except JWTError:
                    # Not a valid JWT — validate as API key
                    if not self._validate_api_key(token):
                        return JSONResponse(
                            status_code=401,
                            content={"error": "Invalid token or API key"},
                        )
                except JWTKeyError as e:
                    # Asymmetric key loading failed — fail-closed
                    logger.error(
                        "JWT verification key unavailable (fail-closed)",
                        extra={"error": str(e)},
                    )
                    return JSONResponse(
                        status_code=401,
                        content={"error": "Authentication service unavailable"},
                    )
            else:
                # Not a Bearer token — reject
                return JSONResponse(
                    status_code=401,
                    content={"error": "Invalid Authorization format. Use: Bearer <token>"},
                )
        else:
            # H-03: Even with API key auth disabled, still validate JWT if present
            # This mode is ONLY for local development/testing
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header[7:]
                try:
                    verification_key = _get_jwt_verification_key(token)
                    payload = jwt.decode(
                        token,
                        verification_key,
                        algorithms=[settings.jwt_algorithm],
                        options={"verify_aud": False, "verify_iss": False},
                    )
                    tenant_id = payload.get("tenant_id", tenant_id)
                    agent_id = payload.get("agent_id", agent_id)
                except (JWTError, JWTKeyError):
                    pass  # In non-auth mode, invalid tokens are ignored

        # Sanitize tenant_id and agent_id against path traversal
        if not _SAFE_ID.match(tenant_id):
            return JSONResponse(
                status_code=400,
                content={"error": "Invalid tenant_id format"},
            )
        if not _SAFE_ID.match(agent_id):
            return JSONResponse(
                status_code=400,
                content={"error": "Invalid agent_id format"},
            )

        # Attach context to request state
        request.state.tenant_id = tenant_id
        request.state.agent_id = agent_id

        return await call_next(request)

    def _validate_api_key(self, key: str) -> bool:
        """Validate API key using constant-time comparison against stored hashes.

        Returns True only if the key matches a pre-configured API key.
        If no API keys are configured (SENTINEL_API_KEYS is empty),
        API key auth is disabled — only JWT auth works.
        """
        if not _API_KEY_HASHES:
            # No API keys configured — reject API key auth attempts
            return False

        if len(key) < 16:
            return False

        key_hash = hashlib.sha256(key.encode()).hexdigest()
        # Use hmac.compare_digest for constant-time comparison
        return any(hmac.compare_digest(key_hash, stored_hash) for stored_hash in _API_KEY_HASHES)
