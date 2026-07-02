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
from typing import Set

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

# H-05 fix: Local revocation cache with short TTL to survive Redis outages.
# On Redis failure, previously-validated tokens get a 30s grace period to
# prevent full DoS on Redis outage while still maintaining security.
from cachetools import TTLCache
_revocation_cache: TTLCache = TTLCache(maxsize=4096, ttl=30.0)  # token_jti -> is_revoked
_REVOCATION_CACHE_MISS = object()  # sentinel for cache miss


def _is_token_revoked(jti: str) -> bool:
    """Check if a JWT ID is in the revocation set (Redis).

    H-05 fix: Uses a local cache with 30s TTL to mitigate Redis DoS.
    - On Redis success: cache the result (True/False) for 30s
    - On Redis failure: return cached value if available (stale grace period)
    - If no cached value AND Redis unavailable: fail-closed (reject)

    This prevents Redis being a single point of failure for availability
    while maintaining security guarantees:
    - Revoked tokens are blocked within 30s of revocation
    - New/unknown tokens are rejected if Redis is unavailable (fail-closed)
    - Known-good tokens get a 30s grace period during Redis outages
    """
    global _revocation_redis, _revocation_redis_init

    # Check local cache first
    cached = _revocation_cache.get(jti, _REVOCATION_CACHE_MISS)
    if cached is not _REVOCATION_CACHE_MISS:
        return cached

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
        is_revoked = bool(_revocation_redis.sismember("sentinel:revoked_tokens", jti))
        # Cache the result (both positive and negative)
        _revocation_cache[jti] = is_revoked
        return is_revoked
    except Exception:
        # H-05: On Redis error, fail-closed for unknown tokens
        # (no cached value = never validated before = reject)
        return True

# Paths that don't require auth (H-13: removed /health/stats, /health/telemetry)
# SECURITY (L-06 fix): Removed /internal/scanners/status — it exposes scanner
# configuration and enabled patterns which is sensitive info disclosure.
PUBLIC_PATHS = {"/health", "/ready", "/health/live", "/docs", "/openapi.json"}

# SECURITY FIX (CRIT-01): API keys are now bound to tenant_id.
# Format: "key:tenant_id" pairs in SENTINEL_API_KEYS.
# Keys without explicit tenant binding default to "default" tenant.
# This prevents cross-tenant impersonation via X-Tenant-ID header spoofing.
_API_KEY_BINDINGS: dict[str, str] = {}  # key_hash -> bound_tenant_id

# Tier 2 Multi-Tenancy: allowed tenants for this pod (empty = serve all)
_ALLOWED_TENANTS: Set[str] = set()


def _init_allowed_tenants() -> Set[str]:
    """Load allowed tenants from config (comma-separated list)."""
    raw = settings.allowed_tenants
    if not raw:
        return set()
    return {t.strip() for t in raw.split(",") if t.strip()}


def _init_api_keys() -> dict[str, str]:
    """Load API keys from config, store as SHA-256 hashes bound to tenant_ids.

    SECURITY FIX (CRIT-01): API keys are now bound to a specific tenant.
    Format options in SENTINEL_API_KEYS:
      - "key1:tenant1,key2:tenant2"   (explicit tenant binding)
      - "key1,key2"                    (backward-compat: binds to "default")

    Returns dict mapping key_hash -> bound_tenant_id.
    """
    bindings: dict[str, str] = {}
    if settings.api_keys:
        for entry in settings.api_keys.split(","):
            entry = entry.strip()
            if not entry:
                continue
            # Parse "key:tenant_id" or just "key" (defaults to "default")
            if ":" in entry:
                # Last colon separates key from tenant (keys may contain colons)
                last_colon = entry.rfind(":")
                key = entry[:last_colon]
                tenant = entry[last_colon + 1:]
                if not tenant:
                    tenant = "default"
            else:
                key = entry
                tenant = "default"
            if len(key) >= 16:
                bindings[hashlib.sha256(key.encode()).hexdigest()] = tenant
    return bindings


# Initialize on module load
_API_KEY_BINDINGS = _init_api_keys()
_ALLOWED_TENANTS = _init_allowed_tenants()


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
                    decode_options = {"require": ["exp", "jti"]}  # type: ignore[var-annotated]
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
                        options=decode_options,  # type: ignore[arg-type]
                        **decode_kwargs,  # type: ignore[arg-type]
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
                    # SECURITY FIX (PENTEST-DEEP CRIT-1): Require tenant_id in JWT.
                    # Without this, a JWT missing tenant_id falls back to the header,
                    # enabling cross-tenant impersonation.
                    if "tenant_id" not in payload:
                        return JSONResponse(
                            status_code=401,
                            content={"error": "JWT missing required tenant_id claim"},
                        )
                    tenant_id = payload["tenant_id"]
                    agent_id = payload.get("agent_id", agent_id)
                except JWTError:
                    # SECURITY (L-01 fix): JWT decode failed. Do NOT fall through
                    # to API key check — this creates a timing oracle that reveals
                    # whether a string is a malformed JWT vs an invalid API key.
                    # If it looks like a JWT (has 2 dots), reject immediately.
                    if token.count(".") == 2:
                        return JSONResponse(
                            status_code=401,
                            content={"error": "Invalid token or API key"},
                        )
                    # Otherwise, try as API key
                    # SECURITY FIX (CRIT-01): Use bound tenant from API key,
                    # ignoring X-Tenant-ID header to prevent impersonation.
                    bound_tenant = self._validate_api_key(token)
                    if bound_tenant is None:
                        return JSONResponse(
                            status_code=401,
                            content={"error": "Invalid token or API key"},
                        )
                    tenant_id = bound_tenant
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

        # Tier 2 Multi-Tenancy: Enforce tenant isolation on dedicated pods.
        # If SENTINEL_ALLOWED_TENANTS is set, only those tenants are served.
        # Requests for other tenants are rejected (they should go to their own pods).
        if _ALLOWED_TENANTS and tenant_id not in _ALLOWED_TENANTS:
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Tenant not served by this endpoint",
                    "detail": f"Tenant '{tenant_id}' is not assigned to this proxy instance.",
                },
            )

        # Attach context to request state
        request.state.tenant_id = tenant_id
        request.state.agent_id = agent_id

        return await call_next(request)

    def _validate_api_key(self, key: str) -> str | None:
        """Validate API key and return its bound tenant_id.

        SECURITY FIX (CRIT-01): Returns the tenant_id that this API key is
        bound to, or None if the key is invalid. The caller MUST use the
        returned tenant_id (ignoring X-Tenant-ID header) to prevent
        cross-tenant impersonation.

        Returns:
            Bound tenant_id if key is valid, None otherwise.
        """
        if not _API_KEY_BINDINGS:
            # No API keys configured — reject API key auth attempts
            return None

        if len(key) < 16:
            return None

        key_hash = hashlib.sha256(key.encode()).hexdigest()
        # Use constant-time comparison against each stored hash
        for stored_hash, bound_tenant in _API_KEY_BINDINGS.items():
            if hmac.compare_digest(key_hash, stored_hash):
                return bound_tenant
        return None
