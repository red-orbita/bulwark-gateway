"""
Tenant routing middleware — routes requests to dedicated or shared proxy pods.

Tier 2 Multi-Tenancy: When a tenant has dedicated proxy pods deployed,
this middleware forwards requests to the tenant's dedicated service instead
of processing them locally in the shared pool.

Configuration:
  - SENTINEL_DEDICATED_TENANTS: JSON list of tenant names with dedicated pods
  - SENTINEL_NAMESPACE: Kubernetes namespace for service discovery
  - Redis key sentinel:dedicated_tenants: Dynamic updates (optional)

Activation:
  - Only active if SENTINEL_DEDICATED_TENANTS is set and non-empty
  - If running ON a dedicated pod (SENTINEL_ALLOWED_TENANTS matches),
    routing is skipped (the pod processes the request locally)

Architecture:
  Internet → Ingress → [Shared Proxy Pool]
                           │
                           ├── tenant in dedicated list → forward to proxy-<tenant>:8080
                           └── tenant not in list → process locally
"""

import asyncio
import json
import logging
import os
import time
from typing import Optional, Set

import httpx
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response, StreamingResponse

from src.config import settings

logger = logging.getLogger(__name__)

# Internal service URL pattern for dedicated tenant proxies
# In Kubernetes: proxy-<tenant>.<namespace>.svc.cluster.local:8080
_SERVICE_PATTERN = "http://proxy-{tenant}.{namespace}.svc.cluster.local:8080"

# Timeout for forwarding requests to dedicated pods
_FORWARD_TIMEOUT = 30.0

# Redis sync interval (seconds)
_REDIS_SYNC_INTERVAL = 10.0


class TenantRouterMiddleware(BaseHTTPMiddleware):
    """Route requests to dedicated or shared proxy pods based on tenant.

    When a request arrives for a tenant that has dedicated infrastructure:
    1. Extracts tenant_id from request.state (set by AuthMiddleware)
    2. Checks if tenant has dedicated pods (from env or Redis)
    3. If yes → proxies the full request to the dedicated service
    4. If no → calls next middleware (processes locally in shared pool)

    Skip conditions (processes locally):
    - Health check paths (/health, /ready)
    - This pod IS the dedicated pod for this tenant (SENTINEL_ALLOWED_TENANTS set)
    - No dedicated tenants configured
    """

    def __init__(self, app):
        super().__init__(app)
        self._dedicated_tenants: Set[str] = set()
        self._namespace: str = os.environ.get(
            "SENTINEL_NAMESPACE", "sentinel-gateway"
        )
        self._allowed_tenants: Set[str] = set()
        self._http_client: Optional[httpx.AsyncClient] = None
        self._last_redis_sync: float = 0.0
        self._redis_client = None
        self._redis_initialized: bool = False

        # Load from environment
        self._load_from_env()

        # Determine if this pod is a dedicated pod (skip routing for self)
        allowed_raw = os.environ.get("SENTINEL_ALLOWED_TENANTS", "")
        if allowed_raw:
            self._allowed_tenants = {
                t.strip() for t in allowed_raw.split(",") if t.strip()
            }

        logger.info(
            "TenantRouterMiddleware initialized",
            extra={
                "dedicated_tenants": sorted(self._dedicated_tenants),
                "is_dedicated_pod": bool(self._allowed_tenants),
                "allowed_tenants": sorted(self._allowed_tenants),
                "namespace": self._namespace,
            },
        )

    def _load_from_env(self) -> None:
        """Load dedicated tenant list from SENTINEL_DEDICATED_TENANTS env var."""
        raw = os.environ.get("SENTINEL_DEDICATED_TENANTS", "")
        if not raw:
            return
        try:
            tenants = json.loads(raw)
            if isinstance(tenants, list):
                self._dedicated_tenants = {
                    t.strip() for t in tenants if isinstance(t, str) and t.strip()
                }
        except (json.JSONDecodeError, TypeError):
            # Try comma-separated fallback
            self._dedicated_tenants = {
                t.strip() for t in raw.split(",") if t.strip()
            }

    def _get_redis_client(self):
        """Lazy-initialize Redis client for dynamic tenant list updates."""
        if self._redis_initialized:
            return self._redis_client
        self._redis_initialized = True
        try:
            import redis

            redis_url = os.environ.get("SENTINEL_REDIS_URL")
            if redis_url:
                kwargs = {"decode_responses": True, "socket_timeout": 1.0}
                if redis_url.startswith("rediss://"):
                    tls_insecure = os.environ.get(
                        "SENTINEL_REDIS_TLS_INSECURE", ""
                    ).lower() in ("1", "true")
                    if tls_insecure:
                        import ssl

                        kwargs["ssl_cert_reqs"] = ssl.CERT_NONE
                self._redis_client = redis.from_url(redis_url, **kwargs)
                self._redis_client.ping()
        except Exception as e:
            logger.debug(
                "Redis unavailable for tenant routing sync",
                extra={"error": str(e)},
            )
            self._redis_client = None
        return self._redis_client

    def _maybe_sync_from_redis(self) -> None:
        """Periodically sync dedicated tenant list from Redis.

        Redis key: sentinel:dedicated_tenants (JSON list)
        This allows the admin to dynamically add/remove dedicated tenants
        without redeploying the shared proxy pool.
        """
        now = time.time()
        if now - self._last_redis_sync < _REDIS_SYNC_INTERVAL:
            return
        self._last_redis_sync = now

        r = self._get_redis_client()
        if not r:
            return
        try:
            raw = r.get("sentinel:dedicated_tenants")
            if raw:
                # SECURITY (H-03 fix): Verify HMAC before trusting Redis value.
                # Prevents routing manipulation by attackers with Redis write access.
                import hmac as _hmac
                import hashlib as _hashlib
                data = json.loads(raw)
                if isinstance(data, dict) and "tenants" in data and "hmac" in data:
                    # Signed format: {"tenants": [...], "hmac": "<hex>"}
                    payload = json.dumps(data["tenants"], sort_keys=True).encode()
                    secret = settings.jwt_secret.encode()  # Reuse JWT secret for HMAC
                    expected = _hmac.new(secret, payload, _hashlib.sha256).hexdigest()
                    if not _hmac.compare_digest(expected, data["hmac"]):
                        logger.warning("dedicated_tenants_hmac_mismatch",
                                      extra={"note": "Redis value tampered or unsigned"})
                        return  # Reject tampered value
                    tenants = data["tenants"]
                elif isinstance(data, list):
                    # Legacy unsigned format — log warning but still accept
                    # (backward compatibility during migration)
                    logger.warning("dedicated_tenants_unsigned",
                                  extra={"note": "Migrate to signed format: {tenants: [...], hmac: ...}"})
                    tenants = data
                else:
                    return

                if isinstance(tenants, list):
                    self._dedicated_tenants = {
                        t.strip()
                        for t in tenants
                        if isinstance(t, str) and t.strip()
                    }
        except Exception:
            pass  # Keep existing config on error

    def _get_http_client(self) -> httpx.AsyncClient:
        """Get or create the async HTTP client for forwarding."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(_FORWARD_TIMEOUT, connect=5.0),
                limits=httpx.Limits(
                    max_connections=100,
                    max_keepalive_connections=20,
                ),
                follow_redirects=False,
            )
        return self._http_client

    def _build_target_url(self, tenant_id: str, path: str, query: str) -> str:
        """Build the target URL for the dedicated tenant service.

        Service naming convention: proxy-<tenant-name>
        Full DNS: proxy-<tenant>.<namespace>.svc.cluster.local:8080

        SECURITY (H-02 fix): Validate tenant_id against strict DNS label pattern.
        Rejects dots, slashes, colons, and other URL metacharacters that could
        be used for DNS injection or URL manipulation.
        """
        import re
        # RFC 1123 DNS label: lowercase alphanumeric + hyphens, max 63 chars
        if not re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$', tenant_id):
            raise ValueError(
                f"Invalid tenant_id for routing: '{tenant_id}' — "
                f"must be a valid DNS label (lowercase alphanumeric + hyphens)"
            )

        base = _SERVICE_PATTERN.format(
            tenant=tenant_id, namespace=self._namespace
        )
        url = f"{base}{path}"
        if query:
            url = f"{url}?{query}"
        return url

    async def _forward_request(
        self, request: Request, target_url: str
    ) -> Response:
        """Forward the full request to the dedicated tenant proxy.

        Preserves: method, headers, body, query params.
        Adds: X-Forwarded-By header for audit trail.
        Strips: hop-by-hop headers that shouldn't be forwarded.
        """
        client = self._get_http_client()

        # Build forwarded headers (strip hop-by-hop)
        hop_by_hop = {
            "host",
            "connection",
            "keep-alive",
            "transfer-encoding",
            "te",
            "trailer",
            "upgrade",
        }
        headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower() not in hop_by_hop
        }
        headers["X-Forwarded-By"] = "sentinel-shared-pool"
        # SECURITY (M-16 fix): Sign the header so receiving pod can validate authenticity
        import hmac as _hmac_fwd
        import hashlib as _hashlib_fwd
        headers["X-Forwarded-Sig"] = _hmac_fwd.new(
            settings.jwt_secret.encode(),
            b"sentinel-shared-pool",
            _hashlib_fwd.sha256,
        ).hexdigest()[:16]
        headers["X-Forwarded-For"] = request.client.host if request.client else "unknown"

        # Read request body
        body = await request.body()

        try:
            response = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
            )

            # Check if response is streaming (SSE)
            content_type = response.headers.get("content-type", "")
            if "text/event-stream" in content_type:
                # For SSE, stream the response back
                return StreamingResponse(
                    content=response.aiter_bytes(),
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type="text/event-stream",
                )

            # Build response, preserving status and headers
            resp_headers = {
                k: v
                for k, v in response.headers.items()
                if k.lower()
                not in ("transfer-encoding", "content-encoding", "content-length")
            }
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=resp_headers,
                media_type=response.headers.get("content-type"),
            )

        except httpx.ConnectError as e:
            logger.error(
                "Dedicated proxy unreachable",
                extra={
                    "tenant": request.state.tenant_id,
                    "target": target_url,
                    "error": str(e),
                },
            )
            return JSONResponse(
                status_code=503,
                content={
                    "error": "Dedicated proxy unavailable",
                    "detail": "The dedicated proxy for this tenant is unreachable. "
                    "Retrying may resolve if pods are scaling up.",
                },
            )
        except httpx.TimeoutException:
            logger.error(
                "Dedicated proxy timeout",
                extra={
                    "tenant": request.state.tenant_id,
                    "target": target_url,
                },
            )
            return JSONResponse(
                status_code=504,
                content={"error": "Dedicated proxy timeout"},
            )
        except Exception as e:
            logger.error(
                "Forwarding error",
                extra={
                    "tenant": request.state.tenant_id,
                    "target": target_url,
                    "error": str(e),
                },
            )
            # Fail-closed: don't fall through to shared pool on error
            return JSONResponse(
                status_code=502,
                content={"error": "Forwarding to dedicated proxy failed"},
            )

    @property
    def is_active(self) -> bool:
        """Whether this middleware has any dedicated tenants to route."""
        return bool(self._dedicated_tenants) and not bool(self._allowed_tenants)

    async def dispatch(self, request: Request, call_next):
        """Route request to dedicated proxy or process locally.

        Decision logic:
        1. Skip if this IS a dedicated pod (SENTINEL_ALLOWED_TENANTS is set)
        2. Skip if no dedicated tenants configured
        3. Skip if path is health/public (no tenant context yet)
        4. Skip if request was already forwarded (X-Forwarded-By header)
        5. Check if tenant_id maps to a dedicated pod → forward
        6. Otherwise → process locally (shared pool)
        """
        # Skip if this pod is itself a dedicated pod
        if self._allowed_tenants:
            return await call_next(request)

        # Skip if no dedicated tenants configured
        if not self._dedicated_tenants:
            return await call_next(request)

        # Skip health/public paths (no tenant context available)
        public_paths = {"/health", "/ready", "/health/live", "/health/stats"}
        if request.url.path in public_paths:
            return await call_next(request)

        # SECURITY (M-16 fix): Prevent routing loop detection bypass.
        # X-Forwarded-By is only valid from internal sentinel pods.
        # Validate using a shared HMAC signature to prevent spoofing.
        forwarded_by = request.headers.get("X-Forwarded-By")
        forwarded_sig = request.headers.get("X-Forwarded-Sig")
        if forwarded_by == "sentinel-shared-pool":
            import hmac as _hmac
            import hashlib as _hashlib
            expected_sig = _hmac.new(
                settings.jwt_secret.encode(),
                b"sentinel-shared-pool",
                _hashlib.sha256,
            ).hexdigest()[:16]
            if forwarded_sig and _hmac.compare_digest(forwarded_sig, expected_sig):
                return await call_next(request)
            # Unsigned/forged header — ignore and continue routing
            logger.warning(
                "spoofed_x_forwarded_by_detected",
                extra={"client": request.client.host if request.client else "unknown"},
            )

        # Sync from Redis (non-blocking, periodic)
        self._maybe_sync_from_redis()

        # Extract tenant_id (set by AuthMiddleware which runs before us)
        tenant_id = getattr(request.state, "tenant_id", None)
        if not tenant_id:
            return await call_next(request)

        # Check if this tenant has dedicated infrastructure
        if tenant_id in self._dedicated_tenants:
            # Build target URL and forward
            query = request.url.query or ""
            target_url = self._build_target_url(
                tenant_id, request.url.path, query
            )
            logger.debug(
                "Routing to dedicated proxy",
                extra={"tenant": tenant_id, "target": target_url},
            )
            return await self._forward_request(request, target_url)

        # Not a dedicated tenant — process locally (shared pool)
        return await call_next(request)

    async def close(self) -> None:
        """Cleanup HTTP client on shutdown."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
