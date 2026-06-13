"""
Per-tenant resource quota enforcement middleware.

Prevents "noisy neighbor" problems in multi-tenancy by enforcing:
  1. max_concurrent_requests — asyncio.Semaphore per tenant (per-process)
  2. max_tokens_per_day — Daily token budget tracked in Redis
  3. max_request_size_bytes — Maximum request payload size
  4. allowed_models — Model access control per tenant
  5. priority_weight — Stored in request state for future fair-queuing

Placement: AFTER AuthMiddleware (needs tenant_id), BEFORE guardrail pipeline.
Degrades gracefully: falls back to in-memory if Redis unavailable.
"""

import asyncio
import json
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

import redis
import structlog
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from src.config import settings

logger = structlog.get_logger()


class TenantQuotaConfig:
    """Quota configuration for a single tenant."""

    __slots__ = (
        "max_concurrent_requests",
        "max_tokens_per_day",
        "max_request_size_bytes",
        "allowed_models",
        "priority_weight",
        "rate_limit_rpm",
    )

    def __init__(
        self,
        max_concurrent_requests: int = 0,
        max_tokens_per_day: int = 0,
        max_request_size_bytes: int = 0,
        allowed_models: list[str] | None = None,
        priority_weight: float = 1.0,
        rate_limit_rpm: int = 0,
    ):
        self.max_concurrent_requests = max_concurrent_requests  # 0 = unlimited
        self.max_tokens_per_day = max_tokens_per_day  # 0 = unlimited
        self.max_request_size_bytes = max_request_size_bytes  # 0 = unlimited
        self.allowed_models = allowed_models  # None = all models allowed
        self.priority_weight = priority_weight
        self.rate_limit_rpm = rate_limit_rpm  # 0 = use global default


# Global quota registry: tenant_id → TenantQuotaConfig
_tenant_quotas: dict[str, TenantQuotaConfig] = {}


def register_tenant_quotas(tenant_id: str, config: TenantQuotaConfig) -> None:
    """Register quota configuration for a tenant (called by AgentRegistry on load)."""
    _tenant_quotas[tenant_id] = config


def get_tenant_quota(tenant_id: str) -> TenantQuotaConfig | None:
    """Get quota config for a tenant. Returns None if no quotas configured."""
    return _tenant_quotas.get(tenant_id)


def clear_tenant_quotas() -> None:
    """Clear all registered quotas (used during reload)."""
    _tenant_quotas.clear()


def _utc_day_end() -> datetime:
    """Get the end of the current UTC day (midnight next day)."""
    now = datetime.now(timezone.utc)
    tomorrow = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    return tomorrow


def _ttl_until_day_end() -> int:
    """Seconds remaining until end of current UTC day."""
    now = datetime.now(timezone.utc)
    end = _utc_day_end()
    return max(1, int((end - now).total_seconds()))


class TokenBudgetTracker:
    """Tracks daily token usage per tenant.

    Uses Redis for distributed tracking across replicas.
    Falls back to in-memory dict if Redis is unavailable.
    """

    def __init__(self, redis_url: Optional[str] = None):
        self._redis: Optional[redis.Redis] = None
        self._fallback: dict[str, int] = {}  # tenant_id → tokens_used_today
        self._fallback_day: str = ""  # YYYY-MM-DD for fallback reset
        self._using_fallback = False

        if redis_url:
            try:
                kwargs = {"decode_responses": True, "socket_timeout": 0.5}
                if redis_url.startswith("rediss://") and settings.redis_tls_insecure:
                    import ssl
                    kwargs["ssl_cert_reqs"] = ssl.CERT_NONE
                self._redis = redis.from_url(redis_url, **kwargs)
                self._redis.ping()
            except Exception:
                self._redis = None
                self._using_fallback = True

        if not self._redis:
            self._using_fallback = True
            import logging
            logging.getLogger(__name__).warning(
                "Token budget tracker using in-memory fallback (no Redis). "
                "Counters are per-process and will reset on restart."
            )

    def _redis_key(self, tenant_id: str) -> str:
        """Redis key for tenant's daily token counter."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return f"sentinel:quota:tokens:{tenant_id}:{today}"

    def _ensure_fallback_day(self) -> None:
        """Reset in-memory fallback at day boundary."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if today != self._fallback_day:
            self._fallback.clear()
            self._fallback_day = today

    def get_used(self, tenant_id: str) -> int:
        """Get tokens used today for a tenant."""
        if self._redis:
            try:
                val = self._redis.get(self._redis_key(tenant_id))
                return int(val) if val else 0
            except Exception:
                pass

        # Fallback
        self._ensure_fallback_day()
        return self._fallback.get(tenant_id, 0)

    def increment(self, tenant_id: str, tokens: int) -> int:
        """Atomically increment token usage. Returns new total."""
        if self._redis:
            try:
                key = self._redis_key(tenant_id)
                pipe = self._redis.pipeline()
                pipe.incrby(key, tokens)
                pipe.expire(key, _ttl_until_day_end())
                results = pipe.execute()
                return int(results[0])
            except Exception:
                pass

        # Fallback
        self._ensure_fallback_day()
        current = self._fallback.get(tenant_id, 0)
        new_total = current + tokens
        self._fallback[tenant_id] = new_total
        return new_total

    def get_remaining(self, tenant_id: str, budget: int) -> int:
        """Get remaining token budget for tenant."""
        used = self.get_used(tenant_id)
        return max(0, budget - used)


class QuotaMiddleware(BaseHTTPMiddleware):
    """Per-tenant resource quota enforcement.

    Enforces concurrency limits, token budgets, request size limits,
    and model access control. Degrades gracefully without Redis.
    """

    def __init__(self, app):
        super().__init__(app)
        self._semaphores: dict[str, asyncio.Semaphore] = {}
        self._token_tracker = TokenBudgetTracker(
            redis_url=getattr(settings, "redis_url", None)
        )
        self._concurrent_counts: dict[str, int] = {}  # tenant → active requests

    def _get_semaphore(self, tenant_id: str, limit: int) -> asyncio.Semaphore:
        """Get or create per-tenant concurrency semaphore."""
        if tenant_id not in self._semaphores:
            self._semaphores[tenant_id] = asyncio.Semaphore(limit)
            self._concurrent_counts[tenant_id] = 0
        return self._semaphores[tenant_id]

    def _concurrent_remaining(self, tenant_id: str, limit: int) -> int:
        """Calculate remaining concurrent request slots."""
        used = self._concurrent_counts.get(tenant_id, 0)
        return max(0, limit - used)

    async def dispatch(self, request: Request, call_next):
        # Skip non-API paths (health checks, admin)
        path = request.url.path
        if path in ("/health", "/health/live", "/health/stats", "/ready"):
            return await call_next(request)
        if path.startswith("/admin"):
            return await call_next(request)

        # Get tenant from auth state (set by AuthMiddleware)
        tenant_id = getattr(request.state, "tenant_id", None)
        if not tenant_id:
            # No tenant = no quotas to enforce (auth will reject if needed)
            return await call_next(request)

        quota = get_tenant_quota(tenant_id)
        if not quota:
            # No quotas configured for this tenant = unlimited (backward compatible)
            return await call_next(request)

        # Store priority_weight in request state for future fair-queuing
        request.state.priority_weight = quota.priority_weight

        # --- Check 1: Request size limit ---
        if quota.max_request_size_bytes > 0:
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > quota.max_request_size_bytes:
                return JSONResponse(
                    status_code=413,
                    content={
                        "error": {
                            "message": "Request payload too large",
                            "type": "quota_exceeded",
                            "code": "payload_too_large",
                            "detail": (
                                f"Max request size: {quota.max_request_size_bytes} bytes. "
                                f"Received: {content_length} bytes."
                            ),
                        }
                    },
                )

        # --- Check 2: Allowed models ---
        if quota.allowed_models is not None and path.startswith("/v"):
            try:
                body = await request.body()
                if body:
                    payload = json.loads(body)
                    requested_model = payload.get("model", "")
                    if requested_model and requested_model not in quota.allowed_models:
                        return JSONResponse(
                            status_code=403,
                            content={
                                "error": {
                                    "message": f"Model '{requested_model}' not authorized for this tenant",
                                    "type": "quota_exceeded",
                                    "code": "model_not_allowed",
                                    "detail": (
                                        f"Allowed models: {quota.allowed_models}"
                                    ),
                                }
                            },
                        )
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass  # Non-JSON body or read error; let downstream handle

        # --- Check 3: Token budget (pre-flight check) ---
        if quota.max_tokens_per_day > 0:
            remaining_tokens = self._token_tracker.get_remaining(
                tenant_id, quota.max_tokens_per_day
            )
            if remaining_tokens <= 0:
                reset_time = _utc_day_end().isoformat().replace("+00:00", "Z")
                return JSONResponse(
                    status_code=429,
                    headers={
                        "Retry-After": str(_ttl_until_day_end()),
                        "X-Quota-Token-Budget-Remaining": "0",
                        "X-Quota-Token-Budget-Reset": reset_time,
                    },
                    content={
                        "error": {
                            "message": "Daily token budget exhausted",
                            "type": "quota_exceeded",
                            "code": "token_budget_exhausted",
                            "detail": (
                                f"Daily limit: {quota.max_tokens_per_day} tokens. "
                                f"Resets at: {reset_time}"
                            ),
                        }
                    },
                )

        # --- Check 4: Concurrent request limit ---
        semaphore: asyncio.Semaphore | None = None
        if quota.max_concurrent_requests > 0:
            semaphore = self._get_semaphore(tenant_id, quota.max_concurrent_requests)
            # Non-blocking acquire attempt
            acquired = semaphore._value > 0  # noqa: SLF001 — check without blocking
            if not acquired:
                concurrent_remaining = self._concurrent_remaining(
                    tenant_id, quota.max_concurrent_requests
                )
                return JSONResponse(
                    status_code=429,
                    headers={
                        "Retry-After": "1",
                        "X-Quota-Concurrent-Remaining": str(concurrent_remaining),
                    },
                    content={
                        "error": {
                            "message": "Too many concurrent requests for this tenant",
                            "type": "quota_exceeded",
                            "code": "concurrent_limit_exceeded",
                            "detail": (
                                f"Max concurrent requests: {quota.max_concurrent_requests}. "
                                "Retry after current requests complete."
                            ),
                        }
                    },
                )

            # Acquire the semaphore
            await semaphore.acquire()
            self._concurrent_counts[tenant_id] = (
                self._concurrent_counts.get(tenant_id, 0) + 1
            )

        try:
            # Forward request
            response = await call_next(request)

            # --- Post-response: Track token usage ---
            response = await self._track_token_usage(
                response, tenant_id, quota
            )

            # --- Add quota headers to response ---
            response = self._add_quota_headers(response, tenant_id, quota)

            return response

        finally:
            # Release concurrency semaphore
            if semaphore is not None:
                semaphore.release()
                self._concurrent_counts[tenant_id] = max(
                    0, self._concurrent_counts.get(tenant_id, 0) - 1
                )

    async def _track_token_usage(
        self, response: Response, tenant_id: str, quota: TenantQuotaConfig
    ) -> Response:
        """Extract token usage from LLM response and update budget counter.

        Parses the `usage.total_tokens` field from OpenAI-compatible responses.
        Updates Redis counter atomically via INCRBY.
        """
        if quota.max_tokens_per_day <= 0:
            return response

        # Only track on successful responses with JSON body
        if response.status_code != 200:
            return response

        content_type = response.headers.get("content-type", "")
        if "application/json" not in content_type:
            return response

        # Read response body to extract token usage
        # Note: For streaming responses, token tracking happens at stream end
        try:
            body_chunks = []
            async for chunk in response.body_iterator:
                if isinstance(chunk, bytes):
                    body_chunks.append(chunk)
                else:
                    body_chunks.append(chunk.encode("utf-8"))

            body_bytes = b"".join(body_chunks)
            body_data = json.loads(body_bytes)

            # Extract token usage from OpenAI-compatible response
            usage = body_data.get("usage", {})
            total_tokens = usage.get("total_tokens", 0)

            if total_tokens > 0:
                new_total = self._token_tracker.increment(tenant_id, total_tokens)
                remaining = max(0, quota.max_tokens_per_day - new_total)

                # Rebuild response with updated headers
                headers = dict(response.headers)
                headers["X-Quota-Token-Budget-Remaining"] = str(remaining)
                headers["X-Quota-Token-Budget-Reset"] = (
                    _utc_day_end().isoformat().replace("+00:00", "Z")
                )

                return Response(
                    content=body_bytes,
                    status_code=response.status_code,
                    headers=headers,
                    media_type=response.media_type,
                )

            # No usage data — return response with body reconstructed
            return Response(
                content=body_bytes,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.media_type,
            )

        except (json.JSONDecodeError, StopAsyncIteration, Exception):
            # If we can't parse the response, don't block it
            # Body may already be consumed; return what we have
            if body_chunks:
                return Response(
                    content=b"".join(body_chunks),
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=response.media_type,
                )
            return response

    def _add_quota_headers(
        self, response: Response, tenant_id: str, quota: TenantQuotaConfig
    ) -> Response:
        """Add quota information headers to response."""
        # Concurrent remaining
        if quota.max_concurrent_requests > 0:
            remaining = self._concurrent_remaining(
                tenant_id, quota.max_concurrent_requests
            )
            response.headers["X-Quota-Concurrent-Remaining"] = str(remaining)

        # Token budget remaining (if not already set by _track_token_usage)
        if quota.max_tokens_per_day > 0:
            if "X-Quota-Token-Budget-Remaining" not in response.headers:
                remaining_tokens = self._token_tracker.get_remaining(
                    tenant_id, quota.max_tokens_per_day
                )
                response.headers["X-Quota-Token-Budget-Remaining"] = str(
                    remaining_tokens
                )
                response.headers["X-Quota-Token-Budget-Reset"] = (
                    _utc_day_end().isoformat().replace("+00:00", "Z")
                )

        return response
