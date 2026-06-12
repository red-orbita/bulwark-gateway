"""
Rate limiting middleware — per-tenant request throttling with Redis backend.

Uses Redis sliding window counter for distributed rate limiting across replicas.
Falls back to in-memory token bucket if Redis is unavailable.
Supports per-tenant rate limit overrides from admin (Redis-synced).
"""

import json
import time

from typing import Optional

import redis
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from src.config import settings


class RedisRateLimiter:
    """Distributed sliding window rate limiter using Redis."""

    def __init__(self, rate_rpm: int, redis_url: Optional[str] = None):
        self.rate_rpm = rate_rpm
        self._redis: Optional[redis.Redis] = None
        if redis_url:
            try:
                kwargs = {"decode_responses": True, "socket_timeout": 0.5}
                # Support TLS connections (rediss:// scheme) with optional cert skip
                if redis_url.startswith("rediss://") and settings.redis_tls_insecure:
                    import ssl
                    kwargs["ssl_cert_reqs"] = ssl.CERT_NONE
                self._redis = redis.from_url(redis_url, **kwargs)
                self._redis.ping()
            except Exception:
                self._redis = None

    @property
    def available(self) -> bool:
        return self._redis is not None

    def consume(self, key: str, limit: int | None = None) -> bool:
        """Check rate limit using Redis sliding window. Returns True if allowed.

        Args:
            key: Rate limit key (e.g., "ip:1.2.3.4" or "tenant:acme-corp")
            limit: Per-key limit override (RPM). Defaults to self.rate_rpm.
        """
        if not self._redis:
            return True  # Fallback handled by caller

        effective_limit = limit if limit is not None else self.rate_rpm
        redis_key = f"sentinel:ratelimit:{key}"
        now = time.time()
        window_start = now - 60.0  # 1-minute sliding window

        try:
            pipe = self._redis.pipeline()
            # Remove expired entries
            pipe.zremrangebyscore(redis_key, 0, window_start)
            # Count current window
            pipe.zcard(redis_key)
            # Add current request
            pipe.zadd(redis_key, {f"{now}": now})
            # Set TTL to auto-cleanup
            pipe.expire(redis_key, 120)
            results = pipe.execute()

            count = results[1]  # zcard result
            return count < effective_limit
        except Exception:
            return False  # Fail-CLOSED on Redis error (C-05)


class InMemoryTokenBucket:
    """Fallback in-memory token bucket for single-instance deployments.

    Uses TTLCache to auto-evict inactive keys, preventing unbounded memory growth.
    """

    def __init__(self, rate: float, burst: int, max_keys: int = 10000, ttl: int = 300):
        self.rate = rate
        self.burst = burst
        from cachetools import TTLCache
        self.tokens: TTLCache = TTLCache(maxsize=max_keys, ttl=ttl)
        self.last_time: TTLCache = TTLCache(maxsize=max_keys, ttl=ttl)

    def consume(self, key: str) -> bool:
        now = time.time()
        last = self.last_time.get(key, now)
        elapsed = now - last
        self.last_time[key] = now
        current = self.tokens.get(key, float(self.burst))
        current = min(self.burst, current + elapsed * self.rate)
        if current >= 1.0:
            self.tokens[key] = current - 1.0
            return True
        self.tokens[key] = current
        return False


# Per-tenant rate limit config (synced from Redis)
_RATE_LIMIT_CONFIG_KEY = "sentinel:rate_limits:config"
_tenant_limits: dict[str, int] = {}  # tenant_id → RPM override
_tenant_limits_version: int = 0


def _load_tenant_limits(r: Optional[redis.Redis]) -> None:
    """Load per-tenant rate limit overrides from Redis."""
    global _tenant_limits, _tenant_limits_version
    if not r:
        return
    try:
        ver = r.get("sentinel:rate_limits:version")
        if ver and int(ver) > _tenant_limits_version:
            raw = r.get(_RATE_LIMIT_CONFIG_KEY)
            if raw:
                _tenant_limits = json.loads(raw)
                _tenant_limits_version = int(ver)
    except Exception:
        pass


def get_tenant_rpm(tenant_id: str) -> int | None:
    """Get per-tenant RPM override, or None for global default."""
    return _tenant_limits.get(tenant_id)


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        rate = settings.rate_limit_rpm / 60.0
        self._redis_limiter = RedisRateLimiter(
            rate_rpm=settings.rate_limit_rpm,
            redis_url=getattr(settings, "redis_url", None),
        )
        self._fallback = InMemoryTokenBucket(rate=rate, burst=settings.rate_limit_rpm_burst)
        self._last_config_check: float = 0.0

    def _maybe_reload_config(self) -> None:
        """Reload per-tenant config from Redis every 5 seconds."""
        now = time.time()
        if now - self._last_config_check < 5.0:
            return
        self._last_config_check = now
        if self._redis_limiter._redis:
            _load_tenant_limits(self._redis_limiter._redis)

    async def dispatch(self, request: Request, call_next):
        if not settings.rate_limit_enabled:
            return await call_next(request)

        # Skip health checks
        if request.url.path in ("/health", "/health/live", "/ready"):
            return await call_next(request)

        # Reload per-tenant config periodically
        self._maybe_reload_config()

        # Red team mode flag (informational only — does NOT bypass rate limiting)
        request.state.redteam_mode = request.headers.get("X-Redteam-Mode") == "true"

        # C-02: Rate limit by authenticated tenant_id (from request.state, set by AuthMiddleware)
        # Falls back to source IP if not authenticated yet (global per-IP limit)
        tenant_id = getattr(request.state, "tenant_id", None)
        source_ip = request.client.host if request.client else "unknown"

        # Per-IP global rate limit (first layer — prevents header spoofing bypass)
        ip_key = f"ip:{source_ip}"
        if self._redis_limiter.available:
            ip_allowed = self._redis_limiter.consume(ip_key)
        else:
            ip_allowed = self._fallback.consume(ip_key)

        if not ip_allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "detail": f"Max {settings.rate_limit_rpm} requests/minute per IP",
                },
            )

        # Per-tenant rate limit (second layer — uses authenticated identity)
        if tenant_id:
            tenant_key = f"tenant:{tenant_id}"
            tenant_rpm = get_tenant_rpm(tenant_id)
            effective_rpm = tenant_rpm if tenant_rpm is not None else settings.rate_limit_rpm

            if self._redis_limiter.available:
                allowed = self._redis_limiter.consume(tenant_key, limit=effective_rpm)
            else:
                allowed = self._fallback.consume(tenant_key)

            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "Rate limit exceeded",
                        "detail": f"Max {effective_rpm} requests/minute",
                    },
                )

        return await call_next(request)
