"""
Rate limiting middleware — per-tenant request throttling.
"""
import time
from collections import defaultdict
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from src.config import settings


class TokenBucket:
    """Simple in-memory token bucket for rate limiting."""

    def __init__(self, rate: float, burst: int):
        self.rate = rate  # tokens per second
        self.burst = burst
        self.tokens: dict[str, float] = defaultdict(lambda: float(burst))
        self.last_time: dict[str, float] = defaultdict(time.time)

    def consume(self, key: str) -> bool:
        now = time.time()
        elapsed = now - self.last_time[key]
        self.last_time[key] = now

        # Refill tokens
        self.tokens[key] = min(
            self.burst, self.tokens[key] + elapsed * self.rate
        )

        if self.tokens[key] >= 1.0:
            self.tokens[key] -= 1.0
            return True
        return False


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        # Convert RPM to tokens/second
        rate = settings.rate_limit_rpm / 60.0
        self.bucket = TokenBucket(rate=rate, burst=settings.rate_limit_rpm_burst)

    async def dispatch(self, request: Request, call_next):
        if not settings.rate_limit_enabled:
            return await call_next(request)

        # Skip health checks
        if request.url.path in ("/health", "/ready"):
            return await call_next(request)

        # Rate limit by tenant
        tenant_id = request.headers.get("X-Tenant-ID", "default")
        if not self.bucket.consume(tenant_id):
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "detail": f"Max {settings.rate_limit_rpm} requests/minute",
                },
            )

        return await call_next(request)
