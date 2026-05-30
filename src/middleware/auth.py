"""
Authentication middleware — validates JWT tokens or API keys.
"""
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from jose import jwt, JWTError
from src.config import settings

# Paths that don't require auth
PUBLIC_PATHS = {"/health", "/ready", "/docs", "/openapi.json"}


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip auth for health checks
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        # Extract tenant and auth
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
                    payload = jwt.decode(
                        token, settings.jwt_secret, algorithms=[settings.jwt_algorithm]
                    )
                    tenant_id = payload.get("tenant_id", tenant_id)
                    agent_id = payload.get("agent_id", agent_id)
                except JWTError:
                    # Not a JWT — treat as API key (validate against store)
                    if not self._validate_api_key(token):
                        return JSONResponse(
                            status_code=401,
                            content={"error": "Invalid token or API key"},
                        )

        # Attach context to request state
        request.state.tenant_id = tenant_id
        request.state.agent_id = agent_id

        return await call_next(request)

    def _validate_api_key(self, key: str) -> bool:
        """Validate API key against configured keys.

        TODO: Replace with Redis/DB lookup for production.
        """
        # For MVP: accept any non-empty key when api_keys_enabled
        # In production: check against a key store
        return len(key) >= 16
