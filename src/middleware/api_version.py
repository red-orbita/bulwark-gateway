"""
API Version Negotiation Middleware — Stripe-style date-based versioning.

Reads X-API-Version header, validates against supported versions,
and attaches version metadata to request.state for route handlers.

Adds response headers:
  - X-API-Version: echoes the resolved version
  - Deprecation: true (when using a deprecated version)
  - Sunset: <date> (retirement date for deprecated versions)
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

logger = structlog.get_logger()

# Date format: YYYY-MM-DD
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


@dataclass(frozen=True)
class APIVersion:
    """Represents a supported API version."""

    version: str  # Date string: "2025-01-01"
    label: str  # Human-friendly label
    deprecated: bool = False
    sunset_date: str | None = None  # ISO date when version will be retired


# Supported versions — ordered oldest to newest
SUPPORTED_VERSIONS: list[APIVersion] = [
    APIVersion(
        version="2025-01-01",
        label="v1 original",
        deprecated=False,
    ),
    APIVersion(
        version="2026-06-01",
        label="v2 with scan endpoint",
        deprecated=False,
    ),
]

# Quick lookups
_VERSION_MAP: dict[str, APIVersion] = {v.version: v for v in SUPPORTED_VERSIONS}
LATEST_VERSION: str = SUPPORTED_VERSIONS[-1].version


def get_version(version_str: str | None) -> APIVersion:
    """Resolve a version string to an APIVersion object.

    Returns the latest version if version_str is None or unrecognized.
    """
    if version_str and version_str in _VERSION_MAP:
        return _VERSION_MAP[version_str]
    return _VERSION_MAP[LATEST_VERSION]


class APIVersionMiddleware(BaseHTTPMiddleware):
    """Middleware that negotiates API version from request headers.

    Sets on request.state:
      - api_version: str (the resolved version date string)
      - api_version_info: APIVersion (full metadata)

    Adds response headers:
      - X-API-Version: resolved version
      - Deprecation: "true" (if version is deprecated)
      - Sunset: ISO date (if version has a sunset date)
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Read version from header
        requested_version = request.headers.get("X-API-Version")

        # Validate format if provided
        if requested_version and not _DATE_RE.match(requested_version):
            requested_version = None

        # Resolve to a supported version
        version_info = get_version(requested_version)

        # Attach to request state for downstream route handlers
        request.state.api_version = version_info.version
        request.state.api_version_info = version_info

        # Log version usage for analytics (fire-and-forget)
        tenant_id = getattr(request.state, "tenant_id", "unknown")
        await logger.adebug(
            "api_version_resolved",
            requested=requested_version,
            resolved=version_info.version,
            deprecated=version_info.deprecated,
            tenant=tenant_id,
            path=request.url.path,
        )

        # Process request
        response = await call_next(request)

        # Add version response headers
        response.headers["X-API-Version"] = version_info.version

        if version_info.deprecated:
            response.headers["Deprecation"] = "true"
            if version_info.sunset_date:
                response.headers["Sunset"] = version_info.sunset_date

        return response
