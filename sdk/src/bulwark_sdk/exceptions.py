"""
Custom exceptions for the Bulwark Gateway SDK.

All SDK-specific errors inherit from BulwarkError, making it easy
to catch any Bulwark-related exception with a single handler.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from bulwark_sdk.models import ScanResult


class BulwarkError(Exception):
    """Base exception for all Bulwark SDK errors."""

    pass


class SecurityError(BulwarkError):
    """Raised when a security scan blocks content.

    Attributes:
        result: The ScanResult that triggered the block (if available).
        reason: Human-readable description of why the content was blocked.
    """

    def __init__(
        self,
        message: str,
        result: ScanResult | None = None,
    ) -> None:
        super().__init__(message)
        self.result = result
        self.reason = message


class ConnectionError(BulwarkError):
    """Raised when the SDK cannot connect to the Bulwark Gateway."""

    def __init__(self, message: str, url: str | None = None) -> None:
        super().__init__(message)
        self.url = url


class AuthenticationError(BulwarkError):
    """Raised when authentication with the Bulwark Gateway fails.

    This typically means the API key is invalid or expired.
    """

    def __init__(self, message: str = "Authentication failed") -> None:
        super().__init__(message)


class RateLimitError(BulwarkError):
    """Raised when the request is rate-limited by the Bulwark Gateway.

    Attributes:
        retry_after: Seconds to wait before retrying (if provided by server).
    """

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class ConfigurationError(BulwarkError):
    """Raised when the SDK is misconfigured.

    Examples: missing required parameters, invalid URLs, etc.
    """

    pass


class GatewayError(BulwarkError):
    """Raised when the Bulwark Gateway returns an unexpected error.

    Attributes:
        status_code: HTTP status code from the gateway.
        response_body: Raw response body (if available).
    """

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        response_body: Any = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body
