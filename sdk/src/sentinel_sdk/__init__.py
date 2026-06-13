"""
sentinel_sdk — Python SDK for Sentinel Gateway.

Provides both remote API access (SentinelClient) and local offline
scanning (SentinelGuard) for AI security guardrails.

Quick start:
    # Remote mode (via Sentinel Gateway API)
    from sentinel_sdk import SentinelClient

    client = SentinelClient(
        base_url="https://sentinel.company.com",
        api_key="sk-...",
        tenant_id="acme-corp",
        agent_id="support-bot",
    )
    result = await client.scan_input("user message")

    # Local mode (no network, regex-based)
    from sentinel_sdk import SentinelGuard

    guard = SentinelGuard()
    result = guard.scan("user message")
"""

from sentinel_sdk.client import SentinelClient
from sentinel_sdk.exceptions import (
    AuthenticationError,
    ConfigurationError,
    ConnectionError,
    GatewayError,
    RateLimitError,
    SecurityError,
    SentinelError,
)
from sentinel_sdk.guard import SentinelGuard
from sentinel_sdk.models import (
    HealthStatus,
    ScanResult,
    SecurityEvent,
    Severity,
    ThreatCategory,
    Verdict,
)

__version__ = "0.1.0"

__all__ = [
    # Core classes
    "SentinelClient",
    "SentinelGuard",
    # Models
    "HealthStatus",
    "ScanResult",
    "SecurityEvent",
    "Severity",
    "ThreatCategory",
    "Verdict",
    # Exceptions
    "AuthenticationError",
    "ConfigurationError",
    "ConnectionError",
    "GatewayError",
    "RateLimitError",
    "SecurityError",
    "SentinelError",
]
