"""
bulwark_sdk — Python SDK for Bulwark Gateway.

Provides both remote API access (BulwarkClient) and local offline
scanning (BulwarkGuard) for AI security guardrails.

Quick start:
    # Remote mode (via Bulwark Gateway API)
    from bulwark_sdk import BulwarkClient

    client = BulwarkClient(
        base_url="https://bulwark.company.com",
        api_key="sk-...",
        tenant_id="acme-corp",
        agent_id="support-bot",
    )
    result = await client.scan_input("user message")

    # Local mode (no network, regex-based)
    from bulwark_sdk import BulwarkGuard

    guard = BulwarkGuard()
    result = guard.scan("user message")
"""

from bulwark_sdk.client import BulwarkClient
from bulwark_sdk.exceptions import (
    AuthenticationError,
    BulwarkError,
    ConfigurationError,
    ConnectionError,  # noqa: A004 - public SDK exception, mirrors requests.exceptions.ConnectionError
    GatewayError,
    RateLimitError,
    SecurityError,
)
from bulwark_sdk.guard import BulwarkGuard
from bulwark_sdk.models import (
    HealthStatus,
    ScanResult,
    SecurityEvent,
    Severity,
    ThreatCategory,
    Verdict,
)

__version__ = "0.2.0"

__all__ = [
    "AuthenticationError",
    "BulwarkClient",
    "BulwarkError",
    "BulwarkGuard",
    "ConfigurationError",
    "ConnectionError",
    "GatewayError",
    "HealthStatus",
    "RateLimitError",
    "ScanResult",
    "SecurityError",
    "SecurityEvent",
    "Severity",
    "ThreatCategory",
    "Verdict",
]
