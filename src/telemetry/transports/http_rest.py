"""
HTTP/REST Transport — for Splunk HEC, Microsoft Sentinel, Datadog, Elasticsearch.

Supports:
    - Bearer token auth (Splunk HEC)
    - HMAC shared key (Azure Log Analytics)
    - API key header (Datadog)
    - Basic auth (Elasticsearch)
    - mTLS (certificate-based)
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse

from ..schema import SecurityTelemetryEvent

logger = logging.getLogger(__name__)

# C-02: SSRF protection for SIEM transport endpoints
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_BLOCKED_HOSTNAMES = {
    "metadata.google.internal", "metadata.google.internal.",
    "metadata", "localhost",
    "kubernetes.default", "kubernetes.default.svc",
    "kubernetes.default.svc.cluster.local",
}


def _is_ssrf_target(url: str) -> bool:
    """Validate SIEM endpoint URL against SSRF targets (C-02)."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        if hostname.lower() in _BLOCKED_HOSTNAMES:
            return True

        # Resolve hostname to IP
        try:
            addrs = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except (socket.gaierror, OSError):
            return True  # Fail-closed: unresolvable = blocked

        for family, _, _, _, sockaddr in addrs:
            ip = ipaddress.ip_address(sockaddr[0])
            for network in _BLOCKED_NETWORKS:
                if ip in network:
                    return True
        return False
    except Exception:
        return True  # Fail-closed


class HttpAuthMethod(str, Enum):
    NONE = "none"
    BEARER = "bearer"
    API_KEY = "api_key"
    BASIC = "basic"
    HMAC = "hmac"
    MTLS = "mtls"


@dataclass
class HttpTransportConfig:
    url: str
    auth_method: HttpAuthMethod = HttpAuthMethod.NONE
    # Auth credentials
    token: Optional[str] = None
    api_key: Optional[str] = None
    api_key_header: str = "Authorization"
    username: Optional[str] = None
    password: Optional[str] = None
    # HMAC (Azure Sentinel)
    workspace_id: Optional[str] = None
    shared_key: Optional[str] = None
    log_type: str = "SentinelGateway"
    # TLS
    tls_cert: Optional[str] = None
    tls_key: Optional[str] = None
    tls_ca: Optional[str] = None
    verify_ssl: bool = True
    # Batching
    compress: bool = False
    timeout_seconds: float = 10.0
    # Format
    format: str = "json"  # json, ndjson


class HttpRestTransport:
    """Async HTTP transport using asyncio + standard lib (no httpx dependency in telemetry)."""

    name = "http_rest"

    def __init__(self, config: HttpTransportConfig):
        self._config = config
        self._session = None

    def _build_headers(self, body: bytes) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}

        if self._config.auth_method == HttpAuthMethod.BEARER:
            headers["Authorization"] = f"Bearer {self._config.token}"
        elif self._config.auth_method == HttpAuthMethod.API_KEY:
            headers[self._config.api_key_header] = self._config.api_key or ""
        elif self._config.auth_method == HttpAuthMethod.BASIC:
            creds = base64.b64encode(
                f"{self._config.username}:{self._config.password}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {creds}"
        elif self._config.auth_method == HttpAuthMethod.HMAC:
            # Azure Log Analytics signature
            date_str = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
            string_to_sign = f"POST\n{len(body)}\napplication/json\nx-ms-date:{date_str}\n/api/logs"
            decoded_key = base64.b64decode(self._config.shared_key or "")
            signature = base64.b64encode(
                hmac.new(decoded_key, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
            ).decode()
            headers["Authorization"] = f"SharedKey {self._config.workspace_id}:{signature}"
            headers["x-ms-date"] = date_str
            headers["Log-Type"] = self._config.log_type

        return headers

    def _serialize_batch(self, events: list[SecurityTelemetryEvent]) -> bytes:
        if self._config.format == "ndjson":
            lines = [e.model_dump_json(by_alias=True, exclude_none=True) for e in events]
            return ("\n".join(lines) + "\n").encode("utf-8")
        else:
            data = [e.to_ecs_json() for e in events]
            return json.dumps(data).encode("utf-8")

    async def send_batch(self, events: list[SecurityTelemetryEvent]) -> bool:
        """Send batch via HTTP POST. Uses httpx if available, falls back to aiohttp."""
        # C-02: SSRF validation on endpoint URL
        if _is_ssrf_target(self._config.url):
            logger.error(
                "http_transport_ssrf_blocked",
                extra={"url": self._config.url},
            )
            return False

        body = self._serialize_batch(events)
        headers = self._build_headers(body)

        try:
            # Use httpx (already a project dependency)
            import httpx

            ssl_context = None
            if self._config.auth_method == HttpAuthMethod.MTLS:
                ssl_context = ssl.create_default_context(cafile=self._config.tls_ca)
                if self._config.tls_cert and self._config.tls_key:
                    ssl_context.load_cert_chain(self._config.tls_cert, self._config.tls_key)

            async with httpx.AsyncClient(
                verify=self._config.verify_ssl if not ssl_context else ssl_context,
                timeout=self._config.timeout_seconds,
            ) as client:
                response = await client.post(
                    self._config.url,
                    content=body,
                    headers=headers,
                )
                if response.status_code >= 400:
                    logger.error(
                        "http_transport_error",
                        extra={"status": response.status_code, "body": response.text[:200]},
                    )
                    return False
                return True

        except ImportError:
            logger.error("http_transport_no_httpx")
            return False
        except Exception as e:
            logger.error("http_transport_error", extra={"error": str(e)})
            return False

    async def close(self) -> None:
        pass
