"""
HTTP/REST Transport — for Splunk HEC, Microsoft Sentinel, Datadog, Elasticsearch.

Supports:
    - API key Authorization scheme (Splunk HEC)
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
import json
import logging
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from urllib.parse import urlparse

from ..schema import SecurityTelemetryEvent
from . import is_ssrf_target_host

logger = logging.getLogger(__name__)


def _is_ssrf_target(url: str) -> bool:
    """Validate SIEM endpoint URL against SSRF targets (C-02).

    Delegates to the shared transport SSRF SSOT (``is_ssrf_target_host``), so
    the blocklist and the ``BULWARK_SIEM_SSRF_ALLOW_PRIVATE`` allowlist stay
    consistent across HTTP, TCP/TLS, and Syslog transports. Fail-closed.
    """
    try:
        parsed = urlparse(url)
        return is_ssrf_target_host(parsed.hostname or "", parsed.port)
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
    api_key_header: str = "Authorization"  # nosemgrep: bulwark-no-hardcoded-jwt-secret — header name, not a secret
    username: Optional[str] = None
    password: Optional[str] = None
    # HMAC (Azure Bulwark)
    workspace_id: Optional[str] = None
    shared_key: Optional[str] = None
    log_type: str = "BulwarkGateway"
    # TLS
    tls_cert: Optional[str] = None
    tls_key: Optional[str] = None
    tls_ca: Optional[str] = None
    verify_ssl: bool = True
    # Batching
    compress: bool = False
    timeout_seconds: float = 10.0
    # Format
    format: str = "json"  # json, ndjson, elastic_bulk, splunk_hec


class HttpRestTransport:
    """Async HTTP transport using asyncio + standard lib (no httpx dependency in telemetry)."""

    name = "http_rest"

    def __init__(self, config: HttpTransportConfig):
        self._config = config
        self._session = None

    def _build_headers(self, body: bytes) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._config.format in ("ndjson", "elastic_bulk"):
            headers["Content-Type"] = "application/x-ndjson"

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
        if self._config.format == "splunk_hec":
            # HEC batches are concatenated envelopes, not a JSON array. Keep
            # the entire ECS document inside event, not only ECS event metadata.
            return ("\n".join(json.dumps({
                "time": datetime.fromisoformat(event.timestamp).timestamp(),
                "source": "bulwark-gateway",
                "event": event.to_ecs_json(),
            }) for event in events) + "\n").encode("utf-8")
        if self._config.format == "elastic_bulk":
            lines: list[str] = []
            for event in events:
                # Stable IDs make re-sending an indexed event idempotent.
                lines.append(json.dumps({"index": {"_id": event.event.id}}))
                lines.append(event.model_dump_json(by_alias=True, exclude_none=True))
            return ("\n".join(lines) + "\n").encode("utf-8")
        if self._config.format == "ndjson":
            lines = [e.model_dump_json(by_alias=True, exclude_none=True) for e in events]
            return ("\n".join(lines) + "\n").encode("utf-8")
        else:
            data = [e.to_ecs_json() for e in events]
            return json.dumps(data).encode("utf-8")

    async def send_batch(self, events: list[SecurityTelemetryEvent]) -> bool:
        """Send a batch and validate the platform acknowledgement."""
        if not events:
            return True
        # C-02: SSRF validation on endpoint URL
        if await asyncio.to_thread(_is_ssrf_target, self._config.url):
            logger.error(
                "http_transport_ssrf_blocked",
                extra={"url": self._config.url},
            )
            return False

        try:
            body = self._serialize_batch(events)
            headers = self._build_headers(body)
            # Use httpx (already a project dependency)
            import httpx

            ssl_context = None
            if self._config.tls_ca or self._config.auth_method == HttpAuthMethod.MTLS:
                ssl_context = ssl.create_default_context(cafile=self._config.tls_ca)
            if self._config.auth_method == HttpAuthMethod.MTLS:
                if not self._config.tls_cert or not self._config.tls_key:
                    logger.error("http_transport_mtls_credentials_missing")
                    return False
                if ssl_context is not None:
                    ssl_context.load_cert_chain(self._config.tls_cert, self._config.tls_key)

            async with httpx.AsyncClient(
                verify=self._config.verify_ssl if not ssl_context else ssl_context,
                timeout=self._config.timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = await client.post(
                    self._config.url,
                    content=body,
                    headers=headers,
                )
                if not 200 <= response.status_code < 300:
                    logger.error(
                        "http_transport_error",
                        extra={"status": response.status_code},
                    )
                    return False
                if self._config.format == "elastic_bulk":
                    result = response.json()
                    items = result.get("items", []) if isinstance(result, dict) else []
                    if (
                        not isinstance(result, dict)
                        or result.get("errors") is not False
                        or not isinstance(items, list)
                        or len(items) != len(events)
                    ):
                        logger.error("elastic_bulk_invalid_or_failed_response")
                        return False
                    for item in items:
                        index = item.get("index") if isinstance(item, dict) else None
                        status = index.get("status") if isinstance(index, dict) else None
                        if type(status) is not int or not 200 <= status < 300:
                            logger.error("elastic_bulk_item_failed")
                            return False
                if self._config.format == "splunk_hec":
                    result = response.json()
                    code = result.get("code") if isinstance(result, dict) else None
                    if type(code) is not int or code != 0:
                        logger.error("splunk_hec_invalid_or_failed_response")
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
