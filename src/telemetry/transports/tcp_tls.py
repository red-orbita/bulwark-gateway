"""
TCP/TLS Transport — Raw TCP with optional TLS for CEF/LEEF forwarding.

Used by: ArcSight, LogRhythm, CrowdStrike Falcon NG SIEM, SentinelOne, FortiSIEM.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from dataclasses import dataclass
from typing import Optional

from ..schema import SecurityTelemetryEvent

logger = logging.getLogger(__name__)


@dataclass
class TcpTlsConfig:
    host: str = "127.0.0.1"
    port: int = 6514
    use_tls: bool = True
    tls_cert: Optional[str] = None
    tls_key: Optional[str] = None
    tls_ca: Optional[str] = None
    format: str = "cef"  # cef, leef, json, ndjson
    delimiter: str = "\n"
    connect_timeout: float = 5.0


class TcpTlsTransport:
    """Async TCP/TLS transport for raw log forwarding."""

    name = "tcp_tls"

    def __init__(self, config: TcpTlsConfig):
        self._config = config
        self._writer: Optional[asyncio.StreamWriter] = None

    async def _ensure_connection(self) -> None:
        if self._writer is not None and not self._writer.is_closing():
            return

        # SECURITY (H-06 fix): Validate destination against SSRF targets
        from . import is_ssrf_target_host
        if is_ssrf_target_host(self._config.host, self._config.port):
            raise ConnectionError(
                f"TCP transport blocked: {self._config.host}:{self._config.port} "
                f"resolves to a restricted network (SSRF protection)"
            )

        ssl_context = None
        if self._config.use_tls:
            ssl_context = ssl.create_default_context(cafile=self._config.tls_ca)
            if self._config.tls_cert and self._config.tls_key:
                ssl_context.load_cert_chain(self._config.tls_cert, self._config.tls_key)

        _, self._writer = await asyncio.wait_for(
            asyncio.open_connection(self._config.host, self._config.port, ssl=ssl_context),
            timeout=self._config.connect_timeout,
        )

    def _format_event(self, event: SecurityTelemetryEvent) -> str:
        if self._config.format == "cef":
            return event.to_cef()
        elif self._config.format == "leef":
            return event.to_leef()
        elif self._config.format == "json":
            return event.model_dump_json(by_alias=True, exclude_none=True)
        else:
            return event.model_dump_json(by_alias=True, exclude_none=True)

    async def send_batch(self, events: list[SecurityTelemetryEvent]) -> bool:
        try:
            await self._ensure_connection()
            payload = (
                self._config.delimiter.join(self._format_event(e) for e in events)
                + self._config.delimiter
            )
            self._writer.write(payload.encode("utf-8"))  # type: ignore
            await self._writer.drain()  # type: ignore
            return True
        except Exception as e:
            logger.error("tcp_tls_send_error", extra={"error": str(e)})
            self._writer = None
            return False

    async def close(self) -> None:
        if self._writer and not self._writer.is_closing():
            self._writer.close()
            await self._writer.wait_closed()
