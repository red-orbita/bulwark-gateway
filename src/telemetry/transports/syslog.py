"""
Syslog Transport — UDP/TCP/TLS for QRadar, Wazuh, Graylog, Security Onion, FortiSIEM.

Supports:
    - RFC 5424 (structured data)
    - CEF format (ArcSight, FortiSIEM)
    - LEEF format (IBM QRadar)
    - JSON (Graylog GELF-compatible)
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from ..schema import SecurityTelemetryEvent

logger = logging.getLogger(__name__)


class SyslogProtocol(str, Enum):
    UDP = "udp"
    TCP = "tcp"
    TLS = "tls"


class SyslogFormat(str, Enum):
    JSON = "json"
    CEF = "cef"
    LEEF = "leef"
    RFC5424 = "rfc5424"


@dataclass
class SyslogConfig:
    host: str = "127.0.0.1"
    port: int = 514
    protocol: SyslogProtocol = SyslogProtocol.TCP
    format: SyslogFormat = SyslogFormat.JSON
    facility: int = 1  # user-level
    tls_cert: Optional[str] = None
    tls_key: Optional[str] = None
    tls_ca: Optional[str] = None


class SyslogTransport:
    """Async syslog sender supporting UDP, TCP, and TLS."""

    name = "syslog"

    def __init__(self, config: SyslogConfig):
        self._config = config
        self._writer: Optional[asyncio.StreamWriter] = None
        self._socket: Optional[socket.socket] = None

    async def _ensure_connection(self) -> None:
        if self._config.protocol == SyslogProtocol.UDP:
            if self._socket is None:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif self._writer is None or self._writer.is_closing():
            ssl_context = None
            if self._config.protocol == SyslogProtocol.TLS:
                ssl_context = ssl.create_default_context(cafile=self._config.tls_ca)
                if self._config.tls_cert and self._config.tls_key:
                    ssl_context.load_cert_chain(self._config.tls_cert, self._config.tls_key)

            _, self._writer = await asyncio.open_connection(
                self._config.host, self._config.port, ssl=ssl_context
            )

    def _format_event(self, event: SecurityTelemetryEvent) -> str:
        if self._config.format == SyslogFormat.CEF:
            return event.to_cef()
        elif self._config.format == SyslogFormat.LEEF:
            return event.to_leef()
        elif self._config.format == SyslogFormat.JSON:
            return event.model_dump_json(by_alias=True, exclude_none=True)
        else:
            # RFC5424
            pri = self._config.facility * 8 + event.event.severity.value
            return f"<{pri}>1 {event.timestamp} sentinel-gateway - - - {event.message}"

    async def send_batch(self, events: list[SecurityTelemetryEvent]) -> bool:
        try:
            await self._ensure_connection()
            for event in events:
                msg = self._format_event(event) + "\n"
                encoded = msg.encode("utf-8")

                if self._config.protocol == SyslogProtocol.UDP:
                    self._socket.sendto(encoded, (self._config.host, self._config.port))  # type: ignore
                else:
                    self._writer.write(encoded)  # type: ignore
                    await self._writer.drain()  # type: ignore
            return True
        except Exception as e:
            logger.error("syslog_send_error", extra={"error": str(e)})
            self._writer = None
            return False

    async def close(self) -> None:
        if self._writer and not self._writer.is_closing():
            self._writer.close()
            await self._writer.wait_closed()
        if self._socket:
            self._socket.close()
