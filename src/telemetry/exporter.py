"""
Telemetry Exporter — Background worker that flushes events to transports.

Design:
    - asyncio.create_task() started at app lifespan
    - Batch flush: every 1s OR when 100 events accumulated (whichever first)
    - Circuit breaker: open after 5 consecutive transport failures, half-open after 30s
    - Retry with exponential backoff (1s, 2s, 4s, max 30s)
    - Multiple transports supported simultaneously (fan-out)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, Protocol

from .queue import TelemetryQueue, get_telemetry_queue
from .schema import SecurityTelemetryEvent

logger = logging.getLogger(__name__)

EXPORTER_ENABLED = os.getenv("SENTINEL_TELEMETRY_ENABLED", "false").lower() == "true"
BATCH_SIZE = int(os.getenv("SENTINEL_TELEMETRY_BATCH_SIZE", "100"))
FLUSH_INTERVAL = float(os.getenv("SENTINEL_TELEMETRY_FLUSH_INTERVAL", "1.0"))
STATS_FILE = Path(os.getenv("SENTINEL_SIEM_STATS_FILE", "shared/siem/siem_stats.json"))
STATS_FLUSH_INTERVAL = 5.0  # seconds


class TransportProtocol(Protocol):
    """Interface that all transports must implement."""

    @property
    def name(self) -> str: ...

    async def send_batch(self, events: list[SecurityTelemetryEvent]) -> bool:
        """Send batch of events. Returns True on success, False on failure."""
        ...

    async def close(self) -> None: ...


class CircuitState(str, Enum):
    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, reject all
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class CircuitBreaker:
    """Per-transport circuit breaker."""

    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    last_failure_time: float = 0.0
    _stats: dict[str, int] = field(
        default_factory=lambda: {"trips": 0, "successes": 0, "failures": 0}
    )

    def record_success(self) -> None:
        self.failure_count = 0
        self.state = CircuitState.CLOSED
        self._stats["successes"] += 1

    def record_failure(self) -> None:
        self.failure_count += 1
        self._stats["failures"] += 1
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN
            self.last_failure_time = time.time()
            self._stats["trips"] += 1
            logger.warning("circuit_breaker_open", extra={"failures": self.failure_count})

    def can_execute(self) -> bool:
        if self.state == CircuitState.CLOSED:
            return True
        if self.state == CircuitState.OPEN:
            if time.time() - self.last_failure_time >= self.recovery_timeout:
                self.state = CircuitState.HALF_OPEN
                return True
            return False
        # HALF_OPEN: allow one attempt
        return True

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)


@dataclass
class TransportWithCircuitBreaker:
    transport: TransportProtocol
    circuit: CircuitBreaker = field(default_factory=CircuitBreaker)
    retry_delay: float = 1.0
    max_retry_delay: float = 30.0


class TelemetryExporter:
    """
    Background worker that reads from queue and sends to transports.
    Started as asyncio task during app lifespan.
    """

    def __init__(
        self,
        queue: Optional[TelemetryQueue] = None,
        batch_size: Optional[int] = None,
        flush_interval: Optional[float] = None,
    ):
        self._queue = queue or get_telemetry_queue()
        self._batch_size = batch_size or BATCH_SIZE
        self._flush_interval = flush_interval or FLUSH_INTERVAL
        self._transports: list[TransportWithCircuitBreaker] = []
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._stats_task: Optional[asyncio.Task] = None
        self._stats = {
            "batches_sent": 0,
            "events_exported": 0,
            "export_errors": 0,
        }

    def add_transport(self, transport: TransportProtocol) -> None:
        self._transports.append(TransportWithCircuitBreaker(transport=transport))
        logger.info("telemetry_transport_added", extra={"transport": transport.name})

    async def start(self) -> None:
        """Start the background exporter loop."""
        enabled = os.getenv("SENTINEL_TELEMETRY_ENABLED", "false").lower() == "true"
        if not enabled:
            logger.info("telemetry_exporter_disabled")
            return

        # Always start stats persistence (even without transports)
        self._running = True
        self._stats_task = asyncio.create_task(self._stats_flush_loop())

        if not self._transports:
            logger.warning("telemetry_no_transports")
            return

        self._task = asyncio.create_task(self._run_loop())
        logger.info("telemetry_exporter_started", extra={"transports": len(self._transports)})

    async def stop(self) -> None:
        """Graceful shutdown: flush remaining events."""
        self._running = False
        if self._stats_task:
            self._stats_task.cancel()
            try:
                await self._stats_task
            except asyncio.CancelledError:
                pass
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

        # Final flush
        remaining = await self._queue.dequeue_batch(batch_size=self._batch_size * 10, timeout=0.1)
        if remaining:
            await self._send_to_transports(remaining)

        for tw in self._transports:
            await tw.transport.close()

        self._queue.close()
        self._persist_stats()
        logger.info("telemetry_exporter_stopped", extra={"stats": self._stats})

    async def _run_loop(self) -> None:
        """Main export loop — runs until stopped."""
        while self._running:
            try:
                batch = await self._queue.dequeue_batch(
                    batch_size=self._batch_size,
                    timeout=self._flush_interval,
                )
                if batch:
                    await self._send_to_transports(batch)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("telemetry_loop_error", extra={"error": str(e)})
                await asyncio.sleep(1.0)

    async def _stats_flush_loop(self) -> None:
        """Periodically persist stats to shared file for admin dashboard."""
        while self._running:
            try:
                await asyncio.sleep(STATS_FLUSH_INTERVAL)
                self._persist_stats()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug("stats_flush_error", extra={"error": str(e)})

    def _persist_stats(self) -> None:
        """Write current stats to Redis (atomic, multi-pod safe) + file fallback."""
        try:
            self._persist_stats_redis()
        except Exception:
            pass
        try:
            STATS_FILE.parent.mkdir(parents=True, exist_ok=True)
            stats_data = {
                **self._stats,
                "queue_memory_depth": self._queue.memory_depth,
                "transports": [
                    {
                        "name": tw.transport.name,
                        "circuit_state": tw.circuit.state.value,
                    }
                    for tw in self._transports
                ],
                "updated_at": time.time(),
            }
            STATS_FILE.write_text(json.dumps(stats_data))
        except Exception:
            pass

    def _persist_stats_redis(self) -> None:
        """Persist cumulative stats to Redis (shared across all pods)."""
        import redis
        redis_url = os.getenv("SENTINEL_REDIS_URL", "")
        if not redis_url:
            return
        pw_file = os.getenv("SENTINEL_REDIS_PASSWORD_FILE", "")
        password = None
        if pw_file:
            try:
                password = open(pw_file).read().strip()
            except Exception:
                pass
        kwargs: dict = {"password": password, "decode_responses": True, "socket_timeout": 1.0}
        if redis_url.startswith("rediss://"):
            tls_insecure = os.getenv("SENTINEL_REDIS_TLS_INSECURE", "false").lower() in ("1", "true", "yes")
            if tls_insecure:
                import ssl
                kwargs["ssl_cert_reqs"] = ssl.CERT_NONE
        r = redis.from_url(redis_url, **kwargs)
        # Use INCRBY for cumulative counters (safe across multiple pods)
        pipe = r.pipeline()
        # Read current values from last flush to compute delta
        prev_batches = int(r.get("sentinel:siem:_last_batches_sent") or 0)
        prev_events = int(r.get("sentinel:siem:_last_events_exported") or 0)
        prev_errors = int(r.get("sentinel:siem:_last_export_errors") or 0)
        # Compute deltas since last flush
        d_batches = self._stats["batches_sent"] - prev_batches
        d_events = self._stats["events_exported"] - prev_events
        d_errors = self._stats["export_errors"] - prev_errors
        if d_batches > 0:
            pipe.incrby("sentinel:siem:batches_sent", d_batches)
        if d_events > 0:
            pipe.incrby("sentinel:siem:events_exported", d_events)
        if d_errors > 0:
            pipe.incrby("sentinel:siem:export_errors", d_errors)
        # Store current values as last-flushed reference
        pipe.set("sentinel:siem:_last_batches_sent", self._stats["batches_sent"])
        pipe.set("sentinel:siem:_last_events_exported", self._stats["events_exported"])
        pipe.set("sentinel:siem:_last_export_errors", self._stats["export_errors"])
        # Transport state (overwrite — latest wins)
        transport_info = json.dumps([
            {"name": tw.transport.name, "circuit_state": tw.circuit.state.value}
            for tw in self._transports
        ])
        pipe.set("sentinel:siem:transports", transport_info)
        pipe.set("sentinel:siem:queue_memory_depth", self._queue.memory_depth)
        pipe.set("sentinel:siem:updated_at", time.time())
        pipe.execute()

    async def _send_to_transports(self, batch: list[SecurityTelemetryEvent]) -> None:
        """Fan-out batch to all registered transports with circuit breaker."""
        for tw in self._transports:
            if not tw.circuit.can_execute():
                continue

            try:
                success = await tw.transport.send_batch(batch)
                if success:
                    tw.circuit.record_success()
                    tw.retry_delay = 1.0  # Reset backoff
                    self._stats["batches_sent"] += 1
                    self._stats["events_exported"] += len(batch)
                else:
                    tw.circuit.record_failure()
                    tw.retry_delay = min(tw.retry_delay * 2, tw.max_retry_delay)
                    self._stats["export_errors"] += 1
            except Exception as e:
                tw.circuit.record_failure()
                tw.retry_delay = min(tw.retry_delay * 2, tw.max_retry_delay)
                self._stats["export_errors"] += 1
                logger.error(
                    "telemetry_transport_error",
                    extra={"transport": tw.transport.name, "error": str(e)},
                )

    @property
    def stats(self) -> dict:
        return {
            **self._stats,
            "queue_memory_depth": self._queue.memory_depth,
            "queue_disk_depth": self._queue.disk_depth,
            "queue_stats": self._queue.stats,
            "transports": [
                {
                    "name": tw.transport.name,
                    "circuit_state": tw.circuit.state.value,
                    "circuit_stats": tw.circuit.stats,
                }
                for tw in self._transports
            ],
        }


# Singleton
_exporter: Optional[TelemetryExporter] = None


def get_exporter() -> TelemetryExporter:
    global _exporter
    if _exporter is None:
        _exporter = TelemetryExporter()
    return _exporter


def load_transports_from_config(exporter: TelemetryExporter) -> None:
    """Load transports from shared config file (written by admin)."""
    config_file = Path(os.getenv("SENTINEL_SIEM_TRANSPORTS_FILE", "shared/siem/siem_transports.json"))
    if not config_file.exists():
        if not EXPORTER_ENABLED:
            logger.info("no_siem_transports_config", extra={"path": str(config_file)})
            return
        # Auto-seed a default file_shipper transport
        default_endpoint = str(config_file.parent / "events.ndjson")
        default_config = [
            {
                "id": "auto-default",
                "platform": "file",
                "transport_type": "file",
                "endpoint": default_endpoint,
                "enabled": True,
                "auto_configured": True,
            }
        ]
        try:
            config_file.parent.mkdir(parents=True, exist_ok=True)
            config_file.write_text(json.dumps(default_config, indent=2))
            logger.info(
                "siem_transport_auto_configured",
                extra={"path": str(config_file), "endpoint": default_endpoint},
            )
        except Exception as e:
            logger.error("siem_transport_auto_config_failed", extra={"error": str(e)})
            return

    try:
        configs = json.loads(config_file.read_text())
    except Exception as e:
        logger.error("siem_transports_config_error", extra={"error": str(e)})
        return

    for cfg in configs:
        if not cfg.get("enabled", True):
            continue
        transport_type = cfg.get("transport_type", "file")
        try:
            if transport_type == "file":
                from .transports.file_shipper import FileShipperTransport, FileShipperConfig
                file_t = FileShipperTransport(FileShipperConfig(
                    path=cfg.get("endpoint", "/var/log/sentinel-gateway/events.ndjson"),
                ))
                exporter.add_transport(file_t)
            elif transport_type == "syslog":
                from .transports.syslog import SyslogTransport, SyslogConfig
                syslog_t = SyslogTransport(SyslogConfig(
                    host=cfg.get("endpoint", "localhost"),
                    port=int(cfg.get("port", 514)),
                ))
                exporter.add_transport(syslog_t)
            elif transport_type == "http":
                from .transports.http_rest import HttpRestTransport, HttpTransportConfig
                http_t = HttpRestTransport(HttpTransportConfig(
                    url=cfg.get("endpoint", "http://localhost:9200"),
                    token=cfg.get("auth_key", ""),
                ))
                exporter.add_transport(http_t)
            elif transport_type == "tcp_tls":
                from .transports.tcp_tls import TcpTlsTransport, TcpTlsConfig
                tcp_t = TcpTlsTransport(TcpTlsConfig(
                    host=cfg.get("endpoint", "localhost"),
                    port=int(cfg.get("port", 6514)),
                ))
                exporter.add_transport(tcp_t)
            else:
                logger.warning("unknown_transport_type", extra={"type": transport_type})
        except Exception as e:
            logger.error("transport_load_error", extra={"type": transport_type, "error": str(e)})
