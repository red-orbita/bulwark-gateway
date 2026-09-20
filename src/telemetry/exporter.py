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
import hashlib
import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field, is_dataclass, replace
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional, Protocol

if TYPE_CHECKING:
    from .shared_outbox import DestinationSnapshot

from .queue import TelemetryQueue, get_telemetry_queue
from .schema import SecurityTelemetryEvent

logger = logging.getLogger(__name__)

EXPORTER_ENABLED = os.getenv("BULWARK_TELEMETRY_ENABLED", "false").lower() == "true"
BATCH_SIZE = int(os.getenv("BULWARK_TELEMETRY_BATCH_SIZE", "100"))
FLUSH_INTERVAL = float(os.getenv("BULWARK_TELEMETRY_FLUSH_INTERVAL", "1.0"))
STATS_FILE = Path(os.getenv("BULWARK_SIEM_STATS_FILE", "shared/siem/siem_stats.json"))
STATS_FLUSH_INTERVAL = 5.0  # seconds
MAX_TLS_MATERIAL_BYTES = 1024 * 1024


def _tls_material(config: dict[str, Any]) -> dict[str, bytes]:
    material = {}
    try:
        for name in ("tls_ca", "tls_cert", "tls_key"):
            if config.get(name):
                with open(config[name], "rb") as source:
                    data = source.read(MAX_TLS_MATERIAL_BYTES + 1)
                if not data or len(data) > MAX_TLS_MATERIAL_BYTES:
                    raise ValueError("Invalid TLS material size")
                material[name] = data
    except (OSError, ValueError, TypeError):
        raise ValueError("TLS material unavailable or invalid") from None
    return material


def _config_revision(transport: TransportProtocol, config: dict[str, Any], material: dict[str, bytes]) -> str:
    identity = {"type": type(transport).__module__ + "." + type(transport).__qualname__, "config": config}
    if material:
        identity["tls_material"] = {name: hashlib.sha256(data).hexdigest() for name, data in material.items()}
    serialized = json.dumps(identity, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode()).hexdigest()


class _PinnedTlsTransport:
    """Use the exact fingerprinted bytes, not mutable secret-mount pathnames.

    Linux sealed memfds keep private keys off disk and prevent check/use races.
    Unsupported platforms fail registration rather than using mutable material.
    """

    def __init__(self, original: TransportProtocol, config: Any, material: dict[str, bytes]):
        from .transports.http_rest import HttpRestTransport
        from .transports.syslog import SyslogTransport
        from .transports.tcp_tls import TcpTlsTransport

        self._fds: list[int] = []
        if type(original) not in (HttpRestTransport, SyslogTransport, TcpTlsTransport):
            raise ValueError("Shared TLS requires a supported pinnable transport")
        self.revision = _config_revision(original, asdict(config), material)
        try:
            import fcntl

            paths = {}
            for name, data in material.items():
                fd = os.memfd_create("bulwark-telemetry-tls", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
                self._fds.append(fd)
                with os.fdopen(os.dup(fd), "wb") as target:
                    target.write(data)
                fcntl.fcntl(fd, fcntl.F_ADD_SEALS,
                            fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
                paths[name] = f"/proc/self/fd/{fd}"
            factory: Any = type(original)
            self.transport: TransportProtocol = factory(replace(config, **paths))
        except Exception:
            self.release()
            raise ValueError("Unable to pin shared TLS material") from None

    def release(self) -> None:
        for fd in self._fds:
            os.close(fd)
        self._fds.clear()


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
    # SECURITY FIX (CRIT-04): Per-transport tenant scope.
    # "global" = receives ALL events (admin-only SIEM endpoints)
    # set of tenant_ids = only receives events from those tenants
    tenant_scope: str | set[str] = "global"
    snapshot: DestinationSnapshot | None = None
    pinned_tls: _PinnedTlsTransport | None = None


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
        self._initialized = False
        self._task: Optional[asyncio.Task] = None
        self._stats_task: Optional[asyncio.Task] = None
        self._stats = {
            "batches_sent": 0,
            "events_exported": 0,
            "export_errors": 0,
            "delivery_retries": 0,
        }
        self._delivery_timeout = 30.0
        self._delivered_indexes: list[int] = []

    def add_transport(self, transport: TransportProtocol, tenant_scope: str | set[str] = "global",
                      *, destination_id: str | None = None, revision: str | None = None) -> None:
        """Add a transport with optional tenant scope filtering.

        Args:
            transport: The transport implementation.
            tenant_scope: "global" for admin SIEM (receives all events),
                         or a set of tenant_ids that this transport is allowed to receive.
        """
        from .transports.file_shipper import FileShipperTransport

        # A file flush is neither crash-durable nor safe for shared rotation.
        if self._queue.durable and isinstance(transport, FileShipperTransport):
            raise ValueError("FileShipperTransport is not supported with durable telemetry (local or shared)")
        snapshot = None
        pinned_tls = None
        if self._queue.shared:
            from .shared_outbox import DestinationSnapshot
            scope = None if tenant_scope == "global" else tuple(sorted(
                tenant_scope if isinstance(tenant_scope, set) else {tenant_scope}
            ))
            config = getattr(transport, "_config", None)
            if is_dataclass(config) and not isinstance(config, type):
                material = _tls_material(asdict(config))
                if material:
                    pinned_tls = _PinnedTlsTransport(transport, config, material)
                fingerprint = _config_revision(transport, asdict(config), material)
            else:
                fingerprint = None
            effective_revision = fingerprint if fingerprint is not None else revision
            if effective_revision is None:
                raise ValueError("Shared custom transport requires an immutable config revision")
            try:
                snapshot = DestinationSnapshot(destination_id=destination_id or transport.name,
                                               revision=effective_revision, tenant_scope=scope)
                snapshots = tuple(tw.snapshot for tw in self._transports if tw.snapshot is not None) + (snapshot,)
                self._queue.set_destinations(snapshots)
            except Exception:
                if pinned_tls is not None:
                    pinned_tls.release()
                raise
        self._transports.append(TransportWithCircuitBreaker(
            transport=transport, tenant_scope=set(tenant_scope) if isinstance(tenant_scope, set) else tenant_scope,
            snapshot=snapshot,
            pinned_tls=pinned_tls,
        ))
        logger.info("telemetry_transport_added", extra={
            "transport": transport.name,
            "tenant_scope": "global" if tenant_scope == "global" else str(tenant_scope),
        })

    async def start(self) -> None:
        """Start the background exporter loop."""
        enabled = os.getenv("BULWARK_TELEMETRY_ENABLED", "false").lower() == "true"
        if not enabled:
            logger.info("telemetry_exporter_disabled")
            return

        if self._queue.durable and not self._transports:
            raise RuntimeError("Durable telemetry requires an explicitly configured supported transport")

        await self._queue.initialize()
        self._initialized = True

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
        try:
            if self._queue.shared:
                if self._initialized:
                    await self._flush_shared()
                remaining = []
            else:
                remaining = await self._queue.dequeue_batch(batch_size=min(self._batch_size * 10, 10000), timeout=0.1)
            if remaining:
                success = await self._send_to_transports(remaining)
                await self._queue.acknowledge_batch(self._delivered_indexes)
                if not success:
                    self._queue.requeue_batch(remaining)
        finally:
            for tw in self._transports:
                try:
                    await asyncio.wait_for(tw.transport.close(), self._delivery_timeout)
                except Exception:
                    logger.warning("telemetry_transport_close_failed")
                finally:
                    if tw.pinned_tls is not None:
                        try:
                            await asyncio.wait_for(tw.pinned_tls.transport.close(), self._delivery_timeout)
                        except Exception:
                            logger.warning("telemetry_pinned_transport_close_failed")
                        finally:
                            tw.pinned_tls.release()
            await self._queue.aclose()
            self._initialized = False
        self._persist_stats()
        logger.info("telemetry_exporter_stopped", extra={"stats": self._stats})

    async def _run_loop(self) -> None:
        """Main export loop — runs until stopped."""
        while self._running:
            batch: list[SecurityTelemetryEvent] = []
            try:
                if self._queue.shared:
                    await self._flush_shared()
                    await asyncio.sleep(self._flush_interval)
                    continue
                batch = await self._queue.dequeue_batch(
                    batch_size=self._batch_size,
                    timeout=self._flush_interval,
                )
                if batch:
                    success = await self._send_to_transports(batch)
                    await self._queue.acknowledge_batch(self._delivered_indexes)
                    if not success:
                        self._queue.requeue_batch(batch)
                        batch = []
                        self._stats["delivery_retries"] += 1
                        await asyncio.sleep(self._flush_interval)
            except asyncio.CancelledError:
                self._queue.requeue_batch(batch)
                break
            except Exception:
                self._queue.requeue_batch(batch)
                logger.error("telemetry_loop_error")
                await asyncio.sleep(1.0)

    @staticmethod
    def _transport_revision(transport: TransportProtocol) -> str | None:
        """Fingerprint the effective built-in config without persisting secrets.

        Custom transports must supply a revision and remain immutable while
        registered. Built-in config mutations are checked again before sending.
        """
        config = getattr(transport, "_config", None)
        if not is_dataclass(config) or isinstance(config, type):
            return None
        values = asdict(config)
        return _config_revision(transport, values, _tls_material(values))

    async def _flush_shared(self) -> None:
        """Claim only exact registered snapshots; acknowledge each destination."""
        outbox = self._queue.shared_outbox
        if outbox is None:
            raise RuntimeError("Shared telemetry store unavailable")
        for tw in self._transports:
            snapshot = tw.snapshot
            if snapshot is None or not tw.circuit.can_execute():
                continue
            try:
                revision = await asyncio.to_thread(self._transport_revision, tw.transport)
            except ValueError:
                self._stats["export_errors"] += 1
                logger.error("shared_outbox_tls_material_unavailable")
                continue
            scope = None if tw.tenant_scope == "global" else tuple(sorted(
                tw.tenant_scope if isinstance(tw.tenant_scope, set) else {tw.tenant_scope}
            ))
            if (revision is not None and revision != snapshot.revision) or scope != snapshot.tenant_scope:
                self._stats["export_errors"] += 1
                logger.error("shared_outbox_destination_changed")
                continue
            leases = await outbox.claim(snapshot, limit=min(self._batch_size, 1000),
                                        lease_seconds=max(60.0, self._delivery_timeout + 15.0))
            if not leases:
                continue
            # Cancellation leaves leases intact for expiry/recovery. No cleanup
            # path can acknowledge data without an explicit transport success.
            try:
                success = await asyncio.wait_for(
                    (tw.pinned_tls.transport if tw.pinned_tls else tw.transport).send_batch(
                        [lease.event for lease in leases]), self._delivery_timeout,
                ) is True
            except Exception:
                success = False
                logger.error("shared_outbox_transport_failed")
            if success:
                tw.circuit.record_success()
                tw.retry_delay = 1.0
                self._stats["batches_sent"] += 1
                self._stats["events_exported"] += len(leases)
            else:
                tw.circuit.record_failure()
                tw.retry_delay = min(tw.retry_delay * 2, tw.max_retry_delay)
                self._stats["export_errors"] += 1
                self._stats["delivery_retries"] += 1
            await outbox.finish(leases, success=success, retry_seconds=tw.retry_delay)
        await outbox.status()

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
        except Exception:  # noqa: S110 — stats persistence to Redis is best-effort (file fallback follows)
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
        except Exception:  # noqa: S110 — stats file fallback is best-effort; never break export
            pass

    def _persist_stats_redis(self) -> None:
        """Persist cumulative stats to Redis (shared across all pods)."""
        import redis
        redis_url = os.getenv("BULWARK_REDIS_URL", "")
        if not redis_url:
            return
        pw_file = os.getenv("BULWARK_REDIS_PASSWORD_FILE", "")
        password = None
        if pw_file:
            try:
                password = open(pw_file).read().strip()
            except Exception:  # noqa: S110 — optional Redis password file; missing/unreadable is tolerated
                pass
        kwargs: dict = {"password": password, "decode_responses": True, "socket_timeout": 1.0}
        if redis_url.startswith("rediss://"):
            tls_insecure = os.getenv("BULWARK_REDIS_TLS_INSECURE", "false").lower() in ("1", "true", "yes")
            if tls_insecure:
                import ssl
                kwargs["ssl_cert_reqs"] = ssl.CERT_NONE
        r = redis.from_url(redis_url, **kwargs)
        # Use INCRBY for cumulative counters (safe across multiple pods)
        pipe = r.pipeline()
        # Read current values from last flush to compute delta
        prev_batches = int(r.get("bulwark:siem:_last_batches_sent") or 0)
        prev_events = int(r.get("bulwark:siem:_last_events_exported") or 0)
        prev_errors = int(r.get("bulwark:siem:_last_export_errors") or 0)
        # Compute deltas since last flush
        d_batches = self._stats["batches_sent"] - prev_batches
        d_events = self._stats["events_exported"] - prev_events
        d_errors = self._stats["export_errors"] - prev_errors
        if d_batches > 0:
            pipe.incrby("bulwark:siem:batches_sent", d_batches)
        if d_events > 0:
            pipe.incrby("bulwark:siem:events_exported", d_events)
        if d_errors > 0:
            pipe.incrby("bulwark:siem:export_errors", d_errors)
        # Store current values as last-flushed reference
        pipe.set("bulwark:siem:_last_batches_sent", self._stats["batches_sent"])
        pipe.set("bulwark:siem:_last_events_exported", self._stats["events_exported"])
        pipe.set("bulwark:siem:_last_export_errors", self._stats["export_errors"])
        # Transport state (overwrite — latest wins)
        transport_info = json.dumps([
            {"name": tw.transport.name, "circuit_state": tw.circuit.state.value}
            for tw in self._transports
        ])
        pipe.set("bulwark:siem:transports", transport_info)
        pipe.set("bulwark:siem:queue_memory_depth", self._queue.memory_depth)
        pipe.set("bulwark:siem:updated_at", time.time())
        pipe.execute()

    async def _send_to_transports(self, batch: list[SecurityTelemetryEvent]) -> bool:
        """Fan-out batch to registered transports with circuit breaker and tenant filtering.

        SECURITY FIX (CRIT-04): Each transport only receives events matching its
        tenant_scope. This prevents cross-tenant information disclosure where a
        tenant-configured SIEM endpoint receives events from ALL tenants.
        """
        if not self._transports:
            self._delivered_indexes = []
            return False
        delivered = True
        covered: set[int] = set()
        failed: set[int] = set()
        self._delivered_indexes = []
        for tw in self._transports:

            # SECURITY FIX (CRIT-04): Filter events by transport's tenant scope
            if tw.tenant_scope == "global":
                filtered_batch = batch
            else:
                # Only send events belonging to this transport's allowed tenants
                allowed_tenants = tw.tenant_scope if isinstance(tw.tenant_scope, set) else {tw.tenant_scope}
                # SECURITY FIX (SGW-XT-001): SecurityTelemetryEvent stores tenant
                # in nested structure event.tenant.id (TenantFields model), NOT event.tenant_id.
                # Previous code used getattr(event, "tenant_id") which always returned None,
                # causing ALL events to be sent to "global" transports regardless of scope.
                filtered_batch = [
                    event for event in batch
                    if (
                        getattr(event, "tenant_id", None)
                        or getattr(getattr(event, "tenant", None), "id", None)
                    ) in allowed_tenants
                ]
                if not filtered_batch:
                    continue  # No events for this transport in this batch

            covered.update(id(event) for event in filtered_batch)
            if not tw.circuit.can_execute():
                delivered = False
                failed.update(id(event) for event in filtered_batch)
                continue

            try:
                success = await asyncio.wait_for(tw.transport.send_batch(filtered_batch), self._delivery_timeout)
                if success:
                    tw.circuit.record_success()
                    tw.retry_delay = 1.0  # Reset backoff
                    self._stats["batches_sent"] += 1
                    self._stats["events_exported"] += len(filtered_batch)
                else:
                    delivered = False
                    failed.update(id(event) for event in filtered_batch)
                    tw.circuit.record_failure()
                    tw.retry_delay = min(tw.retry_delay * 2, tw.max_retry_delay)
                    self._stats["export_errors"] += 1
            except Exception:
                delivered = False
                failed.update(id(event) for event in filtered_batch)
                tw.circuit.record_failure()
                tw.retry_delay = min(tw.retry_delay * 2, tw.max_retry_delay)
                self._stats["export_errors"] += 1
                logger.error(
                    "telemetry_transport_error",
                    extra={"transport": tw.transport.name},
                )
        self._delivered_indexes = [i for i, event in enumerate(batch) if id(event) in covered - failed]
        return delivered and len(covered) == len({id(event) for event in batch})

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


# ─── Admin→proxy transport-config normalization ──────────────────────────────
#
# The admin UI (admin/routes/siem.py + siem.html) persists a transport dict with
# its own vocabulary; the proxy loader below is the single place that maps that
# vocabulary onto the concrete transport config objects. Keeping the mapping
# here (rather than in admin) preserves the src↛admin import boundary.


def _default_api_key_header(platform: str) -> str:
    """Platform-aware default header for API-key auth (Datadog uses DD-API-KEY)."""
    return {"datadog": "DD-API-KEY"}.get((platform or "").lower(), "Authorization")


def _build_http_auth(cfg: dict) -> dict:
    """Map the admin auth vocabulary onto HttpTransportConfig auth kwargs.

    Admin ``auth_type`` values: none | bearer | oauth2 | api_key | basic | hmac | mtls.
    The single ``auth_value`` field carries the credential (token / api key /
    ``user:password`` for basic / shared key for hmac). Multi-field methods
    (hmac workspace, mtls certs) also read explicit optional fields when present.
    """
    from .transports.http_rest import HttpAuthMethod

    platform = (cfg.get("platform") or "").lower()
    auth_type = (cfg.get("auth_type") or "none").lower()
    # Prefer the current field name; accept the legacy ``auth_key`` for compat.
    auth_value = cfg.get("auth_value") or cfg.get("auth_key") or ""

    # Splunk HEC authenticates with the "Splunk <token>" Authorization scheme,
    # not "Bearer <token>". Normalize so an operator can paste the raw HEC token.
    if platform in ("splunk", "splunk_es") and auth_type in ("bearer", "oauth2", "api_key") and auth_value:
        token = auth_value if auth_value.lower().startswith("splunk ") else f"Splunk {auth_value}"
        return {
            "auth_method": HttpAuthMethod.API_KEY,
            "api_key": token,
            "api_key_header": "Authorization",
        }

    if auth_type in ("bearer", "oauth2"):
        return {"auth_method": HttpAuthMethod.BEARER, "token": auth_value}
    if auth_type == "api_key":
        return {
            "auth_method": HttpAuthMethod.API_KEY,
            "api_key": auth_value,
            "api_key_header": cfg.get("api_key_header") or _default_api_key_header(platform),
        }
    if auth_type == "basic":
        user, _, pw = auth_value.partition(":")
        return {
            "auth_method": HttpAuthMethod.BASIC,
            "username": cfg.get("username") or user,
            "password": cfg.get("password") or pw,
        }
    if auth_type == "hmac":
        return {
            "auth_method": HttpAuthMethod.HMAC,
            "workspace_id": cfg.get("workspace_id") or "",
            "shared_key": cfg.get("shared_key") or auth_value,
        }
    if auth_type == "mtls":
        return {
            "auth_method": HttpAuthMethod.MTLS,
            "tls_ca": cfg.get("tls_ca"),
            "tls_cert": cfg.get("tls_cert"),
            "tls_key": cfg.get("tls_key"),
        }
    return {"auth_method": HttpAuthMethod.NONE}


def _map_http_format(fmt: str) -> str:
    """HTTP body framing; plain NDJSON is not Elasticsearch Bulk framing."""
    return {
        "ndjson": "ndjson", "custom_json": "ndjson",
        "elastic_bulk": "elastic_bulk", "splunk_hec": "splunk_hec",
    }.get((fmt or "").lower(), "json")


def _map_syslog_format(fmt: str):
    """Map the admin format vocabulary onto SyslogFormat."""
    from .transports.syslog import SyslogFormat

    return {
        "cef": SyslogFormat.CEF,
        "leef": SyslogFormat.LEEF,
        "rfc5424": SyslogFormat.RFC5424,
        "ecs_json": SyslogFormat.JSON,
        "custom_json": SyslogFormat.JSON,
        "json": SyslogFormat.JSON,
    }.get((fmt or "").lower(), SyslogFormat.JSON)


def _map_tcp_format(fmt: str) -> str:
    """Map the admin format vocabulary onto the tcp_tls format string."""
    return {
        "cef": "cef",
        "leef": "leef",
        "json": "json",
        "ndjson": "ndjson",
        "ecs_json": "json",
        "custom_json": "json",
    }.get((fmt or "").lower(), "cef")


def _add_transport_from_config(exporter: TelemetryExporter, cfg: dict) -> None:
    """Build and register one transport from an admin-written config dict.

    Normalizes the admin ``transport_type`` vocabulary
    (file | http_rest | syslog_udp/tcp/tls | tcp_tls, plus the legacy
    http/syslog/tcp aliases) onto the concrete transport, wiring auth and
    format through so an admin-configured HTTP/syslog SIEM actually receives
    credentials and the requested wire format.
    """
    ttype = (cfg.get("transport_type") or "file").lower()
    fmt = cfg.get("format", "")
    scope = cfg.get("tenant_scope", "global")
    if isinstance(scope, list):
        if not all(isinstance(tenant, str) and tenant for tenant in scope):
            raise ValueError("Invalid telemetry tenant scope")
        scope = set(scope)
    elif not isinstance(scope, str) or not scope:
        raise ValueError("Invalid telemetry tenant scope")
    registration = {"tenant_scope": scope, "destination_id": cfg.get("id")}

    if ttype == "file":
        from .transports.file_shipper import FileShipperConfig, FileShipperTransport
        exporter.add_transport(FileShipperTransport(FileShipperConfig(
            path=cfg.get("endpoint", "/var/log/bulwark-gateway/events.ndjson"),
        )), **registration)
    elif ttype in ("http", "http_rest"):
        from urllib.parse import urlparse

        from .transports.http_rest import HttpRestTransport, HttpTransportConfig
        endpoint = cfg.get("endpoint", "http://localhost:9200")
        http_format = _map_http_format(fmt)
        if (cfg.get("platform") or "").lower() in ("splunk", "splunk_es"):
            http_format = "splunk_hec"
        # Existing Elastic admin configs select ECS/NDJSON for a Bulk endpoint.
        # Logstash HTTP inputs must keep their generic JSON framing.
        if (
            (cfg.get("platform") or "").lower() in ("elastic", "elastic_elk")
            and urlparse(endpoint).path.rstrip("/").endswith("/_bulk")
        ):
            http_format = "elastic_bulk"
        exporter.add_transport(HttpRestTransport(HttpTransportConfig(
            url=endpoint,
            format=http_format,
            verify_ssl=bool(cfg.get("verify_ssl", True)),
            **_build_http_auth(cfg),
        )), **registration)
    elif ttype in ("syslog", "syslog_udp", "syslog_tcp", "syslog_tls"):
        from .transports.syslog import SyslogConfig, SyslogProtocol, SyslogTransport
        protocol = {
            "syslog_udp": SyslogProtocol.UDP,
            "syslog_tls": SyslogProtocol.TLS,
        }.get(ttype, SyslogProtocol.TCP)
        exporter.add_transport(SyslogTransport(SyslogConfig(
            host=cfg.get("endpoint", "localhost"),
            port=int(cfg.get("port", 514)),
            protocol=protocol,
            format=_map_syslog_format(fmt),
        )), **registration)
    elif ttype in ("tcp", "tcp_tls"):
        from .transports.tcp_tls import TcpTlsConfig, TcpTlsTransport
        exporter.add_transport(TcpTlsTransport(TcpTlsConfig(
            host=cfg.get("endpoint", "localhost"),
            port=int(cfg.get("port", 6514)),
            use_tls=bool(cfg.get("use_tls", ttype == "tcp_tls")),
            format=_map_tcp_format(fmt),
        )), **registration)
    else:
        if exporter._queue.durable:
            raise ValueError("Unsupported durable telemetry transport")
        logger.warning("unknown_transport_type", extra={"type": ttype})


def load_transports_from_config(exporter: TelemetryExporter) -> None:
    """Load transports from shared config file (written by admin)."""
    config_file = Path(os.getenv("BULWARK_SIEM_TRANSPORTS_FILE", "shared/siem/siem_transports.json"))
    if not config_file.exists():
        if exporter._queue.durable or not EXPORTER_ENABLED:
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
        if exporter._queue.durable:
            raise RuntimeError("Unable to load durable telemetry transport configuration") from None
        logger.error("siem_transports_config_error", extra={"error": str(e)})
        return

    for cfg in configs:
        if not cfg.get("enabled", True):
            continue
        try:
            _add_transport_from_config(exporter, cfg)
        except Exception as e:
            if exporter._queue.durable:
                raise RuntimeError(
                    "Unable to register durable telemetry transport; FileShipperTransport is unsupported"
                ) from None
            logger.error(
                "transport_load_error",
                extra={"type": cfg.get("transport_type"), "error": str(e)},
            )
