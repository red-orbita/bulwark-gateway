"""Bounded shared outbox with immutable routing and fenced per-destination leases.

The DB is the authority. No network I/O occurs inside transactions; committed
rows survive worker death. Delivery is at-least-once, never exactly-once.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import os
import secrets
from collections.abc import Callable, Coroutine
from typing import Any, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.storage.database import DatabaseEngine, Transaction, create_engine
from src.storage.outbox_migrations import migrate_outbox

from .schema import SecurityTelemetryEvent

logger = logging.getLogger(__name__)
T = TypeVar("T")
MAX_DESTINATIONS = 64
MAX_PAYLOAD_BYTES = 1024 * 1024
MAX_CLAIM_BYTES = 4 * 1024 * 1024
MAX_BATCH = 1000


class DestinationSnapshot(BaseModel):
    """Opaque config identity; credentials/endpoints are never stored here.

    Revision must change for any effective destination/config change. Tenant
    scopes are part of the key, so changing a route cannot widen pending fan-out.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)
    destination_id: str = Field(min_length=1, max_length=128)
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    tenant_scope: tuple[str, ...] | None = Field(default=None, max_length=256)

    @field_validator("tenant_scope")
    @classmethod
    def validate_scope(cls, scope: tuple[str, ...] | None) -> tuple[str, ...] | None:
        if scope is not None:
            if any(not tenant or len(tenant) > 256 for tenant in scope):
                raise ValueError("Invalid tenant scope")
            return tuple(sorted(set(scope)))
        return None

    def allows(self, tenant: str) -> bool:
        return self.tenant_scope is None or tenant in self.tenant_scope

    @property
    def key(self) -> str:
        return hashlib.sha256(self.model_dump_json().encode()).hexdigest()


class DeliveryLease(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    event_key: str
    destination: str
    token: str
    tenant: str
    event: SecurityTelemetryEvent
    attempts: int


class SharedOutbox:
    """SQLite implementation; shares transactional SQL with PostgreSQL.

    One bounded DB operation per instance, rejecting concurrent admissions rather
    than accumulating tasks. A singleton state-row write serializes capacity,
    lease and ack transactions across instances, including PostgreSQL replicas.
    """

    def __init__(self, db: DatabaseEngine, *, max_events: int = 100000,
                 max_bytes: int = 50 * 1024 * 1024):
        if not 1 <= max_events <= 10000000 or not 1 <= max_bytes <= 1024**4:
            raise ValueError("Invalid shared outbox capacity")
        self._db = db
        self._max_events = max_events
        self._max_bytes = max_bytes
        self._lock = asyncio.Lock()
        self._ready = False
        self._closed = False
        self.rejected = 0
        self.errors = 0
        self.corrupted = 0
        self.cached_depth = 0

    async def _run(self, operation: Callable[[], Coroutine[Any, Any, T]]) -> T:
        if self._lock.locked():
            raise RuntimeError("Shared outbox busy")
        async with self._lock:
            # A caller cancellation must not release a connection while its
            # thread/driver is still committing. Observe completion, then cancel.
            task = asyncio.create_task(operation())
            try:
                return await asyncio.shield(task)
            except Exception:
                self.errors += 1
                raise
            except asyncio.CancelledError:
                while not task.done():
                    try:
                        await asyncio.shield(task)
                    except asyncio.CancelledError:
                        continue
                    except Exception:
                        break
                if not task.cancelled():
                    if task.exception() is not None:
                        self.errors += 1
                raise

    async def initialize(self) -> None:
        async def initialize() -> None:
            if self._closed:
                raise RuntimeError("Shared outbox closed")
            if self._ready:
                return
            await self._db.init()
            if self._db.backend == "sqlite":
                await self._db.execute("PRAGMA synchronous=FULL")
            await migrate_outbox(self._db, self._max_events, self._max_bytes)
            self._ready = True
        await self._run(initialize)

    async def _state(self, tx: Transaction) -> float:
        if not self._ready or self._closed:
            raise RuntimeError("Shared outbox not initialized")
        await tx.execute("UPDATE telemetry_outbox_state SET version = version WHERE id = ?", ("outbox",))
        if self._db.backend == "postgresql":
            await tx.execute("SET LOCAL synchronous_commit = on")
            row = await tx.fetch_one("SELECT EXTRACT(EPOCH FROM clock_timestamp())::double precision AS now")
        else:
            row = await tx.fetch_one("SELECT (julianday('now') - 2440587.5) * 86400.0 AS now")
        if row is None:
            raise RuntimeError("Outbox clock unavailable")
        return float(row["now"])

    async def enqueue(self, event: SecurityTelemetryEvent,
                      destinations: tuple[DestinationSnapshot, ...]) -> bool:
        async def append() -> bool:
            tenant = event.tenant.id if event.tenant else "unknown"
            if not tenant or len(tenant) > 256 or not event.event.id or len(event.event.id) > 256:
                raise ValueError("Invalid event identity")
            if not 1 <= len(destinations) <= MAX_DESTINATIONS:
                raise ValueError("No route or too many routes")
            if any(not d.allows(tenant) for d in destinations):
                raise ValueError("Tenant route denied")
            if len({d.key for d in destinations}) != len(destinations):
                raise ValueError("Duplicate destination")
            payload = event.model_dump_json(by_alias=True, exclude_none=True)
            if len(payload.encode()) > MAX_PAYLOAD_BYTES:
                raise ValueError("Outbox payload too large")
            snapshots = [(d.key, d.model_dump_json()) for d in destinations]
            if any(len(snapshot.encode()) > 16384 for _, snapshot in snapshots):
                raise ValueError("Outbox snapshot too large")
            size = len(payload.encode()) + sum(len(s.encode()) for _, s in snapshots)
            key = hashlib.sha256(json.dumps([tenant, event.event.id]).encode()).hexdigest()
            async with self._db.transaction() as tx:
                now = await self._state(tx)
                existing = await tx.fetch_one("SELECT payload FROM telemetry_outbox_events WHERE id = ?", (key,))
                if existing:
                    # Retry cannot attach a new destination to an accepted event.
                    if existing["payload"] != payload:
                        raise ValueError("Event identity collision")
                    return True
                reserved = await tx.execute(
                    "UPDATE telemetry_outbox_state SET events = events + 1, bytes = bytes + ?, "
                    "accepted = accepted + 1 WHERE id = ? AND events < max_events AND bytes + ? <= max_bytes",
                    (size, "outbox", size),
                )
                if not reserved:
                    await tx.execute("UPDATE telemetry_outbox_state SET rejected = rejected + 1 WHERE id = ?",
                                     ("outbox",))
                    return False
                await tx.execute(
                    "INSERT INTO telemetry_outbox_events (id, tenant, payload, size_bytes, created_at) "
                    "VALUES (?, ?, ?, ?, ?)", (key, json.dumps(tenant), payload, size, now),
                )
                for destination, snapshot in snapshots:
                    await tx.execute(
                        "INSERT INTO telemetry_outbox_deliveries (event_id, destination, snapshot) VALUES (?, ?, ?)",
                        (key, destination, snapshot),
                    )
                return True
        try:
            result = await self._run(append)
            if not result:
                self.rejected += 1
            return result
        except Exception:
            self.rejected += 1
            logger.error("shared_outbox_admission_failed")
            return False

    async def claim(self, destination: DestinationSnapshot, *, limit: int = 100,
                    lease_seconds: float = 60.0) -> list[DeliveryLease]:
        if not 1 <= limit <= MAX_BATCH or not math.isfinite(lease_seconds) or not 1 <= lease_seconds <= 3600:
            raise ValueError("Invalid outbox lease bounds")

        async def claim() -> list[DeliveryLease]:
            leases: list[DeliveryLease] = []
            used = 0
            async with self._db.transaction() as tx:
                now = await self._state(tx)
                # Fetch metadata first: even hostile/oversized persisted payloads
                # cannot turn limit * payload_size into an unbounded read.
                rows = await tx.fetch_all(
                    "SELECT d.event_id, d.attempts, e.size_bytes FROM telemetry_outbox_deliveries d "
                    "JOIN telemetry_outbox_events e ON e.id = d.event_id "
                    "WHERE d.destination = ? AND d.lease_until <= ? AND d.available_at <= ? "
                    "ORDER BY d.available_at, e.created_at, e.id LIMIT ?",
                    (destination.key, now, now, limit),
                )
                for row in rows:
                    if not 0 < row["size_bytes"] <= MAX_CLAIM_BYTES:
                        self.corrupted += 1
                        await tx.execute("UPDATE telemetry_outbox_state SET corrupt = corrupt + 1 WHERE id = ?",
                                         ("outbox",))
                        await tx.execute(
                            "UPDATE telemetry_outbox_deliveries SET available_at = ? "
                            "WHERE event_id = ? AND destination = ?",
                            (now + 60, row["event_id"], destination.key),
                        )
                        continue
                    if used + row["size_bytes"] > MAX_CLAIM_BYTES:
                        break
                    used += row["size_bytes"]
                    record = await tx.fetch_one(
                        "SELECT e.payload, e.tenant, d.snapshot FROM telemetry_outbox_events e "
                        "JOIN telemetry_outbox_deliveries d ON e.id = d.event_id "
                        "WHERE e.id = ? AND d.destination = ?",
                        (row["event_id"], destination.key),
                    )
                    try:
                        if record is None:
                            raise ValueError("Missing delivery")
                        tenant = json.loads(record["tenant"])
                        event = SecurityTelemetryEvent.model_validate_json(record["payload"])
                        snapshot = DestinationSnapshot.model_validate_json(record["snapshot"])
                        if (snapshot != destination or not destination.allows(tenant)
                                or (event.tenant.id if event.tenant else "unknown") != tenant):
                            raise ValueError("Outbox tenant mismatch")
                    except Exception:
                        self.corrupted += 1
                        await tx.execute("UPDATE telemetry_outbox_state SET corrupt = corrupt + 1 WHERE id = ?",
                                         ("outbox",))
                        await tx.execute(
                            "UPDATE telemetry_outbox_deliveries SET available_at = ? "
                            "WHERE event_id = ? AND destination = ?",
                            (now + 60, row["event_id"], destination.key),
                        )
                        logger.error("shared_outbox_corrupt_delivery")
                        continue
                    token = secrets.token_hex(32)
                    await tx.execute(
                        "UPDATE telemetry_outbox_deliveries SET lease_token = ?, lease_until = ?, "
                        "attempts = attempts + 1 "
                        "WHERE event_id = ? AND destination = ?",
                        (token, now + lease_seconds, row["event_id"], destination.key),
                    )
                    leases.append(DeliveryLease(event_key=row["event_id"], destination=destination.key,
                                                token=token, tenant=tenant, event=event, attempts=row["attempts"] + 1))
            return leases
        return await self._run(claim)

    async def finish(self, leases: list[DeliveryLease], *, success: bool, retry_seconds: float = 1.0) -> int:
        """Fence stale workers. Failed deliveries retain data with bounded backoff."""
        if len(leases) > MAX_BATCH or not math.isfinite(retry_seconds) or not 0 <= retry_seconds <= 3600:
            raise ValueError("Invalid outbox completion bounds")

        async def finish() -> int:
            completed = 0
            async with self._db.transaction() as tx:
                now = await self._state(tx)
                for lease in leases:
                    params = (lease.event_key, lease.destination, lease.token, now, json.dumps(lease.tenant))
                    if success:
                        changed = await tx.execute(
                            "DELETE FROM telemetry_outbox_deliveries "
                            "WHERE event_id = ? AND destination = ? AND lease_token = ? AND lease_until > ? "
                            "AND EXISTS (SELECT 1 FROM telemetry_outbox_events e "
                            "WHERE e.id = event_id AND e.tenant = ?)",
                            params,
                        )
                    else:
                        changed = await tx.execute(
                            "UPDATE telemetry_outbox_deliveries SET lease_token = '', lease_until = 0, "
                            "available_at = ? WHERE event_id = ? AND destination = ? "
                            "AND lease_token = ? AND lease_until > ? "
                            "AND EXISTS (SELECT 1 FROM telemetry_outbox_events e "
                            "WHERE e.id = event_id AND e.tenant = ?)",
                            (now + retry_seconds, *params),
                        )
                    if not changed:
                        continue
                    completed += 1
                    await tx.execute(
                        "UPDATE telemetry_outbox_state SET acked = acked + ?, failures = failures + ? WHERE id = ?",
                        (int(success), int(not success), "outbox"),
                    )
                    if success:
                        remaining = await tx.fetch_one(
                            "SELECT 1 AS pending FROM telemetry_outbox_deliveries WHERE event_id = ? LIMIT 1",
                            (lease.event_key,),
                        )
                        if not remaining:
                            row = await tx.fetch_one("SELECT size_bytes FROM telemetry_outbox_events WHERE id = ?",
                                                     (lease.event_key,))
                            if row is None:
                                raise RuntimeError("Missing outbox event")
                            await tx.execute("DELETE FROM telemetry_outbox_events WHERE id = ?", (lease.event_key,))
                            await tx.execute(
                                "UPDATE telemetry_outbox_state SET events = events - 1, bytes = bytes - ? WHERE id = ?",
                                (row["size_bytes"], "outbox"),
                            )
            return completed
        return await self._run(finish)

    async def status(self) -> dict[str, int]:
        async def status() -> dict[str, int]:
            row = await self._db.fetch_one("SELECT * FROM telemetry_outbox_state WHERE id = ?", ("outbox",))
            if row is None:
                raise RuntimeError("Missing outbox state")
            self.cached_depth = int(row["events"])
            return {k: int(v) for k, v in row.items() if k != "id"}
        return await self._run(status)

    async def close(self) -> None:
        async def close() -> None:
            self._closed = True
            await self._db.close()
        await self._run(close)


class PostgreSQLSharedOutbox(SharedOutbox):
    """Shared PostgreSQL authority using pooled transactions and database time."""


def get_shared_outbox(*, db: DatabaseEngine | None = None) -> SharedOutbox:
    """Create an inert store; queue owns its lifecycle. No implicit DB connection.

    Without injection, uses the common BULWARK_ADMIN_DB_URL[_FILE] engine
    configuration. PostgreSQL failures NEVER fall back to a local SQLite store.
    """
    engine = db if db is not None else create_engine()
    cls = PostgreSQLSharedOutbox if engine.backend == "postgresql" else SharedOutbox
    return cls(engine,
               max_events=int(os.getenv("BULWARK_SHARED_OUTBOX_MAX_EVENTS", "100000")),
               max_bytes=int(os.getenv("BULWARK_SHARED_OUTBOX_MAX_BYTES", str(50 * 1024 * 1024))))
