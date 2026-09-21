"""
Telemetry Queue — Async bounded queue with disk fallback.

Design:
    - In-memory asyncio.Queue (bounded, default 10,000 events)
    - On overflow: spill to disk (SQLite WAL mode, append-only)
    - Background drainer reads from disk when memory queue has capacity
    - enqueue() is NON-BLOCKING: if queue full, writes to disk synchronously
      but disk write is <1ms for SQLite WAL append

Performance target: enqueue() ≤2ms p95
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .shared_outbox import DestinationSnapshot, SharedOutbox

from .schema import SecurityTelemetryEvent

logger = logging.getLogger(__name__)

DEFAULT_QUEUE_SIZE = 10_000
DEFAULT_DISK_PATH = "data/telemetry_fallback.db"
MAX_PENDING_DURABLE_WRITES = 32  # Includes the active commit; never an executor backlog.
DURABLE_WRITER_WAIT_SECONDS = 1.0


class DiskFallback:
    """SQLite WAL-mode append-only fallback for queue overflow."""

    _MAX_DB_SIZE_BYTES = int(os.environ.get("BULWARK_TELEMETRY_DB_MAX_SIZE", str(50 * 1024 * 1024)))  # 50MB
    _ROTATION_BATCH = 1000  # Delete this many oldest events when limit reached
    _MAX_EVENTS = int(os.environ.get("BULWARK_TELEMETRY_DB_MAX_EVENTS", "100000"))

    def __init__(self, path: str = DEFAULT_DISK_PATH, *, durable: bool = False):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self._durable = durable
        self.rejected = 0
        self.corrupted = 0
        self._init_db()

    def _init_db(self) -> None:
        self._conn = sqlite3.connect(str(self._path), isolation_level=None, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL" if self._durable else "PRAGMA synchronous=NORMAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS events ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  payload TEXT NOT NULL,"
            "  created_at REAL NOT NULL"
            ")"
        )

    def append(self, event: SecurityTelemetryEvent) -> None:
        """Append event to disk. Thread-safe, <1ms for WAL append."""
        payload = event.model_dump_json(by_alias=True, exclude_none=True)
        with self._lock:
            if not self._conn:
                raise RuntimeError("Telemetry store is closed")
            if self._durable:
                # Reserve capacity and append atomically across processes. Never
                # rotate away an unacknowledged event to admit a newer one.
                self._conn.execute("BEGIN IMMEDIATE")
                try:
                    row = self._conn.execute(
                        "SELECT COUNT(*), COALESCE(SUM(length(CAST(payload AS BLOB))), 0) FROM events"
                    ).fetchone()
                    if row[0] >= self._MAX_EVENTS or row[1] + len(payload.encode("utf-8")) > self._MAX_DB_SIZE_BYTES:
                        self.rejected += 1
                        raise OverflowError("Telemetry outbox capacity reached")
                    self._conn.execute(
                        "INSERT INTO events (payload, created_at) VALUES (?, ?)", (payload, time.time()),
                    )
                    self._conn.execute("COMMIT")
                except BaseException:
                    self._conn.execute("ROLLBACK")
                    raise
            else:
                self._maybe_rotate()
                self._conn.execute(
                    "INSERT INTO events (payload, created_at) VALUES (?, ?)",
                    (payload, time.time()),
                )

    def pending(
        self, batch_size: int, after_id: int = 0, cycle_end: int = 0,
    ) -> tuple[list[int], list[SecurityTelemetryEvent], int]:
        """Read without deleting. Failed delivery and process death retain rows."""
        ids: list[int] = []
        events: list[SecurityTelemetryEvent] = []
        with self._lock:
            if self._conn is None:
                raise RuntimeError("Telemetry store is closed")
            if not cycle_end or after_id >= cycle_end:
                after_id = 0
                cycle_end = self._conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
            rows = self._conn.execute(
                "SELECT id, payload FROM events WHERE id > ? AND id <= ? ORDER BY id LIMIT ?",
                (after_id, cycle_end, batch_size),
            ).fetchall()
            if not rows and after_id:
                cycle_end = self._conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
                rows = self._conn.execute(
                    "SELECT id, payload FROM events ORDER BY id LIMIT ?", (batch_size,),
                ).fetchall()
            for row_id, payload in rows:
                try:
                    event = SecurityTelemetryEvent.model_validate_json(payload)
                except Exception:
                    # Stop at poison data; do not silently delete or skip evidence.
                    self.corrupted += 1
                    logger.error("telemetry_outbox_corrupt_row", extra={"row_id": row_id})
                    break
                ids.append(row_id)
                events.append(event)
        return ids, events, cycle_end

    def acknowledge(self, ids: list[int]) -> None:
        """Delete only successfully delivered rows, in one transaction."""
        with self._lock:
            if self._conn is None:
                raise RuntimeError("Telemetry store is closed")
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.executemany("DELETE FROM events WHERE id = ?", [(row_id,) for row_id in ids])
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise

    def _maybe_rotate(self) -> None:
        """Delete oldest events if database exceeds size limit."""
        if not self._conn:
            return
        try:
            # Check page_count * page_size for actual DB size
            cursor = self._conn.execute("PRAGMA page_count")
            page_count = cursor.fetchone()[0]
            cursor = self._conn.execute("PRAGMA page_size")
            page_size = cursor.fetchone()[0]
            db_size = page_count * page_size
            if db_size > self._MAX_DB_SIZE_BYTES:
                # Delete oldest N events
                self._conn.execute(
                    "DELETE FROM events WHERE id IN "
                    "(SELECT id FROM events ORDER BY created_at ASC LIMIT ?)",
                    (self._ROTATION_BATCH,),
                )
                # Reclaim space
                self._conn.execute("PRAGMA incremental_vacuum(100)")

            # Secondary guard: cap total event count
            cursor = self._conn.execute("SELECT COUNT(*) FROM events")
            count = cursor.fetchone()[0]
            if count > self._MAX_EVENTS:
                self._conn.execute(
                    "DELETE FROM events WHERE id IN "
                    "(SELECT id FROM events ORDER BY created_at ASC LIMIT ?)",
                    (self._ROTATION_BATCH,),
                )
                self._conn.execute("PRAGMA incremental_vacuum(100)")
        except Exception:  # noqa: S110 — non-critical DB rotation/vacuum; do not break event flow
            pass  # Non-critical: don't break event flow

    def drain(self, batch_size: int = 100) -> list[SecurityTelemetryEvent]:
        """Read and delete up to batch_size events from disk."""
        events: list[SecurityTelemetryEvent] = []
        with self._lock:
            if not self._conn:
                return events
            rows = self._conn.execute(
                "SELECT id, payload FROM events ORDER BY id LIMIT ?", (batch_size,)
            ).fetchall()
            if not rows:
                return events
            ids = [r[0] for r in rows]
            for _, payload in rows:
                try:
                    data = json.loads(payload)
                    events.append(SecurityTelemetryEvent.model_validate(data))
                except Exception:  # noqa: S110 — skip corrupted persisted event entries
                    pass  # Skip corrupted entries
            # nosec B608: only "?" placeholders are interpolated into the SQL;
            # the actual id values are bound as parameters (never string-formatted).
            placeholders = ",".join("?" * len(ids))
            self._conn.execute(
                f"DELETE FROM events WHERE id IN ({placeholders})", ids  # noqa: S608 — only "?" placeholders interpolated; ids bound as params  # nosec B608
            )
        return events

    @property
    def depth(self) -> int:
        with self._lock:
            if not self._conn:
                return 0
            row = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()
            return row[0] if row else 0

    def close(self) -> None:
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None


class TelemetryQueue:
    """
    Async bounded queue with disk fallback.

    enqueue() is designed to be called from the hot path.
    It MUST complete in ≤2ms and NEVER block.
    """

    def __init__(
        self,
        max_size: int = DEFAULT_QUEUE_SIZE,
        disk_path: str = DEFAULT_DISK_PATH,
        durable: bool | None = None,
        shared_outbox: SharedOutbox | None = None,
        shared: bool | None = None,
    ):
        self.shared = shared_outbox is not None or (
            shared if shared is not None
            else os.getenv("BULWARK_TELEMETRY_SHARED_OUTBOX", "false").lower() == "true"
        )
        self.shared_outbox = shared_outbox
        if self.shared and self.shared_outbox is None:
            from .shared_outbox import get_shared_outbox
            self.shared_outbox = get_shared_outbox()
        self._destinations: tuple[DestinationSnapshot, ...] = ()
        self.durable = (
            True if self.shared else durable if durable is not None
            else os.getenv("BULWARK_TELEMETRY_DURABLE", "false").lower() == "true"
        )
        if not 0 < max_size <= 100000:
            raise ValueError("Telemetry queue size must be between 1 and 100000")
        self._queue: asyncio.Queue[SecurityTelemetryEvent] = asyncio.Queue(maxsize=max_size)
        self._disk = None if self.shared else DiskFallback(disk_path, durable=self.durable)
        self._max_size = max_size
        self._pending_ids: list[int] = []
        self._read_cursor = 0
        self._cycle_end = 0
        self._writer_lock = asyncio.Lock()
        self._pending_writes = 0
        self._stats = {
            "enqueued": 0,
            "disk_spills": 0,
            "dropped": 0,
            "drained_from_disk": 0,
        }

    def enqueue_nowait(self, event: SecurityTelemetryEvent) -> bool:
        """
        Non-blocking enqueue. Called from hot path.
        Returns True if queued (memory or disk), False if dropped.

        Durable mode commits synchronously before accepting. This deliberately
        trades latency for restart safety; it is not the nonblocking fast path.
        """
        if self.shared:
            # A synchronous caller cannot await a shared DB commit. Never claim
            # acceptance or silently fall back to a different authority.
            self._stats["dropped"] += 1
            return False
        if self._disk is None:
            raise RuntimeError("Local telemetry store unavailable")
        if self.durable:
            try:
                self._disk.append(event)
                self._stats["enqueued"] += 1
                return True
            except Exception:
                logger.error("telemetry_outbox_enqueue_failed")
                self._stats["dropped"] += 1
                return False
        try:
            self._queue.put_nowait(event)
            self._stats["enqueued"] += 1
            return True
        except asyncio.QueueFull:
            # Spill to disk — SQLite WAL append is <1ms
            try:
                self._disk.append(event)
                self._stats["disk_spills"] += 1
                return True
            except Exception as e:
                logger.error("telemetry_queue_drop", extra={"error": str(e)})
                self._stats["dropped"] += 1
                return False

    async def enqueue(self, event: SecurityTelemetryEvent) -> bool:
        """Commit durable events off the event loop, without unbounded work queues."""
        if self.shared_outbox is not None:
            tenant = event.tenant.id if event.tenant else "unknown"
            destinations = tuple(d for d in self._destinations if d.allows(tenant))
            accepted = await self.shared_outbox.enqueue(event, destinations)
            self._stats["enqueued" if accepted else "dropped"] += 1
            return accepted
        if not self.durable:
            return self.enqueue_nowait(event)
        # Reserve before the first await, on this queue's event loop. Waiting
        # coroutines are bounded independently of disk capacity and submit no
        # thread work until they own the writer. Admission may cancel sooner.
        if self._pending_writes >= min(self._max_size, MAX_PENDING_DURABLE_WRITES):
            self._stats["dropped"] += 1
            return False
        self._pending_writes += 1
        try:
            try:
                async with asyncio.timeout(DURABLE_WRITER_WAIT_SECONDS):
                    await self._writer_lock.acquire()
            except TimeoutError:
                self._stats["dropped"] += 1
                return False
            try:
                write = asyncio.create_task(asyncio.to_thread(self.enqueue_nowait, event))
                try:
                    return await asyncio.shield(write)
                except asyncio.CancelledError:
                    # Cancelling an await cannot cancel SQLite in a worker thread.
                    # Retain the lock AND pending slot through repeated cancellation
                    # until the commit finishes; cancellation never accepts a row.
                    while not write.done():
                        try:
                            await asyncio.shield(write)
                        except asyncio.CancelledError:
                            continue
                    write.result()
                    raise
            finally:
                self._writer_lock.release()
        finally:
            self._pending_writes -= 1

    async def dequeue_batch(
        self, batch_size: int = 100, timeout: float = 1.0
    ) -> list[SecurityTelemetryEvent]:
        """
        Dequeue up to batch_size events. Called by exporter worker.
        Waits up to timeout seconds for first event, then drains greedily.
        """
        batch: list[SecurityTelemetryEvent] = []
        if self.shared:
            raise RuntimeError("Shared outbox requires per-destination claim/finish")
        if self._disk is None:
            raise RuntimeError("Local telemetry store unavailable")
        if not 0 < batch_size <= 10000:
            raise ValueError("Telemetry batch size must be between 1 and 10000")
        if self.durable:
            # Exactly one exporter owns this queue instance. Other processes may
            # read the same rows; duplicates are allowed, premature deletion is not.
            ids, batch, self._cycle_end = await asyncio.to_thread(
                self._disk.pending, batch_size, self._read_cursor, self._cycle_end,
            )
            self._pending_ids = ids
            if ids:
                self._read_cursor = ids[-1]
            if not batch:
                await asyncio.sleep(timeout)
            return batch

        # Wait for first event (with timeout)
        try:
            first = await asyncio.wait_for(self._queue.get(), timeout=timeout)
            batch.append(first)
        except asyncio.TimeoutError:
            pass

        # Greedily drain remaining (non-blocking)
        while len(batch) < batch_size:
            try:
                batch.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break

        # Also drain from disk if memory queue is below half capacity
        if self._queue.qsize() < self._max_size // 2:
            disk_events = self._disk.drain(batch_size=min(50, batch_size - len(batch)))
            if disk_events:
                batch.extend(disk_events)
                self._stats["drained_from_disk"] += len(disk_events)

        return batch

    async def acknowledge_batch(self, indexes: list[int] | None = None) -> None:
        if self.shared:
            raise RuntimeError("Shared outbox requires fenced per-destination acknowledgement")
        if self.durable and self._pending_ids:
            if self._disk is None:
                raise RuntimeError("Local telemetry store unavailable")
            ids = self._pending_ids if indexes is None else [self._pending_ids[i] for i in indexes]
            await asyncio.to_thread(self._disk.acknowledge, ids)
            self._pending_ids = []

    def requeue_batch(self, batch: list[SecurityTelemetryEvent]) -> None:
        """Legacy retries are best effort; durable rows already remain on disk."""
        if not self.durable:
            for event in batch:
                self.enqueue_nowait(event)

    @property
    def memory_depth(self) -> int:
        return self._queue.qsize()

    @property
    def disk_depth(self) -> int:
        if self.shared_outbox is not None:
            return self.shared_outbox.cached_depth
        return self._disk.depth if self._disk else 0

    @property
    def stats(self) -> dict[str, int]:
        if self.shared_outbox is not None:
            return {**self._stats, "durable": 1, "shared": 1,
                    "outbox_rejected": self.shared_outbox.rejected,
                    "outbox_errors": self.shared_outbox.errors,
                    "outbox_corrupt_reads": self.shared_outbox.corrupted}
        if self._disk is None:
            raise RuntimeError("Local telemetry store unavailable")
        return {**self._stats, "durable": int(self.durable),
                "outbox_rejected": self._disk.rejected, "outbox_corrupt_reads": self._disk.corrupted}

    def close(self) -> None:
        if self._disk:
            self._disk.close()

    def set_destinations(self, destinations: tuple[DestinationSnapshot, ...]) -> None:
        """Replace routes for FUTURE admissions only, never for pending rows."""
        from .shared_outbox import MAX_DESTINATIONS
        if len(destinations) > MAX_DESTINATIONS or len({d.key for d in destinations}) != len(destinations):
            raise ValueError("Invalid shared outbox destination set")
        self._destinations = destinations

    async def initialize(self) -> None:
        if self.shared_outbox is not None:
            await self.shared_outbox.initialize()

    async def aclose(self) -> None:
        if self.shared_outbox is not None:
            await self.shared_outbox.close()
        self.close()


# Singleton
_queue: Optional[TelemetryQueue] = None


def get_telemetry_queue() -> TelemetryQueue:
    global _queue
    if _queue is None:
        disk_path = os.getenv("BULWARK_TELEMETRY_DISK_PATH", DEFAULT_DISK_PATH)
        max_size = int(os.getenv("BULWARK_TELEMETRY_QUEUE_SIZE", str(DEFAULT_QUEUE_SIZE)))
        _queue = TelemetryQueue(max_size=max_size, disk_path=disk_path)
    return _queue
