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
from typing import Optional

from .schema import SecurityTelemetryEvent

logger = logging.getLogger(__name__)

DEFAULT_QUEUE_SIZE = 10_000
DEFAULT_DISK_PATH = "data/telemetry_fallback.db"


class DiskFallback:
    """SQLite WAL-mode append-only fallback for queue overflow."""

    def __init__(self, path: str = DEFAULT_DISK_PATH):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _init_db(self) -> None:
        self._conn = sqlite3.connect(str(self._path), isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
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
            if self._conn:
                self._conn.execute(
                    "INSERT INTO events (payload, created_at) VALUES (?, ?)",
                    (payload, time.time()),
                )

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
                except Exception:
                    pass  # Skip corrupted entries
            self._conn.execute(f"DELETE FROM events WHERE id IN ({','.join('?' * len(ids))})", ids)
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
    ):
        self._queue: asyncio.Queue[SecurityTelemetryEvent] = asyncio.Queue(maxsize=max_size)
        self._disk = DiskFallback(disk_path)
        self._max_size = max_size
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
        """
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

    async def dequeue_batch(
        self, batch_size: int = 100, timeout: float = 1.0
    ) -> list[SecurityTelemetryEvent]:
        """
        Dequeue up to batch_size events. Called by exporter worker.
        Waits up to timeout seconds for first event, then drains greedily.
        """
        batch: list[SecurityTelemetryEvent] = []

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

    @property
    def memory_depth(self) -> int:
        return self._queue.qsize()

    @property
    def disk_depth(self) -> int:
        return self._disk.depth

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    def close(self) -> None:
        self._disk.close()


# Singleton
_queue: Optional[TelemetryQueue] = None


def get_telemetry_queue() -> TelemetryQueue:
    global _queue
    if _queue is None:
        disk_path = os.getenv("SENTINEL_TELEMETRY_DISK_PATH", DEFAULT_DISK_PATH)
        max_size = int(os.getenv("SENTINEL_TELEMETRY_QUEUE_SIZE", str(DEFAULT_QUEUE_SIZE)))
        _queue = TelemetryQueue(max_size=max_size, disk_path=disk_path)
    return _queue
