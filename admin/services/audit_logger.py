"""Audit Logger — Immutable hash-chained change log with SQLite backend.

Each audit entry includes a cryptographic hash of the previous entry,
creating a tamper-proof chain suitable for SOC 2 evidence and forensic
investigations. The chain is append-only and verifiable.

Hash computation:
    entry_hash = SHA-256(sequence_id || timestamp || event_type || actor ||
                         action || resource || details || previous_hash)

Genesis entry uses previous_hash = "sha256:" + "0"*64.
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

from ..models.metrics import AuditEntry, AuditQuery

logger = logging.getLogger(__name__)

AUDIT_DB_PATH = "data/audit_log.db"

# Redis key for persisting chain head across restarts
REDIS_KEY_CHAIN_HEAD = "sentinel:audit:chain_head"
REDIS_KEY_CHAIN_SEQ = "sentinel:audit:chain_sequence"

# Genesis previous_hash (first entry in the chain)
GENESIS_HASH = "sha256:" + "0" * 64


def compute_entry_hash(
    sequence_id: int,
    timestamp: str,
    event_type: str,
    actor: str,
    action: str,
    resource: str,
    details: str,
    previous_hash: str,
) -> str:
    """Compute SHA-256 hash for an audit entry.

    Uses '||' as field separator to prevent ambiguity attacks.
    """
    payload = "||".join([
        str(sequence_id),
        timestamp,
        event_type,
        actor,
        action,
        resource,
        details,
        previous_hash,
    ])
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


class AuditLogger:
    """Append-only audit log with hash-chaining for tamper detection."""

    def __init__(self, db_path: str = AUDIT_DB_PATH):
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.Lock()
        self._sequence_id: int = 0
        self._chain_head: str = GENESIS_HASH

    async def initialize(self) -> None:
        self._conn = sqlite3.connect(str(self._path), isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        # Original table (kept for backward compat with existing data)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                result TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                rollback_ref TEXT
            )
        """)
        # Hash-chain columns (added in Phase 3)
        self._migrate_chain_columns()
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC)
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor)
        """)
        self._conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_sequence
            ON audit_log(sequence_id) WHERE sequence_id IS NOT NULL
        """)
        # Restore chain state from DB or Redis
        self._restore_chain_state()

    def _migrate_chain_columns(self) -> None:
        """Add hash-chain columns if they don't exist (safe migration)."""
        if not self._conn:
            return
        # Check existing columns
        cursor = self._conn.execute("PRAGMA table_info(audit_log)")
        columns = {row[1] for row in cursor.fetchall()}
        if "sequence_id" not in columns:
            self._conn.execute(
                "ALTER TABLE audit_log ADD COLUMN sequence_id INTEGER"
            )
            logger.info("Migrated audit_log: added sequence_id column")
        if "previous_hash" not in columns:
            self._conn.execute(
                "ALTER TABLE audit_log ADD COLUMN previous_hash TEXT"
            )
            logger.info("Migrated audit_log: added previous_hash column")
        if "entry_hash" not in columns:
            self._conn.execute(
                "ALTER TABLE audit_log ADD COLUMN entry_hash TEXT"
            )
            logger.info("Migrated audit_log: added entry_hash column")

    def _restore_chain_state(self) -> None:
        """Restore sequence_id and chain_head from Redis or DB."""
        # Try Redis first (fast path)
        restored = self._restore_from_redis()
        if restored:
            return

        # Fallback: read last chained entry from DB
        if self._conn:
            row = self._conn.execute(
                "SELECT sequence_id, entry_hash FROM audit_log "
                "WHERE sequence_id IS NOT NULL AND entry_hash IS NOT NULL "
                "ORDER BY sequence_id DESC LIMIT 1"
            ).fetchone()
            if row:
                self._sequence_id = row[0]
                self._chain_head = row[1]
                logger.info(
                    "Restored chain state from DB: seq=%d head=%s",
                    self._sequence_id, self._chain_head[:20] + "...",
                )
            else:
                # No chained entries yet — start fresh
                self._sequence_id = 0
                self._chain_head = GENESIS_HASH
                logger.info("No existing chain found, starting from genesis")

    def _restore_from_redis(self) -> bool:
        """Try to restore chain state from Redis. Returns True if successful."""
        try:
            from .redis_sync import get_redis_client
            r = get_redis_client(timeout=1.0)
            if r is None:
                return False
            seq = r.get(REDIS_KEY_CHAIN_SEQ)
            head = r.get(REDIS_KEY_CHAIN_HEAD)
            if seq is not None and head is not None:
                self._sequence_id = int(seq)
                self._chain_head = head
                logger.info(
                    "Restored chain state from Redis: seq=%d head=%s",
                    self._sequence_id, self._chain_head[:20] + "...",
                )
                return True
        except Exception as e:
            logger.debug("Redis restore failed (non-critical): %s", e)
        return False

    def _persist_chain_head(self, sequence_id: int, entry_hash: str) -> None:
        """Persist chain head to Redis (best-effort, non-blocking)."""
        try:
            from .redis_sync import get_redis_client
            r = get_redis_client(timeout=1.0)
            if r is None:
                return
            pipe = r.pipeline()
            pipe.set(REDIS_KEY_CHAIN_SEQ, str(sequence_id))
            pipe.set(REDIS_KEY_CHAIN_HEAD, entry_hash)
            pipe.execute()
        except Exception as e:
            # Non-critical — chain state is always recoverable from DB
            logger.debug("Redis chain head persist failed (non-critical): %s", e)

    async def log(
        self,
        actor: str,
        action: str,
        resource_type: str,
        resource_id: str,
        payload: Optional[str] = None,
        result: str = "success",
        details: Optional[str] = None,
        ip_address: Optional[str] = None,
        rollback_ref: Optional[str] = None,
    ) -> AuditEntry:
        """Record an audit entry with hash-chain linking. Append-only."""
        now = datetime.now(timezone.utc)
        payload_hash = hashlib.sha256((payload or "").encode()).hexdigest()[:16]

        with self._lock:
            # Advance sequence (under lock for thread safety)
            self._sequence_id += 1
            seq_id = self._sequence_id
            previous_hash = self._chain_head

            # Compute entry hash
            resource = f"{resource_type}:{resource_id}"
            entry_hash = compute_entry_hash(
                sequence_id=seq_id,
                timestamp=now.isoformat(),
                event_type=resource_type,
                actor=actor,
                action=action,
                resource=resource,
                details=details or "",
                previous_hash=previous_hash,
            )

            # Update chain head
            self._chain_head = entry_hash

            entry = AuditEntry(
                id=str(uuid4()),
                timestamp=now,
                actor=actor,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                payload_hash=payload_hash,
                result=result,
                details=details,
                ip_address=ip_address,
                rollback_ref=rollback_ref,
                sequence_id=seq_id,
                previous_hash=previous_hash,
                entry_hash=entry_hash,
            )

            if self._conn:
                self._conn.execute(
                    "INSERT INTO audit_log VALUES "
                    "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        entry.id, entry.timestamp.isoformat(), entry.actor,
                        entry.action, entry.resource_type, entry.resource_id,
                        entry.payload_hash, entry.result, entry.details,
                        entry.ip_address, entry.rollback_ref,
                        entry.sequence_id, entry.previous_hash, entry.entry_hash,
                    ),
                )

        # Persist chain head to Redis (outside lock, best-effort)
        self._persist_chain_head(seq_id, entry_hash)
        return entry

    @property
    def chain_head(self) -> str:
        """Current chain head hash."""
        with self._lock:
            return self._chain_head

    @property
    def sequence_id(self) -> int:
        """Current sequence number (last written entry)."""
        with self._lock:
            return self._sequence_id

    async def get_entry_by_sequence(self, seq: int) -> Optional[AuditEntry]:
        """Retrieve a single entry by sequence_id."""
        with self._lock:
            if not self._conn:
                return None
            row = self._conn.execute(
                "SELECT * FROM audit_log WHERE sequence_id = ?", (seq,)
            ).fetchone()
            if not row:
                return None
            return self._row_to_entry(row)

    async def get_entries_range(
        self, start_seq: int, end_seq: int
    ) -> list[AuditEntry]:
        """Retrieve entries in a sequence range (inclusive), ordered by seq."""
        with self._lock:
            if not self._conn:
                return []
            rows = self._conn.execute(
                "SELECT * FROM audit_log "
                "WHERE sequence_id >= ? AND sequence_id <= ? "
                "ORDER BY sequence_id ASC",
                (start_seq, end_seq),
            ).fetchall()
            return [self._row_to_entry(row) for row in rows]

    async def query(self, q: AuditQuery) -> list[AuditEntry]:
        """Query audit log with filters."""
        conditions = []
        params: list = []
        if q.actor:
            conditions.append("actor = ?")
            params.append(q.actor)
        if q.action:
            conditions.append("action = ?")
            params.append(q.action)
        if q.resource_type:
            conditions.append("resource_type = ?")
            params.append(q.resource_type)
        if q.start_date:
            conditions.append("timestamp >= ?")
            params.append(q.start_date.isoformat())
        if q.end_date:
            conditions.append("timestamp <= ?")
            params.append(q.end_date.isoformat())

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"SELECT * FROM audit_log {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([q.limit, q.offset])

        entries = []
        with self._lock:
            if self._conn:
                rows = self._conn.execute(sql, params).fetchall()
                for row in rows:
                    entries.append(self._row_to_entry(row))
        return entries

    def _row_to_entry(self, row: tuple) -> AuditEntry:
        """Convert a DB row tuple to an AuditEntry model."""
        # Handle both old (11-column) and new (14-column) rows
        return AuditEntry(
            id=row[0],
            timestamp=datetime.fromisoformat(row[1]),
            actor=row[2],
            action=row[3],
            resource_type=row[4],
            resource_id=row[5],
            payload_hash=row[6],
            result=row[7],
            details=row[8],
            ip_address=row[9],
            rollback_ref=row[10],
            sequence_id=row[11] if len(row) > 11 else None,
            previous_hash=row[12] if len(row) > 12 else None,
            entry_hash=row[13] if len(row) > 13 else None,
        )

    async def close(self) -> None:
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None


# ─── PostgreSQL Backend (M-11) ────────────────────────────────────────────────


class PostgreSQLAuditLogger(AuditLogger):
    """PostgreSQL-backed audit logger for multi-replica HA deployments.

    Delegates to the shared DatabaseEngine. Chain state is persisted in Redis
    and synced across replicas. Each replica maintains a local cache of
    sequence_id/chain_head and refreshes from Redis on startup.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._sequence_id: int = 0
        self._chain_head: str = GENESIS_HASH
        self._conn = None  # Not used — kept for interface compat
        self._path = None
        self._db = None

    def _get_db(self):
        if self._db is None:
            from .database import get_database
            self._db = get_database()
        return self._db

    async def initialize(self) -> None:
        """Restore chain state from Redis or PostgreSQL."""
        # Try Redis first
        restored = self._restore_from_redis()
        if restored:
            return

        # Fallback: query PostgreSQL for last entry
        try:
            db = self._get_db()
            row = await db.fetch_one(
                "SELECT sequence_id, entry_hash FROM audit_log "
                "WHERE sequence_id IS NOT NULL AND entry_hash IS NOT NULL "
                "ORDER BY sequence_id DESC LIMIT 1"
            )
            if row:
                self._sequence_id = row["sequence_id"] or 0
                self._chain_head = row["entry_hash"] or GENESIS_HASH
                logger.info(
                    "Restored chain state from PostgreSQL: seq=%d",
                    self._sequence_id,
                )
            else:
                self._sequence_id = 0
                self._chain_head = GENESIS_HASH
        except Exception as e:
            logger.warning("PostgreSQL audit chain restore failed: %s", e)
            self._sequence_id = 0
            self._chain_head = GENESIS_HASH

    async def log(
        self,
        actor: str,
        action: str,
        resource_type: str,
        resource_id: str,
        payload: Optional[str] = None,
        result: str = "success",
        details: Optional[str] = None,
        ip_address: Optional[str] = None,
        rollback_ref: Optional[str] = None,
    ) -> AuditEntry:
        """Record an audit entry with hash-chain in PostgreSQL."""
        now = datetime.now(timezone.utc)
        payload_hash = hashlib.sha256((payload or "").encode()).hexdigest()[:16]

        with self._lock:
            self._sequence_id += 1
            seq_id = self._sequence_id
            previous_hash = self._chain_head

            resource = f"{resource_type}:{resource_id}"
            entry_hash = compute_entry_hash(
                sequence_id=seq_id,
                timestamp=now.isoformat(),
                event_type=resource_type,
                actor=actor,
                action=action,
                resource=resource,
                details=details or "",
                previous_hash=previous_hash,
            )
            self._chain_head = entry_hash

        entry = AuditEntry(
            id=str(uuid4()),
            timestamp=now,
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            payload_hash=payload_hash,
            result=result,
            details=details,
            ip_address=ip_address,
            rollback_ref=rollback_ref,
            sequence_id=seq_id,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
        )

        # Write to PostgreSQL
        try:
            db = self._get_db()
            await db.execute(
                "INSERT INTO audit_log (id, timestamp, actor, action, resource_type, resource_id, "
                "payload_hash, result, details, ip_address, rollback_ref, sequence_id, previous_hash, entry_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entry.id, entry.timestamp.isoformat(), entry.actor,
                    entry.action, entry.resource_type, entry.resource_id,
                    entry.payload_hash, entry.result, entry.details,
                    entry.ip_address, entry.rollback_ref,
                    entry.sequence_id, entry.previous_hash, entry.entry_hash,
                ),
            )
        except Exception as e:
            logger.error("Failed to write audit entry to PostgreSQL: %s", e)

        # Persist chain head to Redis
        self._persist_chain_head(seq_id, entry_hash)
        return entry

    async def get_entry_by_sequence(self, seq: int) -> Optional[AuditEntry]:
        try:
            db = self._get_db()
            row = await db.fetch_one(
                "SELECT * FROM audit_log WHERE sequence_id = ?", (seq,)
            )
            if not row:
                return None
            return self._dict_to_entry(dict(row))
        except Exception:
            return None

    async def get_entries_range(self, start_seq: int, end_seq: int) -> list[AuditEntry]:
        try:
            db = self._get_db()
            rows = await db.fetch_all(
                "SELECT * FROM audit_log WHERE sequence_id >= ? AND sequence_id <= ? ORDER BY sequence_id ASC",
                (start_seq, end_seq),
            )
            return [self._dict_to_entry(dict(r)) for r in rows]
        except Exception:
            return []

    async def query(self, q: AuditQuery) -> list[AuditEntry]:
        conditions = []
        params: list = []
        if q.actor:
            conditions.append("actor = ?")
            params.append(q.actor)
        if q.action:
            conditions.append("action = ?")
            params.append(q.action)
        if q.resource_type:
            conditions.append("resource_type = ?")
            params.append(q.resource_type)
        if q.start_date:
            conditions.append("timestamp >= ?")
            params.append(q.start_date.isoformat())
        if q.end_date:
            conditions.append("timestamp <= ?")
            params.append(q.end_date.isoformat())

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"SELECT * FROM audit_log {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([q.limit, q.offset])

        try:
            db = self._get_db()
            rows = await db.fetch_all(sql, params)
            return [self._dict_to_entry(dict(r)) for r in rows]
        except Exception:
            return []

    def _dict_to_entry(self, row: dict) -> AuditEntry:
        """Convert a dict row to AuditEntry model."""
        ts = row.get("timestamp")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        return AuditEntry(
            id=row["id"],
            timestamp=ts,
            actor=row["actor"],
            action=row["action"],
            resource_type=row["resource_type"],
            resource_id=row["resource_id"],
            payload_hash=row.get("payload_hash", ""),
            result=row.get("result", "unknown"),
            details=row.get("details"),
            ip_address=row.get("ip_address"),
            rollback_ref=row.get("rollback_ref"),
            sequence_id=row.get("sequence_id"),
            previous_hash=row.get("previous_hash"),
            entry_hash=row.get("entry_hash"),
        )

    async def close(self) -> None:
        """No-op — connection pool managed by database.py."""
        pass


# ─── Singleton ────────────────────────────────────────────────────────────────

_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get or create the singleton audit logger.

    M-11: Uses PostgreSQL backend when SENTINEL_ADMIN_DB_URL starts with
    'postgresql'. Otherwise uses legacy SQLite (backward compatible).
    """
    global _logger
    if _logger is None:
        from .database import ADMIN_DB_URL
        if ADMIN_DB_URL.startswith("postgresql") or ADMIN_DB_URL.startswith("postgres://"):
            _logger = PostgreSQLAuditLogger()
        else:
            _logger = AuditLogger()
    return _logger
