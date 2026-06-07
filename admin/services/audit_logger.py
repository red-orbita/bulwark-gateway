"""Audit Logger — Immutable change log with SQLite backend."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

from ..models.metrics import AuditEntry, AuditQuery

AUDIT_DB_PATH = "data/audit_log.db"


class AuditLogger:
    """Append-only audit log for all admin operations."""

    def __init__(self, db_path: str = AUDIT_DB_PATH):
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.Lock()

    async def initialize(self) -> None:
        self._conn = sqlite3.connect(str(self._path), isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
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
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC)
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor)
        """)

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
        """Record an audit entry. Append-only, never modified."""
        entry = AuditEntry(
            id=str(uuid4()),
            timestamp=datetime.now(timezone.utc),
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            payload_hash=hashlib.sha256((payload or "").encode()).hexdigest()[:16],
            result=result,
            details=details,
            ip_address=ip_address,
            rollback_ref=rollback_ref,
        )
        with self._lock:
            if self._conn:
                self._conn.execute(
                    "INSERT INTO audit_log VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        entry.id, entry.timestamp.isoformat(), entry.actor,
                        entry.action, entry.resource_type, entry.resource_id,
                        entry.payload_hash, entry.result, entry.details,
                        entry.ip_address, entry.rollback_ref,
                    ),
                )
        return entry

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
                    entries.append(AuditEntry(
                        id=row[0], timestamp=datetime.fromisoformat(row[1]),
                        actor=row[2], action=row[3], resource_type=row[4],
                        resource_id=row[5], payload_hash=row[6], result=row[7],
                        details=row[8], ip_address=row[9], rollback_ref=row[10],
                    ))
        return entries

    async def close(self) -> None:
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None


_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    global _logger
    if _logger is None:
        _logger = AuditLogger()
    return _logger
