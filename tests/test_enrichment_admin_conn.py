"""Regression tests for the admin enrichment route's read-only DB connection.

The proxy owns ``attack_replay.db`` and may replace the file wholesale (backup /
restore from snapshot, PVC remount). The admin route caches a module-level
read-only SQLite connection for performance; previously that handle was cached
*forever*, so after a file swap the admin dashboard kept reading the old inode
and silently froze on a stale entry count while the live DB kept growing.

``_get_conn()`` now tracks the file's ``(st_dev, st_ino)`` identity and
transparently reconnects when the underlying file is swapped.
"""

import os
import sqlite3
from pathlib import Path

import pytest

from admin.routes import enrichment


def _make_db(path: Path, rows: int) -> None:
    """Create a WAL-mode replay DB with ``rows`` rows in ``replay_entries``."""
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS replay_entries "
            "(id INTEGER PRIMARY KEY AUTOINCREMENT, verdict TEXT)"
        )
        conn.executemany(
            "INSERT INTO replay_entries (verdict) VALUES (?)",
            [("block",) for _ in range(rows)],
        )
        conn.commit()
    finally:
        conn.close()


@pytest.fixture
def _reset_conn():
    """Isolate the module-level connection cache around each test."""
    original_path = enrichment._REPLAY_DB_PATH
    enrichment._close_conn()
    yield
    enrichment._close_conn()
    enrichment._REPLAY_DB_PATH = original_path


def _count(path: Path) -> int:
    enrichment._REPLAY_DB_PATH = Path(path)
    row = enrichment._query_one("SELECT COUNT(*) as cnt FROM replay_entries")
    return row["cnt"] if row else -1


def test_count_reflects_current_db(_reset_conn, tmp_path):
    db = tmp_path / "attack_replay.db"
    _make_db(db, 5)
    assert _count(db) == 5


def test_reconnects_after_file_swap(_reset_conn, tmp_path):
    """A wholesale file replacement (new inode) must be picked up transparently."""
    db = tmp_path / "attack_replay.db"
    _make_db(db, 5)

    # Prime the cached connection against the original inode.
    assert _count(db) == 5
    first_ino = db.stat().st_ino

    # Simulate the proxy restoring a fresh DB: build it out-of-place then
    # atomically swap it in so the path points at a brand-new inode.
    replacement = tmp_path / "attack_replay.db.new"
    _make_db(replacement, 12)
    assert replacement.stat().st_ino != first_ino
    os.replace(replacement, db)  # inode of `db` changes

    # Without inode tracking the cached handle would still report 5.
    assert _count(db) == 12


def test_missing_file_then_appears(_reset_conn, tmp_path):
    db = tmp_path / "attack_replay.db"

    # File absent → no connection, query returns nothing (route treats as empty).
    enrichment._REPLAY_DB_PATH = Path(db)
    assert enrichment._get_conn() is None
    assert enrichment._query_one("SELECT COUNT(*) as cnt FROM replay_entries") is None

    # File later created by the proxy → admin transparently connects.
    _make_db(db, 3)
    assert _count(db) == 3


def test_repeated_reads_reuse_connection(_reset_conn, tmp_path):
    """No inode change → the same cached handle is reused (no churn)."""
    db = tmp_path / "attack_replay.db"
    _make_db(db, 4)

    enrichment._REPLAY_DB_PATH = Path(db)
    conn_a = enrichment._get_conn()
    conn_b = enrichment._get_conn()
    assert conn_a is conn_b
    assert conn_a is not None
