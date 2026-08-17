"""Schema migration tests.

Focus: the audit_log hash-chain columns (v4). Regression guard for the
PostgreSQL schema drift where chained INSERTs failed with
'column "sequence_id" of relation "audit_log" does not exist'.

The functional test runs the *real* migration chain against a throwaway
SQLite database and proves audit_log ends up writable with the hash-chain
columns — i.e. the schema the audit loggers actually INSERT into.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from admin.services.database import create_engine
from admin.services.migrations import (
    MIGRATIONS,
    get_migration_status,
    run_migrations,
)

CHAIN_COLUMNS = ("sequence_id", "previous_hash", "entry_hash")


# ─── Structural ──────────────────────────────────────────────────────────────

def test_migration_v4_defines_hash_chain_columns():
    """v4 must exist and add all three hash-chain columns on both backends."""
    v4 = next((m for m in MIGRATIONS if m.version == 4), None)
    assert v4 is not None, "migration v4 is missing"
    for backend in ("sqlite", "postgresql"):
        sql = v4.get_sql(backend).lower()
        for col in CHAIN_COLUMNS:
            assert col in sql, f"v4 ({backend}) does not add {col}"
        assert "alter table audit_log" in sql


def test_postgres_v4_is_self_healing():
    """Running clusters already have a broken audit_log at v3 — the PG path must
    use IF NOT EXISTS so re-adding the columns can't crash startup."""
    v4 = next(m for m in MIGRATIONS if m.version == 4)
    pg = v4.get_sql("postgresql").lower()
    assert pg.count("add column if not exists") == len(CHAIN_COLUMNS)


def test_migration_versions_are_unique_and_ordered():
    versions = [m.version for m in MIGRATIONS]
    assert versions == sorted(versions), "migrations must be in ascending order"
    assert len(versions) == len(set(versions)), "duplicate migration version"


# ─── Functional (real migration chain on a temp SQLite DB) ───────────────────

async def _fresh_engine(tmp_path):
    db_path = tmp_path / "admin_test.db"
    engine = create_engine(f"sqlite:///{db_path}")
    await engine.init()
    return engine


@pytest.mark.asyncio
async def test_full_chain_makes_audit_log_hash_chain_writable(tmp_path):
    engine = await _fresh_engine(tmp_path)
    try:
        await run_migrations(engine)

        # audit_log must physically carry the hash-chain columns now
        cols = {
            row["name"]
            for row in await engine.fetch_all("PRAGMA table_info(audit_log)")
        }
        for col in CHAIN_COLUMNS:
            assert col in cols, f"audit_log missing {col} after migrations"

        # …and be writable through those columns (the exact shape both loggers
        # INSERT). Before v4 this raised 'no column named sequence_id'.
        now = datetime.now(timezone.utc).isoformat()
        await engine.execute(
            "INSERT INTO audit_log (id, timestamp, actor, action, resource_type, "
            "resource_id, payload_hash, result, details, ip_address, rollback_ref, "
            "sequence_id, previous_hash, entry_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()), now, "admin", "login", "session", "s1",
                "deadbeef", "success", None, "127.0.0.1", None,
                1, "sha256:" + "0" * 64, "sha256:" + "a" * 64,
            ),
        )
        row = await engine.fetch_one(
            "SELECT sequence_id, entry_hash FROM audit_log WHERE sequence_id = ?",
            (1,),
        )
        assert row is not None and row["sequence_id"] == 1
    finally:
        await engine.close()


@pytest.mark.asyncio
async def test_full_chain_reports_current_version_at_head(tmp_path):
    engine = await _fresh_engine(tmp_path)
    try:
        await run_migrations(engine)
        status = await get_migration_status(engine)
        assert status["current_version"] == MIGRATIONS[-1].version
        assert status["pending_count"] == 0
    finally:
        await engine.close()


@pytest.mark.asyncio
async def test_migrations_are_idempotent(tmp_path):
    """Re-running migrations must be a no-op, not a crash (rolling restarts)."""
    engine = await _fresh_engine(tmp_path)
    try:
        await run_migrations(engine)
        await run_migrations(engine)  # second pass — nothing pending
        status = await get_migration_status(engine)
        assert status["current_version"] == MIGRATIONS[-1].version
    finally:
        await engine.close()
