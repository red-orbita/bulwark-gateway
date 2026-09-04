"""Live-PostgreSQL backend-parity smoke tests.

These are the first tests that exercise the admin store against a *real*
PostgreSQL (asyncpg). Previously the dual-backend layer
(``admin/services/database.py``) was only ever verified on SQLite plus
string-level ``QueryTranslator`` assertions and a hand-built fake exception for
the UNIQUE classifier — so a genuine dialect divergence (placeholder rewriting,
``INSERT OR REPLACE`` → ``ON CONFLICT`` upsert, a real ``23505`` error) could
ship undetected.

Every test here is gated on the ``pg_engine`` fixture, which skips unless
``BULWARK_TEST_POSTGRES_URL`` points at a throwaway PostgreSQL (CI provisions
one in a dedicated ``test-postgres`` job). Local SQLite-only runs are
unaffected — the whole module simply skips.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio


async def test_engine_inits_and_migrates(pg_engine):
    """A live PG engine reports healthy and the migration chain created tables."""
    health = await pg_engine.health_check()
    assert health["healthy"] is True
    assert health["backend"] == "postgresql"
    # audit_log is created by the real migration chain (v4 hash-chain columns).
    assert await pg_engine.table_exists("audit_log") is True
    assert await pg_engine.table_exists("does_not_exist_table") is False


async def test_crud_roundtrip_translates_placeholders(pg_engine):
    """? placeholders, rowcount, and Row semantics work end-to-end on asyncpg."""
    await pg_engine.execute(
        "CREATE TABLE parity_crud (id TEXT PRIMARY KEY, label TEXT NOT NULL)"
    )
    affected = await pg_engine.execute(
        "INSERT INTO parity_crud (id, label) VALUES (?, ?)", ("a", "alpha")
    )
    assert affected == 1

    row = await pg_engine.fetch_one(
        "SELECT id, label FROM parity_crud WHERE id = ?", ("a",)
    )
    assert row is not None
    assert row["label"] == "alpha"
    assert row.get("missing", "default") == "default"
    assert set(row.keys()) == {"id", "label"}

    await pg_engine.execute(
        "INSERT INTO parity_crud (id, label) VALUES (?, ?)", ("b", "beta")
    )
    rows = await pg_engine.fetch_all("SELECT id FROM parity_crud ORDER BY id")
    assert [r["id"] for r in rows] == ["a", "b"]


async def test_insert_or_replace_becomes_upsert(pg_engine):
    """The translator's INSERT OR REPLACE → ON CONFLICT DO UPDATE path must
    actually upsert on live PostgreSQL, not raise or duplicate."""
    await pg_engine.execute(
        "CREATE TABLE parity_upsert (id TEXT PRIMARY KEY, val TEXT NOT NULL)"
    )
    await pg_engine.execute(
        "INSERT OR REPLACE INTO parity_upsert (id, val) VALUES (?, ?)", ("k", "v1")
    )
    await pg_engine.execute(
        "INSERT OR REPLACE INTO parity_upsert (id, val) VALUES (?, ?)", ("k", "v2")
    )

    rows = await pg_engine.fetch_all("SELECT id, val FROM parity_upsert")
    assert len(rows) == 1
    assert rows[0]["val"] == "v2"


async def test_is_unique_violation_recognises_real_asyncpg_error(pg_engine):
    """The dialect-neutral classifier must recognise a *real* asyncpg
    UniqueViolationError (SQLSTATE 23505), not only a hand-built fake."""
    from admin.services.database import is_unique_violation

    await pg_engine.execute("CREATE TABLE parity_uniq (id TEXT PRIMARY KEY)")
    await pg_engine.execute("INSERT INTO parity_uniq (id) VALUES (?)", ("dup",))

    with pytest.raises(Exception) as excinfo:  # noqa: PT011  (asserted below)
        await pg_engine.execute("INSERT INTO parity_uniq (id) VALUES (?)", ("dup",))

    assert is_unique_violation(excinfo.value) is True


async def test_transaction_commit_and_rollback(pg_engine):
    """Atomic transaction context commits on success and rolls back on error."""
    await pg_engine.execute("CREATE TABLE parity_tx (id TEXT PRIMARY KEY)")

    async with pg_engine.transaction() as tx:
        await tx.execute("INSERT INTO parity_tx (id) VALUES (?)", ("committed",))

    rows = await pg_engine.fetch_all("SELECT id FROM parity_tx")
    assert [r["id"] for r in rows] == ["committed"]

    with pytest.raises(RuntimeError):
        async with pg_engine.transaction() as tx:
            await tx.execute("INSERT INTO parity_tx (id) VALUES (?)", ("rolled-back",))
            raise RuntimeError("force rollback")

    rows = await pg_engine.fetch_all("SELECT id FROM parity_tx ORDER BY id")
    assert [r["id"] for r in rows] == ["committed"]


async def test_timestamptz_reads_back_as_iso_string(pg_engine):
    """A TIMESTAMPTZ column must read back as an ISO-8601 *string*, matching the
    SQLite (TEXT) contract stores are authored against.

    asyncpg natively returns ``datetime`` for TIMESTAMPTZ; the engine's read-side
    normalization (``_pg_row``) coerces it to an ISO string so a store's public
    JSON contract does not silently differ between backends. Regression guard for
    that symmetric-coercion fix.
    """
    from datetime import datetime, timezone

    await pg_engine.execute(
        "CREATE TABLE parity_ts (id TEXT PRIMARY KEY, seen TIMESTAMPTZ NOT NULL)"
    )
    written = datetime(2026, 6, 13, 13, 0, 42, 841174, tzinfo=timezone.utc).isoformat()
    # The write side coerces the ISO string → datetime for asyncpg.
    await pg_engine.execute(
        "INSERT INTO parity_ts (id, seen) VALUES (?, ?)", ("a", written)
    )

    row = await pg_engine.fetch_one("SELECT id, seen FROM parity_ts WHERE id = ?", ("a",))
    assert row is not None
    assert isinstance(row["seen"], str)
    # Round-trips to the exact instant that was written.
    assert datetime.fromisoformat(row["seen"]) == datetime.fromisoformat(written)

