"""PostgreSQL driver mocks, no server, sockets or credentials."""

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock

import pytest

from src.storage.database import PostgreSQLEngine, _PostgreSQLTransaction
from src.storage.outbox_migrations import POSTGRESQL_V1, SQLITE_V1, migrate_outbox
from src.telemetry.shared_outbox import PostgreSQLSharedOutbox, get_shared_outbox

from .test_shared_outbox import destination, event


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Do not access the real user database from root fixtures."""


class Pool:
    def __init__(self, conn):
        self.conn = conn

    @asynccontextmanager
    async def acquire(self):
        yield self.conn


class Connection:
    def __init__(self):
        self.execute = AsyncMock(return_value="UPDATE 1")
        self.fetchrow = AsyncMock()
        self.fetch = AsyncMock(return_value=[])
        self.commits = 0
        self.rollbacks = 0

    @asynccontextmanager
    async def transaction(self):
        try:
            yield
        except BaseException:
            self.rollbacks += 1
            raise
        else:
            self.commits += 1


@pytest.fixture
def pg():
    engine = PostgreSQLEngine("postgresql://unused.invalid/test")
    conn = Connection()
    engine._pool = Pool(conn)
    engine._initialized = True
    return engine, conn


async def test_pg_migration_transaction_lock_and_explicit_dialect(pg):
    engine, conn = pg
    conn.fetchrow.return_value = {"version": 0, "max_events": 10, "max_bytes": 1000}
    await migrate_outbox(engine, 10, 1000)
    calls = [call.args for call in conn.execute.await_args_list]
    assert calls[0] == ("SELECT pg_advisory_xact_lock($1)", 0x42574F38)
    assert all("?" not in args[0] for args in calls)
    assert any("DOUBLE PRECISION" in args[0] for args in calls)
    assert not any("PRAGMA" in args[0] or "SERIAL" in args[0] for args in calls)
    assert conn.commits == 1
    assert len(SQLITE_V1) == len(POSTGRESQL_V1) == 3


async def test_pg_enqueue_claim_ack_sql_and_fencing(pg):
    engine, conn = pg
    outbox = get_shared_outbox(db=engine)
    assert isinstance(outbox, PostgreSQLSharedOutbox)
    outbox._ready = True
    original = event("2026-06-13T13:00:42Z")
    d = destination(tenants=None)
    conn.fetchrow.side_effect = [{"now": 100.0}, None]
    assert await outbox.enqueue(original, (d,))
    inserts = [call.args for call in conn.execute.await_args_list if call.args[0].startswith("INSERT")]
    key = inserts[0][1]
    # Text tenant IDs that look like timestamps stay strings through the legacy
    # translator, because the storage representation is a JSON string literal.
    assert inserts[0][2] == '"2026-06-13T13:00:42Z"'
    assert original.tenant.id not in inserts[0][0]
    conn.fetch.return_value = [{"event_id": key, "attempts": 0, "size_bytes": 1000}]
    conn.fetchrow.side_effect = [
        {"now": 101.0},
        {"tenant": inserts[0][2], "payload": original.model_dump_json(by_alias=True, exclude_none=True),
         "snapshot": d.model_dump_json()},
    ]
    leases = await outbox.claim(d)
    assert len(leases) == 1
    update = next(call.args for call in conn.execute.await_args_list
                  if "lease_token = $1" in call.args[0])
    assert update[2] == 161.0
    conn.fetchrow.side_effect = [{"now": 102.0}, None, {"size_bytes": 1000}]
    assert await outbox.finish(leases, success=True) == 1
    delete = next(call.args for call in conn.execute.await_args_list
                  if call.args[0].startswith("DELETE FROM telemetry_outbox_deliveries"))
    assert "lease_token = $3 AND lease_until > $4" in delete[0]
    assert "e.tenant = $5" in delete[0]
    assert delete[3] == leases[0].token
    assert conn.commits == 3


async def test_pg_failure_rolls_back_and_never_falls_back(pg, caplog):
    engine, conn = pg
    outbox = get_shared_outbox(db=engine)
    outbox._ready = True
    conn.execute.side_effect = RuntimeError("SYNTHETIC_SECRET")
    assert not await outbox.enqueue(event(), (destination(),))
    assert conn.rollbacks == 1
    assert outbox.errors == outbox.rejected == 1
    assert "SYNTHETIC_SECRET" not in caplog.text


def test_admin_shim_reuses_same_engines_and_factory(monkeypatch):
    from admin.services import database as admin_db
    from src.storage import database as shared_db
    assert admin_db.SQLiteEngine is shared_db.SQLiteEngine
    assert admin_db.PostgreSQLEngine is shared_db.PostgreSQLEngine
    assert admin_db._PostgreSQLTransaction is _PostgreSQLTransaction
    monkeypatch.setattr(admin_db, "ADMIN_DB_URL", "postgresql://unused.invalid/test")
    assert isinstance(admin_db.create_engine(), shared_db.PostgreSQLEngine)
