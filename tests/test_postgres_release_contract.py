"""Release-gated real-driver contracts using ONLY the disposable pg_engine fixture.

No Docker opt-in or secondary DSN: CI supplies BULWARK_TEST_POSTGRES_URL.
The shared fixture owns schema reset and engine shutdown, not these tests.
"""

import asyncio
import hashlib
from datetime import datetime, timezone

import pytest

from admin.services.investigation_task_store import TaskStore
from admin.services.migrations import run_migrations
from admin.services.user_store import PostgreSQLUserStore
from src.attachments.store import PostgreSQLAttachmentStore, StoreError
from src.storage.database import create_engine
from src.telemetry.schema import BulwarkFields, SecurityTelemetryEvent, TenantFields
from src.telemetry.shared_outbox import DestinationSnapshot, get_shared_outbox

pytestmark = pytest.mark.asyncio
ISO_TEXT = "2026-06-13T13:00:42.123456+05:30"


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Do not open the unrelated operator user database from the root fixture."""


@pytest.mark.parametrize("path", ["pooled", "direct", "transaction"])
@pytest.mark.parametrize("native", [False, True], ids=["iso", "datetime"])
async def test_timestamp_codecs_preserve_text_and_real_timestamp_columns(pg_engine, path, native):
    await pg_engine.execute(
        "CREATE TABLE release_codec (id TEXT PRIMARY KEY, label TEXT NOT NULL, "
        "local_time TIMESTAMP NOT NULL, instant TIMESTAMPTZ NOT NULL)"
    )
    local = datetime(1999, 12, 31, 23, 59, 59, 999999)
    instant = datetime.fromisoformat(ISO_TEXT)
    params = (ISO_TEXT, ISO_TEXT, local if native else local.isoformat(),
              instant if native else ISO_TEXT)
    insert = "INSERT INTO release_codec (id, label, local_time, instant) VALUES (?, ?, ?, ?)"
    select = "SELECT * FROM release_codec WHERE id = ? AND label = ? AND local_time = ? AND instant = ?"
    if path == "transaction":
        async with pg_engine.transaction() as tx:
            assert await tx.execute(insert, params) == 1
            row = await tx.fetch_one(select, params)
            rows = await tx.fetch_all(select, params)
    elif path == "direct":
        # Direct APIs create independent asyncpg connections, outside the pool.
        assert await asyncio.to_thread(pg_engine.sync_execute, insert, params) == 1
        row = await asyncio.to_thread(pg_engine.sync_fetch_one, select, params)
        rows = await asyncio.to_thread(pg_engine.sync_fetch_all, select, params)
    else:
        assert await pg_engine.execute(insert, params) == 1
        row = await pg_engine.fetch_one(select, params)
        rows = await pg_engine.fetch_all(select, params)
    assert row is not None and len(rows) == 1
    for record in (row, rows[0]):
        assert record["id"] == record["label"] == ISO_TEXT
        assert isinstance(record["local_time"], str) and isinstance(record["instant"], str)
        assert datetime.fromisoformat(record["local_time"]) == local
        assert datetime.fromisoformat(record["instant"]) == instant
    # Transaction writes must also remain readable through the pooled connection.
    assert (await pg_engine.fetch_one(select, params))["label"] == ISO_TEXT


async def test_invalid_timestamp_rolls_back_without_corrupting_text(pg_engine):
    import asyncpg

    await pg_engine.execute("CREATE TABLE release_invalid (label TEXT, instant TIMESTAMPTZ)")
    with pytest.raises(asyncpg.DataError):
        async with pg_engine.transaction() as tx:
            await tx.execute("INSERT INTO release_invalid VALUES (?, ?)", (ISO_TEXT, ISO_TEXT))
            await tx.execute("INSERT INTO release_invalid VALUES (?, ?)", (ISO_TEXT, "2026-06-13T13:00:42"))
    assert not await pg_engine.fetch_all("SELECT * FROM release_invalid")
    await pg_engine.execute("INSERT INTO release_invalid VALUES (?, ?)", (ISO_TEXT, ISO_TEXT))
    assert (await pg_engine.fetch_one("SELECT label FROM release_invalid"))["label"] == ISO_TEXT


async def test_attachment_migrations_scope_and_reclaimed_lease_fencing(pg_engine):
    store = PostgreSQLAttachmentStore(pg_engine)
    await store.initialize()
    replica = PostgreSQLAttachmentStore(pg_engine)
    await replica.initialize()  # Real idempotent migration, not the ready fast path.
    assert await pg_engine.table_exists("attachment_documents")
    assert (await pg_engine.fetch_one("SELECT version FROM attachment_store_state"))["version"] == 1
    scope = {"tenant": ISO_TEXT, "agent": "agent-a", "owner": "owner-a"}
    doc = await store.create(**scope, mime="text/plain", raw=b"release fixture", policy_revision=ISO_TEXT)
    for field in scope:
        wrong = {**scope, field: "other"}
        assert await replica.get(doc["id"], **wrong) is None
        assert not await replica.delete(doc["id"], **wrong)
        with pytest.raises(StoreError, match="^not_found$"):
            await replica.resolve(doc["id"], **wrong, policy_revision=ISO_TEXT)
    first = await store.claim()
    assert first is not None and first["id"] == doc["id"]
    assert await replica.claim() is None
    await pg_engine.execute("UPDATE attachment_documents SET lease_until = 0 WHERE id = ?", (doc["id"],))
    current = await replica.claim()
    assert current is not None and current["lease_token"] != first["lease_token"]
    assert not await store.finish(doc["id"], first["lease_token"], state="approved", text="stale")
    assert await replica.finish(doc["id"], current["lease_token"], state="approved", text=ISO_TEXT)
    assert await store.resolve(doc["id"], **scope, policy_revision=ISO_TEXT) == ISO_TEXT
    with pytest.raises(StoreError, match="^policy_changed$"):
        await store.resolve(doc["id"], **scope, policy_revision="different")
    assert await store.delete(doc["id"], **scope)
    state = await pg_engine.fetch_one("SELECT documents, bytes FROM attachment_store_state")
    assert state["documents"] == state["bytes"] == 0


async def test_outbox_migrations_scope_fanout_and_ack_fencing(pg_engine):
    store = get_shared_outbox(db=pg_engine)
    await store.initialize()
    replica = get_shared_outbox(db=pg_engine)
    await replica.initialize()
    assert await pg_engine.table_exists("telemetry_outbox_deliveries")
    assert (await pg_engine.fetch_one("SELECT version FROM telemetry_outbox_state"))["version"] == 1
    destination = DestinationSnapshot(destination_id="release-a", tenant_scope=(ISO_TEXT,),
                                      revision=hashlib.sha256(b"release").hexdigest())
    second = destination.model_copy(update={"destination_id": "release-b"})
    event = SecurityTelemetryEvent(bulwark=BulwarkFields(verdict="block"), tenant=TenantFields(id=ISO_TEXT))
    wrong = event.model_copy(update={"tenant": TenantFields(id="other")})
    assert not await store.enqueue(wrong, (destination,))
    assert await store.enqueue(event, (destination, second))
    assert not await replica.claim(destination.model_copy(update={"tenant_scope": None}))
    assert not await replica.claim(destination.model_copy(update={"revision": hashlib.sha256(b"changed").hexdigest()}))
    first = await store.claim(destination)
    assert len(first) == 1 and first[0].tenant == ISO_TEXT
    assert not await replica.claim(destination)
    await pg_engine.execute("UPDATE telemetry_outbox_deliveries SET lease_until = 0 WHERE lease_token = ?",
                            (first[0].token,))
    current = await replica.claim(destination)
    assert len(current) == 1 and current[0].token != first[0].token
    assert await store.finish(first, success=True) == 0
    assert await store.finish([current[0].model_copy(update={"tenant": "other"})], success=True) == 0
    assert await replica.finish(current, success=True) == 1
    assert (await store.status())["events"] == 1  # Second destination still unacknowledged.
    pending = await store.claim(second)
    assert len(pending) == 1 and pending[0].event.event.id == event.event.id
    assert await store.finish(pending, success=True) == 1
    state = await replica.status()
    assert state["events"] == state["bytes"] == 0
    assert state["acked"] == 2


async def test_task_due_dates_match_sqlite_and_preserve_timestamp_looking_text(pg_engine, tmp_path, monkeypatch):
    sqlite = create_engine(f"sqlite:///{tmp_path / 'release-tasks.db'}")
    await sqlite.init()
    try:
        await run_migrations(sqlite)
        results = []
        for db in (sqlite, pg_engine):
            store = TaskStore()
            monkeypatch.setattr(store, "_db", lambda db=db: db)
            task = await store.add(case_id="release-case", title=ISO_TEXT, actor=ISO_TEXT,
                                   assignee=ISO_TEXT, due_at=ISO_TEXT)
            expected = datetime.fromisoformat(ISO_TEXT).astimezone(timezone.utc).isoformat()
            assert task["due_at"] == expected
            assert task["title"] == task["created_by"] == task["assignee"] == ISO_TEXT
            assert await store.get("other-case", task["task_id"]) is None
            updated = await store.set_state(case_id="release-case", task_id=task["task_id"],
                                           actor="reviewer", due_at="2026-06-14T13:00:42.654321Z")
            assert updated["due_at"] == "2026-06-14T13:00:42.654321+00:00"
            with pytest.raises(ValueError, match="explicit timezone"):
                await store.set_state(case_id="release-case", task_id=task["task_id"],
                                      actor="reviewer", due_at="2026-06-14T13:00:42")
            assert (await store.get("release-case", task["task_id"]))["due_at"] == updated["due_at"]
            cleared = await store.set_state(case_id="release-case", task_id=task["task_id"],
                                           actor="reviewer", due_at="")
            assert cleared["due_at"] is None
            results.append((task["due_at"], updated["due_at"], cleared["due_at"]))
        assert results[0] == results[1]
    finally:
        await sqlite.close()


async def test_bootstrap_v14_preserves_operator_password_and_rotates_explicit_secret(pg_engine, monkeypatch):
    values = {"ADMIN_PASSWORD": "BootstrapAdminPassw0rd!", "SECURITY_PASSWORD": "BootstrapSecurityPassw0rd!",
              "AUDITOR_PASSWORD": "BootstrapAuditPassw0rd!"}
    monkeypatch.setattr("admin.services.secrets.read_secret", lambda name, default=None: values.get(name, default))
    store = PostgreSQLUserStore()
    store._db = pg_engine
    await asyncio.to_thread(store._sync_seed_defaults, pg_engine)
    account = await asyncio.to_thread(store.get_user, "admin")
    await asyncio.to_thread(store.change_password, account["id"], "OperatorChosenPassw0rd!")
    await run_migrations(pg_engine)
    await asyncio.to_thread(store._sync_seed_defaults, pg_engine)
    assert await asyncio.to_thread(store.verify_password, "admin", "OperatorChosenPassw0rd!")
    assert not await asyncio.to_thread(store.verify_password, "admin", values["ADMIN_PASSWORD"])
    values["ADMIN_PASSWORD"] = "RotatedBootstrapPassw0rd!"
    await asyncio.to_thread(store._sync_passwords_pg, pg_engine)
    assert await asyncio.to_thread(store.verify_password, "admin", values["ADMIN_PASSWORD"])
    assert (await asyncio.to_thread(store.get_user, "admin"))["force_password_change"]
