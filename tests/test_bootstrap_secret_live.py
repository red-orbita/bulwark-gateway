"""Actual PostgreSQL bootstrap migration/rotation on the owned TLS fixture only."""

import asyncio

import pytest

from admin.services.migrations import run_migrations
from admin.services.user_store import PostgreSQLUserStore, _verify_password
from tests.test_storage_database_live import local_pg as local_pg


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Do not initialize any operator database."""


@pytest.fixture
async def store(local_pg, monkeypatch):
    factory, _ = local_pg
    db = factory()
    await db.init()
    try:
        await db.execute_script("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        await run_migrations(db)
        secrets = {"ADMIN_PASSWORD": "BootstrapAdminPassw0rd!",
                   "SECURITY_PASSWORD": "BootstrapSecurityPassw0rd!", "AUDITOR_PASSWORD": "BootstrapAuditPassw0rd!"}
        monkeypatch.setattr("admin.services.secrets.read_secret", lambda name, default=None: secrets.get(name, default))
        instance = PostgreSQLUserStore()
        instance._db = db
        await asyncio.to_thread(instance._sync_seed_defaults, db)
        yield instance, db, secrets
    finally:
        await db.close()


async def test_v14_migrates_idempotently_and_records_bootstrap_hash(store):
    instance, db, _ = store
    await run_migrations(db)
    assert (await db.fetch_one("SELECT MAX(version) AS version FROM schema_migrations"))["version"] == 14
    user = await asyncio.to_thread(instance.get_user, "admin")
    assert user["bootstrap_password_hash"].startswith("$2")
    assert _verify_password("BootstrapAdminPassw0rd!", user["bootstrap_password_hash"])


async def test_user_password_survives_new_connection_and_actual_rotation(store, local_pg):
    instance, _, secrets = store
    account = await asyncio.to_thread(instance.get_user, "admin")
    await asyncio.to_thread(instance.change_password, account["id"], "OperatorChosenPassw0rd!")
    factory, _ = local_pg
    reopened = factory()
    await reopened.init()
    try:
        restarted = PostgreSQLUserStore()
        restarted._db = reopened
        await asyncio.to_thread(restarted._sync_seed_defaults, reopened)
        assert await asyncio.to_thread(restarted.verify_password, "admin", "OperatorChosenPassw0rd!")
        assert not await asyncio.to_thread(restarted.verify_password, "admin", secrets["ADMIN_PASSWORD"])
        assert not (await asyncio.to_thread(restarted.get_user, "admin"))["force_password_change"]
        secrets["ADMIN_PASSWORD"] = "RotatedBootstrapPassw0rd!"
        await asyncio.to_thread(restarted._sync_passwords_pg, reopened)
        assert await asyncio.to_thread(restarted.verify_password, "admin", secrets["ADMIN_PASSWORD"])
        assert not await asyncio.to_thread(restarted.verify_password, "admin", "OperatorChosenPassw0rd!")
        assert (await asyncio.to_thread(restarted.get_user, "admin"))["force_password_change"]
    finally:
        await reopened.close()


async def test_legacy_baseline_and_invalid_secret_preserve_credentials(store):
    instance, db, secrets = store
    account = await asyncio.to_thread(instance.get_user, "admin")
    await asyncio.to_thread(instance.change_password, account["id"], "OperatorChosenPassw0rd!")
    await db.execute("UPDATE users SET bootstrap_password_hash = NULL WHERE username = ?", ("admin",))
    secrets["ADMIN_PASSWORD"] = "\u00e9" * 40
    await asyncio.to_thread(instance._sync_passwords_pg, db)
    assert (await asyncio.to_thread(instance.get_user, "admin"))["bootstrap_password_hash"] is None
    assert await asyncio.to_thread(instance.verify_password, "admin", "OperatorChosenPassw0rd!")
    secrets["ADMIN_PASSWORD"] = "NewBaselineUnknownHistory1!"
    await asyncio.to_thread(instance._sync_passwords_pg, db)
    assert await asyncio.to_thread(instance.verify_password, "admin", "OperatorChosenPassw0rd!")
    assert not await asyncio.to_thread(instance.verify_password, "admin", secrets["ADMIN_PASSWORD"])


async def test_populated_v13_migrates_without_password_reset(local_pg, monkeypatch):
    from admin.services import migrations
    from admin.services.user_store import _hash_password

    factory, _ = local_pg
    db = factory()
    await db.init()
    try:
        await db.execute_script("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        with monkeypatch.context() as patch:
            patch.setattr(migrations, "MIGRATIONS", [m for m in migrations.MIGRATIONS if m.version <= 13])
            await migrations.run_migrations(db)
        original = _hash_password("ExistingOperatorPassw0rd!")
        await db.execute("INSERT INTO users (id,username,password_hash,role,active,force_password_change,created_at,updated_at) "
                         "VALUES (?,?,?,?,1,0,?,?)", ("existing", "admin", original, "admin",
                          "2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z"))
        await migrations.run_migrations(db)
        await migrations.run_migrations(db)
        row = await db.fetch_one("SELECT * FROM users WHERE id = ?", ("existing",))
        assert row["password_hash"] == original and row["bootstrap_password_hash"] is None
        assert not row["force_password_change"]
        monkeypatch.setattr("admin.services.secrets.read_secret", lambda name, default=None:
                            "UnchangedBootstrapPassw0rd!" if name == "ADMIN_PASSWORD" else default)
        instance = PostgreSQLUserStore()
        instance._db = db
        await asyncio.to_thread(instance._sync_passwords_pg, db)
        assert await asyncio.to_thread(instance.verify_password, "admin", "ExistingOperatorPassw0rd!")
        assert not (await asyncio.to_thread(instance.get_user, "admin"))["force_password_change"]
    finally:
        await db.close()
