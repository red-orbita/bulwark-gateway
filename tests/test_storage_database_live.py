"""Opt-in PostgreSQL codec tests on a uniquely owned, cached-image TLS lab.

Run with BULWARK_DB_REVIEW_LIVE=1. Never accepts an external database URL.
"""

import asyncio
import importlib.util
import json
import logging
import os
import ssl
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.storage.database import PostgreSQLEngine


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Never access the operator user database from the root fixture."""


@pytest.fixture(scope="module")
def local_pg(request):
    if os.environ.get("BULWARK_DB_REVIEW_LIVE") != "1":
        pytest.skip("BULWARK_DB_REVIEW_LIVE=1 required for isolated cached PostgreSQL")
    root = Path(__file__).resolve().parents[1]
    from scripts.validation_safety import validation_slot
    slot = validation_slot(root)
    slot.__enter__()
    request.addfinalizer(lambda: slot.__exit__(None, None, None))
    spec = importlib.util.spec_from_file_location("db_review_lab", root / "scripts/validation-live-stores.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    # Reuse containment/ownership/cleanup, but provision ONLY PostgreSQL.
    runner.IMAGES = {"postgres": runner.IMAGES["postgres"]}
    directory = Path(tempfile.mkdtemp(prefix="bulwark-validation-db-review-", dir=root / "shared"))
    lab = runner.Lab(directory, stores=("postgres",))
    patch = pytest.MonkeyPatch()
    for key in tuple(os.environ):
        if key.startswith(("BULWARK_", "ADMIN_", "PG")) or key in {"SSL_CERT_FILE", "SSL_CERT_DIR"}:
            patch.delenv(key)
    previous_logging = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        lab.preflight()
        name = lab.create("postgres")
        port = lab.port(name, 5432)
        patch.setenv("SSL_CERT_FILE", str(directory / "postgres/ca.pem"))
        password = (directory / "postgres/password").read_text()

        def engine(host="localhost", mode="verify-full"):
            return PostgreSQLEngine(
                f"postgresql://validator:{password}@{host}:{port}/validation",
                pool_min=1, pool_max=2, ssl=True, ssl_mode=mode,
            )

        async def ready():
            db = engine()
            try:
                for attempt in range(10):
                    try:
                        await db.init()
                        return
                    except RuntimeError:
                        if attempt == 9:
                            raise runner.LabError("postgres_not_ready") from None
                        await asyncio.sleep(1)
            finally:
                await db.close()

        asyncio.run(asyncio.wait_for(ready(), 90))
        yield engine, lab
    finally:
        try:
            lab.cleanup()
            lab.disk("after_cleanup")
            lab.report["status"] = "completed" if request.session.testsfailed == 0 else "failed"
            runner.private_file(directory / "report.json", json.dumps(lab.report, indent=2))
            assert all(item["status"] == "removed" for item in lab.report["cleanup"])
        finally:
            patch.undo()
            logging.disable(previous_logging)


@pytest.fixture
async def db(local_pg):
    engine, _ = local_pg
    db = engine()
    try:
        await db.init()
        await db.execute("CREATE TABLE IF NOT EXISTS codec_review "
                         "(id TEXT PRIMARY KEY, label TEXT, wall TIMESTAMP, instant TIMESTAMPTZ)")
        await db.execute("TRUNCATE codec_review")
        yield db
    finally:
        await db.close()


@pytest.mark.parametrize("path", ["pooled", "direct", "transaction"])
@pytest.mark.parametrize("native", [False, True])
async def test_live_text_and_timestamp_roundtrip(db, local_pg, path, native):
    _, lab = local_pg
    label = "2026-06-13T13:00:42Z"
    wall = datetime(2026, 6, 13, 13, 0, 42, 123456)
    instant = datetime.fromisoformat("2026-06-13T13:00:42.123456+05:30")
    params = (label, label, wall if native else wall.isoformat(), instant if native else instant.isoformat())
    insert = "INSERT INTO codec_review (id, label, wall, instant) VALUES (?, ?, ?, ?)"
    select = "SELECT * FROM codec_review WHERE id = ? AND wall = ? AND instant = ?"
    predicate = (label, params[2], params[3])
    if path == "direct":
        assert await asyncio.to_thread(db.sync_execute, insert, params) == 1
        row = await asyncio.to_thread(db.sync_fetch_one, select, predicate)
        rows = await asyncio.to_thread(db.sync_fetch_all, select, predicate)
    elif path == "transaction":
        async with db.transaction() as tx:
            assert await tx.execute(insert, params) == 1
            row = await tx.fetch_one(select, predicate)
            rows = await tx.fetch_all(select, predicate)
    else:
        assert await db.execute(insert, params) == 1
        row = await db.fetch_one(select, predicate)
        rows = await db.fetch_all(select, predicate)
    assert row["label"] == row["id"] == label
    assert row["wall"] == wall.isoformat()
    assert row["instant"] == instant.astimezone(timezone.utc).isoformat()
    assert rows[0].to_dict() == row.to_dict()
    # The raw driver still returns datetime, not strings, for actual timestamps.
    async with db._pool.acquire() as conn:
        raw = await conn.fetchrow("SELECT * FROM codec_review")
        assert raw["wall"] == wall and raw["instant"] == instant
        assert isinstance(raw["label"], str)
    lab.check(f"codec_roundtrip_{path}_{native}", True)


async def test_live_pool_growth_reconnect_datestyle_and_arrays(db, local_pg):
    _, lab = local_pg
    value = "1999-12-31T23:59:59.999999Z"
    async with db._pool.acquire() as first, db._pool.acquire() as second:
        for conn in (first, second):
            await conn.execute("SET DateStyle = 'SQL, DMY'; SET TIME ZONE 'Asia/Kolkata'")
            row = await conn.fetchrow("SELECT $1::timestamptz AS instant, $2::timestamp AS wall, "
                                      "$3::timestamptz[] AS instants", value, value[:-1], [value, None])
            assert row["instant"] == datetime.fromisoformat(value)
            assert row["wall"] == datetime.fromisoformat(value[:-1])
            assert row["instants"] == [datetime.fromisoformat(value), None]
            tls = await conn.fetchrow("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
            assert tls["ssl"] is True
    await db._pool.expire_connections()
    assert (await db.fetch_one("SELECT ?::timestamptz AS instant", (value,)))["instant"] == "1999-12-31T23:59:59.999999+00:00"
    lab.check("pool_growth_reconnect_datestyle_arrays_tls", True)


@pytest.mark.parametrize("path", ["pooled", "direct", "transaction"])
async def test_live_invalid_timestamp_rejected_without_timezone_guessing(db, local_pg, path):
    import asyncpg

    for kind, value in (("timestamp", "2026-06-13T13:00:42Z"),
                        ("timestamptz", "2026-06-13T13:00:42"),
                        ("timestamp", "2026-02-30T00:00:00")):
        query = "SELECT ?::timestamp" if kind == "timestamp" else "SELECT ?::timestamptz"
        with pytest.raises(asyncpg.DataError):
            if path == "direct":
                await asyncio.to_thread(db.sync_fetch_one, query, (value,))
            elif path == "transaction":
                async with db.transaction() as tx:
                    await tx.fetch_one(query, (value,))
            else:
                await db.fetch_one(query, (value,))
    assert (await db.fetch_one("SELECT ?::text AS label", (value,)))["label"] == value
    local_pg[1].check("invalid_timestamp_rejected_" + path, True)


async def test_live_real_store_migrations_with_iso_looking_text(db, local_pg, monkeypatch):
    from admin.services import investigation_case_store, investigation_observable_store
    from admin.services.migrations import run_migrations

    await run_migrations(db)
    monkeypatch.setattr(investigation_case_store, "get_database", lambda: db)
    monkeypatch.setattr(investigation_observable_store, "get_database", lambda: db)
    cases = investigation_case_store.CaseStore()
    observables = investigation_observable_store.ObservableStore()
    iso = "2026-06-13T13:00:42Z"
    case = await cases.create_case(title=iso, actor=iso, tenant=iso)
    fetched = await cases.get(case["case_id"])
    assert fetched["title"] == fetched["tenant"] == fetched["created_by"] == iso
    assert datetime.fromisoformat(fetched["created_at"]).tzinfo is not None
    obs = await observables.add(case_id=case["case_id"], observable_type="other", value=iso, actor=iso)
    assert obs["value"] == iso
    assert datetime.fromisoformat(obs["first_seen"]).tzinfo is not None
    local_pg[1].check("real_migrations_case_observable_text_and_timestamptz", True)


async def test_live_tls_policy_still_rejects_wrong_hostname(local_pg):
    engine, lab = local_pg
    bad = engine(host="127.0.0.1")
    with pytest.raises(Exception) as error:
        await asyncio.to_thread(bad.sync_fetch_one, "SELECT 1")
    assert isinstance(error.value, ssl.SSLCertVerificationError)
    lab.check("direct_wrong_hostname_rejected", True)


async def test_live_tls_wrong_ca_and_pooled_hostname_fail_closed(local_pg, monkeypatch):
    engine, lab = local_pg
    for host, ca in (("localhost", "wrong-ca.pem"), ("127.0.0.1", "ca.pem")):
        monkeypatch.setenv("SSL_CERT_FILE", str(lab.directory / "postgres" / ca))
        probe = engine(host=host)
        try:
            with pytest.raises(RuntimeError, match="^Failed to connect to PostgreSQL after 3 attempts$"):
                await probe.init()
            with pytest.raises(ssl.SSLCertVerificationError):
                await asyncio.to_thread(probe.sync_fetch_one, "SELECT 1")
            assert not probe._initialized
        finally:
            await probe.close()
    lab.check("pooled_and_direct_wrong_ca_hostname_rejected", True)
