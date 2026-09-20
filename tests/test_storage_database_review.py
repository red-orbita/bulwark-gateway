"""Offline regressions for shared DB TLS, diagnostics and parameter typing."""

import logging
import ssl
import sys
import traceback
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.storage import database


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Override the root fixture: these tests must not open the user database."""


@pytest.fixture
def driver(monkeypatch):
    conn = SimpleNamespace(
        execute=AsyncMock(return_value="INSERT 0 1"),
        fetchrow=AsyncMock(return_value={"ok": 1}),
        fetch=AsyncMock(return_value=[{"ok": 1}]),
        close=AsyncMock(),
        set_type_codec=AsyncMock(),
    )
    pg = SimpleNamespace(create_pool=AsyncMock(), connect=AsyncMock(return_value=conn))
    monkeypatch.setitem(sys.modules, "asyncpg", pg)
    return pg


@pytest.mark.parametrize("mode", ["verify-full", "verify-ca", "require", "disable"])
@pytest.mark.parametrize("method", ["sync_execute", "sync_fetch_one", "sync_fetch_all"])
async def test_pool_and_direct_connections_share_tls_policy(driver, mode, method):
    engine = database.PostgreSQLEngine(
        "postgresql+asyncpg://unused.invalid/test", ssl=True, ssl_mode=mode,
    )
    await engine.init()
    getattr(engine, method)("SELECT 1")

    for call in (driver.create_pool.call_args, driver.connect.call_args):
        assert call.kwargs["dsn"] == "postgresql://unused.invalid/test"
        context = call.kwargs["ssl"]
        if mode == "disable":
            assert context is False
        else:
            assert isinstance(context, ssl.SSLContext)
            assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
            assert context.check_hostname is (mode == "verify-full")
            expected = ssl.CERT_NONE if mode == "require" else ssl.CERT_REQUIRED
            assert context.verify_mode == expected
    driver.connect.return_value.close.assert_awaited_once()
    assert driver.create_pool.call_args.kwargs["init"] is database._init_pg_codecs
    assert driver.connect.return_value.set_type_codec.await_count == 2
    await engine.close()


async def test_unset_tls_override_preserves_driver_dsn_settings(driver):
    engine = database.PostgreSQLEngine(
        "postgresql://unused.invalid/test?sslmode=verify-full", ssl=False,
    )
    await engine.init()
    engine.sync_fetch_one("SELECT 1")
    assert "ssl" not in driver.create_pool.call_args.kwargs
    assert "ssl" not in driver.connect.call_args.kwargs
    assert driver.connect.call_args.kwargs["dsn"].endswith("sslmode=verify-full")
    await engine.close()


@pytest.mark.parametrize("mode", ["verify-ful", "prefer", "", "/private/TLS_SECRET"])
async def test_unknown_tls_mode_fails_closed_without_disclosing_value(driver, mode):
    engine = database.PostgreSQLEngine("postgresql://unused.invalid/test", ssl=True, ssl_mode=mode)
    with pytest.raises(ValueError, match="^Unsupported PostgreSQL TLS mode$"):
        await engine.init()
    with pytest.raises(ValueError, match="^Unsupported PostgreSQL TLS mode$"):
        engine.sync_fetch_one("SELECT 1")
    driver.create_pool.assert_not_called()
    driver.connect.assert_not_called()


async def test_tls_setup_failure_is_sanitized_and_never_connects(driver, monkeypatch):
    def fail_context():
        raise OSError("/private/CA_SECRET.pem")

    monkeypatch.setattr(ssl, "create_default_context", fail_context)
    engine = database.PostgreSQLEngine("postgresql://unused.invalid/test", ssl=True, ssl_mode="verify-full")
    with pytest.raises(RuntimeError, match="^Failed to configure PostgreSQL TLS$") as error:
        await engine.init()
    assert error.value.__cause__ is None
    assert error.value.__suppress_context__
    assert "CA_SECRET" not in "".join(traceback.format_exception(error.value))
    driver.create_pool.assert_not_called()


@pytest.mark.parametrize("url", [
    "mysql://DB_USER:DB_PASSWORD@private.invalid/private-db?key=DB_KEY",
    "file:///private/DB_PATH?key=DB_KEY",
    "unknown://DB_USER:DB_PASSWORD@private.invalid/DB_PATH\nDB_KEY",
])
def test_unsupported_url_error_never_discloses_dsn(url, caplog):
    # Suppress even an ambient exception: it may itself contain credentials.
    try:
        raise RuntimeError(url)
    except RuntimeError:
        with pytest.raises(ValueError) as error:
            database.create_engine(url)
    assert str(error.value) == "Unsupported database URL scheme. Supported: sqlite, postgresql"
    assert error.value.__cause__ is None
    assert error.value.__suppress_context__
    rendered = "".join(traceback.format_exception(error.value)) + caplog.text
    for secret in ("DB_USER", "DB_PASSWORD", "private.invalid", "DB_PATH", "DB_KEY"):
        assert secret not in rendered


async def test_pool_retry_diagnostics_never_disclose_driver_errors(driver, monkeypatch, caplog):
    driver.create_pool.side_effect = RuntimeError(
        "postgresql://DB_USER:DB_PASSWORD@private.invalid/private-db /private/DB_PATH"
    )
    sleep = AsyncMock()
    monkeypatch.setattr(database.asyncio, "sleep", sleep)
    engine = database.PostgreSQLEngine("postgresql://unused.invalid/test")
    with caplog.at_level(logging.WARNING, logger=database.__name__):
        with pytest.raises(RuntimeError, match="^Failed to connect to PostgreSQL after 3 attempts$") as error:
            await engine.init()
    assert not engine._initialized
    assert engine._pool is None
    assert driver.create_pool.await_count == database.MAX_RETRIES
    assert [call.args[0] for call in sleep.await_args_list] == [0.5, 1.0, 2.0]
    assert len(caplog.records) == database.MAX_RETRIES
    assert all(record.exc_info is None for record in caplog.records)
    assert error.value.__cause__ is None
    assert error.value.__suppress_context__
    rendered = "".join(traceback.format_exception(error.value)) + caplog.text
    for secret in ("DB_USER", "DB_PASSWORD", "private.invalid", "private-db", "DB_PATH"):
        assert secret not in rendered


async def test_pg_health_failure_never_returns_driver_details():
    @asynccontextmanager
    async def acquire():
        raise RuntimeError("DB_PASSWORD /private/DB_PATH")
        yield  # pragma: no cover

    engine = database.PostgreSQLEngine("postgresql://unused.invalid/test")
    engine._pool = SimpleNamespace(acquire=acquire)
    health = await engine.health_check()
    assert health["healthy"] is False
    assert health["error"] == "PostgreSQL health check failed"
    assert "DB_PASSWORD" not in str(health)
    assert "DB_PATH" not in str(health)


@pytest.mark.parametrize("value", [
    "2026-06-13T13:00:42Z",
    "2026-06-13T13:00:42.123456+00:00",
    datetime(2026, 6, 13, 13, 0, 42, tzinfo=timezone.utc),
])
async def test_real_timestamp_parameter_contract_is_preserved(value):
    # investigation_case.created_at is TIMESTAMPTZ in the PostgreSQL migration;
    # Model the resolved type selecting its codec, not translator guessing.
    codec_conn = SimpleNamespace(set_type_codec=AsyncMock())
    await database._init_pg_codecs(codec_conn)
    codec = codec_conn.set_type_codec.await_args_list[1].kwargs

    async def insert(query, timestamp):
        assert query == "INSERT INTO investigation_case (created_at) VALUES ($1)"
        assert timestamp == value
        expected = datetime.fromisoformat(value) if isinstance(value, str) else value
        assert codec["decoder"](codec["encoder"](timestamp)) == expected
        return "INSERT 0 1"

    conn = SimpleNamespace(execute=AsyncMock(side_effect=insert))
    tx = database._PostgreSQLTransaction(conn, database.QueryTranslator("postgresql"))
    assert await tx.execute("INSERT INTO investigation_case (created_at) VALUES (?)", (value,)) == 1
    conn.execute.assert_awaited_once()


async def test_iso_looking_text_parameter_must_remain_text():
    value = "2026-06-13T13:00:42Z"

    async def insert(query, title):
        assert query == "INSERT INTO investigation_case (title) VALUES ($1)"
        # title is TEXT in both dialects, not TIMESTAMPTZ like created_at above.
        assert isinstance(title, str)
        assert title == value
        return "INSERT 0 1"

    conn = SimpleNamespace(execute=AsyncMock(side_effect=insert))
    tx = database._PostgreSQLTransaction(conn, database.QueryTranslator("postgresql"))
    assert await tx.execute("INSERT INTO investigation_case (title) VALUES (?)", (value,)) == 1


def test_sqlite_keeps_iso_text_and_native_timestamps_unchanged():
    params = ("2026-06-13T13:00:42Z", datetime(2026, 6, 13, tzinfo=timezone.utc))
    query = "INSERT INTO investigation_case (title, created_at) VALUES (?, ?)"
    assert database.QueryTranslator("sqlite").translate(query, params) == (query, params)


@pytest.mark.parametrize("aware", [False, True])
async def test_type_codecs_are_exact_and_preserve_microseconds_and_offsets(aware):
    conn = SimpleNamespace(set_type_codec=AsyncMock())
    await database._init_pg_codecs(conn)
    calls = conn.set_type_codec.await_args_list
    assert [call.args for call in calls] == [("timestamp",), ("timestamptz",)]
    assert all(call.kwargs["schema"] == "pg_catalog" and call.kwargs["format"] == "tuple" for call in calls)
    codec = calls[int(aware)].kwargs
    zone = timezone(timedelta(hours=5, minutes=30)) if aware else None
    for value in (datetime(1999, 12, 31, 23, 59, 59, 999999, zone),
                  datetime(2026, 6, 13, 13, 0, 42, 123456, zone)):
        for parameter in (value, value.isoformat()):
            decoded = codec["decoder"](codec["encoder"](parameter))
            assert decoded == value
            assert decoded.tzinfo == (timezone.utc if aware else None)
    assert codec["decoder"]((2**63 - 1,)) == datetime.max
    assert codec["decoder"]((-(2**63),)) == datetime.min


@pytest.mark.parametrize("aware,value", [
    (True, "2026-06-13T13:00:42"),
    (True, datetime(2026, 6, 13)),
    (False, "2026-06-13T13:00:42Z"),
    (False, datetime(2026, 6, 13, tzinfo=timezone.utc)),
    (True, "2026-06-13"),
    (False, "2026-02-30T00:00:00"),
    (True, "now"),
    (True, "infinity"),
    (True, "2026-06-13T13:00:42.1234567Z"),
    (True, "2026-06-13T13:00:42+25:00"),
    (True, "2026-06-13T13:00:42+01:60"),
    (True, "2026-06-13T13:00:42+01:00:60"),
    (False, "PRIVATE_TIMESTAMP_SECRET"),
    (False, "x" * 100_000),
    (False, 100),
])
async def test_timestamp_codecs_reject_ambiguous_or_invalid_values(aware, value):
    conn = SimpleNamespace(set_type_codec=AsyncMock())
    await database._init_pg_codecs(conn)
    codec = conn.set_type_codec.await_args_list[int(aware)].kwargs
    with pytest.raises(ValueError, match="^Expected .* ISO datetime for timestamp") as error:
        codec["encoder"](value)
    assert error.value.__suppress_context__
    assert "PRIVATE_TIMESTAMP_SECRET" not in "".join(traceback.format_exception(error.value))


@pytest.mark.parametrize("method", ["sync_execute", "sync_fetch_one", "sync_fetch_all"])
@pytest.mark.parametrize("in_loop", [False, True])
async def test_direct_codec_setup_failure_closes_connection_before_query(driver, method, in_loop):
    conn = driver.connect.return_value
    conn.set_type_codec.side_effect = RuntimeError("PRIVATE_CODEC_SECRET /private/codec")
    engine = database.PostgreSQLEngine("postgresql://unused.invalid/test")
    import asyncio

    with pytest.raises(RuntimeError, match="^Failed to configure PostgreSQL timestamp codecs$") as error:
        if in_loop:
            getattr(engine, method)("SELECT 1")
        else:
            await asyncio.to_thread(getattr(engine, method), "SELECT 1")
    assert error.value.__suppress_context__
    assert "PRIVATE_CODEC_SECRET" not in "".join(traceback.format_exception(error.value))
    conn.close.assert_awaited_once()
    conn.execute.assert_not_called()
    conn.fetchrow.assert_not_called()
    conn.fetch.assert_not_called()
