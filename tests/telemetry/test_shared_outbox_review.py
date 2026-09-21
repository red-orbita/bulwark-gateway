"""Regression tests for independently reviewed shared-outbox boundary failures."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.storage import database
from src.telemetry.exporter import TelemetryExporter
from src.telemetry.queue import TelemetryQueue
from src.telemetry.shared_outbox import get_shared_outbox
from src.telemetry.transports.http_rest import HttpAuthMethod, HttpRestTransport, HttpTransportConfig

from .test_shared_outbox import Transport, event
from .test_shared_outbox import store as _store

store = _store


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Do not open the operator user database."""


@pytest.mark.parametrize("failure", ["missing", "empty", "whitespace", "unreadable", "unset_path", "directory"])
def test_configured_database_secret_never_falls_back(tmp_path, monkeypatch, failure):
    secret = tmp_path / "database-secret"
    if failure in ("empty", "whitespace", "unreadable"):
        secret.write_text("\n " if failure == "whitespace" else "", encoding="utf-8")
    if failure == "directory":
        secret.mkdir()
    monkeypatch.setenv("BULWARK_ADMIN_DB_URL_FILE", "" if failure == "unset_path" else str(secret))
    monkeypatch.setenv("BULWARK_ADMIN_DB_URL", "sqlite:///forbidden-fallback.db")
    if failure == "unreadable":
        def denied(*args, **kwargs):
            raise PermissionError("SYNTHETIC_SECRET must not escape")
        monkeypatch.setattr("builtins.open", denied)
    with pytest.raises(RuntimeError, match="readable and nonempty") as error:
        database._read_db_url()
    assert "SYNTHETIC_SECRET" not in str(error.value)
    assert str(secret) not in str(error.value)


def test_database_secret_precedence_and_absent_file_setting(tmp_path, monkeypatch):
    secret = tmp_path / "database-secret"
    secret.write_text("postgresql://unused.invalid/authoritative\n", encoding="utf-8")
    monkeypatch.setenv("BULWARK_ADMIN_DB_URL_FILE", str(secret))
    monkeypatch.setenv("BULWARK_ADMIN_DB_URL", "sqlite:///not-selected.db")
    assert database._read_db_url() == "postgresql://unused.invalid/authoritative"
    monkeypatch.delenv("BULWARK_ADMIN_DB_URL_FILE")
    assert database._read_db_url() == "sqlite:///not-selected.db"


def tls_transport(tmp_path):
    paths = {}
    for name in ("tls_ca", "tls_cert", "tls_key"):
        path = tmp_path / name
        path.write_bytes(b"SYNTHETIC_TLS_MATERIAL_" + name.encode())
        paths[name] = str(path)
    return HttpRestTransport(HttpTransportConfig(url="https://unused.invalid/collect",
                                                auth_method=HttpAuthMethod.MTLS, **paths))


@pytest.mark.parametrize("name", ["tls_ca", "tls_cert", "tls_key"])
async def test_tls_same_path_replacement_changes_identity_and_blocks_send(store, tmp_path, name, caplog):
    transport = tls_transport(tmp_path)
    exporter = TelemetryExporter(queue=TelemetryQueue(shared_outbox=store))
    exporter.add_transport(transport)
    tw = exporter._transports[0]
    pinned = tw.pinned_tls
    try:
        assert pinned is not None
        assert await exporter._queue.enqueue(event())
        original = Path(getattr(pinned.transport._config, name)).read_bytes()
        with pytest.raises(OSError):
            Path(getattr(pinned.transport._config, name)).write_bytes(b"overwrite sealed memory")
        pinned.transport.send_batch = AsyncMock(return_value=True)
        Path(getattr(transport._config, name)).write_bytes(b"SYNTHETIC_REPLACEMENT")
        assert TelemetryExporter._transport_revision(transport) != tw.snapshot.revision
        assert Path(getattr(pinned.transport._config, name)).read_bytes() == original
        await exporter._flush_shared()
        pinned.transport.send_batch.assert_not_awaited()
        assert (await store.status())["events"] == 1
        row = await store._db.fetch_one("SELECT snapshot FROM telemetry_outbox_deliveries")
        assert "SYNTHETIC" not in row["snapshot"]
        assert "SYNTHETIC" not in caplog.text
    finally:
        if pinned:
            pinned.release()


async def test_tls_change_after_verification_cannot_change_transport_material(store, tmp_path, monkeypatch):
    transport = tls_transport(tmp_path)
    exporter = TelemetryExporter(queue=TelemetryQueue(shared_outbox=store))
    exporter.add_transport(transport)
    pinned = exporter._transports[0].pinned_tls
    try:
        expected = {name: Path(getattr(transport._config, name)).read_bytes()
                    for name in ("tls_ca", "tls_cert", "tls_key")}
        assert await exporter._queue.enqueue(event())
        claim = store.claim

        async def claim_and_rotate(*args, **kwargs):
            leases = await claim(*args, **kwargs)
            for name in expected:
                Path(getattr(transport._config, name)).write_bytes(b"SYNTHETIC_RACE_REPLACEMENT")
            return leases

        async def send(batch):
            # Simulates the transport's deferred load of CA/cert/private-key.
            for name, data in expected.items():
                assert Path(getattr(pinned.transport._config, name)).read_bytes() == data
            return True

        monkeypatch.setattr(store, "claim", claim_and_rotate)
        monkeypatch.setattr(pinned.transport, "send_batch", AsyncMock(side_effect=send))
        await exporter._flush_shared()
        pinned.transport.send_batch.assert_awaited_once()
        assert (await store.status())["events"] == 0
    finally:
        pinned.release()


async def test_tls_missing_before_send_retains_evidence(store, tmp_path):
    transport = tls_transport(tmp_path)
    exporter = TelemetryExporter(queue=TelemetryQueue(shared_outbox=store))
    exporter.add_transport(transport)
    pinned = exporter._transports[0].pinned_tls
    try:
        assert await exporter._queue.enqueue(event())
        Path(transport._config.tls_key).unlink()
        pinned.transport.send_batch = AsyncMock()
        await exporter._flush_shared()
        pinned.transport.send_batch.assert_not_awaited()
        assert (await store.status())["events"] == 1
    finally:
        pinned.release()


def test_tls_replica_same_paths_different_material_cannot_collide(tmp_path):
    transport = tls_transport(tmp_path)
    first = TelemetryExporter._transport_revision(transport)
    Path(transport._config.tls_cert).write_bytes(b"SYNTHETIC_DIFFERENT_PRINCIPAL")
    assert TelemetryExporter._transport_revision(transport) != first


@pytest.mark.parametrize("backend", ["sqlite", "postgresql"])
@pytest.mark.parametrize("mode", ["disabled", "never_started", "init_failed"])
async def test_shared_stop_without_successful_start_never_flushes(tmp_path, monkeypatch, backend, mode):
    url = f"sqlite:///{tmp_path / 'unstarted.db'}" if backend == "sqlite" else "postgresql://unused.invalid/test"
    engine = database.create_engine(url)
    outbox = get_shared_outbox(db=engine)
    exporter = TelemetryExporter(queue=TelemetryQueue(shared_outbox=outbox))
    transport = Transport()
    exporter.add_transport(transport, revision="a" * 64)
    monkeypatch.setattr(exporter, "_flush_shared", AsyncMock(side_effect=AssertionError("must not flush")))
    monkeypatch.setattr(exporter, "_persist_stats", lambda: None)
    if mode == "disabled":
        monkeypatch.setenv("BULWARK_TELEMETRY_ENABLED", "false")
        await exporter.start()
    elif mode == "init_failed":
        monkeypatch.setenv("BULWARK_TELEMETRY_ENABLED", "true")
        monkeypatch.setattr(engine, "init", AsyncMock(side_effect=RuntimeError("synthetic startup failure")))
        with pytest.raises(RuntimeError):
            await exporter.start()
    await exporter.stop()
    exporter._flush_shared.assert_not_awaited()
    transport.close.assert_awaited_once()
    assert outbox._closed
    assert not exporter._initialized


async def test_http_mtls_reads_pinned_bytes_even_after_source_rotation(store, tmp_path, monkeypatch):
    import httpx

    import src.telemetry.transports.http_rest as http_module

    transport = tls_transport(tmp_path)
    exporter = TelemetryExporter(queue=TelemetryQueue(shared_outbox=store))
    exporter.add_transport(transport)
    pinned = exporter._transports[0].pinned_tls
    expected = {name: Path(getattr(transport._config, name)).read_bytes()
                for name in ("tls_ca", "tls_cert", "tls_key")}
    contexts = []

    class Context:
        def load_cert_chain(self, cert, key):
            assert Path(cert).read_bytes() == expected["tls_cert"]
            assert Path(key).read_bytes() == expected["tls_key"]

    def context(cafile):
        assert Path(cafile).read_bytes() == expected["tls_ca"]
        result = Context()
        contexts.append(result)
        return result

    def rotate_during_ssrf_check(url):
        # send_batch performs this check after the exporter's revision check.
        for name in expected:
            Path(getattr(transport._config, name)).write_bytes(b"SYNTHETIC_NEW_PRINCIPAL")
        return False

    post = AsyncMock(return_value=httpx.Response(200))

    class Client:
        def __init__(self, **kwargs):
            assert kwargs["verify"] is contexts[-1]
            self.post = post

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

    monkeypatch.setattr(http_module, "ssl", SimpleNamespace(create_default_context=context))
    monkeypatch.setattr(http_module, "_is_ssrf_target", rotate_during_ssrf_check)
    monkeypatch.setattr(httpx, "AsyncClient", Client)
    try:
        assert await exporter._queue.enqueue(event())
        await exporter._flush_shared()
        post.assert_awaited_once()
        assert len(contexts) == 1
        assert (await store.status())["events"] == 0
    finally:
        pinned.release()


async def test_pinned_tls_close_failure_still_releases_fds_and_closes_database(store, tmp_path, monkeypatch):
    import os

    exporter = TelemetryExporter(queue=TelemetryQueue(shared_outbox=store))
    exporter.add_transport(tls_transport(tmp_path))
    pinned = exporter._transports[0].pinned_tls
    fds = list(pinned._fds)
    monkeypatch.setattr(pinned.transport, "close", AsyncMock(side_effect=RuntimeError("synthetic close failure")))
    monkeypatch.setattr(exporter, "_persist_stats", lambda: None)
    await exporter.stop()
    assert store._closed
    assert pinned._fds == []
    for fd in fds:
        with pytest.raises(OSError):
            os.fstat(fd)


async def test_tls_sealing_unavailable_fails_registration_without_route(store, tmp_path, monkeypatch):
    import os

    def unavailable(*args):
        raise OSError("SYNTHETIC_OS_ERROR")

    monkeypatch.setattr(os, "memfd_create", unavailable)
    exporter = TelemetryExporter(queue=TelemetryQueue(shared_outbox=store))
    with pytest.raises(ValueError, match="Unable to pin shared TLS material"):
        exporter.add_transport(tls_transport(tmp_path))
    assert exporter._transports == []
    assert not await exporter._queue.enqueue(event())
