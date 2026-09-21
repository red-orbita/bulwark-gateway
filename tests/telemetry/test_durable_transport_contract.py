"""Registration/startup contract, with real transports but no external I/O."""

import json
from unittest.mock import AsyncMock

import pytest

from src.storage.database import create_engine
from src.telemetry import exporter as exporter_module
from src.telemetry.exporter import TelemetryExporter, load_transports_from_config
from src.telemetry.queue import TelemetryQueue
from src.telemetry.shared_outbox import get_shared_outbox
from src.telemetry.transports.file_shipper import FileShipperConfig, FileShipperTransport
from src.telemetry.transports.http_rest import HttpRestTransport, HttpTransportConfig


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Override the root fixture: never open the operator user database."""


@pytest.fixture(params=["local", "shared-sqlite", "shared-postgresql"])
async def durable_exporter(request, tmp_path):
    if request.param == "local":
        queue = TelemetryQueue(disk_path=str(tmp_path / "outbox.db"), durable=True, shared=False)
    else:
        url = (f"sqlite:///{tmp_path / 'shared.db'}" if request.param == "shared-sqlite"
               else "postgresql://unused.invalid/test")
        queue = TelemetryQueue(shared_outbox=get_shared_outbox(db=create_engine(url)))
    try:
        yield TelemetryExporter(queue=queue)
    finally:
        await queue.aclose()


def test_file_shipper_rejected_before_destination_registration(durable_exporter, tmp_path):
    transport = FileShipperTransport(FileShipperConfig(path=str(tmp_path / "events.ndjson")))
    with pytest.raises(ValueError, match="FileShipperTransport.*durable telemetry"):
        durable_exporter.add_transport(transport, destination_id="file", revision="a" * 64)
    assert durable_exporter._transports == []
    assert durable_exporter._queue._destinations == ()
    assert transport._file is None
    assert not (tmp_path / "events.ndjson").exists()


@pytest.mark.parametrize("config", [None, [], [{"transport_type": "file", "enabled": False}]])
async def test_no_default_seed_and_no_start_without_transports(
    durable_exporter, tmp_path, monkeypatch, config,
):
    path = tmp_path / "siem_transports.json"
    if config is not None:
        path.write_text(json.dumps(config))
    monkeypatch.setenv("BULWARK_SIEM_TRANSPORTS_FILE", str(path))
    monkeypatch.setenv("BULWARK_TELEMETRY_ENABLED", "true")
    monkeypatch.setattr(exporter_module, "EXPORTER_ENABLED", True)
    initialize = AsyncMock()
    monkeypatch.setattr(durable_exporter._queue, "initialize", initialize)
    before = set(tmp_path.iterdir())
    load_transports_from_config(durable_exporter)
    with pytest.raises(RuntimeError, match="explicitly configured supported transport"):
        await durable_exporter.start()
    initialize.assert_not_awaited()
    assert not durable_exporter._initialized
    assert not durable_exporter._running
    assert durable_exporter._task is None
    assert durable_exporter._stats_task is None
    assert set(tmp_path.iterdir()) == before


@pytest.mark.parametrize("with_http", [False, True])
def test_configured_file_rejection_is_not_swallowed(durable_exporter, tmp_path, monkeypatch, with_http):
    configs = [{"transport_type": "http_rest", "endpoint": "https://unused.invalid/collect"}] if with_http else []
    configs.append({"transport_type": "file", "endpoint": str(tmp_path / "events.ndjson")})
    path = tmp_path / "siem_transports.json"
    path.write_text(json.dumps(configs))
    monkeypatch.setenv("BULWARK_SIEM_TRANSPORTS_FILE", str(path))
    with pytest.raises(RuntimeError, match="FileShipperTransport is unsupported"):
        load_transports_from_config(durable_exporter)
    assert all(not isinstance(tw.transport, FileShipperTransport) for tw in durable_exporter._transports)
    assert json.loads(path.read_text()) == configs
    assert not (tmp_path / "events.ndjson").exists()


def test_invalid_durable_config_fails_explicitly(durable_exporter, tmp_path, monkeypatch):
    path = tmp_path / "siem_transports.json"
    path.write_text("not json")
    monkeypatch.setenv("BULWARK_SIEM_TRANSPORTS_FILE", str(path))
    with pytest.raises(RuntimeError, match="Unable to load durable telemetry transport configuration"):
        load_transports_from_config(durable_exporter)


def test_mixed_valid_and_unknown_destination_cannot_start(durable_exporter, tmp_path, monkeypatch):
    path = tmp_path / "transports.json"
    path.write_text(json.dumps([
        {"transport_type": "http_rest", "endpoint": "https://unused.invalid/collect"},
        {"transport_type": "http_rets", "endpoint": "https://unused.invalid/other"},
    ]))
    monkeypatch.setenv("BULWARK_SIEM_TRANSPORTS_FILE", str(path))
    with pytest.raises(RuntimeError, match="Unable to register durable"):
        load_transports_from_config(durable_exporter)


async def test_http_permitted_and_can_start(durable_exporter, monkeypatch):
    transport = HttpRestTransport(HttpTransportConfig(url="https://unused.invalid/collect"))
    durable_exporter.add_transport(transport)
    assert durable_exporter._transports[0].transport is transport
    if durable_exporter._queue.shared:
        assert len(durable_exporter._queue._destinations) == 1
    monkeypatch.setenv("BULWARK_TELEMETRY_ENABLED", "true")
    monkeypatch.setattr(durable_exporter._queue, "initialize", AsyncMock())
    monkeypatch.setattr(durable_exporter, "_run_loop", AsyncMock())
    monkeypatch.setattr(durable_exporter, "_stats_flush_loop", AsyncMock())
    monkeypatch.setattr(durable_exporter, "_flush_shared", AsyncMock())
    monkeypatch.setattr(durable_exporter, "_persist_stats", lambda: None)
    try:
        await durable_exporter.start()
        assert durable_exporter._running
        assert durable_exporter._task is not None
    finally:
        await durable_exporter.stop()


async def test_disabled_durable_exporter_remains_inert(durable_exporter, monkeypatch):
    monkeypatch.setenv("BULWARK_TELEMETRY_ENABLED", "false")
    await durable_exporter.start()
    assert not durable_exporter._running
    assert not durable_exporter._initialized


async def test_legacy_empty_start_and_file_auto_seed_unchanged(tmp_path, monkeypatch):
    queue = TelemetryQueue(disk_path=str(tmp_path / "legacy.db"), durable=False, shared=False)
    exporter = TelemetryExporter(queue=queue)
    path = tmp_path / "siem_transports.json"
    monkeypatch.setenv("BULWARK_TELEMETRY_ENABLED", "true")
    monkeypatch.setenv("BULWARK_SIEM_TRANSPORTS_FILE", str(path))
    monkeypatch.setattr(exporter_module, "EXPORTER_ENABLED", True)
    monkeypatch.setattr(exporter, "_persist_stats", lambda: None)
    try:
        await exporter.start()
        assert exporter._running
        assert exporter._stats_task is not None
        assert exporter._task is None
        load_transports_from_config(exporter)
        assert json.loads(path.read_text())[0]["id"] == "auto-default"
        assert isinstance(exporter._transports[0].transport, FileShipperTransport)
    finally:
        await exporter.stop()
