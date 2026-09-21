"""Admission-only tests: temporary SQLite and mocks, no remote services."""

import asyncio
import threading
from unittest.mock import AsyncMock

import pytest

from src.storage.database import create_engine
from src.telemetry.admission import admit_before_upstream
from src.telemetry.exporter import TelemetryExporter
from src.telemetry.queue import TelemetryQueue
from src.telemetry.shared_outbox import SharedOutbox


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Override the root fixture: never open the operator users database."""


class Transport:
    name = "audit-test"

    def __init__(self):
        self.send_batch = AsyncMock(side_effect=AssertionError("No remote calls during admission"))
        self.close = AsyncMock()


def exporter_for(queue, scope="global"):
    exporter = TelemetryExporter(queue=queue)
    exporter.add_transport(Transport(), tenant_scope=scope, revision="a" * 64)
    # Inject lifecycle state without starting background export or stats I/O.
    exporter._initialized = True
    exporter._running = True
    return exporter


async def admit(exporter, **overrides):
    args = dict(required=True, exporter=exporter, authenticated=True,
                tenant_id="tenant-a", agent_id="agent-a", request_id="a" * 32, timeout_ms=1000)
    args.update(overrides)
    return await admit_before_upstream(**args)


@pytest.fixture
def local(tmp_path):
    queue = TelemetryQueue(disk_path=str(tmp_path / "local.db"), durable=True, shared=False)
    exporter = exporter_for(queue)
    try:
        yield exporter
    finally:
        queue.close()


async def test_disabled_does_not_inspect_state_or_validate_context():
    assert await admit(object(), required=False, authenticated=False, timeout_ms=0, tenant_id=None) is None


@pytest.mark.parametrize("value", [0, -1, 10001])
def test_invalid_admission_budget_rejected_at_settings_load(value):
    from pydantic import ValidationError

    from src.config import Settings
    with pytest.raises(ValidationError):
        Settings(audit_admission_timeout_ms=value)


async def test_real_local_commit_count_privacy_and_restart(local, tmp_path):
    for _ in range(3):
        assert await admit(local) is None
    queue = local._queue
    assert queue.stats["enqueued"] == queue.disk_depth == 3
    assert queue.memory_depth == 0
    batch = await queue.dequeue_batch()
    assert len({e.event.id for e in batch}) == 3
    record = batch[0]
    assert record.event.kind == "event"
    assert record.event.category == "web"
    assert record.event.action == "upstream_admission"
    assert record.event.outcome == "unknown"
    assert record.bulwark.verdict == "not_evaluated"
    assert record.bulwark.request_id == "a" * 32
    assert record.tenant.id == "tenant-a"
    assert record.tenant.agent_id == "agent-a"
    assert record.labels == {}
    assert record.source.model_dump(exclude_none=True) == {}
    assert record.bulwark.input_hash is None
    assert record.bulwark.matched_pattern is None
    assert record.bulwark.session_id is None
    local._transports[0].transport.send_batch.assert_not_awaited()
    queue.close()
    reopened = TelemetryQueue(disk_path=str(tmp_path / "local.db"), durable=True, shared=False)
    try:
        assert reopened.disk_depth == 3
        assert [e.event.id for e in await reopened.dequeue_batch()] == [e.event.id for e in batch]
    finally:
        reopened.close()


@pytest.mark.parametrize("timeout", [0, -1, 10001, float("inf"), float("nan"), True, "250"])
async def test_invalid_budget_fails_closed(local, timeout):
    assert await admit(local, timeout_ms=timeout) == "audit_admission_invalid_config"
    assert local._queue.disk_depth == 0


@pytest.mark.parametrize("overrides", [
    {"authenticated": False}, {"tenant_id": ""}, {"tenant_id": "t" * 129},
    {"tenant_id": "tenant\nforged"}, {"tenant_id": "tenant\u200b-a"},
    {"request_id": "https://user:secret@example.test/?token=secret"},
    {"request_id": None}, {"agent_id": "Bearer secret"},
])
async def test_invalid_or_unauthenticated_identity_never_persisted(local, overrides):
    assert await admit(local, **overrides) == "audit_admission_invalid_context"
    assert local._queue.disk_depth == 0


@pytest.mark.parametrize("field", ["_initialized", "_running"])
async def test_inactive_exporter_rejected(local, field):
    setattr(local, field, False)
    assert await admit(local) == "audit_admission_unavailable"
    assert local._queue.disk_depth == 0


async def test_missing_exporter_rejected():
    assert await admit(None) == "audit_admission_unavailable"


async def test_legacy_memory_mode_cannot_claim_durability(tmp_path):
    queue = TelemetryQueue(disk_path=str(tmp_path / "legacy.db"), durable=False, shared=False)
    try:
        assert await admit(exporter_for(queue)) == "audit_admission_not_durable"
        assert queue.memory_depth == queue.disk_depth == 0
    finally:
        queue.close()


@pytest.mark.parametrize("scope", [set(), {"tenant-b"}, "tenant-b", "tenant-a-suffix"])
async def test_missing_tenant_route_rejects_before_enqueue(local, scope):
    local._transports[0].tenant_scope = scope
    assert await admit(local) == "audit_admission_no_route"
    assert local._queue.disk_depth == 0


@pytest.mark.parametrize("scope", ["tenant-a", {"tenant-a"}, "global"])
async def test_matching_route_allows_even_with_remote_circuit_open(local, scope):
    transport = local._transports[0]
    transport.tenant_scope = scope
    for _ in range(5):
        transport.circuit.record_failure()
    assert await admit(local, agent_id=None) is None
    assert local._queue.disk_depth == 1
    transport.transport.send_batch.assert_not_awaited()


async def test_no_transports_rejects(local):
    local._transports.clear()
    assert await admit(local) == "audit_admission_no_route"
    assert local._queue.disk_depth == 0


async def test_full_local_outbox_retains_first_evidence(local, monkeypatch):
    monkeypatch.setattr(local._queue._disk, "_MAX_EVENTS", 1)
    assert await admit(local) is None
    assert await admit(local) == "audit_admission_rejected"
    assert local._queue.disk_depth == local._queue.stats["outbox_rejected"] == 1


async def test_closed_local_store_rejects(local):
    local._queue.close()
    assert await admit(local) == "audit_admission_rejected"


@pytest.mark.parametrize("result", [False, None, 1, "accepted"])
async def test_only_explicit_true_confirms_commit(local, monkeypatch, result):
    monkeypatch.setattr(local._queue, "enqueue", AsyncMock(return_value=result))
    assert await admit(local) == "audit_admission_rejected"


async def test_exception_details_are_never_returned_or_logged(local, monkeypatch, caplog):
    monkeypatch.setattr(local._queue, "enqueue", AsyncMock(side_effect=RuntimeError(
        "postgresql://user:private-secret@host/database /internal/path request-body")))
    assert await admit(local) == "audit_admission_unavailable"
    assert "private-secret" not in caplog.text
    assert "request-body" not in caplog.text


@pytest.mark.parametrize("suppresses_cancel", [False, True])
async def test_timeout_never_authorizes_late_acceptance(local, monkeypatch, suppresses_cancel):
    async def delayed(record):
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            if not suppresses_cancel:
                raise
            return True
    monkeypatch.setattr(local._queue, "enqueue", delayed)
    assert await admit(local, timeout_ms=10) == "audit_admission_timeout"


@pytest.mark.parametrize("cancel", [False, True])
async def test_sqlite_inflight_commit_keeps_lock_and_never_forwards(local, monkeypatch, cancel):
    entered, release = threading.Event(), threading.Event()
    original = local._queue._disk.append

    def delayed(record):
        entered.set()
        if not release.wait(5):
            raise RuntimeError("Test commit release timeout")
        original(record)

    monkeypatch.setattr(local._queue._disk, "append", delayed)
    forwarded = AsyncMock()

    async def caller():
        reason = await admit(local, timeout_ms=10000 if cancel else 10)
        if reason is None:
            await forwarded()
        return reason

    task = asyncio.create_task(caller())
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        if cancel:
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
        else:
            await asyncio.sleep(0.05)
        assert not task.done()  # SQLite commit cannot be cancelled in its worker.
        assert await admit(local, timeout_ms=20) == "audit_admission_timeout"
        assert local._queue._writer_lock.locked()
        assert local._queue._pending_writes == 1
        release.set()
        if cancel:
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 2)
        else:
            assert await asyncio.wait_for(task, 2) == "audit_admission_timeout"
        assert local._queue.disk_depth == 1  # Safe ambiguity: committed, never forwarded.
        assert not local._queue._writer_lock.locked()
        assert local._queue._pending_writes == 0
        forwarded.assert_not_awaited()
    finally:
        release.set()
        await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 2)


async def test_shared_sqlite_capacity_restart_and_tenant_isolation(tmp_path):
    url = f"sqlite:///{tmp_path / 'shared.db'}"
    outbox = SharedOutbox(create_engine(url), max_events=2)
    queue = TelemetryQueue(shared_outbox=outbox)
    exporter = exporter_for(queue, {"tenant-a"})
    snapshot = exporter._transports[0].snapshot
    await queue.initialize()
    try:
        assert await admit(exporter, tenant_id="tenant-b") == "audit_admission_no_route"
        for _ in range(2):
            assert await admit(exporter) is None
        assert await admit(exporter) == "audit_admission_rejected"
        status = await outbox.status()
        assert status["events"] == status["accepted"] == 2
        assert status["rejected"] == 1
    finally:
        await queue.aclose()
    reopened = SharedOutbox(create_engine(url), max_events=2)
    await reopened.initialize()
    try:
        leases = await reopened.claim(snapshot)
        assert len(leases) == 2
        assert {lease.tenant for lease in leases} == {"tenant-a"}
        assert all(lease.event.bulwark.verdict == "not_evaluated" for lease in leases)
        assert len({lease.event.event.id for lease in leases}) == 2
    finally:
        await reopened.close()


async def test_shared_store_not_initialized_rejects(tmp_path):
    outbox = SharedOutbox(create_engine(f"sqlite:///{tmp_path / 'uninitialized.db'}"))
    queue = TelemetryQueue(shared_outbox=outbox)
    try:
        # Even falsely injected exporter readiness cannot bypass the DB check.
        assert await admit(exporter_for(queue)) == "audit_admission_rejected"
    finally:
        await queue.aclose()


async def test_shared_mock_receives_only_matching_snapshots():
    outbox = AsyncMock(spec=SharedOutbox)
    outbox.enqueue.return_value = True
    queue = TelemetryQueue(shared_outbox=outbox)
    exporter = exporter_for(queue, {"tenant-a"})
    exporter.add_transport(Transport(), tenant_scope={"tenant-b"}, revision="b" * 64)
    assert await admit(exporter) is None
    record, snapshots = outbox.enqueue.await_args.args
    assert record.tenant.id == "tenant-a"
    assert snapshots == (exporter._transports[0].snapshot,)
    outbox.enqueue.reset_mock()
    queue.set_destinations(())
    assert await admit(exporter) == "audit_admission_no_route"
    outbox.enqueue.assert_not_awaited()
