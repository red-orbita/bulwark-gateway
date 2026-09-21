"""SQLite temp-only recovery, isolation, bounds and shared exporter tests."""

import asyncio
import hashlib
import json
from unittest.mock import AsyncMock

import pytest

from src.storage.database import create_engine
from src.telemetry.exporter import TelemetryExporter, _add_transport_from_config
from src.telemetry.queue import TelemetryQueue
from src.telemetry.schema import BulwarkFields, SecurityTelemetryEvent, TenantFields
from src.telemetry.shared_outbox import DestinationSnapshot, SharedOutbox, get_shared_outbox


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Override root fixture: these tests never open the operator users DB."""


def event(tenant="tenant-a"):
    return SecurityTelemetryEvent(bulwark=BulwarkFields(verdict="block"), tenant=TenantFields(id=tenant))


def destination(name="siem-a", tenants=("tenant-a",), revision="original"):
    return DestinationSnapshot(destination_id=name, revision=hashlib.sha256(revision.encode()).hexdigest(),
                               tenant_scope=tenants)


@pytest.fixture
async def store(tmp_path):
    outbox = SharedOutbox(create_engine(f"sqlite:///{tmp_path / 'outbox.db'}"))
    await outbox.initialize()
    try:
        yield outbox
    finally:
        await outbox.close()


async def test_fanout_ack_only_successful_destination_and_restart(tmp_path):
    url = f"sqlite:///{tmp_path / 'restart.db'}"
    a, b = destination(), destination("siem-b")
    original = event()
    first = SharedOutbox(create_engine(url))
    await first.initialize()
    assert await first.enqueue(original, (a, b))
    leases = await first.claim(a)
    assert leases[0].event.event.id == original.event.id
    assert await first.finish(leases, success=True) == 1
    assert (await first.status())["events"] == 1
    await first.close()
    second = SharedOutbox(create_engine(url))
    await second.initialize()
    try:
        assert not await second.claim(a)
        pending = await second.claim(b)
        assert pending[0].event.event.id == original.event.id
        assert await second.finish(pending, success=True) == 1
        stats = await second.status()
        assert stats["events"] == stats["bytes"] == 0
        assert stats["acked"] == 2
    finally:
        await second.close()


async def test_worker_death_expiry_and_fencing(store, tmp_path):
    d = destination()
    assert await store.enqueue(event(), (d,))
    old = await store.claim(d)
    other = SharedOutbox(create_engine(f"sqlite:///{tmp_path / 'outbox.db'}"))
    await other.initialize()
    try:
        assert not await other.claim(d)
        await store._db.execute("UPDATE telemetry_outbox_deliveries SET lease_until = 0")
        current = await other.claim(d)
        assert current[0].attempts == 2
        assert old[0].token != current[0].token
        assert await store.finish(old, success=True) == 0
        assert await store.finish(old, success=False) == 0
        assert await other.finish(current, success=True) == 1
    finally:
        await other.close()


async def test_simultaneous_workers_and_atomic_capacity(tmp_path):
    url = f"sqlite:///{tmp_path / 'race.db'}"
    a, b = [SharedOutbox(create_engine(url), max_events=1) for _ in range(2)]
    await asyncio.wait_for(asyncio.gather(a.initialize(), b.initialize()), 5)
    try:
        results = await asyncio.wait_for(asyncio.gather(
            a.enqueue(event(), (destination(),)), b.enqueue(event(), (destination(),)),
        ), 5)
        assert sorted(results) == [False, True]
        claims = await asyncio.wait_for(asyncio.gather(a.claim(destination()), b.claim(destination())), 5)
        assert sorted(map(len, claims)) == [0, 1]
        stats = await a.status()
        assert stats["events"] == stats["accepted"] == stats["rejected"] == 1
    finally:
        await a.close()
        await b.close()


async def test_snapshot_changes_never_widen_routes(store):
    d = destination()
    original = event()
    assert await store.enqueue(original, (d,))
    assert not await store.claim(destination(revision="new endpoint"))
    assert not await store.claim(destination(tenants=None))
    assert not await store.claim(destination(tenants=("tenant-b",)))
    # Same event retried with a newly configured global destination must not fan out.
    new = destination("new", tenants=None)
    assert await store.enqueue(original, (new,))
    assert not await store.claim(new)
    assert len(await store.claim(d)) == 1


async def test_tenant_isolation_and_parameterized_adversarial_identity(store):
    adversarial = "tenant'); DROP TABLE telemetry_outbox_events; -- ?"
    d = destination(tenants=(adversarial,))
    assert not await store.enqueue(event("other"), (d,))
    a = event(adversarial)
    b = event("2026-06-13T13:00:42Z")
    b.event.id = a.event.id
    global_dest = destination("global", tenants=None)
    assert await store.enqueue(a, (d,))
    assert await store.enqueue(b, (global_dest,))
    claimed = await store.claim(d)
    assert claimed[0].tenant == adversarial
    forged = claimed[0].model_copy(update={"tenant": b.tenant.id})
    assert await store.finish([forged], success=True) == 0
    assert (await store.status())["events"] == 2
    assert await store.finish(claimed, success=True) == 1


async def test_payload_or_tenant_corruption_retains_evidence_without_starvation(store):
    d = destination()
    assert await store.enqueue(event(), (d,))
    await store._db.execute("UPDATE telemetry_outbox_events SET tenant = ?", (json.dumps("other"),))
    assert await store.enqueue(event(), (d,))
    good = await store.claim(d)
    assert len(good) == 1
    await store.finish(good, success=True)
    assert (await store.status())["events"] == 1
    assert (await store.status())["corrupt"] == 1
    assert store.corrupted == 1


async def test_no_route_size_capacity_and_collision_rejections(tmp_path):
    outbox = SharedOutbox(create_engine(f"sqlite:///{tmp_path / 'capacity.db'}"), max_bytes=1)
    await outbox.initialize()
    try:
        assert not await outbox.enqueue(event(), (destination(),))
        assert (await outbox.status())["rejected"] == 1
        assert (await outbox.status())["events"] == 0
    finally:
        await outbox.close()


async def test_invalid_admissions_and_limits(store):
    d = destination()
    assert not await store.enqueue(event(), ())
    assert not await store.enqueue(event(), (d, d))
    assert not await store.enqueue(event(), tuple(destination(str(i)) for i in range(65)))
    large = event()
    large.message = "x" * (1024 * 1024 + 1)
    assert not await store.enqueue(large, (d,))
    original = event()
    assert await store.enqueue(original, (d,))
    original.message = "collision"
    assert not await store.enqueue(original, (d,))
    assert store.rejected == 5
    for limit in (0, 1001):
        with pytest.raises(ValueError):
            await store.claim(d, limit=limit)
    for seconds in (float("nan"), float("inf"), -1, 4000):
        with pytest.raises(ValueError):
            await store.claim(d, lease_seconds=seconds)
        with pytest.raises(ValueError):
            await store.finish([], success=True, retry_seconds=seconds)


async def test_failed_delivery_backoff_and_recovery(store):
    d = destination()
    assert await store.enqueue(event(), (d,))
    leases = await store.claim(d)
    assert await store.finish(leases, success=False, retry_seconds=30) == 1
    assert not await store.claim(d)
    await store._db.execute("UPDATE telemetry_outbox_deliveries SET available_at = 0")
    retry = await store.claim(d)
    assert retry[0].attempts == 2
    assert (await store.status())["failures"] == 1
    await store.finish(retry, success=True)


async def test_cancellation_keeps_bounded_commit_and_recoverable_claim(store, monkeypatch):
    entered, release = asyncio.Event(), asyncio.Event()
    original_state = store._state

    async def delayed(tx):
        now = await original_state(tx)
        entered.set()
        await release.wait()
        return now

    monkeypatch.setattr(store, "_state", delayed)
    task = asyncio.create_task(store.enqueue(event(), (destination(),)))
    await asyncio.wait_for(entered.wait(), 1)
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    await asyncio.sleep(0)
    assert not await store.enqueue(event(), (destination(),))
    assert store._lock.locked()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 1)
    assert (await store.status())["accepted"] == 1
    entered.clear()
    release.clear()
    task = asyncio.create_task(store.claim(destination()))
    await asyncio.wait_for(entered.wait(), 1)
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    monkeypatch.setattr(store, "_state", original_state)
    assert not await store.claim(destination())
    await store._db.execute("UPDATE telemetry_outbox_deliveries SET lease_until = 0")
    assert len(await store.claim(destination())) == 1


async def test_write_failure_rolls_back_capacity_and_no_local_fallback(store, monkeypatch, caplog):
    from src.storage.database import _SQLiteTransaction
    execute = _SQLiteTransaction.execute

    async def fail_insert(self, sql, params=None):
        if sql.startswith("INSERT INTO telemetry_outbox_deliveries"):
            raise OSError("SYNTHETIC_SECRET storage full")
        return await execute(self, sql, params)

    monkeypatch.setattr(_SQLiteTransaction, "execute", fail_insert)
    assert not await store.enqueue(event(), (destination(),))
    assert (await store.status())["events"] == (await store.status())["bytes"] == 0
    assert "SYNTHETIC_SECRET" not in caplog.text
    assert store.errors == 1


async def test_ack_failure_preserves_delivery(store, monkeypatch):
    d = destination()
    assert await store.enqueue(event(), (d,))
    leases = await store.claim(d)
    from src.storage.database import _SQLiteTransaction
    execute = _SQLiteTransaction.execute

    async def fail_delete(self, sql, params=None):
        if sql.startswith("DELETE FROM telemetry_outbox_events"):
            raise OSError("simulated disk failure")
        return await execute(self, sql, params)

    monkeypatch.setattr(_SQLiteTransaction, "execute", fail_delete)
    with pytest.raises(OSError):
        await store.finish(leases, success=True)
    assert (await store.status())["acked"] == 0
    monkeypatch.setattr(_SQLiteTransaction, "execute", execute)
    assert await store.finish(leases, success=True) == 1


class Transport:
    name = "mock"

    def __init__(self, success=True):
        self.send_batch = AsyncMock(return_value=success)
        self.close = AsyncMock()


async def test_exporter_partial_success_queue_api_and_scope_snapshot(store):
    q = TelemetryQueue(shared_outbox=store)
    exporter = TelemetryExporter(queue=q)
    a, b, other = Transport(), Transport(False), Transport()
    exporter.add_transport(a, {"tenant-a"}, destination_id="a", revision="a" * 64)
    exporter.add_transport(b, {"tenant-a"}, destination_id="b", revision="b" * 64)
    exporter.add_transport(other, {"tenant-b"}, destination_id="other", revision="c" * 64)
    assert q._disk is None
    assert not q.enqueue_nowait(event())
    assert await q.enqueue(event())
    assert not await q.enqueue(event("unknown"))
    await exporter._flush_shared()
    assert q.disk_depth == 1
    other.send_batch.assert_not_awaited()
    b.send_batch.return_value = True
    await store._db.execute("UPDATE telemetry_outbox_deliveries SET available_at = 0")
    await exporter._flush_shared()
    assert a.send_batch.await_count == 1
    assert b.send_batch.await_count == 2
    assert q.disk_depth == 0
    with pytest.raises(RuntimeError):
        await q.dequeue_batch()
    with pytest.raises(RuntimeError):
        await q.acknowledge_batch()


@pytest.mark.parametrize("failure", ["exception", "timeout", "circuit", "cancel"])
async def test_exporter_failure_and_cancel_retain_lease(store, failure, caplog):
    q = TelemetryQueue(shared_outbox=store)
    exporter = TelemetryExporter(queue=q)
    transport = Transport()
    exporter.add_transport(transport, revision="a" * 64)
    entered = asyncio.Event()

    async def wait(batch):
        entered.set()
        await asyncio.Event().wait()

    if failure == "exception":
        transport.send_batch.side_effect = RuntimeError("SYNTHETIC_SECRET")
    elif failure in ("timeout", "cancel"):
        transport.send_batch.side_effect = wait
        exporter._delivery_timeout = 0.01 if failure == "timeout" else 30
    else:
        for _ in range(5):
            exporter._transports[0].circuit.record_failure()
    assert await q.enqueue(event())
    if failure == "cancel":
        task = asyncio.create_task(exporter._flush_shared())
        await asyncio.wait_for(entered.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        await exporter._flush_shared()
    assert (await store.status())["events"] == 1
    assert (await store.status())["acked"] == 0
    assert "SYNTHETIC_SECRET" not in caplog.text


async def test_loader_snapshots_builtins_and_rejects_mutated_endpoint(store, tmp_path):
    q = TelemetryQueue(shared_outbox=store)
    exporter = TelemetryExporter(queue=q)
    _add_transport_from_config(exporter, {"id": "a", "transport_type": "http_rest",
                                         "endpoint": "https://example.invalid/collect",
                                         "tenant_scope": ["tenant-a"], "auth_type": "bearer",
                                         "auth_value": "SYNTHETIC_SECRET"})
    tw = exporter._transports[0]
    assert tw.snapshot.tenant_scope == ("tenant-a",)
    assert await q.enqueue(event())
    row = await store._db.fetch_one("SELECT snapshot FROM telemetry_outbox_deliveries")
    assert "SYNTHETIC_SECRET" not in row["snapshot"]
    assert "example.invalid" not in row["snapshot"]
    tw.transport.send_batch = AsyncMock(return_value=True)
    tw.transport._config.url = "https://other.invalid/collect"
    await exporter._flush_shared()
    tw.transport.send_batch.assert_not_awaited()
    assert (await store.status())["events"] == 1


async def test_opt_in_start_stop_without_network(tmp_path, monkeypatch):
    monkeypatch.setenv("BULWARK_TELEMETRY_ENABLED", "true")
    monkeypatch.setenv("BULWARK_TELEMETRY_SHARED_OUTBOX", "true")
    store = get_shared_outbox(db=create_engine(f"sqlite:///{tmp_path / 'lifecycle.db'}"))
    q = TelemetryQueue(shared_outbox=store)
    exporter = TelemetryExporter(queue=q)
    transport = Transport()
    exporter.add_transport(transport, revision="a" * 64)
    monkeypatch.setattr(exporter, "_persist_stats", lambda: None)
    await exporter.start()
    assert await q.enqueue(event())
    await exporter.stop()
    transport.close.assert_awaited_once()
    assert store._closed


def test_default_inert_keeps_legacy_queue(tmp_path, monkeypatch):
    monkeypatch.delenv("BULWARK_TELEMETRY_SHARED_OUTBOX", raising=False)
    q = TelemetryQueue(disk_path=str(tmp_path / "legacy.db"), durable=False)
    try:
        assert not q.shared
        assert q.shared_outbox is None
        assert q.enqueue_nowait(event())
    finally:
        q.close()


async def test_migration_version_and_replica_capacity_mismatch(store, tmp_path):
    mismatch = SharedOutbox(create_engine(f"sqlite:///{tmp_path / 'outbox.db'}"), max_events=2)
    try:
        with pytest.raises(ValueError, match="capacity"):
            await mismatch.initialize()
        await store._db.execute("UPDATE telemetry_outbox_state SET version = 2")
        with pytest.raises(RuntimeError, match="schema"):
            await mismatch.initialize()
    finally:
        await mismatch.close()


async def test_claim_byte_budget_and_corrupt_size_recovery(store):
    d = destination()
    for _ in range(6):
        record = event()
        record.message = "x" * 900000
        assert await store.enqueue(record, (d,))
    leases = await store.claim(d)
    assert len(leases) == 4
    await store.finish(leases, success=True)
    await store._db.execute("UPDATE telemetry_outbox_events SET size_bytes = 999999999")
    assert not await store.claim(d)
    assert (await store.status())["corrupt"] == 2


async def test_cancelled_commit_failure_is_observed(store, monkeypatch):
    entered, release = asyncio.Event(), asyncio.Event()

    async def failing(tx):
        entered.set()
        await release.wait()
        raise OSError("simulated failure during cancellation")

    monkeypatch.setattr(store, "_state", failing)
    task = asyncio.create_task(store.enqueue(event(), (destination(),)))
    await asyncio.wait_for(entered.wait(), 1)
    task.cancel()
    await asyncio.sleep(0)
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not store._lock.locked()
    assert (await store.status())["events"] == 0


async def test_scope_mutation_and_duplicate_registration_fail_closed(store):
    q = TelemetryQueue(shared_outbox=store)
    exporter = TelemetryExporter(queue=q)
    transport = Transport()
    with pytest.raises(ValueError):
        exporter.add_transport(transport)
    exporter.add_transport(transport, {"tenant-a"}, revision="a" * 64)
    with pytest.raises(ValueError):
        exporter.add_transport(Transport(), {"tenant-a"}, revision="a" * 64)
    assert len(exporter._transports) == 1
    assert await q.enqueue(event())
    exporter._transports[0].tenant_scope = "global"
    await exporter._flush_shared()
    transport.send_batch.assert_not_awaited()
    assert (await store.status())["events"] == 1


async def test_uninitialized_and_closed_admission_rejected(tmp_path):
    outbox = SharedOutbox(create_engine(f"sqlite:///{tmp_path / 'closed.db'}"))
    assert not await outbox.enqueue(event(), (destination(),))
    await outbox.initialize()
    await outbox.initialize()
    await outbox.close()
    assert not await outbox.enqueue(event(), (destination(),))
    with pytest.raises(RuntimeError, match="closed"):
        await outbox.initialize()


@pytest.mark.parametrize("ttype", ["http_rest", "syslog_udp", "syslog_tls", "tcp_tls", "file"])
async def test_config_loader_scopes_for_all_builtins(store, tmp_path, ttype):
    exporter = TelemetryExporter(queue=TelemetryQueue(shared_outbox=store))
    if ttype == "file":
        with pytest.raises(ValueError):
            _add_transport_from_config(exporter, {"id": "route", "transport_type": ttype,
                                                  "endpoint": str(tmp_path / "events.ndjson")})
        assert not exporter._transports
        return
    _add_transport_from_config(exporter, {"id": "route", "transport_type": ttype,
                                         "endpoint": str(tmp_path / "events.ndjson") if ttype == "file"
                                         else "https://example.invalid", "tenant_scope": ["tenant-a"]})
    assert exporter._transports[0].snapshot.tenant_scope == ("tenant-a",)
    assert not await exporter._queue.enqueue(event("tenant-b"))
    await exporter._transports[0].transport.close()


async def test_shared_factory_env_and_scope_validation(tmp_path, monkeypatch):
    import src.storage.database as database
    monkeypatch.setattr(database, "ADMIN_DB_URL", f"sqlite:///{tmp_path / 'factory.db'}")
    monkeypatch.setenv("BULWARK_TELEMETRY_SHARED_OUTBOX", "true")
    q = TelemetryQueue()
    assert q.shared and q.shared_outbox is not None and q._disk is None
    await q.initialize()
    await q.aclose()
    with pytest.raises(ValueError):
        destination(tenants=("",))
    with pytest.raises(ValueError):
        SharedOutbox(create_engine(f"sqlite:///{tmp_path / 'invalid.db'}"), max_events=0)


async def test_restart_after_claim_and_expired_ack_are_recoverable(tmp_path):
    url = f"sqlite:///{tmp_path / 'claimed.db'}"
    first = SharedOutbox(create_engine(url))
    await first.initialize()
    original = event()
    d = destination()
    assert await first.enqueue(original, (d,))
    old = await first.claim(d)
    await first.close()
    second = SharedOutbox(create_engine(url))
    await second.initialize()
    try:
        assert not await second.claim(d)
        await second._db.execute("UPDATE telemetry_outbox_deliveries SET lease_until = 0")
        # Expiry alone invalidates the old ACK, even before another worker claims.
        assert await second.finish(old, success=True) == 0
        recovered = await second.claim(d)
        assert recovered[0].event.event.id == original.event.id
        assert await second.finish(recovered, success=True) == 1
    finally:
        await second.close()


async def test_expired_lease_still_consumes_capacity(tmp_path):
    outbox = SharedOutbox(create_engine(f"sqlite:///{tmp_path / 'bounded.db'}"), max_events=1)
    await outbox.initialize()
    try:
        assert await outbox.enqueue(event(), (destination(),))
        await outbox.claim(destination())
        await outbox._db.execute("UPDATE telemetry_outbox_deliveries SET lease_until = 0")
        assert not await outbox.enqueue(event(), (destination(),))
        assert (await outbox.status())["events"] == 1
    finally:
        await outbox.close()
