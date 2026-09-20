"""Bounded legacy-store outbox: restart, acknowledgement and destination failures."""

import asyncio
from unittest.mock import AsyncMock

import pytest

from src.telemetry.exporter import TelemetryExporter
from src.telemetry.queue import TelemetryQueue
from src.telemetry.schema import BulwarkFields, SecurityTelemetryEvent, TenantFields


def event(tenant="tenant-a"):
    return SecurityTelemetryEvent(bulwark=BulwarkFields(verdict="block"), tenant=TenantFields(id=tenant))


class Transport:
    name = "test-destination"

    def __init__(self, success=True):
        self.send_batch = AsyncMock(return_value=success)
        self.close = AsyncMock()


async def test_restart_before_ack_retains_event_identity(tmp_path):
    path = str(tmp_path / "outbox.db")
    q = TelemetryQueue(disk_path=path, durable=True)
    original = event()
    assert q.enqueue_nowait(original)
    assert (await q.dequeue_batch(timeout=0.001))[0].event.id == original.event.id
    q.close()  # crash before ack
    q = TelemetryQueue(disk_path=path, durable=True)
    try:
        assert (await q.dequeue_batch(timeout=0.001))[0].event.id == original.event.id
        await q.acknowledge_batch()
        assert q.disk_depth == 0
    finally:
        q.close()


@pytest.mark.parametrize("failure", ["false", "exception", "timeout", "circuit", "missing", "unrouted"])
async def test_failed_delivery_retains_rows(tmp_path, failure):
    q = TelemetryQueue(disk_path=str(tmp_path / "outbox.db"), durable=True)
    exporter = TelemetryExporter(queue=q)
    transport = Transport(False)
    if failure != "missing":
        exporter.add_transport(transport, tenant_scope={"other"} if failure == "unrouted" else "global")
    if failure == "exception":
        transport.send_batch.side_effect = RuntimeError("credential must not be logged")
    elif failure == "timeout":
        async def wait(*args):
            await asyncio.Event().wait()
        transport.send_batch.side_effect = wait
        exporter._delivery_timeout = 0.01
    elif failure == "circuit":
        for _ in range(5):
            exporter._transports[0].circuit.record_failure()
    try:
        assert q.enqueue_nowait(event())
        batch = await q.dequeue_batch(timeout=0.001)
        assert await exporter._send_to_transports(batch) is False
        assert q.disk_depth == 1
    finally:
        q.close()


async def test_partial_fanout_retries_without_cross_tenant_leak(tmp_path):
    q = TelemetryQueue(disk_path=str(tmp_path / "outbox.db"), durable=True)
    exporter = TelemetryExporter(queue=q)
    a, b = Transport(), Transport(False)
    exporter.add_transport(a, tenant_scope={"tenant-a"})
    exporter.add_transport(b, tenant_scope={"tenant-b"})
    try:
        q.enqueue_nowait(event("tenant-a"))
        q.enqueue_nowait(event("tenant-b"))
        batch = await q.dequeue_batch(timeout=0.001)
        assert not await exporter._send_to_transports(batch)
        assert q.disk_depth == 2
        assert {e.tenant.id for e in a.send_batch.await_args.args[0]} == {"tenant-a"}
        assert {e.tenant.id for e in b.send_batch.await_args.args[0]} == {"tenant-b"}
        b.send_batch.return_value = True
        assert await exporter._send_to_transports(batch)
        await q.acknowledge_batch()
        assert q.disk_depth == 0
        assert a.send_batch.await_count == 2  # at least once, duplicates are explicit
    finally:
        q.close()


def test_full_outbox_rejects_new_event_without_rotating_old(tmp_path):
    q = TelemetryQueue(disk_path=str(tmp_path / "outbox.db"), durable=True)
    q._disk._MAX_EVENTS = 1
    try:
        assert q.enqueue_nowait(event())
        assert not q.enqueue_nowait(event())
        assert q.disk_depth == 1
        assert q.stats["dropped"] == 1
        assert q.stats["outbox_rejected"] == 1
    finally:
        q.close()


async def test_export_loop_acknowledges_only_after_recovery(tmp_path):
    q = TelemetryQueue(disk_path=str(tmp_path / "outbox.db"), durable=True)
    exporter = TelemetryExporter(queue=q, flush_interval=0.001)
    transport = Transport()
    exporter.add_transport(transport)
    calls = 0
    async def send(batch):
        nonlocal calls
        calls += 1
        if calls == 1:
            return False
        exporter._running = False
        return True
    transport.send_batch.side_effect = send
    try:
        q.enqueue_nowait(event())
        exporter._running = True
        await asyncio.wait_for(exporter._run_loop(), timeout=1)
        assert q.disk_depth == 0
        assert calls == 2
        assert exporter.stats["delivery_retries"] == 1
    finally:
        q.close()


async def test_unrouted_event_does_not_starve_other_tenants(tmp_path):
    q = TelemetryQueue(disk_path=str(tmp_path / "outbox.db"), durable=True)
    exporter = TelemetryExporter(queue=q, batch_size=1)
    transport = Transport()
    exporter.add_transport(transport, tenant_scope={"tenant-a"})
    try:
        q.enqueue_nowait(event("unknown"))
        q.enqueue_nowait(event("tenant-a"))
        batch = await q.dequeue_batch(batch_size=1, timeout=0.001)
        assert not await exporter._send_to_transports(batch)
        await q.acknowledge_batch(exporter._delivered_indexes)
        batch = await q.dequeue_batch(batch_size=1, timeout=0.001)
        assert batch[0].tenant.id == "tenant-a"
        assert await exporter._send_to_transports(batch)
        await q.acknowledge_batch(exporter._delivered_indexes)
        assert q.disk_depth == 1
        assert (await q.dequeue_batch(batch_size=1, timeout=0.001))[0].tenant.id == "unknown"
    finally:
        q.close()


async def test_repeated_cancel_does_not_release_writer_early(tmp_path, monkeypatch):
    import threading

    q = TelemetryQueue(disk_path=str(tmp_path / "outbox.db"), durable=True)
    entered, release = threading.Event(), threading.Event()
    original = q._disk.append
    def delayed(record):
        entered.set()
        if not release.wait(2):
            raise RuntimeError("Test worker timeout")
        original(record)
    monkeypatch.setattr(q._disk, "append", delayed)
    task = asyncio.create_task(q.enqueue(event()))
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        assert not await q.enqueue(event())
        assert q._writer_lock.locked()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert q.disk_depth == 1
        assert not q._writer_lock.locked()
    finally:
        release.set()
        if not task.done():
            await asyncio.gather(task, return_exceptions=True)
        q.close()


async def test_continuous_arrivals_do_not_starve_old_retries(tmp_path):
    q = TelemetryQueue(disk_path=str(tmp_path / "outbox.db"), durable=True)
    oldest = event("pending")
    try:
        q.enqueue_nowait(oldest)
        q.enqueue_nowait(event("healthy"))
        first = await q.dequeue_batch(batch_size=1, timeout=0.001)
        assert first[0].event.id == oldest.event.id
        await q.acknowledge_batch([])
        q.enqueue_nowait(event("healthy"))
        second = await q.dequeue_batch(batch_size=1, timeout=0.001)
        assert second[0].tenant.id == "healthy"
        await q.acknowledge_batch()
        q.enqueue_nowait(event("healthy"))
        retry = await q.dequeue_batch(batch_size=1, timeout=0.001)
        assert retry[0].event.id == oldest.event.id
    finally:
        q.close()
