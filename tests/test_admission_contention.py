"""Local durable admission contention, using private SQLite and no exporter I/O."""

import asyncio
import threading
from types import SimpleNamespace

import pytest

from src.telemetry.admission import admit_before_upstream
from src.telemetry.queue import TelemetryQueue


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Do not initialize the unrelated operator user database."""


@pytest.fixture
def queue(tmp_path):
    q = TelemetryQueue(disk_path=str(tmp_path / "outbox.db"), durable=True, shared=False)
    yield q
    q.close()


async def admit(queue, index, timeout_ms=2000):
    exporter = SimpleNamespace(_queue=queue, _running=True, _initialized=True,
                               _transports=[SimpleNamespace(tenant_scope={"tenant-a"})])
    return await admit_before_upstream(required=True, exporter=exporter, authenticated=True,
        tenant_id="tenant-a", agent_id="agent-a", request_id=f"request-{index}", timeout_ms=timeout_ms)


def hold_writer(queue, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    original = queue._disk.append

    def append(record):
        entered.set()
        if not release.wait(5):
            raise RuntimeError("test writer release timeout")
        original(record)

    monkeypatch.setattr(queue._disk, "append", append)
    return entered, release


async def test_four_overlapping_admissions_wait_for_real_persistence(queue, monkeypatch, tmp_path):
    entered, release = hold_writer(queue, monkeypatch)
    tasks = [asyncio.create_task(admit(queue, 0))]
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        tasks.extend(asyncio.create_task(admit(queue, i)) for i in range(1, 4))
        await asyncio.sleep(.03)
        assert all(not task.done() for task in tasks)  # Never authorize an uncommitted row.
        assert queue.disk_depth == 0
        release.set()
        assert await asyncio.wait_for(asyncio.gather(*tasks), 3) == [None] * 4
        assert queue.stats["enqueued"] == 4 and queue.stats["dropped"] == 0
        queue.close()
        reopened = TelemetryQueue(disk_path=str(tmp_path / "outbox.db"), durable=True, shared=False)
        try:
            records = await reopened.dequeue_batch()
            assert {e.bulwark.request_id for e in records} == {f"request-{i}" for i in range(4)}
            assert all(e.tenant.id == "tenant-a" for e in records)
        finally:
            reopened.close()
    finally:
        release.set()
        await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 3)


@pytest.mark.parametrize("cancel", [False, True])
async def test_waiter_timeout_or_cancel_never_submits_commit(queue, monkeypatch, cancel):
    entered, release = hold_writer(queue, monkeypatch)
    first = asyncio.create_task(admit(queue, 0))
    waiter = None
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        waiter = asyncio.create_task(admit(queue, 1, timeout_ms=2000 if cancel else 20))
        if cancel:
            await asyncio.sleep(.01)
            waiter.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(waiter, 1)
        else:
            assert await waiter == "audit_admission_timeout"
        assert queue._pending_writes == 1
        release.set()
        assert await asyncio.wait_for(first, 2) is None
        assert queue.disk_depth == 1
        assert queue._pending_writes == 0
        assert await admit(queue, 2) is None
        assert queue.disk_depth == 2
    finally:
        release.set()
        await asyncio.wait_for(asyncio.gather(first, *([waiter] if waiter else []), return_exceptions=True), 3)


@pytest.mark.parametrize("size,limit", [(2, 2), (10000, 32)])
async def test_waiting_work_is_capped_before_thread_submission(queue, monkeypatch, size, limit):
    monkeypatch.setattr(queue, "_max_size", size)
    entered, release = hold_writer(queue, monkeypatch)
    tasks = [asyncio.create_task(admit(queue, 0))]
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        tasks.extend(asyncio.create_task(admit(queue, i)) for i in range(1, limit))
        await asyncio.sleep(.01)
        assert queue._pending_writes == limit
        assert await admit(queue, limit) == "audit_admission_rejected"
        assert queue._pending_writes == limit
        # Exercise the backlog ceiling, not an assumption that this disk can
        # fsync 32 rows within the one-second waiting budget.
        for task in tasks[1:]:
            task.cancel()
        cancelled = await asyncio.wait_for(asyncio.gather(*tasks[1:], return_exceptions=True), 1)
        assert all(isinstance(result, asyncio.CancelledError) for result in cancelled)
        assert queue._pending_writes == 1
        release.set()
        assert await asyncio.wait_for(tasks[0], 2) is None
        assert queue.disk_depth == 1 and queue.stats["dropped"] == 1
    finally:
        release.set()
        await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 3)


async def test_queue_wait_budget_is_bounded_without_admission_timeout(queue, monkeypatch):
    entered, release = hold_writer(queue, monkeypatch)
    first = asyncio.create_task(admit(queue, 0, timeout_ms=4000))
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        assert await admit(queue, 1, timeout_ms=3000) == "audit_admission_rejected"
        assert queue._pending_writes == 1
        release.set()
        assert await asyncio.wait_for(first, 2) is None
        assert queue.disk_depth == 1
    finally:
        release.set()
        await asyncio.wait_for(asyncio.gather(first, return_exceptions=True), 3)


@pytest.mark.parametrize("failure", ["full", "storage_error"])
async def test_contended_commit_failure_does_not_authorize(queue, monkeypatch, failure):
    if failure == "full":
        monkeypatch.setattr(queue._disk, "_MAX_EVENTS", 1)
    else:
        original = queue._disk.append

        def fail_second(record):
            if record.bulwark.request_id == "request-1":
                raise OSError("synthetic persistence failure")
            original(record)

        monkeypatch.setattr(queue._disk, "append", fail_second)
    entered, release = hold_writer(queue, monkeypatch)
    tasks = [asyncio.create_task(admit(queue, 0))]
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        tasks.append(asyncio.create_task(admit(queue, 1)))
        await asyncio.sleep(.01)
        release.set()
        assert await asyncio.wait_for(asyncio.gather(*tasks), 3) == [None, "audit_admission_rejected"]
        assert queue.disk_depth == 1 and queue._pending_writes == 0
    finally:
        release.set()
        await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 3)
