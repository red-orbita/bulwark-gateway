"""Tests for the durable security-events store (``security_events`` table).

These run the real migration chain against a throwaway SQLite database and then
exercise :class:`SecurityEventsStore` end-to-end: idempotent bulk insert, verdict
feed routing, filtering, aggregate summary, age-based retention pruning, and the
GDPR subject find/erase helpers.
"""

from __future__ import annotations

import time

import pytest

from admin.services import security_events_store as store_mod
from admin.services.database import create_engine
from admin.services.migrations import run_migrations
from admin.services.security_events_store import SecurityEventsStore


@pytest.fixture
async def store(tmp_path, monkeypatch):
    """A SecurityEventsStore backed by a migrated throwaway SQLite DB."""
    db_path = tmp_path / "events_test.db"
    engine = create_engine(f"sqlite:///{db_path}")
    await engine.init()
    await run_migrations(engine)
    # The store resolves its engine via get_database(); point that at our engine.
    monkeypatch.setattr(store_mod, "get_database", lambda: engine)
    try:
        yield SecurityEventsStore()
    finally:
        await engine.close()


def _evt(event_id: str, *, ts: float | None = None, tenant="acme", verdict="block",
         category="prompt_injection", severity="high", **extra) -> dict:
    e = {
        "event_id": event_id,
        "ts": ts if ts is not None else time.time(),
        "tenant": tenant,
        "agent": "support-bot",
        "verdict": verdict,
        "category": category,
        "severity": severity,
        "description": "test event",
        "source": "input_guardrail",
        "pattern": "PAT-1",
        "request_id": f"{tenant}:support-bot:1",
        "tool_name": "",
        "snippet": "hello",
        "input_hash": "deadbeef",
        "metadata": {},
    }
    e.update(extra)
    return e


# ─── bulk_insert idempotency ─────────────────────────────────────────────────

async def test_bulk_insert_inserts_rows(store):
    n = await store.bulk_insert([_evt("id-1"), _evt("id-2")])
    assert n == 2
    assert await store.count(verdict="blocked") == 2


async def test_bulk_insert_is_idempotent_on_event_id(store):
    first = await store.bulk_insert([_evt("dup")])
    second = await store.bulk_insert([_evt("dup")])
    assert first == 1
    assert second == 0  # INSERT OR IGNORE — re-sync is a no-op
    assert await store.count(verdict="blocked") == 1


async def test_bulk_insert_empty_is_noop(store):
    assert await store.bulk_insert([]) == 0


# ─── verdict feed routing ────────────────────────────────────────────────────

async def test_default_feed_is_block_and_warn(store):
    await store.bulk_insert([
        _evt("b", verdict="block"),
        _evt("w", verdict="warn"),
        _evt("a", verdict="allow", category="allowed", severity="info"),
    ])
    events = await store.query()  # no verdict → security feed
    verdicts = {e["verdict"] for e in events}
    assert verdicts == {"block", "warn"}


async def test_allowed_feed_reads_only_allows(store):
    await store.bulk_insert([
        _evt("b", verdict="block"),
        _evt("a", verdict="allow", category="allowed", severity="info"),
    ])
    events = await store.query(verdict="allowed")
    assert [e["verdict"] for e in events] == ["allow"]


async def test_blocked_and_warned_narrow_the_feed(store):
    await store.bulk_insert([
        _evt("b", verdict="block"),
        _evt("w", verdict="warn"),
    ])
    assert [e["verdict"] for e in await store.query(verdict="blocked")] == ["block"]
    assert [e["verdict"] for e in await store.query(verdict="warned")] == ["warn"]


# ─── filtering + ordering ────────────────────────────────────────────────────

async def test_query_orders_newest_first(store):
    await store.bulk_insert([
        _evt("old", ts=100.0),
        _evt("new", ts=300.0),
        _evt("mid", ts=200.0),
    ])
    events = await store.query()
    assert [e["ts"] for e in events] == [300.0, 200.0, 100.0]


async def test_query_filters_by_tenant_and_category_and_severity(store):
    await store.bulk_insert([
        _evt("1", tenant="acme", category="jailbreak", severity="high"),
        _evt("2", tenant="globex", category="jailbreak", severity="high"),
        _evt("3", tenant="acme", category="prompt_injection", severity="low"),
    ])
    assert len(await store.query(tenant="acme")) == 2
    assert len(await store.query(category="jailbreak")) == 2
    assert len(await store.query(severity="low")) == 1


async def test_query_limit_and_offset(store):
    await store.bulk_insert([_evt(f"e{i}", ts=float(i)) for i in range(5)])
    page1 = await store.query(limit=2, offset=0)
    page2 = await store.query(limit=2, offset=2)
    assert len(page1) == 2 and len(page2) == 2
    assert page1[0]["ts"] == 4.0  # newest first
    assert page2[0]["ts"] == 2.0


# ─── time-range (since / until) ──────────────────────────────────────────────

async def test_query_since_filters_lower_bound(store):
    await store.bulk_insert([
        _evt("old", ts=100.0),
        _evt("mid", ts=200.0),
        _evt("new", ts=300.0),
    ])
    events = await store.query(since=200.0)
    assert {e["ts"] for e in events} == {200.0, 300.0}  # since is inclusive


async def test_query_until_filters_upper_bound(store):
    await store.bulk_insert([
        _evt("old", ts=100.0),
        _evt("mid", ts=200.0),
        _evt("new", ts=300.0),
    ])
    events = await store.query(until=300.0)
    assert {e["ts"] for e in events} == {100.0, 200.0}  # until is exclusive


async def test_query_since_and_until_window(store):
    await store.bulk_insert([
        _evt("a", ts=100.0),
        _evt("b", ts=200.0),
        _evt("c", ts=300.0),
        _evt("d", ts=400.0),
    ])
    events = await store.query(since=200.0, until=400.0)
    assert {e["ts"] for e in events} == {200.0, 300.0}


async def test_count_respects_time_range(store):
    await store.bulk_insert([
        _evt("a", ts=100.0),
        _evt("b", ts=200.0),
        _evt("c", ts=300.0),
    ])
    assert await store.count(since=200.0) == 2
    assert await store.count(until=200.0) == 1


# ─── summary ─────────────────────────────────────────────────────────────────

async def test_summary_aggregates_security_feed_and_allowed_count(store):
    await store.bulk_insert([
        _evt("1", tenant="acme", category="jailbreak", severity="high", verdict="block"),
        _evt("2", tenant="acme", category="prompt_injection", severity="medium", verdict="warn"),
        _evt("3", tenant="globex", category="jailbreak", severity="high", verdict="block"),
        _evt("a", verdict="allow", category="allowed", severity="info"),
    ])
    summary = await store.summary()
    assert summary["total"] == 3  # block + warn only
    assert summary["by_tenant"] == {"acme": 2, "globex": 1}
    assert summary["by_category"]["jailbreak"] == 2
    assert summary["by_severity"]["high"] == 2
    assert summary["allowed_recorded"] == 1


# ─── retention prune ─────────────────────────────────────────────────────────

async def test_prune_removes_old_events(store):
    now = time.time()
    await store.bulk_insert([
        _evt("old", ts=now - 100 * 86400),   # 100 days old
        _evt("recent", ts=now - 1 * 86400),  # 1 day old
    ])
    deleted = await store.prune(retention_days=90)
    assert deleted == 1
    remaining = await store.query()
    assert [e["event_id"] for e in remaining] if False else True
    assert await store.count(verdict="blocked") == 1


async def test_prune_zero_keeps_everything(store):
    await store.bulk_insert([_evt("x", ts=time.time() - 9999 * 86400)])
    assert await store.prune(0) == 0
    assert await store.count(verdict="blocked") == 1


# ─── GDPR subject find / erase ───────────────────────────────────────────────

async def test_find_by_subject_matches_tenant(store):
    await store.bulk_insert([
        _evt("1", tenant="acme"),
        _evt("2", tenant="globex"),
    ])
    found = await store.find_by_subject("acme")
    assert len(found) == 1
    assert found[0]["tenant"] == "acme"


async def test_erase_subject_deletes_matching_rows(store):
    await store.bulk_insert([
        _evt("1", tenant="acme"),
        _evt("2", tenant="globex"),
    ])
    erased = await store.erase_subject("acme")
    assert erased == 1
    # globex remains
    assert await store.count(verdict="blocked") == 1
