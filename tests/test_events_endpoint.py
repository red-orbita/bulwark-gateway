"""Endpoint tests for the Security Events viewer feed selection.

``list_security_events`` now reads the **durable** ``security_events`` table (not
the Redis live buffer). The ``verdict`` query param selects the feed: ``allowed``
reads the opt-in allowed records, ``blocked``/``warned`` narrow the security feed
by verdict, and the default returns the whole security feed (BLOCK + WARN).

Each test seeds a migrated throwaway SQLite store and drives the route directly.
"""

from __future__ import annotations

import pytest

from admin.routes import events as events_mod
from admin.services import security_events_store as store_mod
from admin.services.database import create_engine
from admin.services.migrations import run_migrations
from admin.services.security_events_store import SecurityEventsStore


@pytest.fixture
async def seeded_store(tmp_path, monkeypatch):
    """Migrated SQLite store, wired into the singleton the route resolves."""
    db_path = tmp_path / "endpoint_test.db"
    engine = create_engine(f"sqlite:///{db_path}")
    await engine.init()
    await run_migrations(engine)
    monkeypatch.setattr(store_mod, "get_database", lambda: engine)
    monkeypatch.setattr(store_mod, "_store", None)

    store = SecurityEventsStore()

    def _evt(event_id, *, ts, tenant, verdict, category, severity):
        return {
            "event_id": event_id, "ts": ts, "tenant": tenant, "agent": "bot",
            "verdict": verdict, "category": category, "severity": severity,
            "description": "d", "source": "input_guardrail", "pattern": "P",
            "request_id": "", "tool_name": "", "snippet": "", "input_hash": "",
            "metadata": {},
        }

    await store.bulk_insert([
        _evt("b", ts=3.0, tenant="acme", verdict="block", category="prompt_injection", severity="high"),
        _evt("w", ts=2.0, tenant="acme", verdict="warn", category="jailbreak", severity="medium"),
        _evt("a", ts=5.0, tenant="acme", verdict="allow", category="allowed", severity="info"),
    ])
    try:
        yield store
    finally:
        await engine.close()


async def _call(**kwargs):
    kwargs.setdefault("tenant", None)
    kwargs.setdefault("category", None)
    kwargs.setdefault("severity", None)
    kwargs.setdefault("verdict", None)
    kwargs.setdefault("limit", 50)
    kwargs.setdefault("offset", 0)
    kwargs.setdefault("user", None)
    return await events_mod.list_security_events(**kwargs)


async def test_default_feed_returns_block_and_warn(seeded_store):
    """No verdict → security feed (BLOCK + WARN), allowed records untouched."""
    result = await _call()
    verdicts = {e["verdict"] for e in result}
    assert verdicts == {"block", "warn"}
    assert "allow" not in verdicts


async def test_verdict_allowed_reads_allowed_feed(seeded_store):
    result = await _call(verdict="allowed")
    assert len(result) == 1
    assert result[0]["verdict"] == "allow"
    assert result[0]["category"] == "allowed"


async def test_verdict_blocked_filters_security_feed(seeded_store):
    result = await _call(verdict="blocked")
    assert [e["verdict"] for e in result] == ["block"]


async def test_verdict_warned_filters_security_feed(seeded_store):
    result = await _call(verdict="warned")
    assert [e["verdict"] for e in result] == ["warn"]


async def test_limit_is_applied(seeded_store):
    result = await _call(limit=1)
    assert len(result) == 1


async def test_summary_counts_full_history(seeded_store):
    summary = await events_mod.event_summary(user=None)
    assert summary["total"] == 2  # block + warn
    assert summary["allowed_recorded"] == 1
    assert summary["by_tenant"] == {"acme": 2}
