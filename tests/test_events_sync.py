"""Tests for the Security Events sync (Redis live buffer → durable store).

Covers the pure helpers (stable event_id, normalisation, SIEM-aware retention
resolution) and one end-to-end ``sync_once`` cycle that drains a stubbed Redis
buffer into a migrated throwaway SQLite store — proving the drain is idempotent
across repeated syncs (the whole point of the stable event_id).
"""

from __future__ import annotations

import pytest

from admin.services import events_settings
from admin.services import events_sync as sync_mod
from admin.services import security_events_store as store_mod
from admin.services.database import create_engine
from admin.services.migrations import run_migrations
from admin.services.security_events_store import SecurityEventsStore

# ─── event_id stability ──────────────────────────────────────────────────────

def test_event_id_is_stable_for_same_entry():
    entry = {"ts": 1.0, "tenant": "acme", "verdict": "block", "pattern": "P", "input_hash": "h"}
    assert sync_mod._event_id(entry) == sync_mod._event_id(dict(entry))


def test_event_id_differs_when_identifying_fields_change():
    a = {"ts": 1.0, "tenant": "acme", "verdict": "block"}
    b = {"ts": 2.0, "tenant": "acme", "verdict": "block"}
    assert sync_mod._event_id(a) != sync_mod._event_id(b)


# ─── normalisation ───────────────────────────────────────────────────────────

def test_normalise_fills_defaults_and_event_id():
    norm = sync_mod._normalise({"ts": 1.0, "tenant": "acme", "verdict": "warn"})
    assert norm["event_id"]
    assert norm["tenant"] == "acme"
    assert norm["verdict"] == "warn"
    assert norm["agent"] == ""  # default-filled


def test_normalise_rejects_non_dict():
    assert sync_mod._normalise("nope") is None


# ─── SIEM-aware retention resolution ─────────────────────────────────────────

def test_retention_explicit_env_wins(monkeypatch):
    events_settings.reset_cache_for_tests()
    monkeypatch.setenv("BULWARK_EVENTS_RETENTION_DAYS", "30")
    monkeypatch.setenv("BULWARK_TELEMETRY_ENABLED", "true")
    assert sync_mod.resolve_retention_days() == 30


def test_retention_defaults_to_90_with_siem(monkeypatch):
    events_settings.reset_cache_for_tests()
    monkeypatch.delenv("BULWARK_EVENTS_RETENTION_DAYS", raising=False)
    monkeypatch.setenv("BULWARK_TELEMETRY_ENABLED", "true")
    assert sync_mod.resolve_retention_days() == 90


def test_retention_unlimited_without_siem(monkeypatch):
    events_settings.reset_cache_for_tests()
    monkeypatch.delenv("BULWARK_EVENTS_RETENTION_DAYS", raising=False)
    monkeypatch.delenv("BULWARK_TELEMETRY_ENABLED", raising=False)
    assert sync_mod.resolve_retention_days() == 0


# ─── end-to-end sync_once ────────────────────────────────────────────────────

@pytest.fixture
async def wired_store(tmp_path, monkeypatch):
    """Migrated SQLite store wired into the store singleton used by the sync."""
    db_path = tmp_path / "sync_test.db"
    engine = create_engine(f"sqlite:///{db_path}")
    await engine.init()
    await run_migrations(engine)
    monkeypatch.setattr(store_mod, "get_database", lambda: engine)
    # Reset the store singleton so it binds to our patched get_database.
    monkeypatch.setattr(store_mod, "_store", None)
    try:
        yield SecurityEventsStore()
    finally:
        await engine.close()


async def test_sync_once_drains_buffer_into_store(wired_store, monkeypatch):
    blocks = [
        {"ts": 3.0, "tenant": "acme", "verdict": "block", "category": "prompt_injection",
         "severity": "high", "pattern": "P1", "input_hash": "h1"},
        {"ts": 2.0, "tenant": "acme", "verdict": "warn", "category": "jailbreak",
         "severity": "medium", "pattern": "P2", "input_hash": "h2"},
    ]
    allowed = [
        {"ts": 5.0, "tenant": "acme", "verdict": "allow", "category": "allowed",
         "severity": "info", "pattern": "", "input_hash": "h3"},
    ]
    # Stub the Redis drain so no live server is needed.
    monkeypatch.setattr(sync_mod, "_drain_redis", lambda max_items: [
        *[sync_mod._normalise(b) for b in blocks],
        *[sync_mod._normalise(a) for a in allowed],
    ])

    sync = sync_mod.SecurityEventsSync(interval_seconds=999, prune_every_n=999)
    inserted = await sync.sync_once()
    assert inserted == 3

    # Re-running the same buffer must be idempotent (stable event_id + IGNORE).
    again = await sync.sync_once()
    assert again == 0

    assert await wired_store.count(verdict="blocked") == 1
    assert await wired_store.count(verdict="warned") == 1
    assert await wired_store.count(verdict="allowed") == 1


async def test_sync_once_empty_buffer(wired_store, monkeypatch):
    monkeypatch.setattr(sync_mod, "_drain_redis", lambda max_items: [])
    sync = sync_mod.SecurityEventsSync(interval_seconds=999)
    assert await sync.sync_once() == 0
