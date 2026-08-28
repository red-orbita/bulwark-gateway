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


def test_event_id_prefers_proxy_stamped_id():
    # The proxy stamps the originating SecurityEvent's id into the buffer entry;
    # it MUST be preserved verbatim so a correlation incident's
    # contributing_event_ids resolve to this durable row (drill-down pivot).
    entry = {
        "event_id": "9254207c34154bc0bf977df6956123bf",
        "ts": 1.0, "tenant": "acme", "verdict": "warn", "pattern": "P",
    }
    assert sync_mod._event_id(entry) == "9254207c34154bc0bf977df6956123bf"
    # And it survives normalisation onto the durable dict.
    assert sync_mod._normalise(entry)["event_id"] == "9254207c34154bc0bf977df6956123bf"


def test_event_id_falls_back_to_hash_without_stamp():
    # Legacy/other push paths omit event_id → the stable content hash still
    # applies (and stays idempotent for the same identifying fields).
    entry = {"ts": 1.0, "tenant": "acme", "verdict": "block", "pattern": "P"}
    eid = sync_mod._event_id(entry)
    assert eid == sync_mod._event_id(dict(entry))
    assert len(eid) == 64  # sha256 hex, distinct from a uuid4-style stamp


def test_event_id_ignores_blank_stamp():
    # A present-but-empty event_id must not shadow the content-hash fallback.
    entry = {"event_id": "  ", "ts": 1.0, "tenant": "acme", "verdict": "block"}
    assert sync_mod._event_id(entry) == sync_mod._event_id(
        {"ts": 1.0, "tenant": "acme", "verdict": "block"}
    )


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


async def test_contributing_event_ids_resolve_after_sync(wired_store, monkeypatch):
    """End-to-end drill-down pivot: an incident's contributing_event_ids (the
    original SecurityEvent ids captured in-memory) must resolve to the durable
    rows after those same events drain through the buffer→sync path.

    This is the guarantee the Investigation Center relies on and that the
    recompute-the-id behaviour silently broke: the input/output detections
    persisted under a *different* id than the incident recorded, so the pivot
    returned nothing.
    """
    # Buffer entries as the proxy's _push_recent_block writes them: the input
    # WARN detections and the corroborating output detection each carry their
    # originating event_id verbatim.
    in_evt = {"event_id": "aaaa1111", "ts": 10.0, "tenant": "acme", "agent": "bot",
              "verdict": "warn", "category": "exfiltration", "severity": "medium",
              "source": "input_guardrail", "pattern": "EX-1"}
    out_evt = {"event_id": "bbbb2222", "ts": 10.1, "tenant": "acme", "agent": "bot",
               "verdict": "warn", "category": "credential_access", "severity": "critical",
               "source": "output_filter", "pattern": "CRED-1"}
    incident = {"event_id": "cccc3333", "ts": 10.2, "tenant": "acme", "agent": "bot",
                "verdict": "warn", "category": "exfiltration", "severity": "critical",
                "source": "correlation_engine",
                "incident_id": "INC-42",
                "metadata": {"incident_id": "INC-42",
                             "contributing_event_ids": ["aaaa1111", "bbbb2222"]}}
    monkeypatch.setattr(sync_mod, "_drain_redis", lambda max_items: [
        sync_mod._normalise(in_evt),
        sync_mod._normalise(out_evt),
        sync_mod._normalise(incident),
    ])

    sync = sync_mod.SecurityEventsSync(interval_seconds=999, prune_every_n=999)
    assert await sync.sync_once() == 3

    # The incident row carries the contributing ids…
    carriers = await wired_store.find_by_incident("INC-42")
    assert len(carriers) == 1
    ids = carriers[0]["metadata"]["contributing_event_ids"]
    assert ids == ["aaaa1111", "bbbb2222"]
    # …and every one of them resolves to a durable detection (pivot works).
    # Before the fix these persisted under a recomputed hash id and returned 0.
    resolved = await wired_store.find_by_event_ids(ids)
    assert len(resolved) == 2
    assert {r["source"] for r in resolved} == {"input_guardrail", "output_filter"}
    assert {r["category"] for r in resolved} == {"exfiltration", "credential_access"}
