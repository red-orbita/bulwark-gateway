"""Tests for the sighting feedback dispatcher (Investigation Phase 5.3).

Cover the pure atom parser (``parse_ioc_atoms``) and the ``dispatch_once`` sweep
against fully faked collaborators (events store, IOC store, integration registry,
audit logger) — no Redis, no network. The dispatcher resolves each blocked IOC
atom's provenance, applies the TLP:RED suppression gate, routes to the right
lookup connector, and de-duplicates already-swept events across cycles.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import admin.services.audit_logger as audit_mod
import admin.services.integrations.registry as registry_mod
import admin.services.ioc_store as ioc_mod
import admin.services.security_events_store as events_mod
from admin.services.integrations.base import ConnectorError
from admin.services.integrations.sighting_dispatcher import (
    SightingDispatcher,
    parse_ioc_atoms,
)

# ─── parse_ioc_atoms (pure) ──────────────────────────────────────────────────


def test_parse_atoms_prefers_metadata():
    event = {
        "metadata": {"ioc_matches": ["domain:evil.test", "ip:1.2.3.4"]},
        "description": "IOC detected in input: url:ignored.test",
    }
    assert parse_ioc_atoms(event) == [("domain", "evil.test"), ("ip", "1.2.3.4")]


def test_parse_atoms_falls_back_to_description():
    event = {"description": "IOC detected in input: url:http://evil.test/x, ip:9.9.9.9"}
    assert parse_ioc_atoms(event) == [
        ("url", "http://evil.test/x"),
        ("ip", "9.9.9.9"),
    ]


def test_parse_atoms_dedups_and_drops_empty_values():
    event = {"metadata": {"ioc_matches": ["ip:1.1.1.1", "ip:1.1.1.1", "domain:", "junk"]}}
    assert parse_ioc_atoms(event) == [("ip", "1.1.1.1")]


def test_parse_atoms_tolerates_garbage():
    assert parse_ioc_atoms({}) == []
    assert parse_ioc_atoms({"metadata": "not-a-dict"}) == []
    assert parse_ioc_atoms({"metadata": {"ioc_matches": "nope"}}) == []


def test_parse_atoms_url_value_with_scheme_colon_kept_whole():
    # partition(":") splits only on the FIRST colon → type "url", value keeps
    # the rest verbatim including the scheme's own colon.
    event = {"metadata": {"ioc_matches": ["url:https://evil.test/a:b"]}}
    assert parse_ioc_atoms(event) == [("url", "https://evil.test/a:b")]


# ─── Fakes ───────────────────────────────────────────────────────────────────


class _FakeEventsStore:
    def __init__(self, events):
        self._events = events
        self.calls = []

    async def query(self, **kwargs):
        self.calls.append(kwargs)
        # Mirror the real store: newest-first.
        return sorted(self._events, key=lambda e: e.get("ts", 0), reverse=True)


class _FakeIOCStore:
    def __init__(self, entries):
        self._entries = entries

    def search(self, query):
        q = query.lower()
        return [e for e in self._entries if q in e.value.lower()]


class _FakeConnector:
    def __init__(self, *, result=None, exc=None):
        self._result = result
        self._exc = exc
        self.calls = []

    async def report_sighting(self, *, observable_type, value):
        self.calls.append((observable_type, value))
        if self._exc is not None:
            raise self._exc
        return self._result


class _FakeRegistry:
    def __init__(self, mapping):
        # mapping: source -> connector (enabled config assumed)
        self._mapping = mapping
        self.configs = [
            SimpleNamespace(enabled=True, type=src, id=f"{src}-1")
            for src in mapping
        ]

    def build_lookup_connector(self, config):
        return self._mapping.get(config.type)


class _FakeAudit:
    def __init__(self):
        self.entries = []

    async def log(self, **kwargs):
        self.entries.append(kwargs)


def _entry(value, *, source, tags=None, iid="e1"):
    return SimpleNamespace(id=iid, value=value, source=source, tags=tags or [])


def _event(value_atom, *, event_id="ev1", ts=100.0, source="ioc_check"):
    return {
        "event_id": event_id,
        "ts": ts,
        "source": source,
        "metadata": {"ioc_matches": [value_atom]},
        "description": f"IOC detected in input: {value_atom}",
    }


@pytest.fixture
def wired(monkeypatch):
    """Wire a dispatcher with faked collaborators + an in-memory watermark."""
    audit = _FakeAudit()
    monkeypatch.setattr(audit_mod, "get_audit_logger", lambda: audit)

    state = {"watermark": 0.0}

    def _build(*, events, ioc_entries, connectors, **kw):
        store = _FakeEventsStore(events)
        monkeypatch.setattr(
            events_mod, "get_security_events_store", lambda: store
        )
        monkeypatch.setattr(
            ioc_mod, "get_ioc_store", lambda: _FakeIOCStore(ioc_entries)
        )
        monkeypatch.setattr(
            registry_mod, "get_integration_registry",
            lambda: _FakeRegistry(connectors),
        )
        d = SightingDispatcher(enabled=True, **kw)
        # Deterministic, Redis-free watermark.
        monkeypatch.setattr(d, "_load_watermark", lambda: state["watermark"])
        monkeypatch.setattr(
            d, "_save_watermark", lambda ts: state.__setitem__("watermark", ts)
        )
        # Expose the stable store so tests can inspect its recorded query kwargs.
        d._test_store = store  # type: ignore[attr-defined]
        return d, audit, state

    return _build


# ─── dispatch_once ───────────────────────────────────────────────────────────


async def test_dispatch_reports_sighting_and_audits(wired):
    conn = _FakeConnector(result={"reported": True, "detail": "sighting created"})
    d, audit, _ = wired(
        events=[_event("domain:evil.test")],
        ioc_entries=[_entry("evil.test", source="opencti")],
        connectors={"opencti": conn},
    )
    stats = await d.dispatch_once()
    assert stats["reported"] == 1
    assert conn.calls == [("domain", "evil.test")]
    assert any(e["action"] == "sighting.reported" for e in audit.entries)
    assert d.total_reported == 1


async def test_dispatch_suppresses_tlp_red(wired):
    conn = _FakeConnector(result={"reported": True})
    d, audit, _ = wired(
        events=[_event("ip:1.2.3.4")],
        ioc_entries=[_entry("1.2.3.4", source="misp", tags=["tlp:red"])],
        connectors={"misp": conn},
    )
    stats = await d.dispatch_once()
    assert stats["suppressed"] == 1
    assert conn.calls == []  # gate blocks the remote call
    assert any(e["action"] == "sighting.suppressed" for e in audit.entries)


async def test_dispatch_skips_unknown_provenance(wired):
    d, _, _ = wired(
        events=[_event("domain:unknown.test")],
        ioc_entries=[],  # value not in the IOC store
        connectors={},
    )
    stats = await d.dispatch_once()
    assert stats["skipped"] == 1
    assert stats["reported"] == 0


async def test_dispatch_skips_non_intel_source(wired):
    # Value known, but sourced from a static feed we can't report sightings to.
    d, _, _ = wired(
        events=[_event("domain:evil.test")],
        ioc_entries=[_entry("evil.test", source="urlhaus")],
        connectors={},
    )
    stats = await d.dispatch_once()
    assert stats["skipped"] == 1


async def test_dispatch_skips_when_no_enabled_connector(wired):
    # Provenance is MISP but no MISP integration is configured/enabled.
    d, _, _ = wired(
        events=[_event("ip:1.2.3.4")],
        ioc_entries=[_entry("1.2.3.4", source="misp")],
        connectors={},  # empty registry
    )
    stats = await d.dispatch_once()
    assert stats["skipped"] == 1


async def test_dispatch_counts_connector_failure(wired):
    conn = _FakeConnector(exc=ConnectorError("boom"))
    d, audit, _ = wired(
        events=[_event("ip:1.2.3.4")],
        ioc_entries=[_entry("1.2.3.4", source="opencti")],
        connectors={"opencti": conn},
    )
    stats = await d.dispatch_once()
    assert stats["failed"] == 1
    assert d.total_failed == 1
    assert any(
        e["action"] == "sighting.failed" and e["result"] == "failure"
        for e in audit.entries
    )


async def test_dispatch_noop_when_nothing_to_sight(wired):
    conn = _FakeConnector(result={"reported": False, "detail": "no match"})
    d, audit, _ = wired(
        events=[_event("ip:1.2.3.4")],
        ioc_entries=[_entry("1.2.3.4", source="opencti")],
        connectors={"opencti": conn},
    )
    stats = await d.dispatch_once()
    assert stats["reported"] == 0
    assert stats["skipped"] == 1  # a benign no-op folds into skipped
    assert any(e["action"] == "sighting.noop" for e in audit.entries)


async def test_dispatch_dedups_across_cycles(wired):
    conn = _FakeConnector(result={"reported": True})
    d, _, _ = wired(
        events=[_event("domain:evil.test", event_id="dup1")],
        ioc_entries=[_entry("evil.test", source="opencti")],
        connectors={"opencti": conn},
    )
    first = await d.dispatch_once()
    second = await d.dispatch_once()
    assert first["reported"] == 1
    assert second["scanned"] == 0  # already-seen event is skipped wholesale
    assert len(conn.calls) == 1


async def test_dispatch_ignores_non_ioc_source(wired):
    d, _, _ = wired(
        events=[_event("domain:evil.test", source="input_guardrail")],
        ioc_entries=[_entry("evil.test", source="opencti")],
        connectors={"opencti": _FakeConnector(result={"reported": True})},
    )
    stats = await d.dispatch_once()
    assert stats["scanned"] == 0


async def test_dispatch_passes_watermark_to_query(wired):
    conn = _FakeConnector(result={"reported": True})
    d, _, state = wired(
        events=[_event("domain:evil.test", ts=500.0)],
        ioc_entries=[_entry("evil.test", source="opencti")],
        connectors={"opencti": conn},
    )
    state["watermark"] = 42.0

    await d.dispatch_once()

    store = d._test_store
    assert store.calls[0]["since"] == 42.0
    assert store.calls[0]["category"] == "malicious_domain"
    assert store.calls[0]["verdict"] == "block"
    # Watermark advanced past the processed event.
    assert state["watermark"] >= 500.0


async def test_dispatch_cap_limits_and_holds_watermark(wired):
    conn = _FakeConnector(result={"reported": True})
    d, _, state = wired(
        events=[
            _event("domain:a.test", event_id="a", ts=10.0),
            _event("domain:b.test", event_id="b", ts=20.0),
        ],
        ioc_entries=[
            _entry("a.test", source="opencti", iid="ea"),
            _entry("b.test", source="opencti", iid="eb"),
        ],
        connectors={"opencti": conn},
        max_per_sweep=1,
    )
    stats = await d.dispatch_once()
    assert stats["scanned"] == 1
    # Capped mid-sweep → watermark parks on the last fully-processed event (10.0),
    # NOT on `now`, so the un-processed one is picked up next cycle.
    assert state["watermark"] == 10.0


# ─── status snapshot + route ─────────────────────────────────────────────────


def test_status_snapshot_shape():
    d = SightingDispatcher(enabled=True, interval_seconds=42.0, sweep_limit=7, max_per_sweep=3)
    snap = d.status()
    assert snap["enabled"] is True
    assert snap["running"] is False
    assert snap["interval_seconds"] == 42.0
    assert snap["sweep_limit"] == 7
    assert snap["max_per_sweep"] == 3
    assert snap["total_reported"] == 0
    assert snap["total_suppressed"] == 0
    assert snap["total_failed"] == 0
    assert snap["last_error"] is None


async def test_sightings_status_route_returns_snapshot(monkeypatch):
    import admin.services.integrations.sighting_dispatcher as disp_mod
    from admin.routes.integrations import sightings_status

    d = SightingDispatcher(enabled=False)
    monkeypatch.setattr(disp_mod, "get_sighting_dispatcher", lambda: d)

    result = await sightings_status(user=SimpleNamespace(sub="admin", role="admin"))
    assert result == {"dispatcher": d.status()}
    assert result["dispatcher"]["enabled"] is False
