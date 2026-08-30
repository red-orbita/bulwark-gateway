"""Tests for the Investigation Center — the SOC triage workspace.

Exercises the feature end-to-end against a real migrated SQLite database:

* :class:`TriageStore` CRUD (status/assignee transitions, append-only notes,
  bounds, upsert idempotency);
* the :class:`SecurityEventsStore` investigation pivots
  (``list_correlation_alerts`` / ``find_by_incident`` / ``find_by_event_ids`` /
  ``find_by_scope_digest``);
* the ``/admin/investigation/*`` route handlers, called directly with a
  :class:`TokenPayload`, covering the alert-queue triage annotation, incident and
  origin drill-downs, triage mutation, RBAC (viewer cannot write) and tenant
  scoping (no cross-tenant existence leak);
* the correlation-engine explainability additions the feature depends on: the
  per-signal :class:`ConfidenceBreakdown` and the incident's
  ``contributing_event_ids`` linkage.
"""

from __future__ import annotations

import fnmatch
import time
from datetime import datetime, timedelta, timezone

import pytest

from admin.models.auth import TokenPayload, UserRole

# ─── shared fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
async def engine(tmp_path):
    """A migrated throwaway SQLite engine shared by the store fixtures."""
    from admin.services.database import create_engine
    from admin.services.migrations import run_migrations

    eng = create_engine(f"sqlite:///{tmp_path / 'inv_test.db'}")
    await eng.init()
    await run_migrations(eng)
    try:
        yield eng
    finally:
        await eng.close()


@pytest.fixture
async def events_store(engine, monkeypatch):
    from admin.services import security_events_store as store_mod
    from admin.services.security_events_store import SecurityEventsStore

    monkeypatch.setattr(store_mod, "get_database", lambda: engine)
    return SecurityEventsStore()


@pytest.fixture
async def triage_store(engine, monkeypatch):
    from admin.services import investigation_store as store_mod
    from admin.services.investigation_store import TriageStore

    monkeypatch.setattr(store_mod, "get_database", lambda: engine)
    return TriageStore()


def _evt(event_id: str, *, ts: float | None = None, tenant="acme", verdict="block",
         category="exfiltration", severity="high", source="correlation_engine",
         incident_id="", scope_digests=None, metadata=None, **extra) -> dict:
    e = {
        "event_id": event_id,
        "ts": ts if ts is not None else time.time(),
        "tenant": tenant,
        "agent": "support-bot",
        "verdict": verdict,
        "category": category,
        "severity": severity,
        "description": "correlated exfiltration",
        "source": source,
        "pattern": "",
        "request_id": f"{tenant}:support-bot:1",
        "tool_name": "",
        "snippet": "redacted",
        "input_hash": "deadbeef",
        "metadata": metadata or {},
        "incident_id": incident_id,
        "scope_digests": scope_digests or [],
    }
    e.update(extra)
    return e


def _token(role: UserRole, tenant: str | None = None) -> TokenPayload:
    now = datetime.now(timezone.utc)
    return TokenPayload(sub=f"{role.value}-user", role=role, tenant=tenant,
                        exp=now + timedelta(hours=1), iat=now)


def _admin(tenant=None):
    return _token(UserRole.ADMIN, tenant)


def _viewer(tenant=None):
    return _token(UserRole.VIEWER, tenant)


# ═══════════════════════════════════════════════════════════════════════
# TriageStore
# ═══════════════════════════════════════════════════════════════════════


class TestTriageStore:
    async def test_get_absent_is_none(self, triage_store):
        assert await triage_store.get("incident", "nope") is None

    async def test_set_state_creates_and_records_action(self, triage_store):
        rec = await triage_store.set_state(
            subject_type="incident", subject_key="inc-1", tenant="acme",
            actor="alice", status="acknowledged", assignee="bob",
        )
        assert rec["status"] == "acknowledged"
        assert rec["assignee"] == "bob"
        assert rec["tenant"] == "acme"
        # The transition is journalled as an actor-stamped action note.
        assert len(rec["notes"]) == 1
        assert rec["notes"][0]["kind"] == "action"
        assert rec["notes"][0]["author"] == "alice"

    async def test_set_state_no_change_adds_no_note(self, triage_store):
        await triage_store.set_state(
            subject_type="incident", subject_key="inc-2", tenant="acme",
            actor="a", status="open",
        )
        rec = await triage_store.set_state(
            subject_type="incident", subject_key="inc-2", tenant="acme",
            actor="a", status="open",
        )
        # open→open is a no-op; the seed create wrote nothing either.
        assert rec["notes"] == []

    async def test_invalid_status_rejected(self, triage_store):
        with pytest.raises(ValueError):
            await triage_store.set_state(
                subject_type="incident", subject_key="inc-3", tenant="acme",
                actor="a", status="bogus",
            )

    async def test_invalid_subject_type_rejected(self, triage_store):
        with pytest.raises(ValueError):
            await triage_store.set_state(
                subject_type="planet", subject_key="x", tenant="acme", actor="a",
                status="open",
            )

    async def test_add_note_appends_and_is_ordered(self, triage_store):
        await triage_store.add_note(
            subject_type="origin", subject_key="session:aaaaaaaaaaaaaaaa",
            tenant="acme", actor="a", text="first",
        )
        rec = await triage_store.add_note(
            subject_type="origin", subject_key="session:aaaaaaaaaaaaaaaa",
            tenant="acme", actor="b", text="second",
        )
        assert [n["text"] for n in rec["notes"]] == ["first", "second"]
        assert [n["kind"] for n in rec["notes"]] == ["note", "note"]

    async def test_add_empty_note_rejected(self, triage_store):
        with pytest.raises(ValueError):
            await triage_store.add_note(
                subject_type="incident", subject_key="inc-4", tenant="acme",
                actor="a", text="   ",
            )

    async def test_note_is_length_bounded(self, triage_store):
        rec = await triage_store.add_note(
            subject_type="incident", subject_key="inc-5", tenant="acme",
            actor="a", text="x" * 9000,
        )
        assert len(rec["notes"][0]["text"]) <= 4000

    async def test_get_map_batches(self, triage_store):
        await triage_store.set_state(
            subject_type="incident", subject_key="inc-a", tenant="acme",
            actor="a", status="resolved",
        )
        await triage_store.set_state(
            subject_type="origin", subject_key="tenant:bbbbbbbbbbbbbbbb",
            tenant="acme", actor="a", status="in_progress",
        )
        m = await triage_store.get_map([
            ("incident", "inc-a"),
            ("origin", "tenant:bbbbbbbbbbbbbbbb"),
            ("incident", "missing"),
        ])
        assert m[("incident", "inc-a")]["status"] == "resolved"
        assert m[("origin", "tenant:bbbbbbbbbbbbbbbb")]["status"] == "in_progress"
        assert ("incident", "missing") not in m

    async def test_get_map_disambiguates_same_key_across_types(self, triage_store):
        # A subject_key can collide across subject types; get_map keys on the pair.
        await triage_store.set_state(
            subject_type="incident", subject_key="shared", tenant="acme",
            actor="a", status="resolved",
        )
        m = await triage_store.get_map([("origin", "shared")])
        # Only the incident row exists; the origin pair must not match it.
        assert ("origin", "shared") not in m

    async def test_list_records_filters_and_orders(self, triage_store):
        await triage_store.set_state(
            subject_type="incident", subject_key="o1", tenant="acme",
            actor="a", status="open",
        )
        await triage_store.set_state(
            subject_type="incident", subject_key="o2", tenant="acme",
            actor="a", status="resolved",
        )
        opens = await triage_store.list_records(status="open")
        assert [r["subject_key"] for r in opens] == ["o1"]
        acme = await triage_store.list_records(tenant="acme")
        assert {r["subject_key"] for r in acme} == {"o1", "o2"}


# ═══════════════════════════════════════════════════════════════════════
# SecurityEventsStore investigation pivots
# ═══════════════════════════════════════════════════════════════════════


class TestEventStorePivots:
    async def test_list_correlation_alerts_only_engine_source(self, events_store):
        await events_store.bulk_insert([
            _evt("c1", source="correlation_engine"),
            _evt("g1", source="input_guardrail"),
        ])
        alerts = await events_store.list_correlation_alerts()
        assert [a["request_id"] for a in alerts]  # non-empty
        assert all(a["source"] == "correlation_engine" for a in alerts)
        assert len(alerts) == 1

    async def test_list_correlation_alerts_verdict_filter(self, events_store):
        await events_store.bulk_insert([
            _evt("b1", verdict="block"),
            _evt("w1", verdict="warn"),
        ])
        warns = await events_store.list_correlation_alerts(verdict="warn")
        assert [a["verdict"] for a in warns] == ["warn"]

    async def test_list_correlation_alerts_tenant_and_time(self, events_store):
        now = time.time()
        await events_store.bulk_insert([
            _evt("acme1", tenant="acme", ts=now),
            _evt("evil1", tenant="evil", ts=now),
            _evt("old1", tenant="acme", ts=now - 10_000),
        ])
        acme_recent = await events_store.list_correlation_alerts(
            tenant="acme", since=now - 100
        )
        assert [a["request_id"] for a in acme_recent] == ["acme:support-bot:1"]

    async def test_find_by_incident(self, events_store):
        await events_store.bulk_insert([
            _evt("inc-evt", incident_id="INC-42"),
            _evt("other", incident_id="INC-99"),
        ])
        rows = await events_store.find_by_incident("INC-42")
        assert len(rows) == 1
        assert rows[0]["incident_id"] == "INC-42"

    async def test_find_by_event_ids(self, events_store):
        await events_store.bulk_insert([
            _evt("in-1", source="input_guardrail"),
            _evt("out-1", source="output_filter"),
            _evt("noise", source="input_guardrail"),
        ])
        rows = await events_store.find_by_event_ids(["in-1", "out-1"])
        # event_id is not surfaced in the row payload, but the query resolved both.
        assert len(rows) == 2

    async def test_find_by_event_ids_empty(self, events_store):
        assert await events_store.find_by_event_ids([]) == []

    async def test_find_by_scope_digest_whole_token_match(self, events_store):
        token = "session:0123456789abcdef"
        await events_store.bulk_insert([
            _evt("s1", scope_digests=[token, "tenant:ffffffffffffffff"]),
            _evt("s2", scope_digests=["tenant:ffffffffffffffff"]),
        ])
        rows = await events_store.find_by_scope_digest(token)
        assert len(rows) == 1
        assert token in rows[0]["scope_digests"]

    async def test_find_by_scope_digest_no_partial_collision(self, events_store):
        # A whole-token LIKE must not match a token that merely contains the query
        # as a substring (padding guards against partial-token collisions).
        await events_store.bulk_insert([
            _evt("p1", scope_digests=["session:0123456789abcdef"]),
        ])
        rows = await events_store.find_by_scope_digest("session:0123456789abcde")
        assert rows == []

    async def test_scope_digests_surface_as_list(self, events_store):
        await events_store.bulk_insert([
            _evt("x1", scope_digests=["session:aaaaaaaaaaaaaaaa", "tenant:bbbbbbbbbbbbbbbb"]),
        ])
        alerts = await events_store.list_correlation_alerts()
        assert alerts[0]["scope_digests"] == [
            "session:aaaaaaaaaaaaaaaa", "tenant:bbbbbbbbbbbbbbbb",
        ]


# ═══════════════════════════════════════════════════════════════════════
# Route handlers
# ═══════════════════════════════════════════════════════════════════════


@pytest.fixture
async def wired(engine, monkeypatch):
    """Wire the investigation route module against the migrated DB + fakes."""
    import admin.routes.investigation as inv
    from admin.services import investigation_store as tstore_mod
    from admin.services import security_events_store as estore_mod
    from admin.services.investigation_store import TriageStore
    from admin.services.security_events_store import SecurityEventsStore

    monkeypatch.setattr(estore_mod, "get_database", lambda: engine)
    monkeypatch.setattr(tstore_mod, "get_database", lambda: engine)

    events = SecurityEventsStore()
    triage = TriageStore()
    monkeypatch.setattr(inv, "get_security_events_store", lambda: events)
    monkeypatch.setattr(inv, "get_triage_store", lambda: triage)

    class _Audit:
        def __init__(self):
            self.entries = []

        async def log(self, **kw):
            self.entries.append(kw)

    audit = _Audit()
    monkeypatch.setattr(inv, "get_audit_logger", lambda: audit)
    # No Redis in unit tests — the origin endpoint degrades gracefully.
    monkeypatch.setattr(inv, "_redis", lambda: None)
    return inv, events, triage, audit


class TestInvestigationEndpoints:
    async def test_status_reports_can_write(self, wired):
        inv, _, _, _ = wired
        out = await inv.investigation_status(user=_admin())
        assert out["can_write"] is True
        assert "open" in out["statuses"]
        assert set(out["subject_types"]) == {"incident", "origin", "session"}

        viewer_out = await inv.investigation_status(user=_viewer())
        assert viewer_out["can_write"] is False

    async def test_alerts_annotated_with_triage(self, wired):
        inv, events, triage, _ = wired
        await events.bulk_insert([_evt("a1", incident_id="INC-1")])
        await triage.set_state(
            subject_type="incident", subject_key="INC-1", tenant="acme",
            actor="a", status="in_progress", assignee="carol",
        )
        out = await inv.investigation_alerts(
            user=_admin(), tenant=None, verdict=None,
            lookback_hours=24, limit=50, offset=0,
        )
        assert out["count"] == 1
        row = out["alerts"][0]
        assert row["subject_type"] == "incident"
        assert row["subject_key"] == "INC-1"
        assert row["triage_status"] == "in_progress"
        assert row["assignee"] == "carol"

    async def test_alerts_default_open_when_untriaged(self, wired):
        inv, events, _, _ = wired
        await events.bulk_insert([_evt("a2", incident_id="INC-2")])
        out = await inv.investigation_alerts(
            user=_admin(), tenant=None, verdict=None,
            lookback_hours=24, limit=50, offset=0,
        )
        assert out["alerts"][0]["triage_status"] == "open"

    async def test_alerts_tenant_scoped(self, wired):
        inv, events, _, _ = wired
        await events.bulk_insert([
            _evt("mine", tenant="acme"),
            _evt("theirs", tenant="evil"),
        ])
        out = await inv.investigation_alerts(
            user=_admin(tenant="acme"), tenant=None, verdict=None,
            lookback_hours=24, limit=50, offset=0,
        )
        assert all(a["tenant"] == "acme" for a in out["alerts"])
        assert out["count"] == 1

    async def test_incident_drilldown(self, wired):
        inv, events, _, _ = wired
        meta = {
            "confidence": 0.85,
            "confidence_breakdown": {"entropy": 0.4, "critical": 0.3, "total": 0.7},
            "contributing_event_ids": ["in-1", "out-1"],
            "input_categories": ["prompt_injection"],
            "output_categories": ["credential_access"],
        }
        await events.bulk_insert([
            _evt("carrier", incident_id="INC-7", metadata=meta),
            _evt("in-1", source="input_guardrail", category="prompt_injection"),
            _evt("out-1", source="output_filter", category="credential_access"),
        ])
        out = await inv.investigation_incident("INC-7", user=_admin())
        assert out["incident_id"] == "INC-7"
        assert out["confidence"] == 0.85
        assert out["confidence_breakdown"]["total"] == 0.7
        assert len(out["contributing_events"]) == 2
        assert out["input_categories"] == ["prompt_injection"]

    async def test_incident_not_found(self, wired):
        inv, _, _, _ = wired
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as ei:
            await inv.investigation_incident("nope", user=_admin())
        assert ei.value.status_code == 404

    async def test_incident_cross_tenant_is_404(self, wired):
        inv, events, _, _ = wired
        from fastapi import HTTPException

        await events.bulk_insert([_evt("c", tenant="evil", incident_id="INC-X")])
        with pytest.raises(HTTPException) as ei:
            await inv.investigation_incident("INC-X", user=_admin(tenant="acme"))
        # No cross-tenant existence leak — 404, not 403.
        assert ei.value.status_code == 404

    async def test_origin_drilldown_timeline(self, wired):
        inv, events, _, _ = wired
        token = "session:0123456789abcdef"
        await events.bulk_insert([
            _evt("t1", scope_digests=[token]),
            _evt("t2", scope_digests=[token]),
        ])
        out = await inv.investigation_origin(
            "session", "0123456789abcdef", user=_admin(),
            lookback_hours=None, limit=200,
        )
        assert out["token"] == token
        assert out["event_count"] == 2
        assert out["risk"] is None  # no Redis wired

    async def test_origin_rejects_bad_scope(self, wired):
        inv, _, _, _ = wired
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as ei:
            await inv.investigation_origin("bogus", "0123456789abcdef", user=_admin())
        assert ei.value.status_code == 400

    async def test_origin_rejects_bad_digest(self, wired):
        inv, _, _, _ = wired
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as ei:
            await inv.investigation_origin("session", "not-hex", user=_admin())
        assert ei.value.status_code == 400

    async def test_origin_timeline_tenant_scoped(self, wired):
        inv, events, _, _ = wired
        token = "session:0123456789abcdef"
        await events.bulk_insert([
            _evt("mine", tenant="acme", scope_digests=[token]),
            _evt("theirs", tenant="evil", scope_digests=[token]),
        ])
        out = await inv.investigation_origin(
            "session", "0123456789abcdef", user=_admin(tenant="acme"),
            lookback_hours=None, limit=200,
        )
        assert out["event_count"] == 1
        assert all(e["tenant"] == "acme" for e in out["timeline"])

    async def test_triage_state_writes_and_audits(self, wired):
        inv, events, _, audit = wired
        await events.bulk_insert([_evt("carrier", incident_id="INC-9")])
        body = inv.TriageStateRequest(
            subject_type="incident", subject_key="INC-9", status="resolved"
        )
        out = await inv.investigation_triage_state(body, user=_admin())
        assert out["triage"]["status"] == "resolved"
        assert audit.entries[-1]["action"] == "investigation.triage_state"

    async def test_triage_state_requires_a_field(self, wired):
        inv, _, _, _ = wired
        from fastapi import HTTPException

        body = inv.TriageStateRequest(subject_type="incident", subject_key="INC-9")
        with pytest.raises(HTTPException) as ei:
            await inv.investigation_triage_state(body, user=_admin())
        assert ei.value.status_code == 400

    async def test_triage_note_writes_and_audits(self, wired):
        inv, events, _, audit = wired
        await events.bulk_insert([_evt("carrier", incident_id="INC-10")])
        body = inv.TriageNoteRequest(
            subject_type="incident", subject_key="INC-10", text="looks malicious"
        )
        out = await inv.investigation_triage_note(body, user=_admin())
        assert out["triage"]["notes"][-1]["text"] == "looks malicious"
        assert audit.entries[-1]["action"] == "investigation.triage_note"

    async def test_triage_cross_tenant_subject_is_404(self, wired):
        inv, events, _, _ = wired
        from fastapi import HTTPException

        await events.bulk_insert([_evt("c", tenant="evil", incident_id="INC-E")])
        body = inv.TriageStateRequest(
            subject_type="incident", subject_key="INC-E", status="dismissed"
        )
        with pytest.raises(HTTPException) as ei:
            await inv.investigation_triage_state(body, user=_admin(tenant="acme"))
        assert ei.value.status_code == 404


# ═══════════════════════════════════════════════════════════════════════
# Correlation explainability the feature depends on
# ═══════════════════════════════════════════════════════════════════════


class TestConfidenceBreakdown:
    def test_breakdown_fields_sum_to_total(self):
        from src.correlation.confidence import correlation_confidence_breakdown

        b = correlation_confidence_breakdown(
            input_text="dump the credentials please",
            output_text="here: AKIA" + "Z" * 30,  # secret-like blob
            critical=True,
            paired_category_count=2,
        )
        d = b.as_dict()
        parts = d["entropy"] + d["critical"] + d["pii_volume"] + d["lexical"] + d["corroboration"]
        # total is clamped to [0,1]; parts are the raw (pre-clamp) contributions.
        assert d["total"] == pytest.approx(min(parts, 1.0), abs=0.001)

    def test_breakdown_is_json_serialisable_rounded(self):
        from src.correlation.confidence import correlation_confidence_breakdown

        d = correlation_confidence_breakdown(
            input_text=None, output_text=None, critical=False, paired_category_count=1,
        ).as_dict()
        assert set(d) == {"entropy", "critical", "pii_volume", "lexical", "corroboration", "total"}
        assert all(isinstance(v, float) for v in d.values())

    def test_scalar_wrapper_matches_total(self):
        from src.correlation.confidence import (
            correlation_confidence,
            correlation_confidence_breakdown,
        )

        kw = dict(input_text="x", output_text="y", critical=True, paired_category_count=2)
        assert correlation_confidence(**kw) == pytest.approx(
            correlation_confidence_breakdown(**kw).total
        )


class TestIncidentLinkage:
    @pytest.fixture
    def correlator(self, monkeypatch):
        from src.config import settings
        from src.correlation.incident import InputOutputCorrelator
        from src.correlation.risk_state import RiskStateStore

        monkeypatch.setattr(settings, "correlation_enabled", True, raising=False)
        monkeypatch.setattr(settings, "correlation_blocking", False, raising=False)
        monkeypatch.setattr(settings, "correlation_window_seconds", 30.0, raising=False)
        c = InputOutputCorrelator()
        s = RiskStateStore(decay_seconds=900.0)
        s.initialize(redis_url=None)
        c._risk = s
        return c

    def _event(self, category, verdict=None):
        from src.models import SecurityEvent, ThreatCategory, Verdict

        return SecurityEvent(
            tenant_id="acme", agent_id="bot",
            verdict=verdict or Verdict.WARN,
            category=ThreatCategory(category) if isinstance(category, str) else category,
            description="t", source="test", severity="high",
        )

    def test_incident_links_contributing_event_ids(self, correlator):
        from src.models import ThreatCategory

        in_evt = self._event(ThreatCategory.PROMPT_INJECTION)
        out_evt = self._event(ThreatCategory.CREDENTIAL_ACCESS)
        incident = correlator.evaluate(
            input_events=[in_evt],
            output_events=[out_evt],
            tenant_id="acme", agent_id="bot",
            input_hash="deadbeef", request_id="acme:bot:1",
        )
        assert incident is not None
        assert incident.contributing_event_ids == [in_evt.event_id, out_evt.event_id]
        # And they survive into the emitted SecurityEvent metadata.
        se = incident.to_security_event()
        assert se.metadata["contributing_event_ids"] == [in_evt.event_id, out_evt.event_id]
        assert "confidence_breakdown" in se.metadata

    def test_contributing_ids_dedup_and_order_stable(self, correlator):
        from src.models import ThreatCategory

        shared = self._event(ThreatCategory.EXFILTRATION)
        out_evt = self._event(ThreatCategory.PII_LEAK)
        incident = correlator.evaluate(
            input_events=[shared, shared],   # duplicate reference
            output_events=[out_evt],
            tenant_id="acme", agent_id="bot",
        )
        assert incident is not None
        assert incident.contributing_event_ids == [shared.event_id, out_evt.event_id]


# ═══════════════════════════════════════════════════════════════════════
# Session-decomposition subject (Fase 1: first-class investigation subject)
# ═══════════════════════════════════════════════════════════════════════


class _FakeRedis:
    """Minimal in-memory Redis stub covering the session readers only.

    Implements just the surface the Session Tracker helpers touch: ``ping``,
    ``scan_iter`` (glob), ``zrange`` (withscores), ``ttl`` and ``hgetall``.
    """

    def __init__(self, zsets=None, hashes=None, ttls=None):
        self._z = zsets or {}       # redis_key -> list[(member, score)]
        self._h = hashes or {}      # redis_key -> dict
        self._ttls = ttls or {}     # redis_key -> int

    def ping(self):
        return True

    def scan_iter(self, match=None, count=100):
        for k in list(self._z.keys()):
            if match is None or fnmatch.fnmatch(k, match):
                yield k

    def zrange(self, key, start, end, withscores=False):
        members = self._z.get(key, [])
        return list(members) if withscores else [m for m, _ in members]

    def ttl(self, key):
        return self._ttls.get(key, -1)

    def hgetall(self, key):
        return dict(self._h.get(key, {}))


class TestSessionSubject:
    async def test_store_accepts_session_subject(self, triage_store):
        rec = await triage_store.set_state(
            subject_type="session", subject_key="a1b2c3d4e5f60718",
            tenant="", actor="alice", status="in_progress",
        )
        assert rec["subject_type"] == "session"
        assert rec["status"] == "in_progress"
        assert rec["notes"][0]["kind"] == "action"

    async def test_session_drilldown_summarises_windows(self, wired, monkeypatch):
        inv, _, _, _ = wired
        digest = "a1b2c3d4e5f60718"
        key5 = f"bulwark:session:{digest}:signals"
        fake = _FakeRedis(
            zsets={key5: [("role_play:3.0", 1000.0), ("obfuscation:2.0", 1001.0)]},
            ttls={key5: 250},
        )
        monkeypatch.setattr(inv, "_redis", lambda: fake)
        out = await inv.investigation_session(digest, user=_admin())
        assert out["digest"] == digest
        assert len(out["windows"]) == 1
        w = out["windows"][0]
        assert w["window"] == "5m"
        assert w["score"] == pytest.approx(5.0)
        # default 5m thresholds: warn 5.0 / block 8.0 → 5.0 crosses WARN only.
        assert w["verdict"] == "warn"
        assert "role_play" in w["distinct_signals"]
        assert w["ttl_seconds"] == 250

    async def test_session_drilldown_block_verdict(self, wired, monkeypatch):
        inv, _, _, _ = wired
        digest = "b" * 16
        key5 = f"bulwark:session:{digest}:signals"
        fake = _FakeRedis(zsets={key5: [("combo:9.0", 1000.0)]})
        monkeypatch.setattr(inv, "_redis", lambda: fake)
        out = await inv.investigation_session(digest, user=_admin())
        assert out["windows"][0]["verdict"] == "block"

    async def test_session_drilldown_rejects_bad_digest(self, wired):
        inv, _, _, _ = wired
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as ei:
            await inv.investigation_session("not-hex-digest!", user=_admin())
        assert ei.value.status_code == 400

    async def test_session_drilldown_no_redis_is_empty(self, wired):
        inv, _, _, _ = wired  # the wired fixture pins _redis -> None
        out = await inv.investigation_session("a" * 16, user=_admin())
        assert out["windows"] == []
        assert out["triage"] is None

    async def test_session_drilldown_surfaces_triage(self, wired, monkeypatch):
        inv, _, triage, _ = wired
        digest = "c" * 16
        await triage.set_state(
            subject_type="session", subject_key=digest, tenant="",
            actor="alice", status="acknowledged",
        )
        monkeypatch.setattr(inv, "_redis", lambda: _FakeRedis())
        out = await inv.investigation_session(digest, user=_admin())
        assert out["triage"]["status"] == "acknowledged"

    async def test_sessions_list_sorted_and_annotated(self, wired, monkeypatch):
        inv, _, triage, _ = wired
        d1, d2 = "a" * 16, "b" * 16
        fake = _FakeRedis(zsets={
            f"bulwark:session:{d1}:signals": [("x:2.0", 1.0)],
            f"bulwark:session:{d2}:signals": [("y:9.0", 2.0)],
        })
        monkeypatch.setattr(inv, "_redis", lambda: fake)
        await triage.set_state(
            subject_type="session", subject_key=d2, tenant="",
            actor="a", status="in_progress",
        )
        out = await inv.investigation_sessions(user=_admin(), limit=50)
        assert out["redis_connected"] is True
        # highest score first
        assert [s["session_key"] for s in out["sessions"]] == [d2, d1]
        assert out["sessions"][0]["verdict"] == "block"
        assert out["sessions"][0]["triage_status"] == "in_progress"
        assert out["sessions"][1]["triage_status"] == "open"

    async def test_sessions_list_no_redis(self, wired):
        inv, _, _, _ = wired
        out = await inv.investigation_sessions(user=_admin(), limit=50)
        assert out["redis_connected"] is False
        assert out["sessions"] == []

    async def test_session_triage_state_writes_and_audits(self, wired):
        inv, _, _, audit = wired
        body = inv.TriageStateRequest(
            subject_type="session", subject_key="d" * 16, status="resolved",
        )
        out = await inv.investigation_triage_state(body, user=_admin())
        assert out["triage"]["status"] == "resolved"
        assert out["triage"]["subject_type"] == "session"
        assert any(e["action"] == "investigation.triage_state" for e in audit.entries)


class TestBulkTriage:
    async def test_bulk_updates_multiple_subjects(self, wired):
        inv, _, triage, audit = wired
        body = inv.BulkTriageRequest(
            subjects=[
                {"subject_type": "incident", "subject_key": "INC-1"},
                {"subject_type": "incident", "subject_key": "INC-2"},
            ],
            status="in_progress",
            assignee="carol",
        )
        out = await inv.investigation_triage_bulk(body, user=_admin())
        assert out["updated"] == 2
        assert out["failed"] == 0
        assert all(r["ok"] for r in out["results"])
        # both rows now carry the applied state.
        rec = await triage.get("incident", "INC-1")
        assert rec["status"] == "in_progress"
        assert rec["assignee"] == "carol"
        assert any(e["action"] == "investigation.triage_bulk" for e in audit.entries)

    async def test_bulk_requires_a_field(self, wired):
        inv, _, _, _ = wired
        from fastapi import HTTPException

        body = inv.BulkTriageRequest(
            subjects=[{"subject_type": "incident", "subject_key": "INC-1"}],
        )
        with pytest.raises(HTTPException) as ei:
            await inv.investigation_triage_bulk(body, user=_admin())
        assert ei.value.status_code == 400

    async def test_bulk_invalid_status_is_400(self, wired):
        inv, _, _, _ = wired
        from fastapi import HTTPException

        body = inv.BulkTriageRequest(
            subjects=[{"subject_type": "incident", "subject_key": "INC-1"}],
            status="bogus",
        )
        with pytest.raises(HTTPException) as ei:
            await inv.investigation_triage_bulk(body, user=_admin())
        assert ei.value.status_code == 400

    async def test_bulk_partial_failure_isolated(self, wired):
        inv, _, _, _ = wired
        body = inv.BulkTriageRequest(
            subjects=[
                {"subject_type": "incident", "subject_key": "INC-1"},
                {"subject_type": "planet", "subject_key": "x"},
            ],
            status="acknowledged",
        )
        out = await inv.investigation_triage_bulk(body, user=_admin())
        assert out["updated"] == 1
        assert out["failed"] == 1
        bad = [r for r in out["results"] if not r["ok"]]
        assert bad and bad[0]["subject_type"] == "planet"

    async def test_bulk_cross_tenant_subject_recorded_as_failed(self, wired):
        inv, events, _, _ = wired
        await events.bulk_insert([_evt("c", tenant="evil", incident_id="INC-E")])
        body = inv.BulkTriageRequest(
            subjects=[{"subject_type": "incident", "subject_key": "INC-E"}],
            status="resolved",
        )
        # tenant-scoped operator: cross-tenant subject fails (404) but does not raise.
        out = await inv.investigation_triage_bulk(body, user=_admin(tenant="acme"))
        assert out["updated"] == 0
        assert out["failed"] == 1
        assert out["results"][0]["ok"] is False
