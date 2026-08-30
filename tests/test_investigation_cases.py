"""Tests for Investigation *Cases* — grouping subjects into one investigation.

Exercises the Fase 2 case layer end-to-end against a real migrated SQLite
database (migration v7):

* :class:`CaseStore` CRUD — create, status/severity/assignee transitions,
  append-only notes, subject link/unlink idempotency, bounds, the reverse
  ``find_cases_for_subject`` lookup, and input validation;
* the ``/admin/investigation/cases/*`` route handlers, called directly with a
  :class:`TokenPayload`, covering create/list/detail, state + note mutation,
  subject linking (validated through the shared ``_authorize_subject`` gate),
  RBAC (viewer cannot write) and tenant scoping (no cross-tenant existence leak).
"""

from __future__ import annotations

import json
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

    eng = create_engine(f"sqlite:///{tmp_path / 'cases_test.db'}")
    await eng.init()
    await run_migrations(eng)
    try:
        yield eng
    finally:
        await eng.close()


@pytest.fixture
async def case_store(engine, monkeypatch):
    from admin.services import investigation_case_store as store_mod
    from admin.services.investigation_case_store import CaseStore

    monkeypatch.setattr(store_mod, "get_database", lambda: engine)
    return CaseStore()


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
# CaseStore
# ═══════════════════════════════════════════════════════════════════════


class TestCaseStore:
    async def test_create_case_seeds_action_note(self, case_store):
        case = await case_store.create_case(
            title="Prompt-injection campaign", actor="alice",
            severity="high", tenant="acme", summary="several correlated hits",
        )
        assert case["case_id"].startswith("case_")
        assert case["title"] == "Prompt-injection campaign"
        assert case["status"] == "open"
        assert case["severity"] == "high"
        assert case["tenant"] == "acme"
        assert case["summary"] == "several correlated hits"
        assert case["subjects"] == []
        # opening is journalled as an actor-stamped action note.
        assert len(case["notes"]) == 1
        assert case["notes"][0]["kind"] == "action"
        assert case["notes"][0]["author"] == "alice"

    async def test_create_requires_title(self, case_store):
        with pytest.raises(ValueError):
            await case_store.create_case(title="   ", actor="a")

    async def test_create_rejects_invalid_severity(self, case_store):
        with pytest.raises(ValueError):
            await case_store.create_case(title="x", actor="a", severity="apocalyptic")

    async def test_get_absent_is_none(self, case_store):
        assert await case_store.get("case_deadbeef") is None
        assert await case_store.get("") is None

    async def test_set_state_records_each_change(self, case_store):
        case = await case_store.create_case(title="t", actor="a")
        cid = case["case_id"]
        updated = await case_store.set_state(
            case_id=cid, actor="bob", status="investigating",
            severity="critical", assignee="carol",
        )
        assert updated["status"] == "investigating"
        assert updated["severity"] == "critical"
        assert updated["assignee"] == "carol"
        # one action note appended, journalling all three transitions in one entry.
        action_notes = [n for n in updated["notes"] if n["kind"] == "action"]
        assert len(action_notes) == 2  # open + this transition
        assert "status open → investigating" in action_notes[-1]["text"]
        assert "severity medium → critical" in action_notes[-1]["text"]

    async def test_set_state_no_change_adds_no_note(self, case_store):
        case = await case_store.create_case(title="t", actor="a")
        cid = case["case_id"]
        before = len(case["notes"])
        updated = await case_store.set_state(case_id=cid, actor="a", status="open")
        # open→open is a no-op; note count is unchanged.
        assert len(updated["notes"]) == before

    async def test_set_state_absent_is_none(self, case_store):
        assert await case_store.set_state(case_id="case_nope", actor="a", status="closed") is None

    async def test_set_state_invalid_status_rejected(self, case_store):
        case = await case_store.create_case(title="t", actor="a")
        with pytest.raises(ValueError):
            await case_store.set_state(case_id=case["case_id"], actor="a", status="bogus")

    async def test_set_state_can_reopen_closed(self, case_store):
        case = await case_store.create_case(title="t", actor="a")
        cid = case["case_id"]
        await case_store.set_state(case_id=cid, actor="a", status="closed")
        reopened = await case_store.set_state(case_id=cid, actor="a", status="open")
        assert reopened["status"] == "open"

    async def test_add_note_appends_and_orders(self, case_store):
        case = await case_store.create_case(title="t", actor="a")
        cid = case["case_id"]
        await case_store.add_note(case_id=cid, actor="a", text="first")
        updated = await case_store.add_note(case_id=cid, actor="b", text="second")
        analyst = [n for n in updated["notes"] if n["kind"] == "note"]
        assert [n["text"] for n in analyst] == ["first", "second"]

    async def test_add_empty_note_rejected(self, case_store):
        case = await case_store.create_case(title="t", actor="a")
        with pytest.raises(ValueError):
            await case_store.add_note(case_id=case["case_id"], actor="a", text="   ")

    async def test_note_is_length_bounded(self, case_store):
        case = await case_store.create_case(title="t", actor="a")
        updated = await case_store.add_note(
            case_id=case["case_id"], actor="a", text="x" * 9000
        )
        assert len(updated["notes"][-1]["text"]) <= 4000

    async def test_add_note_absent_is_none(self, case_store):
        assert await case_store.add_note(case_id="case_nope", actor="a", text="hi") is None

    async def test_add_action_note_records_kind_action(self, case_store):
        case = await case_store.create_case(title="t", actor="a")
        cid = case["case_id"]
        updated = await case_store.add_action_note(
            case_id=cid, actor="responder", text="raised origin risk"
        )
        action_notes = [n for n in updated["notes"] if n["kind"] == "action"]
        # seed "case opened" action note + our response action note.
        last = action_notes[-1]
        assert last["text"] == "raised origin risk"
        assert last["author"] == "responder"
        assert last["kind"] == "action"

    async def test_add_action_note_empty_rejected(self, case_store):
        case = await case_store.create_case(title="t", actor="a")
        with pytest.raises(ValueError):
            await case_store.add_action_note(case_id=case["case_id"], actor="a", text="  ")

    async def test_add_action_note_absent_is_none(self, case_store):
        assert (
            await case_store.add_action_note(case_id="case_nope", actor="a", text="hi")
            is None
        )

    async def test_add_subject_links_and_is_idempotent(self, case_store):
        case = await case_store.create_case(title="t", actor="a")
        cid = case["case_id"]
        await case_store.add_subject(
            case_id=cid, subject_type="incident", subject_key="INC-1", actor="a"
        )
        again = await case_store.add_subject(
            case_id=cid, subject_type="incident", subject_key="INC-1", actor="a"
        )
        # linked exactly once despite the duplicate call.
        assert len(again["subjects"]) == 1
        assert again["subjects"][0]["subject_type"] == "incident"
        assert again["subjects"][0]["subject_key"] == "INC-1"

    async def test_add_subject_rejects_invalid_type(self, case_store):
        case = await case_store.create_case(title="t", actor="a")
        with pytest.raises(ValueError):
            await case_store.add_subject(
                case_id=case["case_id"], subject_type="planet",
                subject_key="x", actor="a",
            )

    async def test_add_subject_absent_case_is_none(self, case_store):
        got = await case_store.add_subject(
            case_id="case_nope", subject_type="incident", subject_key="INC-1", actor="a"
        )
        assert got is None

    async def test_remove_subject_unlinks(self, case_store):
        case = await case_store.create_case(title="t", actor="a")
        cid = case["case_id"]
        await case_store.add_subject(
            case_id=cid, subject_type="session", subject_key="a" * 16, actor="a"
        )
        updated = await case_store.remove_subject(
            case_id=cid, subject_type="session", subject_key="a" * 16, actor="a"
        )
        assert updated["subjects"] == []

    async def test_remove_subject_absent_case_is_none(self, case_store):
        assert await case_store.remove_subject(
            case_id="case_nope", subject_type="session", subject_key="x", actor="a"
        ) is None

    async def test_list_cases_filters_and_counts(self, case_store):
        c1 = await case_store.create_case(title="one", actor="a", tenant="acme")
        c2 = await case_store.create_case(title="two", actor="a", tenant="acme")
        await case_store.set_state(case_id=c2["case_id"], actor="a", status="closed")
        await case_store.add_subject(
            case_id=c1["case_id"], subject_type="incident", subject_key="INC-1", actor="a"
        )

        opens = await case_store.list_cases(status="open")
        assert [c["case_id"] for c in opens] == [c1["case_id"]]
        assert opens[0]["subject_count"] == 1

        acme = await case_store.list_cases(tenant="acme")
        assert {c["case_id"] for c in acme} == {c1["case_id"], c2["case_id"]}

    async def test_list_cases_tenant_isolation(self, case_store):
        await case_store.create_case(title="mine", actor="a", tenant="acme")
        await case_store.create_case(title="theirs", actor="a", tenant="evil")
        acme = await case_store.list_cases(tenant="acme")
        assert [c["tenant"] for c in acme] == ["acme"]

    async def test_find_cases_for_subject(self, case_store):
        c1 = await case_store.create_case(title="one", actor="a", tenant="acme")
        c2 = await case_store.create_case(title="two", actor="a", tenant="acme")
        await case_store.add_subject(
            case_id=c1["case_id"], subject_type="incident", subject_key="INC-9", actor="a"
        )
        await case_store.add_subject(
            case_id=c2["case_id"], subject_type="incident", subject_key="INC-9", actor="a"
        )
        found = await case_store.find_cases_for_subject("incident", "INC-9")
        assert {c["case_id"] for c in found} == {c1["case_id"], c2["case_id"]}
        # brief projection only.
        assert set(found[0]) == {"case_id", "title", "status", "severity", "tenant"}

    async def test_find_cases_for_subject_empty_args(self, case_store):
        assert await case_store.find_cases_for_subject("", "x") == []
        assert await case_store.find_cases_for_subject("incident", "") == []


# ═══════════════════════════════════════════════════════════════════════
# Route handlers
# ═══════════════════════════════════════════════════════════════════════


@pytest.fixture
async def wired(engine, monkeypatch):
    """Wire the cases route module against the migrated DB + fakes."""
    import admin.routes.investigation as inv
    import admin.routes.investigation_cases as inv_cases
    from admin.services import investigation_case_store as cstore_mod
    from admin.services import security_events_store as estore_mod
    from admin.services.investigation_case_store import CaseStore
    from admin.services.security_events_store import SecurityEventsStore

    monkeypatch.setattr(cstore_mod, "get_database", lambda: engine)
    monkeypatch.setattr(estore_mod, "get_database", lambda: engine)

    cases = CaseStore()
    events = SecurityEventsStore()
    monkeypatch.setattr(inv_cases, "get_case_store", lambda: cases)
    # _authorize_subject (shared from investigation) resolves subjects via the
    # events store; wire it so incident-subject linking validates against the DB.
    monkeypatch.setattr(inv, "get_security_events_store", lambda: events)
    monkeypatch.setattr(inv, "_redis", lambda: None)

    class _Audit:
        def __init__(self):
            self.entries = []

        async def log(self, **kw):
            self.entries.append(kw)

    audit = _Audit()
    monkeypatch.setattr(inv_cases, "get_audit_logger", lambda: audit)
    return inv_cases, cases, events, audit


class TestCaseEndpoints:
    async def test_create_and_list(self, wired):
        inv_cases, _, _, audit = wired
        body = inv_cases.CaseCreateRequest(title="Campaign X", severity="high")
        created = await inv_cases.create_case(body=body, user=_admin())
        assert created["case"]["title"] == "Campaign X"
        assert audit.entries[-1]["action"] == "investigation.case_create"

        out = await inv_cases.list_cases(
            user=_admin(), status=None, severity=None, assignee=None, search=None,
            sort="updated_at", order="desc", limit=100, offset=0,
        )
        assert out["count"] == 1
        assert out["can_write"] is True
        assert "open" in out["statuses"]
        assert "critical" in out["severities"]

    async def test_list_can_write_false_for_viewer(self, wired):
        inv_cases, _, _, _ = wired
        out = await inv_cases.list_cases(
            user=_viewer(), status=None, severity=None, assignee=None, search=None,
            sort="updated_at", order="desc", limit=100, offset=0,
        )
        assert out["can_write"] is False

    async def test_get_case_detail(self, wired):
        inv_cases, cases, _, _ = wired
        made = await cases.create_case(title="t", actor="a")
        out = await inv_cases.get_case(made["case_id"], user=_admin())
        assert out["case"]["case_id"] == made["case_id"]
        assert out["case"]["subjects"] == []

    async def test_get_case_not_found(self, wired):
        inv_cases, _, _, _ = wired
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as ei:
            await inv_cases.get_case("case_nope", user=_admin())
        assert ei.value.status_code == 404

    async def test_get_case_cross_tenant_is_404(self, wired):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        made = await cases.create_case(title="t", actor="a", tenant="evil")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.get_case(made["case_id"], user=_admin(tenant="acme"))
        # no cross-tenant existence leak — 404, not 403.
        assert ei.value.status_code == 404

    async def test_create_pins_tenant_scope(self, wired):
        inv_cases, _, _, _ = wired
        # A tenant-scoped operator cannot open a case for another tenant.
        body = inv_cases.CaseCreateRequest(title="t", tenant="evil")
        created = await inv_cases.create_case(body=body, user=_admin(tenant="acme"))
        assert created["case"]["tenant"] == "acme"

    async def test_set_state_requires_a_field(self, wired):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        made = await cases.create_case(title="t", actor="a")
        body = inv_cases.CaseStateRequest()
        with pytest.raises(HTTPException) as ei:
            await inv_cases.set_case_state(made["case_id"], body=body, user=_admin())
        assert ei.value.status_code == 400

    async def test_set_state_writes_and_audits(self, wired):
        inv_cases, cases, _, audit = wired
        made = await cases.create_case(title="t", actor="a")
        body = inv_cases.CaseStateRequest(status="resolved")
        out = await inv_cases.set_case_state(made["case_id"], body=body, user=_admin())
        assert out["case"]["status"] == "resolved"
        assert audit.entries[-1]["action"] == "investigation.case_state"

    async def test_set_state_invalid_is_400(self, wired):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        made = await cases.create_case(title="t", actor="a")
        body = inv_cases.CaseStateRequest(status="bogus")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.set_case_state(made["case_id"], body=body, user=_admin())
        assert ei.value.status_code == 400

    async def test_add_note_writes_and_audits(self, wired):
        inv_cases, cases, _, audit = wired
        made = await cases.create_case(title="t", actor="a")
        body = inv_cases.CaseNoteRequest(text="looks like a campaign")
        out = await inv_cases.add_case_note(made["case_id"], body=body, user=_admin())
        analyst = [n for n in out["case"]["notes"] if n["kind"] == "note"]
        assert analyst[-1]["text"] == "looks like a campaign"
        assert audit.entries[-1]["action"] == "investigation.case_note"

    async def test_link_incident_subject(self, wired):
        inv_cases, cases, events, audit = wired
        await events.bulk_insert([_evt("carrier", incident_id="INC-1", tenant="acme")])
        made = await cases.create_case(title="t", actor="a", tenant="acme")
        body = inv_cases.CaseSubjectRequest(subject_type="incident", subject_key="INC-1")
        out = await inv_cases.add_case_subject(made["case_id"], body=body, user=_admin())
        assert len(out["case"]["subjects"]) == 1
        assert out["case"]["subjects"][0]["subject_key"] == "INC-1"
        assert audit.entries[-1]["action"] == "investigation.case_link"

    async def test_link_cross_tenant_subject_is_404(self, wired):
        inv_cases, cases, events, _ = wired
        from fastapi import HTTPException

        await events.bulk_insert([_evt("c", tenant="evil", incident_id="INC-E")])
        made = await cases.create_case(title="t", actor="a", tenant="acme")
        body = inv_cases.CaseSubjectRequest(subject_type="incident", subject_key="INC-E")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.add_case_subject(
                made["case_id"], body=body, user=_admin(tenant="acme")
            )
        assert ei.value.status_code == 404

    async def test_link_invalid_subject_type_is_400(self, wired):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        made = await cases.create_case(title="t", actor="a")
        body = inv_cases.CaseSubjectRequest(subject_type="planet", subject_key="x")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.add_case_subject(made["case_id"], body=body, user=_admin())
        assert ei.value.status_code == 400

    async def test_unlink_subject(self, wired):
        inv_cases, cases, _, audit = wired
        made = await cases.create_case(title="t", actor="a")
        await cases.add_subject(
            case_id=made["case_id"], subject_type="session",
            subject_key="a" * 16, actor="a",
        )
        out = await inv_cases.remove_case_subject(
            made["case_id"], user=_admin(),
            subject_type="session", subject_key="a" * 16,
        )
        assert out["case"]["subjects"] == []
        assert audit.entries[-1]["action"] == "investigation.case_unlink"

    async def test_cases_for_subject_tenant_filtered(self, wired):
        inv_cases, cases, _, _ = wired
        mine = await cases.create_case(title="mine", actor="a", tenant="acme")
        theirs = await cases.create_case(title="theirs", actor="a", tenant="evil")
        await cases.add_subject(
            case_id=mine["case_id"], subject_type="incident", subject_key="INC-9", actor="a"
        )
        await cases.add_subject(
            case_id=theirs["case_id"], subject_type="incident", subject_key="INC-9", actor="a"
        )
        out = await inv_cases.cases_for_subject(
            "incident", "INC-9", user=_admin(tenant="acme")
        )
        assert [c["case_id"] for c in out["cases"]] == [mine["case_id"]]


# ═══════════════════════════════════════════════════════════════════════
# Phase 3 — search / filter / sort / paging / stats (store)
# ═══════════════════════════════════════════════════════════════════════


class TestCaseListPhase3:
    async def test_search_matches_title_and_summary_literally(self, case_store):
        await case_store.create_case(title="Exfil campaign", actor="a", summary="via DNS")
        await case_store.create_case(title="Benign review", actor="a", summary="nothing")
        hits = await case_store.list_cases(search="exfil")
        assert [c["title"] for c in hits] == ["Exfil campaign"]
        # summary is searched too.
        dns = await case_store.list_cases(search="dns")
        assert [c["title"] for c in dns] == ["Exfil campaign"]

    async def test_search_wildcards_are_escaped(self, case_store):
        # An underscore is a LIKE wildcard; escaped, a literal "a_b" search must
        # not match the title "axb" (it would if '_' matched any single char).
        await case_store.create_case(title="axb", actor="a")
        assert await case_store.list_cases(search="a_b") == []
        # '%' never appears in a hex case_id or these titles, so a literal '%'
        # search matches nothing rather than acting as match-all.
        assert await case_store.list_cases(search="%") == []

    async def test_filter_by_severity_and_assignee(self, case_store):
        c1 = await case_store.create_case(title="hi", actor="a", severity="critical")
        await case_store.create_case(title="lo", actor="a", severity="low")
        await case_store.set_state(case_id=c1["case_id"], actor="a", assignee="carol")

        crit = await case_store.list_cases(severity="critical")
        assert [c["case_id"] for c in crit] == [c1["case_id"]]
        mine = await case_store.list_cases(assignee="carol")
        assert [c["case_id"] for c in mine] == [c1["case_id"]]

    async def test_sort_by_severity_rank_then_direction(self, case_store):
        low = await case_store.create_case(title="l", actor="a", severity="low")
        crit = await case_store.create_case(title="c", actor="a", severity="critical")
        med = await case_store.create_case(title="m", actor="a", severity="medium")
        desc = await case_store.list_cases(sort="severity", descending=True)
        assert [c["case_id"] for c in desc] == [crit["case_id"], med["case_id"], low["case_id"]]
        asc = await case_store.list_cases(sort="severity", descending=False)
        assert [c["case_id"] for c in asc] == [low["case_id"], med["case_id"], crit["case_id"]]

    async def test_sort_by_title(self, case_store):
        await case_store.create_case(title="zebra", actor="a")
        await case_store.create_case(title="alpha", actor="a")
        asc = await case_store.list_cases(sort="title", descending=False)
        assert [c["title"] for c in asc] == ["alpha", "zebra"]

    async def test_count_cases_mirrors_filters(self, case_store):
        await case_store.create_case(title="a", actor="a", tenant="acme", severity="high")
        await case_store.create_case(title="b", actor="a", tenant="acme", severity="low")
        await case_store.create_case(title="c", actor="a", tenant="evil", severity="high")
        assert await case_store.count_cases(tenant="acme") == 2
        assert await case_store.count_cases(tenant="acme", severity="high") == 1
        assert await case_store.count_cases(search="nomatch") == 0

    async def test_paging_is_stable_with_offset(self, case_store):
        ids = []
        for i in range(5):
            c = await case_store.create_case(title=f"case {i}", actor="a")
            ids.append(c["case_id"])
        page1 = await case_store.list_cases(sort="created_at", descending=False, limit=2, offset=0)
        page2 = await case_store.list_cases(sort="created_at", descending=False, limit=2, offset=2)
        assert [c["case_id"] for c in page1] == ids[:2]
        assert [c["case_id"] for c in page2] == ids[2:4]

    async def test_stats_rollup_and_my_work(self, case_store):
        o1 = await case_store.create_case(title="o1", actor="a", tenant="acme", severity="high")
        await case_store.create_case(title="o2", actor="a", tenant="acme", severity="low")
        closed = await case_store.create_case(title="done", actor="a", tenant="acme")
        await case_store.set_state(case_id=closed["case_id"], actor="a", status="closed")
        await case_store.set_state(case_id=o1["case_id"], actor="a", assignee="carol")

        stats = await case_store.stats(tenant="acme", assignee="carol")
        assert stats["total"] == 3
        assert stats["open"] == 2  # o1 + o2 open, "done" closed
        assert stats["by_status"]["closed"] == 1
        assert stats["by_severity"]["high"] == 1
        assert stats["mine"]["total"] == 1
        assert stats["mine"]["open"] == 1

    async def test_stats_tenant_isolation(self, case_store):
        await case_store.create_case(title="x", actor="a", tenant="acme")
        await case_store.create_case(title="y", actor="a", tenant="evil")
        stats = await case_store.stats(tenant="acme")
        assert stats["total"] == 1


# ═══════════════════════════════════════════════════════════════════════
# Phase 3 — Markdown export rendering (pure)
# ═══════════════════════════════════════════════════════════════════════


class TestCaseMarkdownExport:
    def test_render_includes_metadata_subjects_and_notes(self):
        from admin.services.investigation_case_store import render_case_markdown

        case = {
            "case_id": "case_abc",
            "title": "Campaign",
            "status": "investigating",
            "severity": "high",
            "assignee": "carol",
            "tenant": "acme",
            "created_by": "alice",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-02T00:00:00Z",
            "summary": "several correlated hits",
            "subjects": [
                {"subject_type": "incident", "subject_key": "INC-1",
                 "added_by": "alice", "added_at": "2026-01-01T01:00:00Z"},
            ],
            "notes": [
                {"ts": "2026-01-01T00:00:00Z", "author": "alice",
                 "kind": "action", "text": "case opened (high)"},
            ],
        }
        md = render_case_markdown(case)
        assert "# Investigation Case: Campaign" in md
        assert "case_abc" in md
        assert "several correlated hits" in md
        assert "INC-1" in md
        assert "case opened (high)" in md
        assert "## Linked Subjects (1)" in md
        assert "## Note Trail (1)" in md

    def test_render_handles_empty_case(self):
        from admin.services.investigation_case_store import render_case_markdown

        md = render_case_markdown({"case_id": "case_x", "title": ""})
        assert "(untitled case)" in md
        assert "_No subjects linked._" in md
        assert "_No notes recorded._" in md

    def test_render_omits_compliance_when_absent(self):
        from admin.services.investigation_case_store import render_case_markdown

        md = render_case_markdown({"case_id": "case_x", "title": "t"})
        assert "## Compliance & MITRE Mapping" not in md

    def test_render_compliance_section_links_badged_and_lists_plain(self):
        from admin.services.investigation_case_store import render_case_markdown

        case = {
            "case_id": "case_c",
            "title": "Campaign",
            "compliance": {
                "owasp_version": "2025",
                "categories": ["exfiltration", "prompt_injection"],
                "codes": {
                    "owasp_llm": ["LLM01", "LLM02"],
                    "mitre_attack": ["T1041", "T1059"],
                    "nist_ai_rmf": ["MANAGE-4.1", "MEASURE-2.7"],
                    "eu_ai_act": ["Article 15"],
                },
                "catalog": {
                    "LLM01": {
                        "label": "OWASP LLM01: Prompt Injection",
                        "url": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
                        "framework": "owasp",
                    },
                },
            },
        }
        md = render_case_markdown(case)
        assert "## Compliance & MITRE Mapping" in md
        assert "OWASP LLM Top 10 2025" in md
        assert "**Threat categories:** exfiltration, prompt_injection" in md
        # A catalogued code renders as a link; an uncatalogued one falls back to code.
        assert "[OWASP LLM01: Prompt Injection](https://genai.owasp.org/" in md
        assert "- LLM02" in md
        # Plain (NIST/EU) axes render as an inline comma list, not links.
        assert "- **NIST AI RMF:** MANAGE-4.1, MEASURE-2.7" in md
        assert "- **EU AI Act:** Article 15" in md


# ═══════════════════════════════════════════════════════════════════════
# Phase 3 — route: list params, stats, export
# ═══════════════════════════════════════════════════════════════════════


class TestCaseEndpointsPhase3:
    async def test_list_reports_total_and_paging_metadata(self, wired):
        inv_cases, cases, _, _ = wired
        for i in range(3):
            await cases.create_case(title=f"c{i}", actor="a")
        out = await inv_cases.list_cases(
            user=_admin(), status=None, severity=None, assignee=None, search=None,
            sort="updated_at", order="desc", limit=2, offset=0,
        )
        assert out["total"] == 3
        assert out["count"] == 2
        assert out["limit"] == 2
        assert out["order"] == "desc"
        assert "updated_at" in out["sort_keys"]

    async def test_list_unknown_sort_falls_back(self, wired):
        inv_cases, cases, _, _ = wired
        await cases.create_case(title="c", actor="a")
        out = await inv_cases.list_cases(
            user=_admin(), status=None, severity=None, assignee=None, search=None,
            sort="; DROP TABLE", order="desc", limit=100, offset=0,
        )
        assert out["sort"] == "updated_at"

    async def test_list_search_filters(self, wired):
        inv_cases, cases, _, _ = wired
        await cases.create_case(title="Exfil campaign", actor="a")
        await cases.create_case(title="Benign", actor="a")
        out = await inv_cases.list_cases(
            user=_admin(), status=None, severity=None, assignee=None, search="exfil",
            sort="updated_at", order="desc", limit=100, offset=0,
        )
        assert out["count"] == 1
        assert out["cases"][0]["title"] == "Exfil campaign"

    async def test_stats_endpoint(self, wired):
        inv_cases, cases, _, _ = wired
        await cases.create_case(title="a", actor="a", tenant="acme")
        out = await inv_cases.case_stats(user=_admin(tenant="acme"), assignee=None)
        assert out["stats"]["total"] == 1
        assert "by_status" in out["stats"]

    async def test_export_json(self, wired):
        inv_cases, cases, _, audit = wired
        made = await cases.create_case(title="t", actor="a")
        resp = await inv_cases.export_case(made["case_id"], user=_admin(), format="json")
        assert resp.headers["content-disposition"].endswith(f'{made["case_id"]}.json"')
        assert audit.entries[-1]["action"] == "investigation.case_export"
        # The body must be valid JSON carrying the full case record.
        body = resp.body.decode() if isinstance(resp.body, bytes) else resp.body
        parsed = json.loads(body)
        assert parsed["case"]["case_id"] == made["case_id"]

    async def test_export_json_serializes_datetime(self, wired, monkeypatch):
        """Postgres returns timestamp columns as datetime objects (sqlite returns
        ISO strings). A raw JSONResponse would 500 on datetime, so the route must
        run the payload through jsonable_encoder — assert a datetime survives."""
        inv_cases, cases, _, _ = wired
        made = await cases.create_case(title="t", actor="a")
        ts = datetime(2025, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

        async def _fake_scoped(user, case_id):
            case = dict(made)
            case["updated_at"] = ts  # force a non-JSON-native value
            return case

        monkeypatch.setattr(inv_cases, "_get_case_scoped", _fake_scoped)
        resp = await inv_cases.export_case(made["case_id"], user=_admin(), format="json")
        body = resp.body.decode() if isinstance(resp.body, bytes) else resp.body
        parsed = json.loads(body)  # must not raise
        assert "2025-01-02T03:04:05" in parsed["case"]["updated_at"]

    async def test_export_markdown(self, wired):
        inv_cases, cases, _, _ = wired
        made = await cases.create_case(title="Campaign", actor="a")
        resp = await inv_cases.export_case(made["case_id"], user=_admin(), format="md")
        assert resp.media_type.startswith("text/markdown")
        body = resp.body.decode() if isinstance(resp.body, bytes) else resp.body
        assert "# Investigation Case: Campaign" in body

    async def test_export_invalid_format_is_400(self, wired):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        made = await cases.create_case(title="t", actor="a")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.export_case(made["case_id"], user=_admin(), format="pdf")
        assert ei.value.status_code == 400

    async def test_export_cross_tenant_is_404(self, wired):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        made = await cases.create_case(title="t", actor="a", tenant="evil")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.export_case(
                made["case_id"], user=_admin(tenant="acme"), format="json"
            )
        assert ei.value.status_code == 404


# ═══════════════════════════════════════════════════════════════════════
# Phase 4C — export enrichment: OWASP/MITRE/NIST/EU compliance roll-up
# ═══════════════════════════════════════════════════════════════════════


class TestCaseComplianceExport:
    async def _case_with_incident(self, cases, events, *, category, incident_id,
                                  metadata=None, tenant="acme"):
        await events.bulk_insert([
            _evt("carrier-" + incident_id, incident_id=incident_id, tenant=tenant,
                 category=category, metadata=metadata or {}),
        ])
        made = await cases.create_case(title="t", actor="a", tenant=tenant)
        await cases.add_subject(
            case_id=made["case_id"], subject_type="incident",
            subject_key=incident_id, actor="a",
        )
        return made

    async def test_json_export_carries_compliance_from_incident_category(self, wired):
        inv_cases, cases, events, _ = wired
        made = await self._case_with_incident(
            cases, events, category="prompt_injection", incident_id="INC-PI",
        )
        resp = await inv_cases.export_case(made["case_id"], user=_admin(), format="json")
        body = resp.body.decode() if isinstance(resp.body, bytes) else resp.body
        parsed = json.loads(body)
        comp = parsed["case"]["compliance"]
        assert comp["owasp_version"] == "2025"
        assert comp["categories"] == ["prompt_injection"]
        # prompt_injection → LLM01 / AML.T0051 / T1059 (see src/telemetry/compliance).
        assert comp["codes"]["owasp_llm"] == ["LLM01"]
        assert comp["codes"]["mitre_atlas"] == ["AML.T0051"]
        assert comp["codes"]["mitre_attack"] == ["T1059"]
        # NIST/EU axes are present but carry no catalog entry.
        assert "MEASURE-2.7" in comp["codes"]["nist_ai_rmf"]
        assert comp["catalog"]["LLM01"]["framework"] == "owasp"
        assert "LLM01" in comp["catalog"] and "MEASURE-2.7" not in comp["catalog"]

    async def test_md_export_renders_compliance_section(self, wired):
        inv_cases, cases, events, _ = wired
        made = await self._case_with_incident(
            cases, events, category="prompt_injection", incident_id="INC-PI2",
        )
        resp = await inv_cases.export_case(made["case_id"], user=_admin(), format="md")
        body = resp.body.decode() if isinstance(resp.body, bytes) else resp.body
        assert "## Compliance & MITRE Mapping" in body
        assert "OWASP LLM01: Prompt Injection" in body
        assert "ATLAS AML.T0051" in body

    async def test_compliance_merges_metadata_categories(self, wired):
        inv_cases, cases, events, _ = wired
        # Carrier event category + metadata input/output categories all contribute.
        made = await self._case_with_incident(
            cases, events, category="prompt_injection", incident_id="INC-MIX",
            metadata={
                "input_categories": ["jailbreak"],
                "output_categories": ["exfiltration"],
            },
        )
        resp = await inv_cases.export_case(made["case_id"], user=_admin(), format="json")
        comp = json.loads(resp.body.decode())["case"]["compliance"]
        assert comp["categories"] == ["exfiltration", "jailbreak", "prompt_injection"]
        # Union across the three: LLM01 (PI+JB) and LLM02 (exfiltration).
        assert set(comp["codes"]["owasp_llm"]) == {"LLM01", "LLM02"}

    async def test_unmapped_category_yields_no_compliance(self, wired):
        inv_cases, cases, events, _ = wired
        made = await self._case_with_incident(
            cases, events, category="totally_bogus_category", incident_id="INC-BOGUS",
        )
        resp = await inv_cases.export_case(made["case_id"], user=_admin(), format="json")
        parsed = json.loads(resp.body.decode())
        assert "compliance" not in parsed["case"]
        md = await inv_cases.export_case(made["case_id"], user=_admin(), format="md")
        assert "## Compliance & MITRE Mapping" not in md.body.decode()

    async def test_no_incident_subject_yields_no_compliance(self, wired):
        inv_cases, cases, _, _ = wired
        made = await cases.create_case(title="t", actor="a")
        # A session subject carries no threat category → no compliance block.
        await cases.add_subject(
            case_id=made["case_id"], subject_type="session",
            subject_key="s" * 16, actor="a",
        )
        resp = await inv_cases.export_case(made["case_id"], user=_admin(), format="json")
        assert "compliance" not in json.loads(resp.body.decode())["case"]


# ═══════════════════════════════════════════════════════════════════════
# Phase 5A — timeline reconstruction: unify a case's dispersed evidence
# ═══════════════════════════════════════════════════════════════════════


class TestTimelineHelpers:
    """The pure merge/normalise helpers — no request, no database."""

    def test_iso_from_epoch_and_parse_roundtrip(self):
        from admin.routes.investigation_cases import _iso_from_epoch, _parse_iso_ts

        iso = _iso_from_epoch(1_700_000_000.0)
        assert iso.startswith("2023-")
        assert abs(_parse_iso_ts(iso) - 1_700_000_000.0) < 1.0

    def test_bad_timestamps_do_not_raise(self):
        from admin.routes.investigation_cases import _iso_from_epoch, _parse_iso_ts

        assert _iso_from_epoch("not-a-number") == ""
        assert _iso_from_epoch(None) == ""
        assert _parse_iso_ts("garbage") == 0.0
        assert _parse_iso_ts(None) == 0.0

    def test_assemble_sorts_ascending_and_merges(self):
        from admin.routes.investigation_cases import _assemble_timeline

        events = [_evt("e-late", ts=2000.0), _evt("e-early", ts=1000.0)]
        notes = [{"ts": _iso_from_epoch_str(1500.0), "author": "a",
                  "kind": "note", "text": "mid"}]
        entries, truncated = _assemble_timeline(events, notes, limit=100)
        assert truncated is False
        assert [e["epoch"] for e in entries] == [1000.0, 1500.0, 2000.0]
        assert [e["type"] for e in entries] == ["event", "note", "event"]

    def test_assemble_dedupes_events_by_id(self):
        from admin.routes.investigation_cases import _assemble_timeline

        # Same detection surfaced via two subjects → one entry (first wins).
        dup = [_evt("shared", ts=100.0), _evt("shared", ts=100.0)]
        entries, _ = _assemble_timeline(dup, [], limit=100)
        assert len([e for e in entries if e["event_id"] == "shared"]) == 1

    def test_assemble_truncates_to_most_recent(self):
        from admin.routes.investigation_cases import _assemble_timeline

        events = [_evt(f"e{i}", ts=float(i)) for i in range(5)]
        entries, truncated = _assemble_timeline(events, [], limit=2)
        assert truncated is True
        # keeps the two most recent (highest epoch), still ascending.
        assert [e["event_id"] for e in entries] == ["e3", "e4"]


def _iso_from_epoch_str(ts: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


class TestCaseTimeline:
    async def _linked_incident_case(
        self, cases, events, *, incident_id="INC-T", tenant="acme",
        ts=1_000_000_000.0, metadata=None,
    ):
        await events.bulk_insert([
            _evt("carrier-" + incident_id, incident_id=incident_id, tenant=tenant,
                 ts=ts, metadata=metadata or {}),
        ])
        made = await cases.create_case(title="t", actor="a", tenant=tenant)
        await cases.add_subject(
            case_id=made["case_id"], subject_type="incident",
            subject_key=incident_id, actor="a",
        )
        return made

    async def test_timeline_merges_incident_events_and_notes(self, wired):
        inv_cases, cases, events, _ = wired
        made = await self._linked_incident_case(cases, events)
        out = await inv_cases.case_timeline(made["case_id"], user=_admin(), limit=500)

        assert {e["type"] for e in out["timeline"]} == {"event", "note"}
        # 2001-era event precedes the freshly-stamped opening/link notes.
        assert out["timeline"][0]["type"] == "event"
        assert out["timeline"][0]["category"] == "exfiltration"
        assert out["timeline"][0]["via"] == "incident:INC-T"
        assert out["subject_counts"] == {"incident": 1, "origin": 0}
        assert out["truncated"] is False
        epochs = [e["epoch"] for e in out["timeline"]]
        assert epochs == sorted(epochs)

    async def test_timeline_includes_contributing_detections(self, wired):
        inv_cases, cases, events, _ = wired
        await events.bulk_insert([
            _evt("in-1", tenant="acme", ts=1_000_000_100.0,
                 source="input_guardrail", category="prompt_injection"),
            _evt("out-1", tenant="acme", ts=1_000_000_200.0,
                 source="output_filter", category="exfiltration"),
        ])
        made = await self._linked_incident_case(
            cases, events, incident_id="INC-C", ts=1_000_000_300.0,
            metadata={"contributing_event_ids": ["in-1", "out-1"]},
        )
        out = await inv_cases.case_timeline(made["case_id"], user=_admin(), limit=500)
        ids = {e["event_id"] for e in out["timeline"] if e["type"] == "event"}
        assert {"in-1", "out-1", "carrier-INC-C"} <= ids

    async def test_timeline_origin_ledger(self, wired):
        inv_cases, cases, events, _ = wired
        token = "origin:aabbccddeeff0011"
        await events.bulk_insert([
            _evt("o-1", tenant="acme", ts=1_000_000_000.0, scope_digests=[token]),
        ])
        made = await cases.create_case(title="t", actor="a", tenant="acme")
        await cases.add_subject(
            case_id=made["case_id"], subject_type="origin",
            subject_key=token, actor="a",
        )
        out = await inv_cases.case_timeline(made["case_id"], user=_admin(), limit=500)
        surfaced = [e for e in out["timeline"] if e.get("event_id") == "o-1"]
        assert surfaced and surfaced[0]["via"] == token
        assert out["subject_counts"]["origin"] == 1

    async def test_timeline_session_subject_has_no_events(self, wired):
        inv_cases, cases, _, _ = wired
        made = await cases.create_case(title="t", actor="a", tenant="acme")
        await cases.add_subject(
            case_id=made["case_id"], subject_type="session",
            subject_key="s" * 16, actor="a",
        )
        out = await inv_cases.case_timeline(made["case_id"], user=_admin(), limit=500)
        # Only the case's own notes — a session carries no durable events.
        assert all(e["type"] == "note" for e in out["timeline"])
        assert out["subject_counts"] == {"incident": 0, "origin": 0}

    async def test_timeline_tenant_scoping_filters_events(self, wired):
        inv_cases, cases, events, _ = wired
        # Two tenants' events share one origin token; the acme case links it.
        token = "origin:1122334455667788"
        await events.bulk_insert([
            _evt("acme-ev", tenant="acme", ts=1_000_000_000.0, scope_digests=[token]),
            _evt("evil-ev", tenant="evil", ts=1_000_000_001.0, scope_digests=[token]),
        ])
        made = await cases.create_case(title="t", actor="a", tenant="acme")
        await cases.add_subject(
            case_id=made["case_id"], subject_type="origin",
            subject_key=token, actor="a",
        )
        # A tenant-scoped acme operator sees only the acme event.
        scoped = await inv_cases.case_timeline(
            made["case_id"], user=_admin(tenant="acme"), limit=500
        )
        scoped_ids = {e["event_id"] for e in scoped["timeline"] if e["type"] == "event"}
        assert scoped_ids == {"acme-ev"}
        # A global operator (no tenant) sees both.
        globl = await inv_cases.case_timeline(made["case_id"], user=_admin(), limit=500)
        global_ids = {e["event_id"] for e in globl["timeline"] if e["type"] == "event"}
        assert global_ids == {"acme-ev", "evil-ev"}

    async def test_timeline_cross_tenant_case_is_404(self, wired):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        made = await cases.create_case(title="t", actor="a", tenant="evil")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.case_timeline(made["case_id"], user=_admin(tenant="acme"))
        assert ei.value.status_code == 404

    async def test_timeline_respects_limit_and_flags_truncation(self, wired):
        inv_cases, cases, events, _ = wired
        rows = [
            _evt(f"e{i}", incident_id="INC-LIM", tenant="acme", ts=1_000_000_000.0 + i)
            for i in range(4)
        ]
        await events.bulk_insert(rows)
        made = await cases.create_case(title="t", actor="a", tenant="acme")
        await cases.add_subject(
            case_id=made["case_id"], subject_type="incident",
            subject_key="INC-LIM", actor="a",
        )
        out = await inv_cases.case_timeline(made["case_id"], user=_admin(), limit=1)
        assert out["truncated"] is True
        assert out["count"] == 1
        assert out["limit"] == 1
        # The single kept entry is the most recent of the whole merged stream
        # (the link/open notes are stamped "now", newer than the 2001 events).
        assert out["timeline"][0]["type"] == "note"

    async def test_timeline_not_found_is_404(self, wired):
        inv_cases, _, _, _ = wired
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as ei:
            await inv_cases.case_timeline("case_nope", user=_admin(), limit=500)
        assert ei.value.status_code == 404
