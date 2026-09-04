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


@pytest.fixture
async def observable_store(engine, monkeypatch):
    from admin.services import investigation_observable_store as store_mod
    from admin.services.investigation_observable_store import ObservableStore

    monkeypatch.setattr(store_mod, "get_database", lambda: engine)
    return ObservableStore()


@pytest.fixture
async def task_store(engine, monkeypatch):
    from admin.services import investigation_task_store as store_mod
    from admin.services.investigation_task_store import TaskStore

    monkeypatch.setattr(store_mod, "get_database", lambda: engine)
    return TaskStore()


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
    from admin.services import investigation_observable_store as ostore_mod
    from admin.services import investigation_task_store as tstore_mod
    from admin.services import security_events_store as estore_mod
    from admin.services.investigation_case_store import CaseStore
    from admin.services.investigation_observable_store import ObservableStore
    from admin.services.investigation_task_store import TaskStore
    from admin.services.security_events_store import SecurityEventsStore

    monkeypatch.setattr(cstore_mod, "get_database", lambda: engine)
    monkeypatch.setattr(estore_mod, "get_database", lambda: engine)
    monkeypatch.setattr(ostore_mod, "get_database", lambda: engine)
    monkeypatch.setattr(tstore_mod, "get_database", lambda: engine)

    cases = CaseStore()
    events = SecurityEventsStore()
    monkeypatch.setattr(inv_cases, "get_case_store", lambda: cases)
    # First-class observable/task stores back the interop exports (Fase 0); wire
    # them against the same migrated DB so a case's evidence is exportable.
    observables = ObservableStore()
    tasks = TaskStore()
    monkeypatch.setattr(inv_cases, "get_observable_store", lambda: observables)
    monkeypatch.setattr(inv_cases, "get_task_store", lambda: tasks)
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

    def test_render_omits_timeline_when_absent(self):
        from admin.services.investigation_case_store import render_case_markdown

        md = render_case_markdown({"case_id": "case_x", "title": "t"})
        assert "## Timeline" not in md

    def test_render_timeline_section_events_and_notes(self):
        from admin.services.investigation_case_store import render_case_markdown

        case = {
            "case_id": "case_tl",
            "title": "Reconstruction",
            "timeline": [
                {
                    "type": "event", "ts": "2026-01-01T00:00:00+00:00",
                    "verdict": "block", "category": "exfiltration", "severity": "high",
                    "description": "data egress", "via": "incident:INC-1",
                },
                {
                    "type": "note", "ts": "2026-01-01T00:05:00+00:00",
                    "note_kind": "action", "author": "carol",
                    "text": "response: raised origin risk",
                },
            ],
            "timeline_truncated": False,
        }
        md = render_case_markdown(case)
        assert "## Timeline (2)" in md
        # Event entry: descriptor + provenance + description.
        assert "**[2026-01-01T00:00:00+00:00] event** (BLOCK/exfiltration/high)" in md
        assert "data egress" in md
        assert "via `incident:INC-1`" in md
        # Note/action entry keeps its kind + author + text.
        assert "**[2026-01-01T00:05:00+00:00] carol** _(action)_: response: raised origin risk" in md

    def test_render_timeline_flags_truncation_and_empty(self):
        from admin.services.investigation_case_store import render_case_markdown

        md = render_case_markdown(
            {"case_id": "c", "title": "t", "timeline": [], "timeline_truncated": True}
        )
        assert "## Timeline (0)" in md
        assert "_Timeline truncated" in md
        assert "_No reconstructed timeline entries._" in md


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
# Phase 0 — interop exports: STIX 2.1 / TheHive / DFIR-IRIS
# ═══════════════════════════════════════════════════════════════════════


class TestCaseInteropExport:
    """The ``stix`` / ``thehive`` / ``iris`` export shapes carry a case's
    first-class observables and tasks out to an external platform. Exercised
    through the route so the store wiring, filename and audit trail are covered.
    """

    async def _case_with_evidence(self, engine, cases):
        from admin.services.investigation_observable_store import ObservableStore
        from admin.services.investigation_task_store import TaskStore

        made = await cases.create_case(title="Exfil campaign", actor="a",
                                       severity="high", summary="correlated hits")
        cid = made["case_id"]
        obs = ObservableStore()
        await obs.add(case_id=cid, observable_type="ip", value="203.0.113.9",
                      actor="a", is_ioc=True, tlp="red")
        await obs.add(case_id=cid, observable_type="domain", value="evil.example",
                      actor="a", is_ioc=True)
        await obs.add(case_id=cid, observable_type="user", value="mallory", actor="a")
        tasks = TaskStore()
        await tasks.add(case_id=cid, title="Contain host", actor="a")
        return made

    def _parse(self, resp):
        body = resp.body.decode() if isinstance(resp.body, bytes) else resp.body
        return json.loads(body)

    async def test_stix_export(self, wired, engine):
        inv_cases, cases, _, audit = wired
        made = await self._case_with_evidence(engine, cases)
        resp = await inv_cases.export_case(made["case_id"], user=_admin(), format="stix")
        assert resp.headers["content-disposition"].endswith(
            f'{made["case_id"]}.stix.json"'
        )
        assert audit.entries[-1]["details"] == "format=stix"
        bundle = self._parse(resp)
        assert bundle["type"] == "bundle"
        types = [o["type"] for o in bundle["objects"]]
        # identity + SCOs (ipv4/domain-name/user-account) + 2 indicators + report.
        assert "identity" in types
        assert "report" in types
        assert "ipv4-addr" in types
        assert "domain-name" in types
        assert types.count("indicator") == 2  # only the two flagged IOCs
        report = next(o for o in bundle["objects"] if o["type"] == "report")
        assert report["name"] == "Exfil campaign"

    async def test_stix_export_is_deterministic(self, wired, engine):
        inv_cases, cases, _, _ = wired
        made = await self._case_with_evidence(engine, cases)
        first = self._parse(
            await inv_cases.export_case(made["case_id"], user=_admin(), format="stix")
        )
        second = self._parse(
            await inv_cases.export_case(made["case_id"], user=_admin(), format="stix")
        )
        assert first["id"] == second["id"]
        assert [o["id"] for o in first["objects"]] == [
            o["id"] for o in second["objects"]
        ]

    async def test_thehive_export(self, wired, engine):
        inv_cases, cases, _, _ = wired
        made = await self._case_with_evidence(engine, cases)
        resp = await inv_cases.export_case(
            made["case_id"], user=_admin(), format="thehive"
        )
        assert resp.headers["content-disposition"].endswith(
            f'{made["case_id"]}.thehive.json"'
        )
        hive = self._parse(resp)
        assert hive["title"] == "Exfil campaign"
        assert hive["severity"] == 3  # high → 3
        assert len(hive["artifacts"]) == 3
        assert len(hive["tasks"]) == 1
        ip_artifact = next(a for a in hive["artifacts"] if a["dataType"] == "ip")
        assert ip_artifact["ioc"] is True
        assert ip_artifact["tlp"] == 3  # red → 3

    async def test_iris_export(self, wired, engine):
        inv_cases, cases, _, _ = wired
        made = await self._case_with_evidence(engine, cases)
        resp = await inv_cases.export_case(made["case_id"], user=_admin(), format="iris")
        assert resp.headers["content-disposition"].endswith(
            f'{made["case_id"]}.iris.json"'
        )
        iris = self._parse(resp)
        assert iris["case_name"] == "Exfil campaign"
        assert iris["case_severity"] == 3
        assert len(iris["iocs"]) == 3
        assert len(iris["tasks"]) == 1
        ip_ioc = next(i for i in iris["iocs"] if i["ioc_type"] == "ip-any")
        assert ip_ioc["ioc_value"] == "203.0.113.9"

    async def test_interop_export_cross_tenant_is_404(self, wired, engine):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        made = await cases.create_case(title="t", actor="a", tenant="evil")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.export_case(
                made["case_id"], user=_admin(tenant="acme"), format="stix"
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
# Phase 5C — enriched export: the portable record carries the reconstructed
# timeline (durable evidence + the note/action trail), not just metadata.
# ═══════════════════════════════════════════════════════════════════════


class TestCaseExportTimeline:
    async def _incident_case(self, cases, events, *, incident_id="INC-X", tenant="acme"):
        await events.bulk_insert([
            _evt("carrier-" + incident_id, incident_id=incident_id, tenant=tenant,
                 ts=1_000_000_000.0, category="exfiltration"),
        ])
        made = await cases.create_case(title="t", actor="a", tenant=tenant)
        await cases.add_subject(
            case_id=made["case_id"], subject_type="incident",
            subject_key=incident_id, actor="a",
        )
        return made

    async def test_json_export_embeds_reconstructed_timeline(self, wired):
        inv_cases, cases, events, _ = wired
        made = await self._incident_case(cases, events, incident_id="INC-JE")
        resp = await inv_cases.export_case(made["case_id"], user=_admin(), format="json")
        case = json.loads(resp.body.decode())["case"]
        assert "timeline" in case and isinstance(case["timeline"], list)
        assert case["timeline_truncated"] is False
        assert case["timeline_subject_counts"] == {"incident": 1, "origin": 0}
        types = {e["type"] for e in case["timeline"]}
        assert types == {"event", "note"}
        # The durable carrier event surfaced with its provenance marker.
        ev = [e for e in case["timeline"] if e["type"] == "event"][0]
        assert ev["category"] == "exfiltration"
        assert ev["via"] == "incident:INC-JE"

    async def test_json_export_timeline_carries_action_notes(self, wired):
        inv_cases, cases, events, _ = wired
        made = await self._incident_case(cases, events, incident_id="INC-ACT")
        await cases.add_action_note(
            case_id=made["case_id"], actor="carol",
            text="response: raised origin risk",
        )
        resp = await inv_cases.export_case(made["case_id"], user=_admin(), format="json")
        case = json.loads(resp.body.decode())["case"]
        actions = [
            e for e in case["timeline"]
            if e["type"] == "note" and e.get("note_kind") == "action"
            and "raised origin risk" in (e.get("text") or "")
        ]
        assert actions, "5B action note must flow into the exported timeline"

    async def test_md_export_renders_timeline_section(self, wired):
        inv_cases, cases, events, _ = wired
        made = await self._incident_case(cases, events, incident_id="INC-MD")
        resp = await inv_cases.export_case(made["case_id"], user=_admin(), format="md")
        body = resp.body.decode() if isinstance(resp.body, bytes) else resp.body
        assert "## Timeline (" in body
        assert "via `incident:INC-MD`" in body

    async def test_export_timeline_is_tenant_scoped(self, wired):
        inv_cases, cases, events, _ = wired
        made = await self._incident_case(cases, events, incident_id="INC-TS", tenant="acme")
        # An event from another tenant stamped on the same incident must not leak.
        await events.bulk_insert([
            _evt("evil-ev", incident_id="INC-TS", tenant="evil", ts=1_000_000_500.0),
        ])
        resp = await inv_cases.export_case(
            made["case_id"], user=_admin(tenant="acme"), format="json"
        )
        case = json.loads(resp.body.decode())["case"]
        ids = {e.get("event_id") for e in case["timeline"] if e["type"] == "event"}
        assert "evil-ev" not in ids


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


# ═══════════════════════════════════════════════════════════════════════
# Phase 5D — cross-case correlation: cases sharing a subject are a campaign
# signal (the same indicator/actor across separate investigations).
# ═══════════════════════════════════════════════════════════════════════


class TestFindRelatedCasesStore:
    async def test_shared_subject_links_two_cases(self, case_store):
        c1 = await case_store.create_case(title="one", actor="a", tenant="acme")
        c2 = await case_store.create_case(title="two", actor="a", tenant="acme")
        for cid in (c1["case_id"], c2["case_id"]):
            await case_store.add_subject(
                case_id=cid, subject_type="incident", subject_key="INC-9", actor="a"
            )
        related = await case_store.find_related_cases(c1["case_id"])
        assert [r["case_id"] for r in related] == [c2["case_id"]]
        r = related[0]
        assert r["shared_count"] == 1
        assert r["shared_subjects"] == [{"subject_type": "incident", "subject_key": "INC-9"}]
        assert r["title"] == "two" and r["tenant"] == "acme"

    async def test_ranked_by_overlap_strength(self, case_store):
        target = await case_store.create_case(title="t", actor="a")
        weak = await case_store.create_case(title="weak", actor="a")
        strong = await case_store.create_case(title="strong", actor="a")
        # Target links three subjects; strong shares two, weak shares one.
        subs = [("incident", "INC-A"), ("incident", "INC-B"), ("origin", "origin:" + "a" * 16)]
        for st, sk in subs:
            await case_store.add_subject(
                case_id=target["case_id"], subject_type=st, subject_key=sk, actor="a"
            )
        for st, sk in subs[:2]:
            await case_store.add_subject(
                case_id=strong["case_id"], subject_type=st, subject_key=sk, actor="a"
            )
        await case_store.add_subject(
            case_id=weak["case_id"], subject_type=subs[0][0], subject_key=subs[0][1], actor="a"
        )
        related = await case_store.find_related_cases(target["case_id"])
        assert [r["case_id"] for r in related] == [strong["case_id"], weak["case_id"]]
        assert related[0]["shared_count"] == 2
        assert related[1]["shared_count"] == 1

    async def test_excludes_self_and_dedupes_subjects(self, case_store):
        c1 = await case_store.create_case(title="one", actor="a")
        c2 = await case_store.create_case(title="two", actor="a")
        # Two distinct shared subjects between the same pair.
        for st, sk in (("incident", "INC-1"), ("session", "s" * 16)):
            for cid in (c1["case_id"], c2["case_id"]):
                await case_store.add_subject(
                    case_id=cid, subject_type=st, subject_key=sk, actor="a"
                )
        related = await case_store.find_related_cases(c1["case_id"])
        # Self excluded; the single related case lists both shared subjects once each.
        assert [r["case_id"] for r in related] == [c2["case_id"]]
        assert related[0]["shared_count"] == 2

    async def test_no_shared_subjects_is_empty(self, case_store):
        c1 = await case_store.create_case(title="one", actor="a")
        c2 = await case_store.create_case(title="two", actor="a")
        await case_store.add_subject(
            case_id=c1["case_id"], subject_type="incident", subject_key="INC-X", actor="a"
        )
        await case_store.add_subject(
            case_id=c2["case_id"], subject_type="incident", subject_key="INC-Y", actor="a"
        )
        assert await case_store.find_related_cases(c1["case_id"]) == []

    async def test_empty_case_id_is_empty(self, case_store):
        assert await case_store.find_related_cases("") == []


class TestRelatedCasesEndpoint:
    async def _linked_pair(self, cases, *, subject="INC-9", tenant="acme"):
        c1 = await cases.create_case(title="one", actor="a", tenant=tenant)
        c2 = await cases.create_case(title="two", actor="a", tenant=tenant)
        for cid in (c1["case_id"], c2["case_id"]):
            await cases.add_subject(
                case_id=cid, subject_type="incident", subject_key=subject, actor="a"
            )
        return c1, c2

    async def test_related_returns_sharing_case(self, wired):
        inv_cases, cases, _, _ = wired
        c1, c2 = await self._linked_pair(cases)
        out = await inv_cases.related_cases(c1["case_id"], user=_admin())
        assert out["count"] == 1
        assert out["related"][0]["case_id"] == c2["case_id"]
        assert out["related"][0]["shared_subjects"][0]["subject_key"] == "INC-9"

    async def test_related_tenant_scoped_hides_other_tenant(self, wired):
        inv_cases, cases, _, _ = wired
        # Same shared subject across tenants must not cross the tenant boundary.
        mine = await cases.create_case(title="mine", actor="a", tenant="acme")
        theirs = await cases.create_case(title="theirs", actor="a", tenant="evil")
        for cid in (mine["case_id"], theirs["case_id"]):
            await cases.add_subject(
                case_id=cid, subject_type="incident", subject_key="INC-SHARED", actor="a"
            )
        out = await inv_cases.related_cases(mine["case_id"], user=_admin(tenant="acme"))
        assert out["count"] == 0

    async def test_related_global_admin_sees_cross_tenant(self, wired):
        inv_cases, cases, _, _ = wired
        a = await cases.create_case(title="a", actor="a", tenant="acme")
        b = await cases.create_case(title="b", actor="a", tenant="evil")
        for cid in (a["case_id"], b["case_id"]):
            await cases.add_subject(
                case_id=cid, subject_type="incident", subject_key="INC-G", actor="a"
            )
        out = await inv_cases.related_cases(a["case_id"], user=_admin())
        assert {r["case_id"] for r in out["related"]} == {b["case_id"]}

    async def test_related_cross_tenant_case_is_404(self, wired):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        made = await cases.create_case(title="t", actor="a", tenant="evil")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.related_cases(made["case_id"], user=_admin(tenant="acme"))
        assert ei.value.status_code == 404

    async def test_related_not_found_is_404(self, wired):
        inv_cases, _, _, _ = wired
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as ei:
            await inv_cases.related_cases("case_nope", user=_admin())
        assert ei.value.status_code == 404


# ═══════════════════════════════════════════════════════════════════════
# Phase 5E — programme analytics: MTTR, opened-vs-resolved trends, top origins.
# ═══════════════════════════════════════════════════════════════════════


class TestResolutionHelpers:
    def test_parse_iso_epoch_round_trips_and_tolerates_junk(self):
        from admin.services.investigation_case_store import _parse_iso_epoch

        assert _parse_iso_epoch("2026-01-01T00:00:00+00:00") is not None
        assert _parse_iso_epoch("") is None
        assert _parse_iso_epoch("not-a-date") is None
        assert _parse_iso_epoch(None) is None

    def test_resolution_epoch_uses_terminal_transition_note(self):
        from admin.services.investigation_case_store import (
            _parse_iso_epoch,
            _resolution_epoch,
        )

        case = {
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T09:00:00+00:00",
            "status": "resolved",
            "notes": [
                {"ts": "2026-01-01T00:30:00+00:00", "kind": "action",
                 "text": "status open → investigating"},
                {"ts": "2026-01-01T01:00:00+00:00", "kind": "action",
                 "text": "status investigating → resolved"},
            ],
        }
        # The terminal transition note wins over the later (unrelated) updated_at.
        assert _resolution_epoch(case) == _parse_iso_epoch("2026-01-01T01:00:00+00:00")

    def test_resolution_epoch_prefers_latest_terminal_transition(self):
        from admin.services.investigation_case_store import (
            _parse_iso_epoch,
            _resolution_epoch,
        )

        case = {
            "created_at": "2026-01-01T00:00:00+00:00",
            "status": "closed",
            "notes": [
                {"ts": "2026-01-01T01:00:00+00:00", "text": "status open → resolved"},
                {"ts": "2026-01-01T02:00:00+00:00", "text": "status resolved → closed"},
            ],
        }
        assert _resolution_epoch(case) == _parse_iso_epoch("2026-01-01T02:00:00+00:00")

    def test_resolution_epoch_falls_back_to_updated_at(self):
        from admin.services.investigation_case_store import (
            _parse_iso_epoch,
            _resolution_epoch,
        )

        case = {
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T05:00:00+00:00",
            "status": "resolved",
            "notes": [],
        }
        assert _resolution_epoch(case) == _parse_iso_epoch("2026-01-01T05:00:00+00:00")

    def test_resolution_epoch_none_when_nothing_parseable(self):
        from admin.services.investigation_case_store import _resolution_epoch

        assert _resolution_epoch({"status": "resolved", "notes": []}) is None


class TestCaseAnalyticsStore:
    async def test_analytics_extends_stats_rollup(self, case_store):
        await case_store.create_case(title="a", actor="a", tenant="acme", severity="high")
        await case_store.create_case(title="b", actor="a", tenant="acme", severity="low")
        out = await case_store.analytics(tenant="acme")
        # Inherits the stats surface …
        assert out["total"] == 2
        assert out["by_severity"]["high"] == 1
        assert out["by_status"]["open"] == 2
        # … and adds the 5E blocks.
        assert set(out) >= {"mttr", "trends", "top_origins", "trend_days"}

    async def test_analytics_mttr_counts_resolved_cases(self, case_store):
        c = await case_store.create_case(title="r", actor="a", tenant="acme")
        await case_store.set_state(case_id=c["case_id"], actor="a", status="resolved")
        await case_store.create_case(title="open", actor="a", tenant="acme")
        out = await case_store.analytics(tenant="acme")
        # One terminal case → MTTR sample of one; created≈resolved so mean is ~0 but real.
        assert out["mttr"]["count"] == 1
        assert out["mttr"]["mean_seconds"] is not None
        assert out["mttr"]["mean_seconds"] >= 0
        assert out["mttr"]["median_seconds"] is not None

    async def test_analytics_mttr_none_without_resolved(self, case_store):
        await case_store.create_case(title="open", actor="a", tenant="acme")
        out = await case_store.analytics(tenant="acme")
        assert out["mttr"]["count"] == 0
        assert out["mttr"]["mean_seconds"] is None
        assert out["mttr"]["median_seconds"] is None

    async def test_analytics_trends_span_window_and_count_today(self, case_store):
        from datetime import datetime, timezone

        await case_store.create_case(title="a", actor="a", tenant="acme")
        c = await case_store.create_case(title="b", actor="a", tenant="acme")
        await case_store.set_state(case_id=c["case_id"], actor="a", status="resolved")
        out = await case_store.analytics(tenant="acme", trend_days=7)
        assert out["trend_days"] == 7
        assert len(out["trends"]) == 7
        today = datetime.now(timezone.utc).date().isoformat()
        row = [t for t in out["trends"] if t["date"] == today][0]
        assert row["opened"] == 2  # both cases opened today
        assert row["resolved"] == 1  # one resolved today
        # Window is chronological, oldest→newest, ending today.
        assert out["trends"][-1]["date"] == today
        assert [t["date"] for t in out["trends"]] == sorted(t["date"] for t in out["trends"])

    async def test_analytics_top_origins_ranked_by_case_count(self, case_store):
        c1 = await case_store.create_case(title="one", actor="a", tenant="acme")
        c2 = await case_store.create_case(title="two", actor="a", tenant="acme")
        c3 = await case_store.create_case(title="three", actor="a", tenant="acme")
        hot = "origin:" + "a" * 16
        cold = "origin:" + "b" * 16
        for cid in (c1["case_id"], c2["case_id"], c3["case_id"]):
            await case_store.add_subject(
                case_id=cid, subject_type="origin", subject_key=hot, actor="a"
            )
        await case_store.add_subject(
            case_id=c1["case_id"], subject_type="origin", subject_key=cold, actor="a"
        )
        out = await case_store.analytics(tenant="acme")
        keys = [o["subject_key"] for o in out["top_origins"]]
        assert keys[:2] == [hot, cold]
        assert out["top_origins"][0]["case_count"] == 3
        assert out["top_origins"][1]["case_count"] == 1

    async def test_analytics_is_tenant_isolated(self, case_store):
        mine = await case_store.create_case(title="mine", actor="a", tenant="acme")
        await case_store.add_subject(
            case_id=mine["case_id"], subject_type="origin",
            subject_key="origin:" + "c" * 16, actor="a",
        )
        theirs = await case_store.create_case(title="theirs", actor="a", tenant="evil")
        await case_store.add_subject(
            case_id=theirs["case_id"], subject_type="origin",
            subject_key="origin:" + "d" * 16, actor="a",
        )
        out = await case_store.analytics(tenant="acme")
        assert out["total"] == 1
        assert [o["subject_key"] for o in out["top_origins"]] == ["origin:" + "c" * 16]


class TestCaseAnalyticsEndpoint:
    async def test_analytics_endpoint_returns_payload(self, wired):
        inv_cases, cases, _, _ = wired
        c = await cases.create_case(title="r", actor="a", tenant="acme")
        await cases.set_state(case_id=c["case_id"], actor="a", status="resolved")
        out = await inv_cases.case_analytics(user=_admin(tenant="acme"), trend_days=14, top_origins=10)
        a = out["analytics"]
        assert a["total"] == 1
        assert a["mttr"]["count"] == 1
        assert a["trend_days"] == 14 and len(a["trends"]) == 14

    async def test_analytics_endpoint_tenant_scoped(self, wired):
        inv_cases, cases, _, _ = wired
        await cases.create_case(title="mine", actor="a", tenant="acme")
        await cases.create_case(title="theirs", actor="a", tenant="evil")
        out = await inv_cases.case_analytics(user=_admin(tenant="acme"), trend_days=14, top_origins=10)
        assert out["analytics"]["total"] == 1


# ═══════════════════════════════════════════════════════════════════════
# Phase 0 — ObservableStore CRUD
# ═══════════════════════════════════════════════════════════════════════


class TestObservableStore:
    async def test_add_and_list(self, observable_store):
        made = await observable_store.add(
            case_id="case_1", observable_type="ip", value="203.0.113.5", actor="a",
        )
        assert made["observable_id"].startswith("obs_")
        assert made["type"] == "ip"
        assert made["value"] == "203.0.113.5"
        assert made["is_ioc"] is False
        assert made["tlp"] == "amber" and made["pap"] == "amber"
        rows = await observable_store.list_for_case("case_1")
        assert len(rows) == 1 and rows[0]["value"] == "203.0.113.5"

    async def test_add_normalises_value(self, observable_store):
        made = await observable_store.add(
            case_id="c", observable_type="domain", value="  EVIL.Example  ", actor="a",
        )
        # network/host/hash/email indicators are lower-cased + stripped.
        assert made["value"] == "evil.example"

    async def test_add_preserves_case_for_filename(self, observable_store):
        made = await observable_store.add(
            case_id="c", observable_type="filename", value="Payload.EXE", actor="a",
        )
        assert made["value"] == "Payload.EXE"

    async def test_add_is_idempotent_per_case_type_value(self, observable_store):
        first = await observable_store.add(
            case_id="c", observable_type="ip", value="203.0.113.5", actor="a",
        )
        second = await observable_store.add(
            case_id="c", observable_type="ip", value="203.0.113.5", actor="a",
            is_ioc=True, tlp="red",
        )
        # Same indicator: refreshed in place, not duplicated.
        assert second["observable_id"] == first["observable_id"]
        assert second["is_ioc"] is True and second["tlp"] == "red"
        rows = await observable_store.list_for_case("c")
        assert len(rows) == 1

    async def test_same_value_different_case_is_distinct(self, observable_store):
        await observable_store.add(
            case_id="c1", observable_type="ip", value="203.0.113.5", actor="a",
        )
        await observable_store.add(
            case_id="c2", observable_type="ip", value="203.0.113.5", actor="a",
        )
        assert len(await observable_store.list_for_case("c1")) == 1
        assert len(await observable_store.list_for_case("c2")) == 1

    async def test_add_rejects_invalid_type(self, observable_store):
        with pytest.raises(ValueError):
            await observable_store.add(
                case_id="c", observable_type="bogus", value="x", actor="a",
            )

    async def test_add_rejects_invalid_tlp(self, observable_store):
        with pytest.raises(ValueError):
            await observable_store.add(
                case_id="c", observable_type="ip", value="1.1.1.1", actor="a",
                tlp="purple",
            )

    async def test_add_rejects_empty_value(self, observable_store):
        with pytest.raises(ValueError):
            await observable_store.add(
                case_id="c", observable_type="ip", value="   ", actor="a",
            )

    async def test_tags_normalised_and_deduped(self, observable_store):
        made = await observable_store.add(
            case_id="c", observable_type="domain", value="evil.example", actor="a",
            tags=["APT", "apt", "  C2  ", ""],
        )
        assert made["tags"] == ["apt", "c2"]

    async def test_get_is_case_scoped(self, observable_store):
        made = await observable_store.add(
            case_id="c1", observable_type="ip", value="1.1.1.1", actor="a",
        )
        assert await observable_store.get("c1", made["observable_id"]) is not None
        # A right id under the wrong case must not resolve (no cross-case leak).
        assert await observable_store.get("c2", made["observable_id"]) is None

    async def test_remove(self, observable_store):
        made = await observable_store.add(
            case_id="c", observable_type="ip", value="1.1.1.1", actor="a",
        )
        assert await observable_store.remove(
            case_id="c", observable_id=made["observable_id"]
        ) is True
        assert await observable_store.list_for_case("c") == []
        # Removing a second time is a no-op returning False.
        assert await observable_store.remove(
            case_id="c", observable_id=made["observable_id"]
        ) is False

    # ─── set_enrichment (Phase 2) ────────────────────────────────────────────

    async def test_set_enrichment_merges_and_marks_ioc(self, observable_store):
        made = await observable_store.add(
            case_id="c", observable_type="ip", value="1.2.3.4", actor="a",
        )
        oid = made["observable_id"]
        updated = await observable_store.set_enrichment(
            case_id="c", observable_id=oid, key="cortex",
            data={"verdict": "malicious", "is_malicious": True}, mark_ioc=True,
        )
        assert updated is not None
        assert updated["enrichment"]["cortex"]["verdict"] == "malicious"
        assert updated["is_ioc"] is True

    async def test_set_enrichment_preserves_prior_blobs(self, observable_store):
        made = await observable_store.add(
            case_id="c", observable_type="ip", value="1.2.3.4", actor="a",
        )
        oid = made["observable_id"]
        await observable_store.set_enrichment(
            case_id="c", observable_id=oid, key="cortex", data={"verdict": "safe"},
        )
        updated = await observable_store.set_enrichment(
            case_id="c", observable_id=oid, key="opencti", data={"hits": 3},
        )
        assert updated is not None
        assert set(updated["enrichment"]) == {"cortex", "opencti"}
        # is_ioc is sticky/only-raised — a non-malicious second blob never clears it.
        assert updated["is_ioc"] is False

    async def test_set_enrichment_missing_observable_is_none(self, observable_store):
        assert await observable_store.set_enrichment(
            case_id="c", observable_id="obs_nope", key="cortex", data={},
        ) is None

    async def test_set_enrichment_is_case_scoped(self, observable_store):
        made = await observable_store.add(
            case_id="c1", observable_type="ip", value="1.1.1.1", actor="a",
        )
        # Right id under the wrong case must not resolve (no cross-case write).
        assert await observable_store.set_enrichment(
            case_id="c2", observable_id=made["observable_id"], key="cortex", data={},
        ) is None

    async def test_set_enrichment_rejects_empty_key(self, observable_store):
        made = await observable_store.add(
            case_id="c", observable_type="ip", value="1.1.1.1", actor="a",
        )
        with pytest.raises(ValueError):
            await observable_store.set_enrichment(
                case_id="c", observable_id=made["observable_id"], key="   ", data={},
            )

    async def test_set_enrichment_evicts_oldest_key_past_cap(self, observable_store):
        from admin.services.investigation_observable_store import _MAX_ENRICHMENT_KEYS

        made = await observable_store.add(
            case_id="c", observable_type="ip", value="1.1.1.1", actor="a",
        )
        oid = made["observable_id"]
        for i in range(_MAX_ENRICHMENT_KEYS + 5):
            await observable_store.set_enrichment(
                case_id="c", observable_id=oid, key=f"k{i}", data={"n": i},
            )
        got = await observable_store.get("c", oid)
        assert got is not None
        assert len(got["enrichment"]) == _MAX_ENRICHMENT_KEYS
        assert "k0" not in got["enrichment"]  # oldest evicted
        assert f"k{_MAX_ENRICHMENT_KEYS + 4}" in got["enrichment"]  # newest kept


# ═══════════════════════════════════════════════════════════════════════
# Phase 0 — TaskStore CRUD
# ═══════════════════════════════════════════════════════════════════════


class TestTaskStore:
    async def test_add_and_list(self, task_store):
        made = await task_store.add(case_id="c", title="Contain host", actor="a")
        assert made["task_id"].startswith("task_")
        assert made["status"] == "todo"
        assert made["order_index"] == 0
        rows = await task_store.list_for_case("c")
        assert len(rows) == 1 and rows[0]["title"] == "Contain host"

    async def test_order_index_increments(self, task_store):
        await task_store.add(case_id="c", title="one", actor="a")
        await task_store.add(case_id="c", title="two", actor="a")
        rows = await task_store.list_for_case("c")
        assert [t["order_index"] for t in rows] == [0, 1]
        assert [t["title"] for t in rows] == ["one", "two"]

    async def test_add_requires_title(self, task_store):
        with pytest.raises(ValueError):
            await task_store.add(case_id="c", title="   ", actor="a")

    async def test_set_state_transitions_and_journals(self, task_store):
        made = await task_store.add(case_id="c", title="t", actor="a")
        updated = await task_store.set_state(
            case_id="c", task_id=made["task_id"], actor="bob", status="in_progress",
        )
        assert updated["status"] == "in_progress"
        # The transition is journalled as an actor-stamped action note.
        assert any(
            n["kind"] == "action" and "status" in n["text"] for n in updated["notes"]
        )

    async def test_set_state_rejects_invalid_status(self, task_store):
        made = await task_store.add(case_id="c", title="t", actor="a")
        with pytest.raises(ValueError):
            await task_store.set_state(
                case_id="c", task_id=made["task_id"], actor="a", status="bogus",
            )

    async def test_set_state_missing_task_returns_none(self, task_store):
        assert await task_store.set_state(
            case_id="c", task_id="task_nope", actor="a", status="done",
        ) is None

    async def test_add_note(self, task_store):
        made = await task_store.add(case_id="c", title="t", actor="a")
        updated = await task_store.add_note(
            case_id="c", task_id=made["task_id"], actor="a", text="looked into it",
        )
        assert any(
            n["kind"] == "note" and n["text"] == "looked into it"
            for n in updated["notes"]
        )

    async def test_add_note_requires_text(self, task_store):
        made = await task_store.add(case_id="c", title="t", actor="a")
        with pytest.raises(ValueError):
            await task_store.add_note(
                case_id="c", task_id=made["task_id"], actor="a", text="   ",
            )

    async def test_remove(self, task_store):
        made = await task_store.add(case_id="c", title="t", actor="a")
        assert await task_store.remove(case_id="c", task_id=made["task_id"]) is True
        assert await task_store.list_for_case("c") == []
        assert await task_store.remove(case_id="c", task_id=made["task_id"]) is False

    async def test_progress_rollup(self, task_store):
        await task_store.add(case_id="c", title="a", actor="x")
        b = await task_store.add(case_id="c", title="b", actor="x")
        d = await task_store.add(case_id="c", title="d", actor="x")
        await task_store.set_state(case_id="c", task_id=b["task_id"], actor="x", status="done")
        await task_store.set_state(case_id="c", task_id=d["task_id"], actor="x", status="cancelled")
        prog = await task_store.progress("c")
        # done + cancelled both count as closed.
        assert prog == {"total": 3, "done": 2, "open": 1}

    async def test_get_is_case_scoped(self, task_store):
        made = await task_store.add(case_id="c1", title="t", actor="a")
        assert await task_store.get("c1", made["task_id"]) is not None
        assert await task_store.get("c2", made["task_id"]) is None


# ═══════════════════════════════════════════════════════════════════════
# Phase 0 — observable endpoints
# ═══════════════════════════════════════════════════════════════════════


class TestObservableEndpoints:
    async def test_add_list_remove(self, wired):
        inv_cases, cases, _, audit = wired
        made = await cases.create_case(title="t", actor="a")
        cid = made["case_id"]
        body = inv_cases.ObservableAddRequest(
            type="ip", value="203.0.113.7", is_ioc=True, tlp="red",
        )
        added = await inv_cases.add_case_observable(cid, body=body, user=_admin())
        assert added["observable"]["value"] == "203.0.113.7"
        assert audit.entries[-1]["action"] == "investigation.observable_add"

        listed = await inv_cases.list_case_observables(cid, user=_admin())
        assert listed["count"] == 1
        assert listed["can_write"] is True
        assert "ip" in listed["types"] and "red" in listed["tlp_levels"]

        obs_id = added["observable"]["observable_id"]
        out = await inv_cases.remove_case_observable(cid, obs_id, user=_admin())
        assert out["message"] == "Observable removed"
        assert (await inv_cases.list_case_observables(cid, user=_admin()))["count"] == 0

    async def test_list_can_write_false_for_viewer(self, wired):
        inv_cases, cases, _, _ = wired
        made = await cases.create_case(title="t", actor="a")
        out = await inv_cases.list_case_observables(made["case_id"], user=_viewer())
        assert out["can_write"] is False

    async def test_add_invalid_type_is_400(self, wired):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        made = await cases.create_case(title="t", actor="a")
        body = inv_cases.ObservableAddRequest(type="bogus", value="x")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.add_case_observable(made["case_id"], body=body, user=_admin())
        assert ei.value.status_code == 400

    async def test_add_cross_tenant_is_404(self, wired):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        made = await cases.create_case(title="t", actor="a", tenant="evil")
        body = inv_cases.ObservableAddRequest(type="ip", value="1.1.1.1")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.add_case_observable(
                made["case_id"], body=body, user=_admin(tenant="acme")
            )
        assert ei.value.status_code == 404

    async def test_remove_missing_is_404(self, wired):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        made = await cases.create_case(title="t", actor="a")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.remove_case_observable(
                made["case_id"], "obs_nope", user=_admin()
            )
        assert ei.value.status_code == 404

    async def test_promote_ioc(self, wired, tmp_path, monkeypatch):
        inv_cases, cases, _, _ = wired
        from admin.services import ioc_store as ioc_mod
        from admin.services.ioc_store import IOCStore

        store = IOCStore(
            ioc_path=tmp_path / "iocs.json", feed_state_path=tmp_path / "feed.json"
        )
        monkeypatch.setattr(ioc_mod, "get_ioc_store", lambda: store)

        made = await cases.create_case(title="t", actor="a")
        cid = made["case_id"]
        body = inv_cases.ObservableAddRequest(type="domain", value="evil.example")
        added = await inv_cases.add_case_observable(cid, body=body, user=_admin())
        obs_id = added["observable"]["observable_id"]

        out = await inv_cases.promote_observable_to_ioc(cid, obs_id, user=_admin())
        assert out["ioc_type"] == "domain"
        assert out["ioc_id"]
        # The observable is flagged is_ioc after promotion.
        listed = await inv_cases.list_case_observables(cid, user=_admin())
        assert listed["observables"][0]["is_ioc"] is True

    async def test_promote_unpromotable_type_is_400(self, wired):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        made = await cases.create_case(title="t", actor="a")
        cid = made["case_id"]
        body = inv_cases.ObservableAddRequest(type="user", value="mallory")
        added = await inv_cases.add_case_observable(cid, body=body, user=_admin())
        with pytest.raises(HTTPException) as ei:
            await inv_cases.promote_observable_to_ioc(
                cid, added["observable"]["observable_id"], user=_admin()
            )
        assert ei.value.status_code == 400


# ═══════════════════════════════════════════════════════════════════════
# Phase 2 — observable enrichment (Cortex)
# ═══════════════════════════════════════════════════════════════════════


class _FakeConfig:
    def __init__(self, *, type: str = "cortex", enabled: bool = True):
        self.type = type
        self.enabled = enabled


class _FakeCortexConnector:
    """Stand-in for :class:`CortexConnector` — records calls, returns/raises."""

    def __init__(self, *, result=None, error=None, responder_result=None, responder_error=None):
        self._result = result or {}
        self._error = error
        self._responder_result = responder_result or {}
        self._responder_error = responder_error
        self.calls: list[dict] = []
        self.responder_calls: list[dict] = []

    async def enrich_observable(self, **kwargs):
        self.calls.append(kwargs)
        if self._error is not None:
            raise self._error
        return self._result

    async def run_responder(self, **kwargs):
        self.responder_calls.append(kwargs)
        if self._responder_error is not None:
            raise self._responder_error
        return self._responder_result


class _FakeRedis:
    """Minimal Redis stand-in for the origin auto-raise path (HASH ops + ping)."""

    def __init__(self, *, ping_error=False):
        self._store: dict[str, dict] = {}
        self._ping_error = ping_error

    def ping(self):
        if self._ping_error:
            raise RuntimeError("redis down")
        return True

    def hgetall(self, key):
        return dict(self._store.get(key, {}))

    def hset(self, key, mapping=None):
        self._store.setdefault(key, {}).update(mapping or {})

    def expire(self, key, ttl):
        return True

    def ttl(self, key):
        return 3600


class _FakeOpenCtiConnector:
    """Stand-in for :class:`OpenCTIConnector` — records lookups, returns/raises."""

    def __init__(self, *, result=None, error=None, kind="opencti"):
        self._result = result or {}
        self._error = error
        self.kind = kind
        self.calls: list[dict] = []

    async def lookup_observable(self, **kwargs):
        self.calls.append(kwargs)
        if self._error is not None:
            raise self._error
        return self._result


class _FakeRegistry:
    def __init__(self, *, config=None, connector=None):
        self._config = config
        self._connector = connector

    def get(self, integration_id):
        return self._config

    def build_enrichment_connector(self, config):
        return self._connector

    def build_lookup_connector(self, config):
        return self._connector


class TestObservableEnrichEndpoint:
    async def _seed_observable(self, inv_cases, cases, otype="ip", value="1.2.3.4"):
        made = await cases.create_case(title="t", actor="a")
        cid = made["case_id"]
        body = inv_cases.ObservableAddRequest(type=otype, value=value)
        added = await inv_cases.add_case_observable(cid, body=body, user=_admin())
        return cid, added["observable"]["observable_id"]

    async def test_enrich_success_marks_ioc(self, wired, monkeypatch):
        inv_cases, cases, _, audit = wired
        cid, oid = await self._seed_observable(inv_cases, cases)

        result = {
            "connector": "cortex", "data_type": "ip", "verdict": "malicious",
            "is_malicious": True, "analyzers": [{"analyzer": "VT", "level": "malicious"}],
        }
        connector = _FakeCortexConnector(result=result)
        registry = _FakeRegistry(config=_FakeConfig(), connector=connector)
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)

        body = inv_cases.ObservableEnrichRequest(
            integration_id="cx1", analyzer_ids=["VT"], tlp="green",
        )
        out = await inv_cases.enrich_case_observable(cid, oid, body=body, user=_admin())
        assert out["enrichment"]["verdict"] == "malicious"
        assert out["observable"]["enrichment"]["cortex"]["verdict"] == "malicious"
        assert out["observable"]["is_ioc"] is True
        # The connector was driven with the observable's type/value + requested tlp.
        assert connector.calls[0]["observable_type"] == "ip"
        assert connector.calls[0]["value"] == "1.2.3.4"
        assert connector.calls[0]["tlp"] == "green"
        assert audit.entries[-1]["action"] == "investigation.observable_enrich"

    async def test_enrich_defaults_tlp_to_observable(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        cid, oid = await self._seed_observable(inv_cases, cases)
        connector = _FakeCortexConnector(result={"verdict": "safe", "is_malicious": False})
        registry = _FakeRegistry(config=_FakeConfig(), connector=connector)
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)

        body = inv_cases.ObservableEnrichRequest(integration_id="cx1", analyzer_ids=["VT"])
        await inv_cases.enrich_case_observable(cid, oid, body=body, user=_admin())
        # No tlp on the request → falls back to the observable's own tlp (amber).
        assert connector.calls[0]["tlp"] == "amber"

    async def test_enrich_observable_missing_is_404(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        made = await cases.create_case(title="t", actor="a")
        registry = _FakeRegistry(config=_FakeConfig(), connector=_FakeCortexConnector())
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        body = inv_cases.ObservableEnrichRequest(integration_id="cx1", analyzer_ids=["VT"])
        with pytest.raises(HTTPException) as ei:
            await inv_cases.enrich_case_observable(
                made["case_id"], "obs_nope", body=body, user=_admin()
            )
        assert ei.value.status_code == 404

    async def test_enrich_integration_not_found_404(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        cid, oid = await self._seed_observable(inv_cases, cases)
        registry = _FakeRegistry(config=None)
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        body = inv_cases.ObservableEnrichRequest(integration_id="nope", analyzer_ids=["VT"])
        with pytest.raises(HTTPException) as ei:
            await inv_cases.enrich_case_observable(cid, oid, body=body, user=_admin())
        assert ei.value.status_code == 404

    async def test_enrich_wrong_type_is_400(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        cid, oid = await self._seed_observable(inv_cases, cases)
        registry = _FakeRegistry(config=_FakeConfig(type="thehive"))
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        body = inv_cases.ObservableEnrichRequest(integration_id="th1", analyzer_ids=["VT"])
        with pytest.raises(HTTPException) as ei:
            await inv_cases.enrich_case_observable(cid, oid, body=body, user=_admin())
        assert ei.value.status_code == 400

    async def test_enrich_disabled_is_400(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        cid, oid = await self._seed_observable(inv_cases, cases)
        registry = _FakeRegistry(config=_FakeConfig(enabled=False))
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        body = inv_cases.ObservableEnrichRequest(integration_id="cx1", analyzer_ids=["VT"])
        with pytest.raises(HTTPException) as ei:
            await inv_cases.enrich_case_observable(cid, oid, body=body, user=_admin())
        assert ei.value.status_code == 400

    async def test_enrich_not_configured_is_400(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        cid, oid = await self._seed_observable(inv_cases, cases)
        registry = _FakeRegistry(config=_FakeConfig(), connector=None)
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        body = inv_cases.ObservableEnrichRequest(integration_id="cx1", analyzer_ids=["VT"])
        with pytest.raises(HTTPException) as ei:
            await inv_cases.enrich_case_observable(cid, oid, body=body, user=_admin())
        assert ei.value.status_code == 400

    async def test_enrich_invalid_tlp_is_400(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        cid, oid = await self._seed_observable(inv_cases, cases)
        registry = _FakeRegistry(config=_FakeConfig(), connector=_FakeCortexConnector())
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        body = inv_cases.ObservableEnrichRequest(
            integration_id="cx1", analyzer_ids=["VT"], tlp="purple",
        )
        with pytest.raises(HTTPException) as ei:
            await inv_cases.enrich_case_observable(cid, oid, body=body, user=_admin())
        assert ei.value.status_code == 400

    async def test_enrich_connector_error_is_502_fail_open(self, wired, monkeypatch):
        inv_cases, cases, _, audit = wired
        from fastapi import HTTPException

        from admin.services.integrations.base import ConnectorError

        cid, oid = await self._seed_observable(inv_cases, cases)
        connector = _FakeCortexConnector(error=ConnectorError("cortex unreachable"))
        registry = _FakeRegistry(config=_FakeConfig(), connector=connector)
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        body = inv_cases.ObservableEnrichRequest(integration_id="cx1", analyzer_ids=["VT"])
        with pytest.raises(HTTPException) as ei:
            await inv_cases.enrich_case_observable(cid, oid, body=body, user=_admin())
        assert ei.value.status_code == 502
        # Fail-open: the observable is never mutated on a failed enrichment.
        listed = await inv_cases.list_case_observables(cid, user=_admin())
        assert listed["observables"][0]["enrichment"] == {}
        assert listed["observables"][0]["is_ioc"] is False
        assert audit.entries[-1]["action"] == "investigation.observable_enrich_failed"

    async def test_enrich_cross_tenant_is_404(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        made = await cases.create_case(title="t", actor="a", tenant="evil")
        body_add = inv_cases.ObservableAddRequest(type="ip", value="1.1.1.1")
        # Seed as the owning tenant so the observable exists.
        added = await inv_cases.add_case_observable(
            made["case_id"], body=body_add, user=_admin(tenant="evil")
        )
        registry = _FakeRegistry(config=_FakeConfig(), connector=_FakeCortexConnector())
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        body = inv_cases.ObservableEnrichRequest(integration_id="cx1", analyzer_ids=["VT"])
        with pytest.raises(HTTPException) as ei:
            await inv_cases.enrich_case_observable(
                made["case_id"], added["observable"]["observable_id"],
                body=body, user=_admin(tenant="acme"),
            )
        assert ei.value.status_code == 404


# ═══════════════════════════════════════════════════════════════════════
# Phase 2 — enrichment auto-raise of a case's origins (malicious verdict)
# ═══════════════════════════════════════════════════════════════════════


_ORIGIN_TOKEN = "session:0123456789abcdef"


class TestEnrichAutoRaiseOrigins:
    async def _seed_case_with_origin(self, inv_cases, cases, *, malicious=True):
        made = await cases.create_case(title="t", actor="a")
        cid = made["case_id"]
        add = inv_cases.ObservableAddRequest(type="ip", value="9.9.9.9")
        added = await inv_cases.add_case_observable(cid, body=add, user=_admin())
        await cases.add_subject(
            case_id=cid, subject_type="origin", subject_key=_ORIGIN_TOKEN, actor="a"
        )
        result = {
            "connector": "cortex", "verdict": "malicious" if malicious else "safe",
            "is_malicious": malicious, "analyzers": [],
        }
        connector = _FakeCortexConnector(result=result)
        registry = _FakeRegistry(config=_FakeConfig(), connector=connector)
        return cid, added["observable"]["observable_id"], registry

    async def test_malicious_auto_raises_case_origin(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        cid, oid, registry = await self._seed_case_with_origin(inv_cases, cases)
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        monkeypatch.setattr(inv_cases, "_redis", lambda: _FakeRedis())
        monkeypatch.setattr(inv_cases, "_correlation_enabled", lambda: True)
        monkeypatch.setattr(inv_cases, "_enrich_auto_raise_enabled", lambda: True)

        body = inv_cases.ObservableEnrichRequest(integration_id="cx1", analyzer_ids=["VT"])
        out = await inv_cases.enrich_case_observable(cid, oid, body=body, user=_admin())

        risk = out["origin_risk"]
        assert risk["correlation_enabled"] is True
        assert len(risk["raised"]) == 1
        raised = risk["raised"][0]
        assert raised["token"] == _ORIGIN_TOKEN
        # Score is pushed to (at least) the effective block threshold (7.0).
        assert raised["new_score"] >= 7.0
        # The escalation is journalled onto the case's action trail.
        case = await cases.get(cid)
        assert any(
            n.get("kind") == "action" and "auto-raised" in n.get("text", "")
            for n in case["notes"]
        )

    async def test_gate_off_surfaces_eligible_origins_without_raising(
        self, wired, monkeypatch
    ):
        # Default posture: auto-raise is OFF. A malicious verdict must still flag the
        # observable is_ioc, but must NOT harden any origin — it only surfaces the
        # eligible tokens for a deliberate operator action. No Redis touch, no note.
        inv_cases, cases, _, _ = wired
        cid, oid, registry = await self._seed_case_with_origin(inv_cases, cases)
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        # A live Redis would be a bug to touch; make any use blow up loudly.
        def _boom():
            raise AssertionError("Redis must not be touched when auto-raise is gated off")
        monkeypatch.setattr(inv_cases, "_redis", _boom)
        monkeypatch.setattr(inv_cases, "_enrich_auto_raise_enabled", lambda: False)

        body = inv_cases.ObservableEnrichRequest(integration_id="cx1", analyzer_ids=["VT"])
        out = await inv_cases.enrich_case_observable(cid, oid, body=body, user=_admin())

        risk = out["origin_risk"]
        assert risk["raised"] == []
        assert risk["skipped_reason"] == "auto_raise_disabled"
        assert risk["eligible_origins"] == [_ORIGIN_TOKEN]
        # The observable is still marked an IOC (detective fact is preserved)...
        assert out["observable"]["is_ioc"] is True
        # ...but nothing is journalled as an enforcement action.
        case = await cases.get(cid)
        assert not any(
            n.get("kind") == "action" and "auto-raised" in n.get("text", "")
            for n in case["notes"]
        )

    async def test_malicious_without_origins_is_skipped(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        # Seed a case + observable but NO origin subject.
        made = await cases.create_case(title="t", actor="a")
        cid = made["case_id"]
        add = inv_cases.ObservableAddRequest(type="ip", value="8.8.8.8")
        added = await inv_cases.add_case_observable(cid, body=add, user=_admin())
        oid = added["observable"]["observable_id"]
        connector = _FakeCortexConnector(
            result={"verdict": "malicious", "is_malicious": True, "analyzers": []}
        )
        registry = _FakeRegistry(config=_FakeConfig(), connector=connector)
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        monkeypatch.setattr(inv_cases, "_redis", lambda: _FakeRedis())

        body = inv_cases.ObservableEnrichRequest(integration_id="cx1", analyzer_ids=["VT"])
        out = await inv_cases.enrich_case_observable(cid, oid, body=body, user=_admin())
        assert out["origin_risk"]["raised"] == []
        assert out["origin_risk"]["skipped_reason"] == "no_origin_subjects"
        # The observable is still flagged as an IOC.
        assert out["observable"]["is_ioc"] is True

    async def test_malicious_redis_unavailable_still_succeeds(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        cid, oid, registry = await self._seed_case_with_origin(inv_cases, cases)
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        monkeypatch.setattr(inv_cases, "_redis", lambda: None)
        monkeypatch.setattr(inv_cases, "_enrich_auto_raise_enabled", lambda: True)

        body = inv_cases.ObservableEnrichRequest(integration_id="cx1", analyzer_ids=["VT"])
        out = await inv_cases.enrich_case_observable(cid, oid, body=body, user=_admin())
        assert out["origin_risk"]["raised"] == []
        assert out["origin_risk"]["skipped_reason"] == "redis_unavailable"
        assert out["observable"]["is_ioc"] is True

    async def test_malicious_redis_ping_failure_is_skipped(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        cid, oid, registry = await self._seed_case_with_origin(inv_cases, cases)
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        monkeypatch.setattr(inv_cases, "_redis", lambda: _FakeRedis(ping_error=True))
        monkeypatch.setattr(inv_cases, "_enrich_auto_raise_enabled", lambda: True)

        body = inv_cases.ObservableEnrichRequest(integration_id="cx1", analyzer_ids=["VT"])
        out = await inv_cases.enrich_case_observable(cid, oid, body=body, user=_admin())
        assert out["origin_risk"]["skipped_reason"] == "redis_unavailable"

    async def test_benign_verdict_does_not_raise(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        cid, oid, registry = await self._seed_case_with_origin(
            inv_cases, cases, malicious=False
        )
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        monkeypatch.setattr(inv_cases, "_redis", lambda: _FakeRedis())

        body = inv_cases.ObservableEnrichRequest(integration_id="cx1", analyzer_ids=["VT"])
        out = await inv_cases.enrich_case_observable(cid, oid, body=body, user=_admin())
        # A non-malicious verdict never touches origin risk.
        assert "origin_risk" not in out
        assert out["observable"]["is_ioc"] is False

    async def test_malformed_origin_token_is_ignored(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        made = await cases.create_case(title="t", actor="a")
        cid = made["case_id"]
        add = inv_cases.ObservableAddRequest(type="ip", value="7.7.7.7")
        added = await inv_cases.add_case_observable(cid, body=add, user=_admin())
        oid = added["observable"]["observable_id"]
        # An incident subject (not an origin) + an origin with a non-hex digest.
        await cases.add_subject(
            case_id=cid, subject_type="incident", subject_key="inc-123", actor="a"
        )
        await cases.add_subject(
            case_id=cid, subject_type="origin", subject_key="session:not-a-digest", actor="a"
        )
        connector = _FakeCortexConnector(
            result={"verdict": "malicious", "is_malicious": True, "analyzers": []}
        )
        registry = _FakeRegistry(config=_FakeConfig(), connector=connector)
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        monkeypatch.setattr(inv_cases, "_redis", lambda: _FakeRedis())

        body = inv_cases.ObservableEnrichRequest(integration_id="cx1", analyzer_ids=["VT"])
        out = await inv_cases.enrich_case_observable(cid, oid, body=body, user=_admin())
        # Neither malformed subject yields a raise.
        assert out["origin_risk"]["raised"] == []
        assert out["origin_risk"]["skipped_reason"] == "no_origin_subjects"


# ═══════════════════════════════════════════════════════════════════════
# Phase 2 — observable responder (Cortex response action)
# ═══════════════════════════════════════════════════════════════════════


class TestObservableResponderEndpoint:
    async def _seed_observable(self, inv_cases, cases, otype="ip", value="1.2.3.4"):
        made = await cases.create_case(title="t", actor="a")
        cid = made["case_id"]
        body = inv_cases.ObservableAddRequest(type=otype, value=value)
        added = await inv_cases.add_case_observable(cid, body=body, user=_admin())
        return cid, added["observable"]["observable_id"]

    async def test_responder_success_records_outcome(self, wired, monkeypatch):
        inv_cases, cases, _, audit = wired
        cid, oid = await self._seed_observable(inv_cases, cases)
        outcome = {"responder": "block-ip", "job_id": "j1", "status": "Success"}
        connector = _FakeCortexConnector(responder_result=outcome)
        registry = _FakeRegistry(config=_FakeConfig(), connector=connector)
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)

        body = inv_cases.ObservableResponderRequest(
            integration_id="cx1", responder_id="block-ip", tlp="red",
        )
        out = await inv_cases.run_observable_responder(cid, oid, body=body, user=_admin())
        assert out["responder"]["status"] == "Success"
        assert out["observable"]["enrichment"]["cortex_responder"]["job_id"] == "j1"
        # A responder is an action, not a verdict — it never flags is_ioc.
        assert out["observable"]["is_ioc"] is False
        assert connector.responder_calls[0]["responder_id"] == "block-ip"
        assert connector.responder_calls[0]["value"] == "1.2.3.4"
        assert connector.responder_calls[0]["tlp"] == "red"
        assert audit.entries[-1]["action"] == "investigation.observable_respond"

    async def test_responder_defaults_tlp_to_observable(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        cid, oid = await self._seed_observable(inv_cases, cases)
        connector = _FakeCortexConnector(responder_result={"status": "Success"})
        registry = _FakeRegistry(config=_FakeConfig(), connector=connector)
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        body = inv_cases.ObservableResponderRequest(integration_id="cx1", responder_id="r1")
        await inv_cases.run_observable_responder(cid, oid, body=body, user=_admin())
        assert connector.responder_calls[0]["tlp"] == "amber"

    async def test_responder_connector_error_is_502_fail_open(self, wired, monkeypatch):
        inv_cases, cases, _, audit = wired
        from fastapi import HTTPException

        from admin.services.integrations.base import ConnectorError

        cid, oid = await self._seed_observable(inv_cases, cases)
        connector = _FakeCortexConnector(responder_error=ConnectorError("cortex down"))
        registry = _FakeRegistry(config=_FakeConfig(), connector=connector)
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        body = inv_cases.ObservableResponderRequest(integration_id="cx1", responder_id="r1")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.run_observable_responder(cid, oid, body=body, user=_admin())
        assert ei.value.status_code == 502
        # Fail-open: observable untouched.
        listed = await inv_cases.list_case_observables(cid, user=_admin())
        assert listed["observables"][0]["enrichment"] == {}
        assert audit.entries[-1]["action"] == "investigation.observable_respond_failed"

    async def test_responder_wrong_type_is_400(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        cid, oid = await self._seed_observable(inv_cases, cases)
        registry = _FakeRegistry(config=_FakeConfig(type="thehive"))
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        body = inv_cases.ObservableResponderRequest(integration_id="th1", responder_id="r1")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.run_observable_responder(cid, oid, body=body, user=_admin())
        assert ei.value.status_code == 400

    async def test_responder_integration_not_found_404(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        cid, oid = await self._seed_observable(inv_cases, cases)
        registry = _FakeRegistry(config=None)
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        body = inv_cases.ObservableResponderRequest(integration_id="nope", responder_id="r1")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.run_observable_responder(cid, oid, body=body, user=_admin())
        assert ei.value.status_code == 404

    async def test_responder_observable_missing_404(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        made = await cases.create_case(title="t", actor="a")
        registry = _FakeRegistry(config=_FakeConfig(), connector=_FakeCortexConnector())
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        body = inv_cases.ObservableResponderRequest(integration_id="cx1", responder_id="r1")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.run_observable_responder(
                made["case_id"], "obs_nope", body=body, user=_admin()
            )
        assert ei.value.status_code == 404

    async def test_responder_invalid_tlp_is_400(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        cid, oid = await self._seed_observable(inv_cases, cases)
        registry = _FakeRegistry(config=_FakeConfig(), connector=_FakeCortexConnector())
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        body = inv_cases.ObservableResponderRequest(
            integration_id="cx1", responder_id="r1", tlp="purple",
        )
        with pytest.raises(HTTPException) as ei:
            await inv_cases.run_observable_responder(cid, oid, body=body, user=_admin())
        assert ei.value.status_code == 400

    async def test_responder_cross_tenant_is_404(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        made = await cases.create_case(title="t", actor="a", tenant="evil")
        add = inv_cases.ObservableAddRequest(type="ip", value="1.1.1.1")
        added = await inv_cases.add_case_observable(
            made["case_id"], body=add, user=_admin(tenant="evil")
        )
        registry = _FakeRegistry(config=_FakeConfig(), connector=_FakeCortexConnector())
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        body = inv_cases.ObservableResponderRequest(integration_id="cx1", responder_id="r1")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.run_observable_responder(
                made["case_id"], added["observable"]["observable_id"],
                body=body, user=_admin(tenant="acme"),
            )
        assert ei.value.status_code == 404


# ═══════════════════════════════════════════════════════════════════════
# Phase 2 — observable lookup (OpenCTI threat-intel)
# ═══════════════════════════════════════════════════════════════════════


class TestObservableLookupEndpoint:
    async def _seed_observable(self, inv_cases, cases, otype="ip", value="1.2.3.4"):
        made = await cases.create_case(title="t", actor="a")
        cid = made["case_id"]
        body = inv_cases.ObservableAddRequest(type=otype, value=value)
        added = await inv_cases.add_case_observable(cid, body=body, user=_admin())
        return cid, added["observable"]["observable_id"]

    def _oc_config(self, inv_cases, **kw):
        return _FakeConfig(type="opencti", **kw)

    async def test_lookup_malicious_marks_ioc(self, wired, monkeypatch):
        inv_cases, cases, _, audit = wired
        cid, oid = await self._seed_observable(inv_cases, cases)
        result = {
            "connector": "opencti", "verdict": "malicious", "is_malicious": True,
            "found": True, "score": 85, "indicator_count": 2,
            "labels": ["apt"], "indicators": [],
        }
        connector = _FakeOpenCtiConnector(result=result)
        registry = _FakeRegistry(config=self._oc_config(inv_cases), connector=connector)
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)

        body = inv_cases.ObservableLookupRequest(integration_id="oc1")
        out = await inv_cases.lookup_case_observable(cid, oid, body=body, user=_admin())
        assert out["enrichment"]["verdict"] == "malicious"
        assert out["observable"]["enrichment"]["opencti"]["score"] == 85
        assert out["observable"]["is_ioc"] is True
        # The connector was driven with the observable's type + value.
        assert connector.calls[0]["observable_type"] == "ip"
        assert connector.calls[0]["value"] == "1.2.3.4"
        assert audit.entries[-1]["action"] == "investigation.observable_lookup"

    async def test_lookup_clean_does_not_mark_ioc(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        cid, oid = await self._seed_observable(inv_cases, cases)
        result = {"verdict": "not_found", "is_malicious": False, "found": False}
        connector = _FakeOpenCtiConnector(result=result)
        registry = _FakeRegistry(config=self._oc_config(inv_cases), connector=connector)
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)

        body = inv_cases.ObservableLookupRequest(integration_id="oc1")
        out = await inv_cases.lookup_case_observable(cid, oid, body=body, user=_admin())
        assert out["observable"]["is_ioc"] is False
        # A non-malicious verdict never touches origin risk.
        assert "origin_risk" not in out

    async def test_lookup_malicious_auto_raises_origin(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        made = await cases.create_case(title="t", actor="a")
        cid = made["case_id"]
        add = inv_cases.ObservableAddRequest(type="ip", value="9.9.9.9")
        added = await inv_cases.add_case_observable(cid, body=add, user=_admin())
        oid = added["observable"]["observable_id"]
        await cases.add_subject(
            case_id=cid, subject_type="origin",
            subject_key="session:0123456789abcdef", actor="a",
        )
        connector = _FakeOpenCtiConnector(
            result={"verdict": "malicious", "is_malicious": True, "indicator_count": 1}
        )
        registry = _FakeRegistry(config=self._oc_config(inv_cases), connector=connector)
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        monkeypatch.setattr(inv_cases, "_redis", lambda: _FakeRedis())
        monkeypatch.setattr(inv_cases, "_correlation_enabled", lambda: True)
        monkeypatch.setattr(inv_cases, "_enrich_auto_raise_enabled", lambda: True)

        body = inv_cases.ObservableLookupRequest(integration_id="oc1")
        out = await inv_cases.lookup_case_observable(cid, oid, body=body, user=_admin())
        risk = out["origin_risk"]
        assert len(risk["raised"]) == 1
        assert risk["raised"][0]["new_score"] >= 7.0

    async def test_lookup_observable_missing_is_404(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        made = await cases.create_case(title="t", actor="a")
        registry = _FakeRegistry(
            config=self._oc_config(inv_cases), connector=_FakeOpenCtiConnector()
        )
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        body = inv_cases.ObservableLookupRequest(integration_id="oc1")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.lookup_case_observable(
                made["case_id"], "obs_nope", body=body, user=_admin()
            )
        assert ei.value.status_code == 404

    async def test_lookup_integration_not_found_404(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        cid, oid = await self._seed_observable(inv_cases, cases)
        registry = _FakeRegistry(config=None)
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        body = inv_cases.ObservableLookupRequest(integration_id="nope")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.lookup_case_observable(cid, oid, body=body, user=_admin())
        assert ei.value.status_code == 404

    async def test_lookup_wrong_type_is_400(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        cid, oid = await self._seed_observable(inv_cases, cases)
        registry = _FakeRegistry(config=_FakeConfig(type="cortex"))
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        body = inv_cases.ObservableLookupRequest(integration_id="cx1")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.lookup_case_observable(cid, oid, body=body, user=_admin())
        assert ei.value.status_code == 400

    async def test_lookup_disabled_is_400(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        cid, oid = await self._seed_observable(inv_cases, cases)
        registry = _FakeRegistry(config=self._oc_config(inv_cases, enabled=False))
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        body = inv_cases.ObservableLookupRequest(integration_id="oc1")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.lookup_case_observable(cid, oid, body=body, user=_admin())
        assert ei.value.status_code == 400

    async def test_lookup_not_configured_is_400(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        cid, oid = await self._seed_observable(inv_cases, cases)
        registry = _FakeRegistry(config=self._oc_config(inv_cases), connector=None)
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        body = inv_cases.ObservableLookupRequest(integration_id="oc1")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.lookup_case_observable(cid, oid, body=body, user=_admin())
        assert ei.value.status_code == 400

    async def test_lookup_connector_error_is_502_fail_open(self, wired, monkeypatch):
        inv_cases, cases, _, audit = wired
        from fastapi import HTTPException

        from admin.services.integrations.base import ConnectorError

        cid, oid = await self._seed_observable(inv_cases, cases)
        connector = _FakeOpenCtiConnector(error=ConnectorError("opencti unreachable"))
        registry = _FakeRegistry(config=self._oc_config(inv_cases), connector=connector)
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        body = inv_cases.ObservableLookupRequest(integration_id="oc1")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.lookup_case_observable(cid, oid, body=body, user=_admin())
        assert ei.value.status_code == 502
        # Fail-open: the observable is never mutated on a failed lookup.
        listed = await inv_cases.list_case_observables(cid, user=_admin())
        assert listed["observables"][0]["enrichment"] == {}
        assert listed["observables"][0]["is_ioc"] is False
        assert audit.entries[-1]["action"] == "investigation.observable_lookup_failed"

    async def test_lookup_cross_tenant_is_404(self, wired, monkeypatch):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        made = await cases.create_case(title="t", actor="a", tenant="evil")
        add = inv_cases.ObservableAddRequest(type="ip", value="1.1.1.1")
        added = await inv_cases.add_case_observable(
            made["case_id"], body=add, user=_admin(tenant="evil")
        )
        registry = _FakeRegistry(
            config=self._oc_config(inv_cases), connector=_FakeOpenCtiConnector()
        )
        monkeypatch.setattr(inv_cases, "get_integration_registry", lambda: registry)
        body = inv_cases.ObservableLookupRequest(integration_id="oc1")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.lookup_case_observable(
                made["case_id"], added["observable"]["observable_id"],
                body=body, user=_admin(tenant="acme"),
            )
        assert ei.value.status_code == 404


class TestTaskEndpoints:
    async def test_add_list_progress(self, wired):
        inv_cases, cases, _, audit = wired
        made = await cases.create_case(title="t", actor="a")
        cid = made["case_id"]
        body = inv_cases.TaskAddRequest(title="Contain host")
        added = await inv_cases.add_case_task(cid, body=body, user=_admin())
        assert added["task"]["title"] == "Contain host"
        assert audit.entries[-1]["action"] == "investigation.task_add"

        out = await inv_cases.list_case_tasks(cid, user=_admin())
        assert out["count"] == 1
        assert out["progress"] == {"total": 1, "done": 0, "open": 1}
        assert out["can_write"] is True

    async def test_state_transition(self, wired):
        inv_cases, cases, _, _ = wired
        made = await cases.create_case(title="t", actor="a")
        cid = made["case_id"]
        added = await inv_cases.add_case_task(
            cid, body=inv_cases.TaskAddRequest(title="t"), user=_admin()
        )
        tid = added["task"]["task_id"]
        body = inv_cases.TaskStateRequest(status="done")
        out = await inv_cases.set_case_task_state(cid, tid, body=body, user=_admin())
        assert out["task"]["status"] == "done"
        prog = (await inv_cases.list_case_tasks(cid, user=_admin()))["progress"]
        assert prog["done"] == 1

    async def test_state_empty_body_is_400(self, wired):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        made = await cases.create_case(title="t", actor="a")
        cid = made["case_id"]
        added = await inv_cases.add_case_task(
            cid, body=inv_cases.TaskAddRequest(title="t"), user=_admin()
        )
        with pytest.raises(HTTPException) as ei:
            await inv_cases.set_case_task_state(
                cid, added["task"]["task_id"], body=inv_cases.TaskStateRequest(),
                user=_admin(),
            )
        assert ei.value.status_code == 400

    async def test_state_missing_task_is_404(self, wired):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        made = await cases.create_case(title="t", actor="a")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.set_case_task_state(
                made["case_id"], "task_nope",
                body=inv_cases.TaskStateRequest(status="done"), user=_admin(),
            )
        assert ei.value.status_code == 404

    async def test_note_and_remove(self, wired):
        inv_cases, cases, _, _ = wired
        made = await cases.create_case(title="t", actor="a")
        cid = made["case_id"]
        added = await inv_cases.add_case_task(
            cid, body=inv_cases.TaskAddRequest(title="t"), user=_admin()
        )
        tid = added["task"]["task_id"]
        noted = await inv_cases.add_case_task_note(
            cid, tid, body=inv_cases.TaskNoteRequest(text="hello"), user=_admin()
        )
        assert any(n["text"] == "hello" for n in noted["task"]["notes"])
        out = await inv_cases.remove_case_task(cid, tid, user=_admin())
        assert out["message"] == "Task removed"

    async def test_add_cross_tenant_is_404(self, wired):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        made = await cases.create_case(title="t", actor="a", tenant="evil")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.add_case_task(
                made["case_id"], body=inv_cases.TaskAddRequest(title="x"),
                user=_admin(tenant="acme"),
            )
        assert ei.value.status_code == 404


# ═══════════════════════════════════════════════════════════════════════
# Phase 0 — case tags + manual timeline endpoints
# ═══════════════════════════════════════════════════════════════════════


class TestCaseTagsAndTimelineEndpoints:
    async def test_set_tags(self, wired):
        inv_cases, cases, _, audit = wired
        made = await cases.create_case(title="t", actor="a")
        body = inv_cases.CaseTagsRequest(tags=["APT29", "apt29", " C2 "])
        out = await inv_cases.set_case_tags(made["case_id"], body=body, user=_admin())
        # normalised + deduped by the store.
        assert out["case"]["tags"] == ["apt29", "c2"]
        assert audit.entries[-1]["action"] == "investigation.case_tags"

    async def test_set_tags_cross_tenant_is_404(self, wired):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        made = await cases.create_case(title="t", actor="a", tenant="evil")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.set_case_tags(
                made["case_id"], body=inv_cases.CaseTagsRequest(tags=["x"]),
                user=_admin(tenant="acme"),
            )
        assert ei.value.status_code == 404

    async def test_add_manual_timeline_entry(self, wired):
        inv_cases, cases, _, audit = wired
        made = await cases.create_case(title="t", actor="a")
        body = inv_cases.CaseTimelineEntryRequest(
            text="attacker pivoted", event_ts="2025-01-02T03:04:05+00:00",
        )
        out = await inv_cases.add_case_timeline_entry(
            made["case_id"], body=body, user=_admin()
        )
        assert any(
            n.get("kind") == "timeline" and n.get("text") == "attacker pivoted"
            for n in out["case"]["notes"]
        )
        assert audit.entries[-1]["action"] == "investigation.case_timeline_entry"

    async def test_timeline_entry_bad_event_ts_is_400(self, wired):
        inv_cases, cases, _, _ = wired
        from fastapi import HTTPException

        made = await cases.create_case(title="t", actor="a")
        body = inv_cases.CaseTimelineEntryRequest(text="x", event_ts="not-a-date")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.add_case_timeline_entry(
                made["case_id"], body=body, user=_admin()
            )
        assert ei.value.status_code == 400

    async def test_manual_entry_surfaces_in_reconstructed_timeline(self, wired):
        inv_cases, cases, _, _ = wired
        made = await cases.create_case(title="t", actor="a")
        cid = made["case_id"]
        await inv_cases.add_case_timeline_entry(
            cid,
            body=inv_cases.CaseTimelineEntryRequest(
                text="observed beacon", event_ts="2025-06-01T00:00:00+00:00"
            ),
            user=_admin(),
        )
        tl = await inv_cases.case_timeline(cid, user=_admin(), limit=500)
        assert any(
            e["type"] == "note" and e.get("note_kind") == "timeline"
            and e["text"] == "observed beacon"
            for e in tl["timeline"]
        )


# ═══════════════════════════════════════════════════════════════════════
# Phase 0 — case templates
# ═══════════════════════════════════════════════════════════════════════


class TestCaseTemplates:
    @pytest.fixture
    def templates_dir(self, tmp_path, monkeypatch):
        from admin.services import investigation_templates as tmpl_mod

        d = tmp_path / "templates"
        d.mkdir()
        (d / "exfil.yaml").write_text(
            "id: exfil\n"
            "name: Data Exfiltration\n"
            "description: standard exfil response\n"
            "severity: high\n"
            "summary: suspected data exfiltration\n"
            "tags: [exfiltration, dlp]\n"
            "tasks:\n"
            "  - title: Identify scope\n"
            "  - title: Contain\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(tmpl_mod, "TEMPLATES_DIR", d)
        monkeypatch.setattr(tmpl_mod, "_cache", {})
        return d

    async def test_list_templates_endpoint(self, wired, templates_dir):
        inv_cases, _, _, _ = wired
        out = await inv_cases.list_case_templates(user=_admin())
        ids = [t["id"] for t in out["templates"]]
        assert "exfil" in ids

    async def test_create_with_template_seeds_defaults(self, wired, templates_dir):
        inv_cases, _, _, _ = wired
        body = inv_cases.CaseCreateRequest(title="IR-1", template_id="exfil")
        out = await inv_cases.create_case(body=body, user=_admin())
        case = out["case"]
        # severity + summary + tags seeded from the template.
        assert case["severity"] == "high"
        assert case["summary"] == "suspected data exfiltration"
        assert case["tags"] == ["exfiltration", "dlp"]
        # tasks seeded onto the case's task list.
        tasks = await inv_cases.list_case_tasks(case["case_id"], user=_admin())
        assert [t["title"] for t in tasks["tasks"]] == ["Identify scope", "Contain"]

    async def test_create_explicit_severity_overrides_template(self, wired, templates_dir):
        inv_cases, _, _, _ = wired
        body = inv_cases.CaseCreateRequest(
            title="IR-2", template_id="exfil", severity="critical",
        )
        out = await inv_cases.create_case(body=body, user=_admin())
        assert out["case"]["severity"] == "critical"

    async def test_create_unknown_template_is_400(self, wired, templates_dir):
        inv_cases, _, _, _ = wired
        from fastapi import HTTPException

        body = inv_cases.CaseCreateRequest(title="IR-3", template_id="nope")
        with pytest.raises(HTTPException) as ei:
            await inv_cases.create_case(body=body, user=_admin())
        assert ei.value.status_code == 400


# ═══════════════════════════════════════════════════════════════════════
# Per-operator rate limit on the external-TI endpoints (enrich/lookup/respond)
# ═══════════════════════════════════════════════════════════════════════


def _sa_token(account_id="abc123"):
    """A service-account TokenPayload (the shape ``require_permission_automation``
    mints — ``sub='service-account:<id>'``, lowest role)."""
    now = datetime.now(timezone.utc)
    return TokenPayload(
        sub=f"service-account:{account_id}", role=UserRole.VIEWER,
        exp=now + timedelta(minutes=1), iat=now,
    )


class TestSessionToolRateLimit:
    """The enrich/lookup/respond dependency (`_require_tool_call`) caps operator
    sessions per-minute while letting already-throttled service-account keys pass."""

    async def test_operator_capped_after_budget(self, wired, monkeypatch):
        inv_cases, _, _, audit = wired
        from fastapi import HTTPException

        from admin.services import automation_rate_limit as arl

        # Force the in-memory window (no Redis) for a deterministic budget, and use
        # a fresh limiter so no other test's hits bleed into this one.
        monkeypatch.setattr(arl, "get_redis_client", lambda *a, **k: None)
        limiter = arl.AutomationRateLimiter()
        monkeypatch.setattr(arl, "get_automation_rate_limiter", lambda: limiter)
        monkeypatch.setattr(inv_cases, "_session_tool_rpm", lambda: 2)

        dep = inv_cases._require_tool_call("investigation:write")
        # The first two operator calls consume the budget...
        assert (await dep(case_id="case_1", user=_admin())).sub == "admin-user"
        assert (await dep(case_id="case_1", user=_admin())).sub == "admin-user"
        # ...the third is throttled with a 429 + Retry-After + an audit record.
        with pytest.raises(HTTPException) as ei:
            await dep(case_id="case_1", user=_admin())
        assert ei.value.status_code == 429
        assert ei.value.headers["Retry-After"] == "60"
        assert audit.entries[-1]["action"] == "investigation.tool_call_rate_limited"
        assert audit.entries[-1]["resource_id"] == "case_1"

    async def test_operator_budget_is_per_user(self, wired, monkeypatch):
        inv_cases, _, _, _ = wired
        from admin.services import automation_rate_limit as arl

        monkeypatch.setattr(arl, "get_redis_client", lambda *a, **k: None)
        limiter = arl.AutomationRateLimiter()
        monkeypatch.setattr(arl, "get_automation_rate_limiter", lambda: limiter)
        monkeypatch.setattr(inv_cases, "_session_tool_rpm", lambda: 1)

        dep = inv_cases._require_tool_call("investigation:write")
        # Two different operators each get their own window (distinct sub).
        assert (await dep(case_id="c", user=_token(UserRole.ADMIN))).role == UserRole.ADMIN
        assert (await dep(case_id="c", user=_token(UserRole.SECURITY))).role == UserRole.SECURITY

    async def test_service_account_bypasses_operator_cap(self, wired, monkeypatch):
        inv_cases, _, _, _ = wired
        from admin.services import automation_rate_limit as arl

        class _DenyAll:
            def consume(self, *a, **k):  # pragma: no cover - must never be reached
                raise AssertionError("service-account must not hit the operator budget")

        monkeypatch.setattr(arl, "get_automation_rate_limiter", lambda: _DenyAll())
        monkeypatch.setattr(inv_cases, "_session_tool_rpm", lambda: 1)

        dep = inv_cases._require_tool_call("investigation:write")
        # A service-account key (already per-key throttled upstream) passes through
        # without ever consulting the operator budget.
        out = await dep(case_id="case_1", user=_sa_token())
        assert out.sub == "service-account:abc123"

    async def test_disabled_budget_allows_all(self, wired, monkeypatch):
        inv_cases, _, _, _ = wired
        from admin.services import automation_rate_limit as arl

        monkeypatch.setattr(arl, "get_redis_client", lambda *a, **k: None)
        limiter = arl.AutomationRateLimiter()
        monkeypatch.setattr(arl, "get_automation_rate_limiter", lambda: limiter)
        # rpm <= 0 disables the operator cap entirely.
        monkeypatch.setattr(inv_cases, "_session_tool_rpm", lambda: 0)

        dep = inv_cases._require_tool_call("investigation:write")
        for _ in range(5):
            assert (await dep(case_id="c", user=_admin())).sub == "admin-user"

    def test_session_tool_rpm_reads_setting(self, monkeypatch):
        import admin.routes.investigation_cases as inv_cases
        from src.config import settings

        monkeypatch.setattr(settings, "investigation_session_tool_rpm", 42)
        assert inv_cases._session_tool_rpm() == 42
