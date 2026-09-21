"""Task due dates have the same validated contract on SQLite and PostgreSQL."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import HTTPException

from admin.services import investigation_task_store as task_module
from src.storage.database import create_engine
from tests.test_storage_database_live import local_pg  # noqa: F401 - owned TLS lab fixture


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Do not access the operator's user database."""


INVALID_DUE = [
    "2026-09-13",  # No invented end-of-day or timezone for date-only input.
    "2026-09-13T10:20:30",
    "2026-09-13 10:20:30",
    "2026-02-30T10:20:30Z",
    "2026-09-13T10:20:30+01:60",
    "2026-09-13T10:20:30+24:00",
    "2026-09-13T10:20:30.1234567Z",
    "0001-01-01T00:00:00+01:00",  # UTC conversion underflow.
    "now",
    "PRIVATE_DUE_SECRET",
    "x" * 65,
]
ERROR = "due_at must be an ISO-8601 datetime with an explicit timezone offset"


@pytest.mark.parametrize("operation", ["add", "set_state"])
@pytest.mark.parametrize("due", INVALID_DUE + [123, False])
async def test_invalid_due_rejected_before_any_store_db_access(monkeypatch, operation, due):
    get_db = Mock(side_effect=AssertionError("must validate before any DB read or write"))
    monkeypatch.setattr(task_module, "get_database", get_db)
    store = task_module.TaskStore()
    kwargs = {"case_id": "case", "actor": "analyst", "due_at": due}
    kwargs.update({"title": "Collect evidence"} if operation == "add" else {"task_id": "task", "status": "done"})
    with pytest.raises(ValueError, match="^" + ERROR + "$") as error:
        await getattr(store, operation)(**kwargs)
    assert error.value.__suppress_context__
    get_db.assert_not_called()


@pytest.mark.parametrize("operation", ["add", "set_state"])
@pytest.mark.parametrize("due", INVALID_DUE[:-1])
async def test_routes_map_invalid_due_to_400_without_task_access(monkeypatch, operation, due):
    from admin.routes import investigation_cases as routes

    monkeypatch.setattr(routes, "_get_case_scoped", AsyncMock(return_value={"case_id": "case"}))
    monkeypatch.setattr(routes, "get_task_store", task_module.TaskStore)
    get_db = Mock(side_effect=AssertionError("task DB must not be accessed"))
    audit = Mock()
    monkeypatch.setattr(task_module, "get_database", get_db)
    monkeypatch.setattr(routes, "get_audit_logger", audit)
    with pytest.raises(HTTPException) as error:
        if operation == "add":
            await routes.add_case_task("case", routes.TaskAddRequest(title="Task", due_at=due),
                                       user=SimpleNamespace(sub="analyst"))
        else:
            await routes.set_case_task_state("case", "task", routes.TaskStateRequest(status="done", due_at=due),
                                             user=SimpleNamespace(sub="analyst"))
    assert error.value.status_code == 400
    assert error.value.detail == ERROR
    get_db.assert_not_called()
    audit.assert_not_called()


@pytest.fixture(params=["sqlite", "postgresql"])
def engine(request, tmp_path):
    if request.param == "postgresql":
        factory, _ = request.getfixturevalue("local_pg")
        return factory()
    return create_engine(f"sqlite:///{tmp_path / 'tasks.db'}")


@pytest.fixture
async def task_case(engine, monkeypatch):
    from admin.services import investigation_case_store as case_module
    from admin.services.migrations import run_migrations

    await engine.init()
    try:
        await run_migrations(engine)
        monkeypatch.setattr(task_module, "get_database", lambda: engine)
        monkeypatch.setattr(case_module, "get_database", lambda: engine)
        case = await case_module.CaseStore().create_case(title="Due date parity", actor="analyst")
        yield task_module.TaskStore(), case["case_id"]
    finally:
        await engine.close()


@pytest.mark.parametrize("due,expected", [
    ("2026-09-13T10:20:30Z", "2026-09-13T10:20:30+00:00"),
    ("2026-09-13T10:20:30.123456+05:30", "2026-09-13T04:50:30.123456+00:00"),
    (" 2026-09-13 10:20:30-03:00 ", "2026-09-13T13:20:30+00:00"),
    ("2026-09-13T10:20:30.5+01:00:30", "2026-09-13T09:20:00.500000+00:00"),
])
async def test_create_update_and_equivalent_instant_are_backend_agnostic(task_case, due, expected):
    store, cid = task_case
    created = await store.add(case_id=cid, title="Collect evidence", actor="a", due_at=due)
    assert created["due_at"] == expected
    updated = await store.set_state(case_id=cid, task_id=created["task_id"], actor="a", due_at=expected)
    assert updated["due_at"] == expected
    assert updated["notes"] == []  # Same instant, no spurious due-date action.
    updated = await store.set_state(case_id=cid, task_id=created["task_id"], actor="a",
                                   due_at="2027-01-01T01:00:00+01:00")
    assert updated["due_at"] == "2027-01-01T00:00:00+00:00"
    assert len(updated["notes"]) == 1
    assert "2027-01-01T00:00:00+00:00" in updated["notes"][0]["text"]
    assert (await store.get(cid, created["task_id"]))["due_at"] == updated["due_at"]


@pytest.mark.parametrize("empty", [None, "", " \t "])
async def test_null_unchanged_and_empty_clear_semantics(task_case, empty):
    store, cid = task_case
    created = await store.add(case_id=cid, title="Task", actor="a", due_at=empty)
    assert created["due_at"] is None
    tid = created["task_id"]
    due = "2026-09-13T10:20:30+00:00"
    await store.set_state(case_id=cid, task_id=tid, actor="a", due_at=due)
    updated = await store.set_state(case_id=cid, task_id=tid, actor="a", status="done", due_at=empty)
    assert updated["due_at"] == (due if empty is None else None)
    assert updated["status"] == "done"
    omitted = await store.set_state(case_id=cid, task_id=tid, actor="a", assignee="analyst")
    assert omitted["due_at"] == updated["due_at"]


async def test_invalid_mutation_is_atomic_on_both_backends(task_case):
    store, cid = task_case
    created = await store.add(case_id=cid, title="Task", actor="a", due_at="2026-09-13T10:20:30Z")
    for due in INVALID_DUE:
        with pytest.raises(ValueError, match="^" + ERROR + "$"):
            await store.add(case_id=cid, title="Rejected", actor="a", due_at=due)
        with pytest.raises(ValueError, match="^" + ERROR + "$"):
            await store.set_state(case_id=cid, task_id=created["task_id"], actor="a",
                                  status="done", assignee="other", due_at=due)
    assert await store.list_for_case(cid) == [created]


async def test_route_clear_and_null_semantics(task_case, monkeypatch):
    from admin.routes import investigation_cases as routes

    store, cid = task_case
    monkeypatch.setattr(routes, "get_task_store", lambda: store)
    monkeypatch.setattr(routes, "_get_case_scoped", AsyncMock(return_value={"case_id": cid}))
    monkeypatch.setattr(routes, "get_audit_logger", lambda: SimpleNamespace(log=AsyncMock()))
    user = SimpleNamespace(sub="analyst")
    added = await routes.add_case_task(cid, routes.TaskAddRequest(title="Task", due_at="2026-09-13T10:20:30Z"), user)
    tid = added["task"]["task_id"]
    with pytest.raises(HTTPException) as error:
        await routes.set_case_task_state(cid, tid, routes.TaskStateRequest(due_at=None), user)
    assert error.value.status_code == 400  # Existing no-op request behavior.
    updated = await routes.set_case_task_state(cid, tid, routes.TaskStateRequest(status="done", due_at=None), user)
    assert updated["task"]["due_at"] == "2026-09-13T10:20:30+00:00"
    cleared = await routes.set_case_task_state(cid, tid, routes.TaskStateRequest(due_at=""), user)
    assert cleared["task"]["due_at"] is None
