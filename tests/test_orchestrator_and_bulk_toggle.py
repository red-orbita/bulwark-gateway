"""Tests for the guardrail bulk-toggle endpoint and the orchestrator task runner.

These are lightweight route tests: a minimal FastAPI app mounts the real routers
and overrides ``get_current_user`` so we exercise the endpoint logic (RBAC,
validation, state mutation, task lifecycle) without the full admin app / DB.
"""

from __future__ import annotations

import os

# Must be set before importing admin modules (config validates JWT secret length).
os.environ.setdefault("ADMIN_DEBUG", "true")
os.environ.setdefault(
    "ADMIN_JWT_SECRET", "test-secret-that-is-at-least-32-characters-long-xx"
)
os.environ.setdefault(
    "BULWARK_JWT_SECRET", "test-secret-that-is-at-least-32-characters-long-xx"
)

import time  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from admin.models.auth import TokenPayload, UserRole  # noqa: E402
from admin.routes import guardrails as guardrails_route  # noqa: E402
from admin.routes import validate as validate_route  # noqa: E402
from admin.services.auth_service import get_current_user  # noqa: E402

# ruff: noqa: I001 - imports intentionally follow required env setup above


# --------------------------------------------------------------------------- #
# Fakes                                                                        #
# --------------------------------------------------------------------------- #


class _FakeAudit:
    """Records audit calls instead of persisting them.

    Mirrors the real AuditLogger contract: ``details`` must be a ``str`` (it is
    hash-chained via ``"||".join(...)``), so passing a dict is rejected here the
    same way it would blow up in production.
    """

    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def log(self, **kwargs) -> None:
        details = kwargs.get("details")
        if details is not None and not isinstance(details, str):
            raise TypeError(
                f"audit details must be str, got {type(details).__name__}"
            )
        self.calls.append(kwargs)


class _FakeStore:
    def __init__(self) -> None:
        self.saved = 0

    def save_state(self) -> None:
        self.saved += 1


def _token(role: UserRole = UserRole.ADMIN) -> TokenPayload:
    now = datetime.now(timezone.utc)
    return TokenPayload(
        sub="tester",
        role=role,
        exp=now + timedelta(hours=1),
        iat=now,
    )


# --------------------------------------------------------------------------- #
# Fixtures                                                                     #
# --------------------------------------------------------------------------- #


@pytest.fixture
def role_holder() -> dict:
    """Mutable container so individual tests can flip the acting user's role."""
    return {"role": UserRole.ADMIN}


@pytest.fixture
def guardrails_client(monkeypatch, role_holder):
    fake_audit = _FakeAudit()
    fake_store = _FakeStore()

    monkeypatch.setattr(guardrails_route, "get_audit_logger", lambda: fake_audit)
    monkeypatch.setattr(guardrails_route, "get_guardrails_store", lambda: fake_store)
    # Avoid writing to /app/data during tests.
    monkeypatch.setattr(guardrails_route, "_save_persisted_state", lambda: None)

    # Reset module state to a known baseline (module-level global).
    guardrails_route._module_state.clear()
    guardrails_route._module_state.update(
        {"input": True, "tool_policy": True, "output": True}
    )

    app = FastAPI()
    app.include_router(guardrails_route.router, prefix="/admin/guardrails")
    app.dependency_overrides[get_current_user] = lambda: _token(role_holder["role"])

    client = TestClient(app)
    client.fake_audit = fake_audit  # type: ignore[attr-defined]
    client.fake_store = fake_store  # type: ignore[attr-defined]
    return client


@pytest.fixture
def validate_client(monkeypatch, role_holder):
    fake_audit = _FakeAudit()
    monkeypatch.setattr(validate_route, "get_audit_logger", lambda: fake_audit)

    validate_route._TASKS.clear()

    app = FastAPI()
    app.include_router(validate_route.router, prefix="/admin/validate")
    app.dependency_overrides[get_current_user] = lambda: _token(role_holder["role"])

    client = TestClient(app)
    client.fake_audit = fake_audit  # type: ignore[attr-defined]
    return client


# --------------------------------------------------------------------------- #
# bulk-toggle                                                                  #
# --------------------------------------------------------------------------- #


def test_bulk_toggle_enables_and_disables(guardrails_client):
    resp = guardrails_client.post(
        "/admin/guardrails/bulk-toggle",
        json={"enable": ["input"], "disable": ["output"]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["module_state"]["input"] is True
    assert body["module_state"]["output"] is False
    assert "input" in body["enabled"]
    assert "output" in body["disabled"]
    # Audit fired once per applied module.
    assert len(guardrails_client.fake_audit.calls) == 2
    assert guardrails_client.fake_store.saved >= 1


def test_bulk_toggle_disable_overrides_enable(guardrails_client):
    """An id present in both lists must end up disabled (fail-closed)."""
    resp = guardrails_client.post(
        "/admin/guardrails/bulk-toggle",
        json={"enable": ["tool_policy"], "disable": ["tool_policy"]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["module_state"]["tool_policy"] is False
    assert "tool_policy" in body["disabled"]
    assert "tool_policy" not in body["enabled"]


def test_bulk_toggle_logical_ids_do_not_collapse_engine_phases(guardrails_client):
    """Disabling a high-level UI id must not switch off an engine phase."""
    resp = guardrails_client.post(
        "/admin/guardrails/bulk-toggle",
        json={"disable": ["prompt_injection", "output_filter"]},
    )
    assert resp.status_code == 200
    body = resp.json()
    # Engine phases remain enabled.
    assert body["module_state"]["input"] is True
    assert body["module_state"]["output"] is True
    # Logical ids are recorded as their own (disabled) intent.
    assert body["module_state"]["prompt_injection"] is False
    assert body["module_state"]["output_filter"] is False
    assert set(body["disabled"]) == {"prompt_injection", "output_filter"}


def test_bulk_toggle_invalid_body_rejected(guardrails_client):
    resp = guardrails_client.post(
        "/admin/guardrails/bulk-toggle",
        json={"disable": "output"},  # not a list
    )
    assert resp.status_code == 400


def test_bulk_toggle_dedups_repeated_ids(guardrails_client):
    resp = guardrails_client.post(
        "/admin/guardrails/bulk-toggle",
        json={"enable": ["input", "input", "input"]},
    )
    assert resp.status_code == 200
    assert resp.json()["enabled"].count("input") == 1


def test_bulk_toggle_requires_write_permission(guardrails_client, role_holder):
    role_holder["role"] = UserRole.VIEWER  # lacks guardrails:write
    resp = guardrails_client.post(
        "/admin/guardrails/bulk-toggle",
        json={"disable": ["output"]},
    )
    assert resp.status_code == 403


# --------------------------------------------------------------------------- #
# orchestrator task runner                                                     #
# --------------------------------------------------------------------------- #


def test_trigger_unknown_task_returns_404(validate_client):
    resp = validate_client.post("/admin/validate/trigger/does-not-exist")
    assert resp.status_code == 404


def test_get_unknown_task_returns_404(validate_client):
    resp = validate_client.get("/admin/validate/task/nope-123")
    assert resp.status_code == 404


def test_trigger_requires_test_permission(validate_client, role_holder):
    role_holder["role"] = UserRole.VIEWER  # lacks guardrails:test
    resp = validate_client.post("/admin/validate/trigger/qa-validation")
    assert resp.status_code == 403


def test_trigger_and_poll_completes(monkeypatch, validate_client):
    """End-to-end: trigger a task backed by a fast fake runner, then poll it."""

    async def _fast_runner() -> dict:
        return {
            "status": "pass",
            "passed": 3,
            "failed": 0,
            "total": 3,
            "results": [{"name": "x", "pass": True, "expected": "a", "actual": "a"}],
        }

    monkeypatch.setitem(
        validate_route._TASK_RUNNERS,
        "qa-validation",
        ("QA Validation", _fast_runner),
    )

    resp = validate_client.post("/admin/validate/trigger/qa-validation")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "running"
    task_id = body["task_id"]
    assert task_id.startswith("qa-validation-")

    # Audit recorded the trigger.
    assert any(
        c.get("action") == "orchestrator_trigger"
        for c in validate_client.fake_audit.calls
    )

    # Poll until the background task finishes.
    final = None
    for _ in range(40):
        poll = validate_client.get(f"/admin/validate/task/{task_id}")
        assert poll.status_code == 200
        final = poll.json()
        if final["status"] in ("completed", "failed"):
            break
        time.sleep(0.05)

    assert final is not None
    assert final["status"] == "completed"
    assert "QA Validation: PASS" in final["output"]
    assert "3/3 passed" in final["output"]


def test_trigger_reports_runner_failure(monkeypatch, validate_client):
    async def _boom() -> dict:
        raise RuntimeError("kaboom")

    monkeypatch.setitem(
        validate_route._TASK_RUNNERS,
        "redteam-audit",
        ("Red Team Audit", _boom),
    )

    resp = validate_client.post("/admin/validate/trigger/redteam-audit")
    assert resp.status_code == 200
    task_id = resp.json()["task_id"]

    final = None
    for _ in range(40):
        final = validate_client.get(f"/admin/validate/task/{task_id}").json()
        if final["status"] in ("completed", "failed"):
            break
        time.sleep(0.05)

    assert final is not None
    assert final["status"] == "failed"
    assert "kaboom" in final["output"]
    assert final["error"] == "kaboom"


def test_task_registry_is_bounded():
    """The in-memory registry must evict oldest entries past the cap."""
    validate_route._TASKS.clear()
    try:
        for i in range(validate_route._MAX_TASKS + 25):
            validate_route._TASKS[f"t-{i}"] = {"task_id": f"t-{i}"}
            validate_route._prune_tasks()
        assert len(validate_route._TASKS) == validate_route._MAX_TASKS
        # Oldest evicted, newest retained.
        assert "t-0" not in validate_route._TASKS
        assert f"t-{validate_route._MAX_TASKS + 24}" in validate_route._TASKS
    finally:
        validate_route._TASKS.clear()


# --------------------------------------------------------------------------- #
# _format_output unit tests                                                    #
# --------------------------------------------------------------------------- #


def test_format_output_qa_validation():
    out = validate_route._format_output(
        "qa-validation",
        {
            "status": "pass",
            "passed": 2,
            "failed": 1,
            "total": 3,
            "results": [
                {"name": "ok", "pass": True, "expected": "allow", "actual": "allow"},
                {"name": "bad", "pass": False, "expected": "block", "actual": "allow"},
            ],
        },
    )
    assert "QA Validation: PASS" in out
    assert "2/3 passed, 1 failed" in out
    assert "[PASS] ok" in out
    assert "[FAIL] bad" in out


def test_format_output_benchmark():
    out = validate_route._format_output(
        "performance-benchmark",
        {
            "status": "fail",
            "target_p95_ms": 40,
            "iterations": 100,
            "p50_ms": 5,
            "p95_ms": 273,
            "p99_ms": 400,
            "max_ms": 500,
            "avg_ms": 12,
        },
    )
    assert "Benchmark: FAIL" in out
    assert "target p95 < 40ms" in out
    assert "p95=273ms" in out


def test_format_output_redteam():
    out = validate_route._format_output(
        "redteam-audit",
        {
            "detected": 19,
            "total_attacks": 20,
            "detection_rate": 0.95,
            "bypass_rate": 0.05,
            "false_positive_rate": 0.0,
            "categories": [
                {"name": "prompt_injection", "detected": 5, "total": 5, "rate": 1.0},
            ],
        },
    )
    assert "19/20 attacks detected" in out
    assert "detection=95.0%" in out
    assert "prompt_injection: 5/5" in out
