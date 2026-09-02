"""Tests for the inbound automation idempotency layer (Phase 3.2b).

Two units:

* :class:`IdempotencyStore` — cache roundtrip, TTL expiry, per-credential /
  per-endpoint scope isolation, oversized-body skip, empty-key no-op and the
  fail-open contract; and
* the ``automation_idempotency`` ASGI middleware — a repeated service-account
  ``Idempotency-Key`` replays the stored response (without re-executing the
  handler) and is stamped ``Idempotency-Replay: true``, while a fresh key, a
  missing key, a non-2xx response and a non-service-account caller all bypass the
  cache. Plus the ``_is_service_account_request`` CSRF-exemption helper.
"""

from __future__ import annotations

import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request

# ─── shared fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
async def engine(tmp_path):
    from admin.services.database import create_engine
    from admin.services.migrations import run_migrations

    eng = create_engine(f"sqlite:///{tmp_path / 'idem_test.db'}")
    await eng.init()
    await run_migrations(eng)
    try:
        yield eng
    finally:
        await eng.close()


@pytest.fixture
def patched_db(engine, monkeypatch):
    """Point the idempotency store at the throwaway migrated engine."""
    from admin.services import idempotency_store as mod

    monkeypatch.setattr(mod, "get_database", lambda: engine)
    return engine


# ═══════════════════════════════════════════════════════════════════════════
# IdempotencyStore
# ═══════════════════════════════════════════════════════════════════════════


class TestIdempotencyStore:
    async def test_put_then_get_roundtrip(self, patched_db):
        from admin.services.idempotency_store import IdempotencyStore

        store = IdempotencyStore()
        assert await store.get("scope-a", "POST", "/p", "k1") is None
        assert await store.put("scope-a", "POST", "/p", "k1", 201, '{"ok":true}') is True
        cached = await store.get("scope-a", "POST", "/p", "k1")
        assert cached == {"status_code": 201, "response_body": '{"ok":true}'}

    async def test_scope_isolates_callers(self, patched_db):
        from admin.services.idempotency_store import IdempotencyStore

        store = IdempotencyStore()
        await store.put("scope-a", "POST", "/p", "k1", 200, "A")
        # Same key, different credential scope → independent (no cross-caller replay).
        assert await store.get("scope-b", "POST", "/p", "k1") is None

    async def test_method_and_path_isolate(self, patched_db):
        from admin.services.idempotency_store import IdempotencyStore

        store = IdempotencyStore()
        await store.put("s", "POST", "/p", "k1", 200, "A")
        assert await store.get("s", "PUT", "/p", "k1") is None
        assert await store.get("s", "POST", "/other", "k1") is None

    async def test_ttl_expiry_is_a_miss(self, patched_db):
        from admin.services.idempotency_store import IdempotencyStore

        store = IdempotencyStore()
        await store.put("s", "POST", "/p", "k1", 200, "A", ttl_seconds=1)
        # Force the row to be already expired.
        await patched_db.execute(
            "UPDATE automation_idempotency SET expires_at = ? WHERE idem_key = ?",
            [time.time() - 10, "k1"],
        )
        assert await store.get("s", "POST", "/p", "k1") is None

    async def test_prune_removes_expired_on_put(self, patched_db):
        from admin.services.idempotency_store import IdempotencyStore

        store = IdempotencyStore()
        await store.put("s", "POST", "/p", "old", 200, "A")
        await patched_db.execute(
            "UPDATE automation_idempotency SET expires_at = ? WHERE idem_key = ?",
            [time.time() - 10, "old"],
        )
        # A later put opportunistically prunes the expired row.
        await store.put("s", "POST", "/p", "new", 200, "B")
        row = await patched_db.fetch_one(
            "SELECT COUNT(*) AS c FROM automation_idempotency WHERE idem_key = ?", ["old"]
        )
        assert row.to_dict()["c"] == 0

    async def test_oversized_body_not_cached(self, patched_db):
        from admin.services.idempotency_store import IdempotencyStore

        store = IdempotencyStore()
        big = "x" * (256 * 1024 + 1)
        assert await store.put("s", "POST", "/p", "k1", 200, big) is False
        assert await store.get("s", "POST", "/p", "k1") is None

    async def test_empty_key_is_noop(self, patched_db):
        from admin.services.idempotency_store import IdempotencyStore

        store = IdempotencyStore()
        assert await store.put("s", "POST", "/p", "", 200, "A") is False
        assert await store.get("s", "POST", "/p", "") is None

    async def test_get_fail_open_on_db_error(self, monkeypatch):
        from admin.services import idempotency_store as mod
        from admin.services.idempotency_store import IdempotencyStore

        def boom():
            raise RuntimeError("db down")

        monkeypatch.setattr(mod, "get_database", boom)
        # Fail-open: a storage error degrades to "no cache", never raises.
        assert await IdempotencyStore().get("s", "POST", "/p", "k1") is None
        assert await IdempotencyStore().put("s", "POST", "/p", "k1", 200, "A") is False


class TestCallerScope:
    def test_scope_hashes_credential_and_never_stores_raw(self):
        from admin.services.idempotency_store import caller_scope

        header = "Bearer bwk_sa_deadbeef"
        scope = caller_scope(header)
        assert scope != header
        assert len(scope) == 64  # sha256 hex
        assert caller_scope(header) == scope  # deterministic

    def test_absent_header_collapses_to_anon(self):
        from admin.services.idempotency_store import caller_scope

        assert caller_scope(None) == "anon"
        assert caller_scope("") == "anon"


# ═══════════════════════════════════════════════════════════════════════════
# _is_service_account_request helper (CSRF exemption)
# ═══════════════════════════════════════════════════════════════════════════


def _request_with_auth(auth: str | None) -> Request:
    headers = [(b"authorization", auth.encode())] if auth is not None else []
    return Request({"type": "http", "headers": headers, "query_string": b""})


class TestServiceAccountRequestHelper:
    def test_true_only_for_service_account_bearer(self):
        from admin.main import _is_service_account_request

        assert _is_service_account_request(_request_with_auth("Bearer bwk_sa_abc")) is True

    def test_false_for_session_and_other_bearers(self):
        from admin.main import _is_service_account_request

        assert _is_service_account_request(_request_with_auth(None)) is False
        assert _is_service_account_request(_request_with_auth("Bearer eyJ.jwt.tok")) is False
        assert _is_service_account_request(_request_with_auth("Bearer bwk_vk_other")) is False


# ═══════════════════════════════════════════════════════════════════════════
# automation_idempotency middleware (end-to-end via a minimal app)
# ═══════════════════════════════════════════════════════════════════════════


@pytest.fixture
def client(patched_db):
    """A minimal app wired with the REAL middleware under test."""
    from admin.main import automation_idempotency

    app = FastAPI()
    app.middleware("http")(automation_idempotency)

    state = {"calls": 0}

    @app.post("/admin/investigation/cases")
    async def create_case():
        state["calls"] += 1
        return {"id": "case-1", "calls": state["calls"]}

    @app.post("/admin/investigation/fail")
    async def always_400():
        from fastapi.responses import JSONResponse

        state["calls"] += 1
        return JSONResponse({"calls": state["calls"]}, status_code=400)

    tc = TestClient(app)
    tc.state = state  # type: ignore[attr-defined]
    return tc


_SA = {"Authorization": "Bearer bwk_sa_testkey", "Idempotency-Key": "req-1"}


class TestIdempotencyMiddleware:
    def test_replays_cached_response_without_re_executing(self, client):
        first = client.post("/admin/investigation/cases", headers=_SA)
        assert first.status_code == 200
        assert first.json()["calls"] == 1
        assert "idempotency-replay" not in {k.lower() for k in first.headers}

        second = client.post("/admin/investigation/cases", headers=_SA)
        assert second.status_code == 200
        # Handler NOT re-executed — same body replayed.
        assert second.json()["calls"] == 1
        assert second.headers.get("Idempotency-Replay") == "true"
        assert client.state["calls"] == 1

    def test_different_key_re_executes(self, client):
        client.post("/admin/investigation/cases", headers=_SA)
        other = client.post(
            "/admin/investigation/cases",
            headers={"Authorization": "Bearer bwk_sa_testkey", "Idempotency-Key": "req-2"},
        )
        assert other.json()["calls"] == 2

    def test_no_key_bypasses_cache(self, client):
        h = {"Authorization": "Bearer bwk_sa_testkey"}
        client.post("/admin/investigation/cases", headers=h)
        client.post("/admin/investigation/cases", headers=h)
        assert client.state["calls"] == 2

    def test_non_service_account_bypasses_cache(self, client):
        h = {"Authorization": "Bearer session-jwt", "Idempotency-Key": "req-1"}
        client.post("/admin/investigation/cases", headers=h)
        client.post("/admin/investigation/cases", headers=h)
        assert client.state["calls"] == 2

    def test_non_2xx_is_not_cached(self, client):
        client.post("/admin/investigation/fail", headers=_SA)
        second = client.post("/admin/investigation/fail", headers=_SA)
        # Both executed — a failure stays freely retryable.
        assert second.status_code == 400
        assert client.state["calls"] == 2
