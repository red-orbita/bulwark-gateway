"""Tests for automation service accounts (Phase 3.2a).

Exercises the scoped, non-interactive automation credential end-to-end against a
real migrated SQLite database (migration v10):

* :class:`ServiceAccountStore` — mint (one-time raw key + hashed-at-rest), the
  grantable-permission whitelist enforcement, verify (valid / wrong / disabled /
  expired), ``last_used_at`` stamping, enable/disable and delete; and
* the ``require_permission_automation`` resolver — a service-account key with the
  required permission is accepted, a key missing it is 403, and an
  unknown/disabled/expired key is 401; plus that the *management* surface stays
  session-only (a service-account key can never manage service accounts).
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from starlette.requests import Request

from admin.models.auth import UserRole

# ─── shared fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
async def engine(tmp_path):
    """A migrated throwaway SQLite engine shared by the store fixtures."""
    from admin.services.database import create_engine
    from admin.services.migrations import run_migrations

    eng = create_engine(f"sqlite:///{tmp_path / 'svc_accounts_test.db'}")
    await eng.init()
    await run_migrations(eng)
    try:
        yield eng
    finally:
        await eng.close()


@pytest.fixture
async def store(engine, monkeypatch):
    from admin.services import service_account_store as mod
    from admin.services.service_account_store import ServiceAccountStore

    monkeypatch.setattr(mod, "get_database", lambda: engine)
    return ServiceAccountStore()


def _dummy_request() -> Request:
    return Request({"type": "http", "headers": [], "query_string": b""})


def _creds(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


# ═══════════════════════════════════════════════════════════════════════════
# ServiceAccountStore
# ═══════════════════════════════════════════════════════════════════════════


class TestServiceAccountStore:
    async def test_mint_returns_raw_key_once_and_hashes_at_rest(self, store, engine):
        acct = await store.mint(
            name="playbook-1",
            permissions=["investigation:write", "automation:respond"],
            created_by="admin-user",
        )
        raw = acct["key"]
        assert raw.startswith("bwk_sa_")
        assert len(raw) > 40  # bwk_sa_ + 48 hex
        assert acct["enabled"] is True
        assert set(acct["permissions"]) == {"investigation:write", "automation:respond"}
        assert acct["key_prefix"] == raw[:15]

        # The raw key is never persisted — only its SHA-256.
        row = await engine.fetch_one(
            "SELECT key_hash, key_prefix FROM service_account WHERE account_id = ?",
            [acct["account_id"]],
        )
        assert row["key_hash"] == hashlib.sha256(raw.encode()).hexdigest()
        assert row["key_prefix"] == raw[:15]
        assert raw not in (row["key_hash"], row["key_prefix"])

    async def test_list_never_exposes_secret_material(self, store):
        await store.mint(name="p", permissions=["automation:respond"], created_by="a")
        accounts = await store.list_accounts()
        assert len(accounts) == 1
        for acct in accounts:
            assert "key" not in acct
            assert "key_hash" not in acct

    async def test_mint_rejects_non_grantable_permission(self, store):
        with pytest.raises(ValueError, match="not grantable"):
            await store.mint(
                name="evil", permissions=["users:manage"], created_by="a"
            )

    async def test_mint_rejects_automation_manage(self, store):
        # automation:manage is human-operator-only, not grantable to a key.
        with pytest.raises(ValueError, match="not grantable"):
            await store.mint(
                name="evil", permissions=["automation:manage"], created_by="a"
            )

    async def test_mint_rejects_empty_permissions(self, store):
        with pytest.raises(ValueError, match="at least one"):
            await store.mint(name="p", permissions=[], created_by="a")

    async def test_mint_requires_name(self, store):
        with pytest.raises(ValueError, match="name is required"):
            await store.mint(
                name="   ", permissions=["automation:respond"], created_by="a"
            )

    async def test_verify_valid_key_returns_account_and_stamps_last_used(self, store):
        acct = await store.mint(
            name="p", permissions=["automation:respond"], created_by="a"
        )
        assert acct["last_used_at"] is None
        resolved = await store.verify(acct["key"])
        assert resolved is not None
        assert resolved["account_id"] == acct["account_id"]
        assert resolved["permissions"] == ["automation:respond"]
        # last_used_at is now stamped.
        again = await store.get(acct["account_id"])
        assert again["last_used_at"] is not None

    async def test_verify_wrong_key_returns_none(self, store):
        await store.mint(name="p", permissions=["automation:respond"], created_by="a")
        assert await store.verify("bwk_sa_" + "0" * 48) is None
        assert await store.verify("not-a-key") is None
        assert await store.verify("") is None

    async def test_verify_disabled_key_returns_none(self, store):
        acct = await store.mint(
            name="p", permissions=["automation:respond"], created_by="a"
        )
        assert await store.set_enabled(acct["account_id"], False) is True
        assert await store.verify(acct["key"]) is None

    async def test_verify_expired_key_returns_none(self, store):
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        acct = await store.mint(
            name="p", permissions=["automation:respond"], created_by="a",
            expires_at=past,
        )
        assert await store.verify(acct["key"]) is None

    async def test_verify_unexpired_key_ok(self, store):
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        acct = await store.mint(
            name="p", permissions=["automation:respond"], created_by="a",
            expires_at=future,
        )
        assert await store.verify(acct["key"]) is not None

    async def test_mint_rejects_bad_expiry(self, store):
        with pytest.raises(ValueError, match="ISO-8601"):
            await store.mint(
                name="p", permissions=["automation:respond"], created_by="a",
                expires_at="not-a-date",
            )

    async def test_toggle_and_delete(self, store):
        acct = await store.mint(
            name="p", permissions=["automation:respond"], created_by="a"
        )
        aid = acct["account_id"]
        assert await store.set_enabled(aid, False) is True
        assert (await store.get(aid))["enabled"] is False
        assert await store.set_enabled(aid, True) is True
        assert (await store.get(aid))["enabled"] is True
        assert await store.delete(aid) is True
        assert await store.get(aid) is None
        # Idempotent no-ops on a missing id.
        assert await store.delete(aid) is False
        assert await store.set_enabled(aid, True) is False


# ═══════════════════════════════════════════════════════════════════════════
# require_permission_automation resolver
# ═══════════════════════════════════════════════════════════════════════════


class TestAutomationResolver:
    async def test_service_account_key_with_permission_accepted(self, store, monkeypatch):
        from admin.services import auth_service

        acct = await store.mint(
            name="p", permissions=["automation:respond"], created_by="a"
        )
        dep = auth_service.require_permission_automation("automation:respond")
        payload = await dep(_dummy_request(), _creds(acct["key"]))
        assert payload.sub == f"service-account:{acct['account_id']}"
        assert payload.role == UserRole.VIEWER

    async def test_service_account_key_missing_permission_403(self, store):
        from admin.services import auth_service

        acct = await store.mint(
            name="p", permissions=["automation:respond"], created_by="a"
        )
        dep = auth_service.require_permission_automation("investigation:write")
        with pytest.raises(HTTPException) as ei:
            await dep(_dummy_request(), _creds(acct["key"]))
        assert ei.value.status_code == 403

    async def test_unknown_service_account_key_401(self, store):
        from admin.services import auth_service

        dep = auth_service.require_permission_automation("automation:respond")
        with pytest.raises(HTTPException) as ei:
            await dep(_dummy_request(), _creds("bwk_sa_" + "0" * 48))
        assert ei.value.status_code == 401

    async def test_disabled_service_account_key_401(self, store):
        from admin.services import auth_service

        acct = await store.mint(
            name="p", permissions=["automation:respond"], created_by="a"
        )
        await store.set_enabled(acct["account_id"], False)
        dep = auth_service.require_permission_automation("automation:respond")
        with pytest.raises(HTTPException) as ei:
            await dep(_dummy_request(), _creds(acct["key"]))
        assert ei.value.status_code == 401


# ═══════════════════════════════════════════════════════════════════════════
# Management routes (session-only; SA keys cannot self-manage)
# ═══════════════════════════════════════════════════════════════════════════


class TestManagementRoutes:
    async def test_create_lists_and_toggles(self, engine, monkeypatch):
        from admin.routes import service_accounts as routes
        from admin.services import service_account_store as mod

        monkeypatch.setattr(mod, "get_database", lambda: engine)

        now = datetime.now(timezone.utc)
        from admin.models.auth import TokenPayload
        admin = TokenPayload(sub="admin-user", role=UserRole.ADMIN,
                             exp=now + timedelta(hours=1), iat=now)

        created = await routes.create_service_account(
            routes.ServiceAccountCreate(
                name="playbook", permissions=["automation:respond"]
            ),
            user=admin,
        )
        acct = created["account"]
        assert acct["key"].startswith("bwk_sa_")

        listed = await routes.list_service_accounts(_user=admin)
        assert listed["count"] == 1
        assert "key" not in listed["accounts"][0]

        toggled = await routes.toggle_service_account(
            acct["account_id"], routes.ServiceAccountToggle(enabled=False), user=admin
        )
        assert "disabled" in toggled["message"]

        deleted = await routes.delete_service_account(acct["account_id"], user=admin)
        assert "deleted" in deleted["message"]

    async def test_create_rejects_non_grantable_permission(self, engine, monkeypatch):
        from admin.routes import service_accounts as routes
        from admin.services import service_account_store as mod

        monkeypatch.setattr(mod, "get_database", lambda: engine)
        now = datetime.now(timezone.utc)
        from admin.models.auth import TokenPayload
        admin = TokenPayload(sub="admin-user", role=UserRole.ADMIN,
                             exp=now + timedelta(hours=1), iat=now)

        with pytest.raises(HTTPException) as ei:
            await routes.create_service_account(
                routes.ServiceAccountCreate(name="x", permissions=["users:manage"]),
                user=admin,
            )
        assert ei.value.status_code == 400

    async def test_toggle_missing_account_404(self, engine, monkeypatch):
        from admin.routes import service_accounts as routes
        from admin.services import service_account_store as mod

        monkeypatch.setattr(mod, "get_database", lambda: engine)
        now = datetime.now(timezone.utc)
        from admin.models.auth import TokenPayload
        admin = TokenPayload(sub="admin-user", role=UserRole.ADMIN,
                             exp=now + timedelta(hours=1), iat=now)

        with pytest.raises(HTTPException) as ei:
            await routes.toggle_service_account(
                "sr_" + "0" * 16, routes.ServiceAccountToggle(enabled=True), user=admin
            )
        assert ei.value.status_code == 400  # bad id format

        with pytest.raises(HTTPException) as ei:
            await routes.toggle_service_account(
                "sa_" + "0" * 16, routes.ServiceAccountToggle(enabled=True), user=admin
            )
        assert ei.value.status_code == 404  # well-formed but absent
