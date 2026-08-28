"""Regression tests for PostgreSQL built-in-account secret rotation sync.

The PostgreSQL user store previously only seeded default users when the table
was empty. On a persistent volume, rotating a Docker/K8s secret (e.g.
ADMIN_PASSWORD) left a stale bcrypt hash in the DB, locking the operator out
because login verifies against the stored hash, not the mounted secret.

These tests pin the fixed behaviour of ``PostgreSQLUserStore._sync_passwords_pg``
and its wiring through ``_sync_seed_defaults``:

* rotation detected  -> hash updated + force_password_change=1
* secret unchanged   -> no write (idempotent)
* default/unset      -> skipped (never overwrite with a built-in default)
* empty table        -> seed path runs, sync path does not
"""

from __future__ import annotations

import pytest

from admin.services.user_store import (
    PostgreSQLUserStore,
    _hash_password,
    _verify_password,
)


class FakeDB:
    """Minimal in-memory stand-in for the sync DatabaseEngine interface."""

    def __init__(self, users: dict | None = None):
        # username -> {password_hash, force_password_change, updated_at}
        self.users = users if users is not None else {}
        self.executed: list[tuple[str, tuple]] = []

    @staticmethod
    def _norm(query: str) -> str:
        return " ".join(query.split())

    def sync_fetch_one(self, query, params=()):  # noqa: ANN001
        q = self._norm(query)
        if q.startswith("SELECT COUNT(*)"):
            return {"cnt": len(self.users)}
        if q.startswith("SELECT password_hash FROM users WHERE username"):
            user = self.users.get(params[0])
            return {"password_hash": user["password_hash"]} if user else None
        return None

    def sync_execute(self, query, params=()):  # noqa: ANN001
        q = self._norm(query)
        self.executed.append((q, params))
        if q.startswith("UPDATE users SET password_hash"):
            new_hash, now, username = params
            user = self.users.get(username)
            if user:
                user["password_hash"] = new_hash
                user["force_password_change"] = 1
                user["updated_at"] = now
        elif q.startswith("INSERT INTO users"):
            _id, username, ph, _role, _now, _now2 = params
            self.users[username] = {"password_hash": ph, "force_password_change": 1}

    @property
    def update_count(self) -> int:
        return sum(1 for q, _ in self.executed if q.startswith("UPDATE users SET password_hash"))


@pytest.fixture()
def store() -> PostgreSQLUserStore:
    return PostgreSQLUserStore()


def _set_secret(monkeypatch, mapping: dict[str, str]) -> None:
    """Patch read_secret used inside the store to return controlled values."""

    def fake_read_secret(key, default=None):
        return mapping.get(key, default)

    monkeypatch.setattr("admin.services.secrets.read_secret", fake_read_secret)


def test_rotation_detected_updates_hash_and_forces_change(store, monkeypatch):
    old_pw, new_pw = "OldSecretPassw0rd!", "RotatedSecretPassw0rd!"
    db = FakeDB({
        "admin": {"password_hash": _hash_password(old_pw), "force_password_change": 0},
    })
    _set_secret(monkeypatch, {"ADMIN_PASSWORD": new_pw})

    store._sync_passwords_pg(db)

    stored = db.users["admin"]["password_hash"]
    assert _verify_password(new_pw, stored), "hash should now match the rotated secret"
    assert not _verify_password(old_pw, stored), "old password must no longer verify"
    assert db.users["admin"]["force_password_change"] == 1
    assert db.update_count == 1


def test_no_rotation_is_idempotent(store, monkeypatch):
    pw = "SteadySecretPassw0rd!"
    original_hash = _hash_password(pw)
    db = FakeDB({
        "admin": {"password_hash": original_hash, "force_password_change": 0},
    })
    _set_secret(monkeypatch, {"ADMIN_PASSWORD": pw})

    store._sync_passwords_pg(db)

    # Secret already matches stored hash -> no UPDATE, flag untouched
    assert db.update_count == 0
    assert db.users["admin"]["password_hash"] == original_hash
    assert db.users["admin"]["force_password_change"] == 0


def test_default_secret_is_never_synced(store, monkeypatch):
    # read_secret returns the built-in fallback => operator has NOT configured a
    # real secret; we must not clobber the stored password with a default.
    db = FakeDB({
        "admin": {"password_hash": _hash_password("SomeRealPassw0rd!"), "force_password_change": 0},
    })
    _set_secret(monkeypatch, {})  # everything falls back to defaults

    store._sync_passwords_pg(db)

    assert db.update_count == 0
    assert db.users["admin"]["force_password_change"] == 0


def test_missing_user_row_is_skipped(store, monkeypatch):
    db = FakeDB({})  # no admin row present
    _set_secret(monkeypatch, {"ADMIN_PASSWORD": "AnythingStrong123!"})

    store._sync_passwords_pg(db)  # must not raise

    assert db.update_count == 0


def test_only_builtin_accounts_are_targeted(store, monkeypatch):
    # A non-builtin user with a stale hash must be left alone.
    db = FakeDB({
        "alice": {"password_hash": _hash_password("AlicePassw0rd!"), "force_password_change": 0},
    })
    _set_secret(monkeypatch, {"ADMIN_PASSWORD": "RotatedSecretPassw0rd!"})

    store._sync_passwords_pg(db)

    assert db.update_count == 0
    assert db.users["alice"]["force_password_change"] == 0


def test_seed_seed_path_runs_only_when_table_empty(store, monkeypatch):
    db = FakeDB({})  # empty table -> seed
    _set_secret(monkeypatch, {
        "ADMIN_PASSWORD": "AdminSeedPassw0rd!",
        "SECURITY_PASSWORD": "SecuritySeedPassw0rd!",
        "AUDITOR_PASSWORD": "AuditorSeedPassw0rd!",
    })

    store._sync_seed_defaults(db)

    assert set(db.users) == {"admin", "security", "auditor"}
    assert _verify_password("AdminSeedPassw0rd!", db.users["admin"]["password_hash"])
    # Seed uses INSERT, not the rotation UPDATE
    assert db.update_count == 0


def test_seed_dispatch_runs_sync_when_table_populated(store, monkeypatch):
    old_pw, new_pw = "OldSecretPassw0rd!", "RotatedSecretPassw0rd!"
    db = FakeDB({
        "admin": {"password_hash": _hash_password(old_pw), "force_password_change": 0},
    })
    _set_secret(monkeypatch, {"ADMIN_PASSWORD": new_pw})

    # Non-empty table -> _sync_seed_defaults must dispatch to _sync_passwords_pg
    store._sync_seed_defaults(db)

    assert db.update_count == 1
    assert _verify_password(new_pw, db.users["admin"]["password_hash"])
    assert db.users["admin"]["force_password_change"] == 1
