"""Regression tests for 3rd-pass RBAC persistence + reset drift (A1, A2).

A1  admin/routes/rbac.py — a persisted override to a BUILT-IN role's permissions
    was only written back into the live ``ROLE_PERMISSIONS`` dict inside the PUT
    handler (request-time). On an admin restart nothing re-applied it, so
    ``require_permission`` (which reads ``ROLE_PERMISSIONS``) silently reverted to
    the hardcoded defaults. ``apply_persisted_overrides()`` now reconciles the
    persisted file into the matrix at boot.

A2  admin/routes/rbac.py — the reset handler restored built-in roles from a
    hardcoded ``defaults`` dict (and validated against a hardcoded
    ``ALL_PERMISSIONS`` list) that had drifted far behind the real SSOT in
    ``admin/models/auth.py`` — resetting admin would have stripped ~25 real
    permissions. Reset and the known-permission set now derive from the frozen
    SSOT snapshot.
"""

from __future__ import annotations

import os

os.environ.setdefault("ADMIN_JWT_SECRET", "rbac-persist-test-secret-32chars-minimum!!")
os.environ.setdefault("BULWARK_JWT_SECRET", "rbac-persist-test-secret-32chars-minimum!!")
os.environ.setdefault("BULWARK_KEY_ENCRYPTION_KEY", "rbac-persist-encryption-32chars-minimum!")

import importlib

import pytest

from admin.models.auth import (
    ALL_KNOWN_PERMISSIONS,
    DEFAULT_ROLE_PERMISSIONS,
    ROLE_PERMISSIONS,
    UserRole,
)


@pytest.fixture
def rbac(tmp_path, monkeypatch):
    """Fresh rbac module bound to a temp data dir, matrix restored after test."""
    monkeypatch.setenv("BULWARK_DATA_DIR", str(tmp_path))
    from admin.routes import rbac as rbac_mod

    rbac_mod = importlib.reload(rbac_mod)
    # Snapshot + restore the process-global matrix so tests don't leak into others.
    saved = {role: set(perms) for role, perms in ROLE_PERMISSIONS.items()}
    try:
        yield rbac_mod
    finally:
        for role, perms in saved.items():
            ROLE_PERMISSIONS[role] = perms


# ─── A2: SSOT is complete and reset restores from it ─────────────────────────


def test_all_known_permissions_covers_sessions_and_correlation():
    # The stale hardcoded list omitted these entirely.
    for perm in (
        "sessions:write", "correlation:write", "investigation:write",
        "integrations:write", "automation:manage", "plugins:write",
    ):
        assert perm in ALL_KNOWN_PERMISSIONS


def test_rbac_all_permissions_derived_from_ssot(rbac):
    assert set(rbac.ALL_PERMISSIONS) == set(ALL_KNOWN_PERMISSIONS)
    # And nothing was lost vs. the union of default roles.
    union = {p for perms in DEFAULT_ROLE_PERMISSIONS.values() for p in perms}
    assert set(rbac.ALL_PERMISSIONS) == union


def test_default_snapshot_is_immutable_against_matrix_mutation():
    # Mutating the live matrix must NOT change the frozen defaults snapshot.
    before = set(DEFAULT_ROLE_PERMISSIONS[UserRole.ADMIN])
    ROLE_PERMISSIONS[UserRole.ADMIN].discard("investigation:write")
    try:
        assert "investigation:write" in DEFAULT_ROLE_PERMISSIONS[UserRole.ADMIN]
        assert set(DEFAULT_ROLE_PERMISSIONS[UserRole.ADMIN]) == before
    finally:
        ROLE_PERMISSIONS[UserRole.ADMIN].add("investigation:write")


def test_reset_restores_full_ssot_not_stale_defaults(rbac):
    # Simulate an override that narrowed admin, then reset.
    rbac._save_overrides({"admin": ["admin:read", "users:manage"]})
    rbac.apply_persisted_overrides()
    assert ROLE_PERMISSIONS[UserRole.ADMIN] == {"admin:read", "users:manage"}

    # Reset must restore the RICH SSOT default, not the old ~20-perm hardcoded copy.
    result = rbac.reset_role_permissions("admin", _user=None)
    assert result["reset"] is True
    restored = ROLE_PERMISSIONS[UserRole.ADMIN]
    assert restored == set(DEFAULT_ROLE_PERMISSIONS[UserRole.ADMIN])
    for perm in ("investigation:write", "integrations:write", "automation:manage",
                 "correlation:write", "sessions:write"):
        assert perm in restored


# ─── A1: overrides reconciled at startup ─────────────────────────────────────


def test_apply_persisted_overrides_reconciles_builtin_role(rbac):
    # Persist a broadened viewer, then wipe the in-memory matrix to simulate a
    # fresh process boot with the default (narrow) viewer.
    rbac._save_overrides({"viewer": ["admin:read", "siem:read", "iocs:write"]})
    ROLE_PERMISSIONS[UserRole.VIEWER] = set(DEFAULT_ROLE_PERMISSIONS[UserRole.VIEWER])
    assert "iocs:write" not in ROLE_PERMISSIONS[UserRole.VIEWER]

    applied = rbac.apply_persisted_overrides()
    assert applied == 1
    assert ROLE_PERMISSIONS[UserRole.VIEWER] == {"admin:read", "siem:read", "iocs:write"}


def test_apply_persisted_overrides_drops_unknown_permissions(rbac):
    rbac._save_overrides({"viewer": ["admin:read", "bogus:permission"]})
    rbac.apply_persisted_overrides()
    assert ROLE_PERMISSIONS[UserRole.VIEWER] == {"admin:read"}


def test_apply_persisted_overrides_ignores_custom_roles(rbac):
    # A custom role has no UserRole enum entry — it must be skipped, not crash.
    rbac._save_overrides({"my_custom_role": ["admin:read"]})
    applied = rbac.apply_persisted_overrides()
    assert applied == 0


def test_apply_persisted_overrides_no_file_is_noop(rbac):
    assert rbac.apply_persisted_overrides() == 0
