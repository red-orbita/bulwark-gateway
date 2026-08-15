"""Regression tests for policy backup/rollback under hardened container security.

Production containers run with a read-only root filesystem, dropped Linux
capabilities and a seccomp profile. Under those conditions ``os.listxattr``
raises ``PermissionError: [Errno 1] Operation not permitted``. ``shutil.copy2``
(and ``shutil.copy``'s ``copymode``) invoke xattr/stat syscalls, so using them
to back up a policy made policy UPDATE and DELETE return HTTP 500 in production.

These tests reproduce that exact condition by denying ``os.listxattr`` and assert
that the backup/rollback helpers still succeed (they must copy data only).
"""

from __future__ import annotations

import os

import pytest

from admin.services import config_validator
from admin.services.config_validator import HotReloader


@pytest.fixture()
def isolated_policies(tmp_path, monkeypatch):
    """Point the module-level POLICIES_DIR / BACKUP_DIR at a temp directory."""
    policies_dir = tmp_path / "policies"
    backup_dir = policies_dir / ".backup"
    policies_dir.mkdir(parents=True)
    monkeypatch.setattr(config_validator, "POLICIES_DIR", policies_dir)
    monkeypatch.setattr(config_validator, "BACKUP_DIR", backup_dir)
    return policies_dir, backup_dir


@pytest.fixture()
def deny_xattr(monkeypatch):
    """Simulate a hardened container where xattr syscalls are not permitted."""
    def _raise(*_args, **_kwargs):
        raise PermissionError(1, "Operation not permitted")

    # os.listxattr may not exist on all platforms; only patch if present.
    if hasattr(os, "listxattr"):
        monkeypatch.setattr(os, "listxattr", _raise)
    if hasattr(os, "setxattr"):
        monkeypatch.setattr(os, "setxattr", _raise)


def test_backup_policy_survives_denied_xattr(isolated_policies, deny_xattr):
    policies_dir, backup_dir = isolated_policies
    content = "tenant: acme\nagents:\n  - id: bot\n    sandbox_level: strict\n"
    (policies_dir / "acme.yaml").write_text(content)

    backup_path = HotReloader.backup_policy("acme")

    assert backup_path is not None
    assert backup_dir.exists()
    backups = list(backup_dir.glob("acme.*.yaml"))
    assert len(backups) == 1
    # Content must be preserved exactly (data-only copy).
    assert backups[0].read_text() == content


def test_backup_missing_policy_returns_none(isolated_policies, deny_xattr):
    assert HotReloader.backup_policy("does-not-exist") is None


def test_rollback_policy_survives_denied_xattr(isolated_policies, deny_xattr):
    policies_dir, _ = isolated_policies
    original = "tenant: acme\nversion: 1\n"
    (policies_dir / "acme.yaml").write_text(original)

    # First backup captures v1, then we mutate the live policy to v2.
    HotReloader.backup_policy("acme")
    (policies_dir / "acme.yaml").write_text("tenant: acme\nversion: 2\n")

    assert HotReloader.rollback_policy("acme") is True
    # Rolled back to the v1 backup content.
    assert (policies_dir / "acme.yaml").read_text() == original


def test_delete_flow_backup_then_unlink(isolated_policies, deny_xattr):
    """Mirror the admin DELETE route: backup_policy() then unlink()."""
    policies_dir, _ = isolated_policies
    path = policies_dir / "acme.yaml"
    path.write_text("tenant: acme\n")

    # This is the exact sequence that returned 500 before the fix.
    HotReloader.backup_policy("acme")
    path.unlink()

    assert not path.exists()
