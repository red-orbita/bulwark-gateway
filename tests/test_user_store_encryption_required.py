"""Configured encryption must never silently become a plaintext user database."""

from unittest.mock import Mock

import pytest


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Do not initialize the operator database."""


def test_unavailable_sqlcipher_refuses_before_creating_database(monkeypatch, tmp_path):
    from admin.services import user_store

    monkeypatch.setattr(user_store, "_get_db_encryption_key", lambda: "a" * 64)
    monkeypatch.setattr(user_store, "_HAS_SQLCIPHER", False)
    connect = Mock(side_effect=AssertionError("Plaintext database must not open"))
    monkeypatch.setattr(user_store.sqlite3, "connect", connect)
    store = user_store.UserStore(str(tmp_path / "users.db"))
    with pytest.raises(SystemExit, match="SQLCipher is unavailable"):
        store.initialize()
    connect.assert_not_called()
    assert not (tmp_path / "users.db").exists()


@pytest.mark.parametrize("fault", ["missing", "empty", "whitespace", "directory", "oversize", "invalid_utf8"])
def test_bad_key_mount_cannot_fall_back_to_environment(monkeypatch, tmp_path, fault):
    from admin.services.user_store import _get_db_encryption_key

    path = tmp_path / "key"
    if fault == "directory":
        path.mkdir()
    elif fault != "missing":
        path.write_bytes({"empty": b"", "whitespace": b" \n", "oversize": b"a" * 4097,
                          "invalid_utf8": b"\xff"}[fault])
    monkeypatch.setenv("DB_ENCRYPTION_KEY_FILE", str(path))
    monkeypatch.setenv("DB_ENCRYPTION_KEY", "b" * 64)
    with pytest.raises(SystemExit, match="key file is unavailable or invalid"):
        _get_db_encryption_key()


def test_projected_secret_symlink_and_newline_are_supported(monkeypatch, tmp_path):
    from admin.services.user_store import _get_db_encryption_key

    target = tmp_path / "payload"
    target.write_text("a" * 64 + "\n")
    link = tmp_path / "key"
    link.symlink_to(target)
    monkeypatch.setenv("DB_ENCRYPTION_KEY_FILE", str(link))
    monkeypatch.setenv("DB_ENCRYPTION_KEY", "b" * 64)
    assert _get_db_encryption_key() == "a" * 64


def test_unconfigured_key_keeps_development_mode(monkeypatch):
    from admin.services.user_store import _get_db_encryption_key

    monkeypatch.delenv("DB_ENCRYPTION_KEY_FILE", raising=False)
    monkeypatch.delenv("DB_ENCRYPTION_KEY", raising=False)
    assert _get_db_encryption_key() is None
