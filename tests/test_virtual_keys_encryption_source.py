"""
GAP-G regression tests — virtual-key encryption key sourcing.

``BULWARK_KEY_ENCRYPTION_KEY`` encrypts every backend API key at rest. It was
required as a *direct* env var only, so Docker Compose and Helm (which provision
every other secret as a mounted file via the ``*_FILE`` pattern) left the
virtual-key vault dead. These tests pin the sourcing contract:

  * direct ``BULWARK_KEY_ENCRYPTION_KEY`` still works
  * ``BULWARK_KEY_ENCRYPTION_KEY_FILE`` (Docker/K8s secret) is honored
  * the derived key is identical regardless of which channel supplied it
    (so proxy reading the file and admin reading the env decrypt the same vault)
  * a missing key still fails closed (SystemExit)
"""

from __future__ import annotations

import pytest

from src.services.virtual_keys import VirtualKeyManager

ENC_KEY_MATERIAL = "gap-g-shared-encryption-key-0123456789abcdef"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("BULWARK_KEY_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("BULWARK_KEY_ENCRYPTION_KEY_FILE", raising=False)
    monkeypatch.delenv("KEY_ENCRYPTION_KEY_FILE", raising=False)
    yield


def _derive(monkeypatch, *, env=None, file_env=None):
    if env is not None:
        monkeypatch.setenv("BULWARK_KEY_ENCRYPTION_KEY", env)
    if file_env is not None:
        monkeypatch.setenv("BULWARK_KEY_ENCRYPTION_KEY_FILE", file_env)
    # Call the pure derivation directly — avoids Redis/socket setup in __init__.
    return VirtualKeyManager._derive_encryption_key(object.__new__(VirtualKeyManager))


def test_direct_env_var(monkeypatch):
    key = _derive(monkeypatch, env=ENC_KEY_MATERIAL)
    assert isinstance(key, bytes) and len(key) == 32


def test_file_fallback(monkeypatch, tmp_path):
    secret_file = tmp_path / "key_encryption_key"
    secret_file.write_text(ENC_KEY_MATERIAL + "\n")  # trailing newline must be stripped
    key = _derive(monkeypatch, file_env=str(secret_file))
    assert isinstance(key, bytes) and len(key) == 32


def test_env_and_file_derive_identical_key(monkeypatch, tmp_path):
    """Proxy (file) and admin (env) must derive the SAME key for one secret."""
    secret_file = tmp_path / "key_encryption_key"
    secret_file.write_text(ENC_KEY_MATERIAL)

    from_env = _derive(monkeypatch, env=ENC_KEY_MATERIAL)
    monkeypatch.delenv("BULWARK_KEY_ENCRYPTION_KEY", raising=False)
    from_file = _derive(monkeypatch, file_env=str(secret_file))

    assert from_env == from_file


def test_direct_env_takes_precedence_over_file(monkeypatch, tmp_path):
    other = tmp_path / "key_encryption_key"
    other.write_text("a-different-secret-value-not-used-here")
    key_env_only = _derive(monkeypatch, env=ENC_KEY_MATERIAL)
    monkeypatch.delenv("BULWARK_KEY_ENCRYPTION_KEY", raising=False)
    key_env_and_file = _derive(monkeypatch, env=ENC_KEY_MATERIAL, file_env=str(other))
    assert key_env_only == key_env_and_file


def test_missing_key_fails_closed(monkeypatch):
    with pytest.raises(SystemExit):
        _derive(monkeypatch)


def test_empty_file_fails_closed(monkeypatch, tmp_path):
    empty = tmp_path / "key_encryption_key"
    empty.write_text("   \n")
    with pytest.raises(SystemExit):
        _derive(monkeypatch, file_env=str(empty))


def test_missing_file_path_fails_closed(monkeypatch, tmp_path):
    with pytest.raises(SystemExit):
        _derive(monkeypatch, file_env=str(tmp_path / "does-not-exist"))
