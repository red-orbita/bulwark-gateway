"""Regression tests for Redis password handling in admin.services.redis_sync.

Covers VULN 1.7 and the "Port could not be cast to integer" outage:

A Redis password read from a secret file was interpolated directly into the
connection URL (``redis://:{password}@host:port/db``). When the password
contains URL-special characters — routine in base64-encoded secrets from
managed Redis (Azure/AWS/GCP), e.g. ``/``, ``:``, ``@`` — this corrupts the
netloc:

  * ``/`` truncates the authority  -> "Port could not be cast to integer"
    (the admin System Status showed Redis as ``unhealthy``), and
  * ``@`` lets an attacker-influenced password redirect the connection to an
    arbitrary host (VULN 1.7).

The fix passes the password as a ``redis-py`` connection kwarg and never
mutates the URL. These tests assert that contract.
"""

from __future__ import annotations

import importlib

import pytest


@pytest.fixture
def redis_sync(monkeypatch):
    """Import the module fresh and neutralize its pool singleton per test."""
    mod = importlib.import_module("admin.services.redis_sync")
    # Reset singleton state so each test builds a fresh pool.
    mod._redis_pool = None
    mod._redis_url_resolved = ""
    mod._pool_created_at = 0.0
    return mod


def _capture_from_url(monkeypatch, redis_sync):
    """Patch ConnectionPool.from_url to record (url, kwargs) without connecting."""
    captured: dict = {}

    def fake_from_url(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        return object()  # opaque sentinel pool — never used to connect

    monkeypatch.setattr(redis_sync.redis.ConnectionPool, "from_url", fake_from_url)
    return captured


def _write_secret(tmp_path, value: str) -> str:
    p = tmp_path / "redis-password"
    p.write_text(value)
    return str(p)


# ─── Positive: the bug scenario must no longer corrupt the URL ──────────────


def test_password_with_slash_does_not_corrupt_url(monkeypatch, tmp_path, redis_sync):
    """A '/' in the password (base64 secret) must NOT be spliced into the URL."""
    secret = _write_secret(tmp_path, "U50UaXXXXXXXXXXXXXXXXXXXXX/ZP")
    monkeypatch.setenv("BULWARK_REDIS_URL", "redis://redis:6379/0")
    monkeypatch.setenv("BULWARK_REDIS_PASSWORD_FILE", secret)
    captured = _capture_from_url(monkeypatch, redis_sync)

    pool = redis_sync._get_pool()

    assert pool is not None
    # URL is passed through untouched — no ":{password}@" injection.
    assert captured["url"] == "redis://redis:6379/0"
    assert "@" not in captured["url"]
    # Password delivered safely as a connection kwarg.
    assert captured["kwargs"]["password"] == "U50UaXXXXXXXXXXXXXXXXXXXXX/ZP"  # noqa: S105


def test_password_with_at_sign_is_not_interpolated(monkeypatch, tmp_path, redis_sync):
    """An '@' in the password must never reach the netloc (VULN 1.7 host redirect)."""
    secret = _write_secret(tmp_path, "p@ss/w:rd=evil@attacker.example")
    monkeypatch.setenv("BULWARK_REDIS_URL", "redis://redis:6379/0")
    monkeypatch.setenv("BULWARK_REDIS_PASSWORD_FILE", secret)
    captured = _capture_from_url(monkeypatch, redis_sync)

    pool = redis_sync._get_pool()

    assert pool is not None
    # Host stays 'redis' — the attacker-controlled fragment cannot redirect us.
    assert captured["url"] == "redis://redis:6379/0"
    assert "attacker.example" not in captured["url"]
    assert captured["kwargs"]["password"] == "p@ss/w:rd=evil@attacker.example"  # noqa: S105


# ─── Negative: benign inputs still behave correctly ─────────────────────────


def test_alphanumeric_password_passed_as_kwarg(monkeypatch, tmp_path, redis_sync):
    """A plain alphanumeric secret (Helm internal randAlphaNum) still works."""
    secret = _write_secret(tmp_path, "abc123DEF456ghi789")
    monkeypatch.setenv("BULWARK_REDIS_URL", "redis://redis:6379/0")
    monkeypatch.setenv("BULWARK_REDIS_PASSWORD_FILE", secret)
    captured = _capture_from_url(monkeypatch, redis_sync)

    pool = redis_sync._get_pool()

    assert pool is not None
    assert captured["url"] == "redis://redis:6379/0"
    assert captured["kwargs"]["password"] == "abc123DEF456ghi789"  # noqa: S105


def test_no_password_file_sets_no_password_kwarg(monkeypatch, redis_sync):
    """Without a secret file, no password kwarg is added and URL is untouched."""
    monkeypatch.setenv("BULWARK_REDIS_URL", "redis://redis:6379/0")
    monkeypatch.delenv("BULWARK_REDIS_PASSWORD_FILE", raising=False)
    captured = _capture_from_url(monkeypatch, redis_sync)

    pool = redis_sync._get_pool()

    assert pool is not None
    assert captured["url"] == "redis://redis:6379/0"
    assert "password" not in captured["kwargs"]


def test_no_url_returns_none_without_building_pool(monkeypatch, redis_sync):
    """No BULWARK_REDIS_URL -> graceful None, no pool creation attempted."""
    monkeypatch.delenv("BULWARK_REDIS_URL", raising=False)
    captured = _capture_from_url(monkeypatch, redis_sync)

    assert redis_sync._get_pool() is None
    assert captured == {}
