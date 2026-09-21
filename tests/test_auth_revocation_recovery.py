"""Isolated revocation retries/configuration; no operator stores or live sockets."""

import ssl
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from cachetools import TTLCache

from src.middleware import auth


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Override root fixture: never mutate the operator database."""


@pytest.fixture
def state(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(auth, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(auth, "settings", SimpleNamespace(
        redis_url="redis://unused.invalid/0", redis_password=None, redis_tls_insecure=False,
    ))
    monkeypatch.setattr(auth, "_revocation_redis", None)
    monkeypatch.setattr(auth, "_revocation_redis_init", False)
    monkeypatch.setattr(auth, "_revocation_retry_at", 0.0)
    monkeypatch.setattr(auth, "_auth_cache", TTLCache(16, 2, timer=lambda: clock[0]))
    monkeypatch.setattr(auth, "_revoked_cache", TTLCache(16, 60, timer=lambda: clock[0]))
    client = Mock()
    client.connection_pool.connection_kwargs = {}
    client.sismember.return_value = False
    factory = Mock(return_value=client)
    monkeypatch.setattr("redis.from_url", factory)
    return clock, client, factory


def test_cold_failure_retries_only_after_cooldown_and_recovers(state, caplog):
    clock, client, factory = state
    client.sismember.side_effect = [ConnectionError("SYNTHETIC_SECRET"), False, True]
    assert auth._is_token_revoked("unknown") is True
    assert not auth._revocation_redis_init
    assert "unknown" not in auth._auth_cache
    client.close.assert_called_once()
    for _ in range(100):
        assert auth._is_token_revoked("unknown") is True
    assert factory.call_count == 1
    clock[0] += auth._REVOCATION_RETRY_SECONDS
    assert auth._is_token_revoked("clean") is False
    assert auth._revocation_redis_init
    assert auth._is_token_revoked("revoked") is True
    assert factory.call_count == 2
    assert "SYNTHETIC_SECRET" not in caplog.text


def test_repeated_failure_backoff_and_client_cleanup(state):
    clock, client, factory = state
    client.sismember.side_effect = TimeoutError("offline")
    for expected in range(1, 4):
        assert auth._is_token_revoked("unknown") is True
        assert factory.call_count == expected
        assert client.close.call_count == expected
        assert auth._is_token_revoked("unknown") is True
        assert factory.call_count == expected
        clock[0] += auth._REVOCATION_RETRY_SECONDS


def test_factory_failure_and_missing_url_recover(state):
    clock, client, factory = state
    factory.side_effect = [ValueError("bad config"), client]
    assert auth._is_token_revoked("unknown")
    clock[0] += auth._REVOCATION_RETRY_SECONDS
    auth.settings.redis_url = None
    assert auth._is_token_revoked("unknown")
    assert factory.call_count == 1
    clock[0] += auth._REVOCATION_RETRY_SECONDS
    auth.settings.redis_url = "redis://unused.invalid/0"
    assert auth._is_token_revoked("clean") is False


def test_existing_client_outage_preserves_cache_contract(state):
    clock, client, factory = state
    client.sismember.side_effect = [False, True, ConnectionError("offline"), False]
    assert auth._is_token_revoked("clean") is False
    assert auth._is_token_revoked("revoked") is True
    assert auth._is_token_revoked("unknown") is True
    assert auth._is_token_revoked("clean") is False
    assert auth._is_token_revoked("revoked") is True
    clock[0] += 2.1
    assert auth._is_token_revoked("clean") is True
    assert factory.call_count == 1
    clock[0] += auth._REVOCATION_RETRY_SECONDS
    assert auth._is_token_revoked("clean") is False
    assert factory.call_count == 2


def test_revocation_observed_after_positive_ttl(state):
    clock, client, _ = state
    client.sismember.side_effect = [False, True]
    assert auth._is_token_revoked("jti") is False
    assert auth._is_token_revoked("jti") is False
    assert client.sismember.call_count == 1
    clock[0] += 2.1
    assert auth._is_token_revoked("jti") is True
    assert auth._is_token_revoked("jti") is True
    assert client.sismember.call_count == 2


def test_close_failure_still_fails_closed_without_raw_logs(state, caplog):
    _, client, _ = state
    client.sismember.side_effect = RuntimeError("SYNTHETIC_SECRET")
    client.close.side_effect = RuntimeError("SYNTHETIC_SECRET")
    assert auth._is_token_revoked("unknown") is True
    assert auth._revocation_redis is None
    assert "revocation_redis_close_failed" in caplog.text
    assert "SYNTHETIC_SECRET" not in caplog.text


@pytest.mark.parametrize("insecure", [False, True])
def test_real_pool_options_tls_password_and_budgets(state, monkeypatch, insecure):
    import redis
    from redis.connection import SSLConnection

    # Restore the real factory, but prohibit network I/O at the Redis operation.
    monkeypatch.setattr(redis, "from_url", redis.Redis.from_url)
    monkeypatch.setattr(redis.Redis, "sismember", lambda *a: False)
    auth.settings.redis_url = (
        "rediss://acl-user:url%40password@unused.invalid:6380/2?ssl_ca_certs=/lab/ca.pem"
        "&ssl_certfile=/lab/client.pem&ssl_keyfile=/lab/client.key"
        "&ssl_check_hostname=false&ssl_cert_reqs=none&socket_timeout=99"
        "&socket_connect_timeout=99&retry_on_timeout=true"
    )
    auth.settings.redis_password = "fallback-password"
    auth.settings.redis_tls_insecure = insecure
    try:
        assert auth._is_token_revoked("clean") is False
        pool = auth._revocation_redis.connection_pool
        options = pool.connection_kwargs
        assert pool.connection_class is SSLConnection
        assert options["username"] == "acl-user"
        assert options["password"] == "url@password"
        assert options["ssl_ca_certs"] == "/lab/ca.pem"
        assert options["ssl_certfile"] == "/lab/client.pem"
        assert options["ssl_keyfile"] == "/lab/client.key"
        assert options["ssl_cert_reqs"] == (ssl.CERT_NONE if insecure else ssl.CERT_REQUIRED)
        assert options["ssl_check_hostname"] is (not insecure)
        assert options["ssl_min_version"] == ssl.TLSVersion.TLSv1_2
        assert options["socket_timeout"] == options["socket_connect_timeout"] == 0.1
        assert options["retry"].get_retries() == 0
        assert options["retry_on_timeout"] is False
        assert options["retry_on_error"] == []
        assert pool.max_connections == 2
    finally:
        if auth._revocation_redis:
            auth._revocation_redis.close()


def test_separate_password_plain_redis_and_sync_contract(state):
    _, _, factory = state
    auth.settings.redis_password = "synthetic@password"
    auth.settings.redis_tls_insecure = True
    assert auth._is_token_revoked("clean-a") is False
    assert auth._is_token_revoked("clean-b") is False
    assert factory.call_args.kwargs["password"] == "synthetic@password"
    assert not any(key.startswith("ssl_") for key in auth._revocation_redis.connection_pool.connection_kwargs)


@pytest.mark.parametrize("jti", ["unicode-\u202e-token", "x" * 10000, "'); delete revoked; --"])
def test_adversarial_jti_is_redis_argument_not_command(state, jti):
    _, client, _ = state
    client.sismember.return_value = True
    assert auth._is_token_revoked(jti) is True
    client.sismember.assert_called_once_with("bulwark:revoked_tokens", jti)
