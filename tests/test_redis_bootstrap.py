"""Tests for the shared Redis bootstrap helper and cross-store namespace safety.

Covers WS10 (#9): the four Redis-backed hot-path stores (risk state, session
decomposition tracker, dialog session store, correlation runtime config) now build
their client through :func:`src.redis_bootstrap.connect_redis`. These tests lock:

* the helper produces the exact client options the inlined blocks used
  (``decode_responses``, ``socket_timeout``, and the ``rediss://`` + tls-insecure
  → ``ssl.CERT_NONE`` handling), and
* the four stores occupy **disjoint** Redis key namespaces, so consolidating the
  *connection* bootstrap never risks one store reading/overwriting another's keys.
"""

from __future__ import annotations

import ssl

import pytest
import redis as _redis_pkg

from src.redis_bootstrap import connect_redis


class _FakeClient:
    def __init__(self, url: str, **kwargs):
        self.url = url
        self.kwargs = kwargs
        self.pinged = False

    def ping(self) -> bool:
        self.pinged = True
        return True


@pytest.fixture
def capture_from_url(monkeypatch):
    """Patch ``redis.from_url`` to record (url, kwargs) without connecting."""
    captured: dict = {}

    def fake_from_url(url, **kwargs):
        client = _FakeClient(url, **kwargs)
        captured["url"] = url
        captured["kwargs"] = kwargs
        captured["client"] = client
        return client

    monkeypatch.setattr(_redis_pkg, "from_url", fake_from_url)
    return captured


# --- helper option construction --------------------------------------------


def test_plain_redis_uses_standard_options_and_pings(capture_from_url):
    client = connect_redis("redis://localhost:6379/0")
    assert capture_from_url["url"] == "redis://localhost:6379/0"
    assert capture_from_url["kwargs"]["decode_responses"] is True
    assert capture_from_url["kwargs"]["socket_timeout"] == 1.0
    # Plain redis:// must never disable TLS verification (no ssl kwarg at all).
    assert "ssl_cert_reqs" not in capture_from_url["kwargs"]
    assert client.pinged is True


def test_rediss_with_tls_insecure_disables_cert_verification(capture_from_url):
    connect_redis("rediss://secure:6380/0", redis_tls_insecure=True)
    assert capture_from_url["kwargs"]["ssl_cert_reqs"] == ssl.CERT_NONE


def test_rediss_without_tls_insecure_keeps_verification(capture_from_url):
    connect_redis("rediss://secure:6380/0", redis_tls_insecure=False)
    assert "ssl_cert_reqs" not in capture_from_url["kwargs"]


def test_plain_redis_ignores_tls_insecure(capture_from_url):
    # tls_insecure only applies to rediss:// — a plain URL must stay untouched.
    connect_redis("redis://localhost:6379", redis_tls_insecure=True)
    assert "ssl_cert_reqs" not in capture_from_url["kwargs"]


def test_custom_socket_timeout_is_honoured(capture_from_url):
    connect_redis("redis://localhost:6379", socket_timeout=0.1)
    assert capture_from_url["kwargs"]["socket_timeout"] == 0.1


def test_ping_can_be_deferred(capture_from_url):
    client = connect_redis("redis://localhost:6379", ping=False)
    assert client.pinged is False


def test_connection_error_propagates(monkeypatch):
    # The helper must NOT swallow errors — callers own their degradation path.
    def boom(url, **kwargs):
        raise ConnectionError("no redis")

    monkeypatch.setattr(_redis_pkg, "from_url", boom)
    with pytest.raises(ConnectionError):
        connect_redis("redis://localhost:6379")


# --- stores actually route through the helper ------------------------------


def test_risk_state_initialize_uses_helper(capture_from_url, monkeypatch):
    from src.correlation.risk_state import RiskStateStore

    # register_script is called after connect on the fake client.
    monkeypatch.setattr(
        _FakeClient, "register_script", lambda self, script: "sha", raising=False
    )
    store = RiskStateStore()
    store.initialize(redis_url="rediss://x:6380", redis_tls_insecure=True)
    assert store._redis is capture_from_url["client"]
    assert capture_from_url["kwargs"]["ssl_cert_reqs"] == ssl.CERT_NONE


def test_session_tracker_initialize_uses_helper(capture_from_url):
    from src.guardrails.session_tracker import SessionDecompositionTracker

    t = SessionDecompositionTracker()
    t.initialize(redis_url="redis://x:6379")
    assert t._redis is capture_from_url["client"]
    assert t._initialized is True


def test_dialog_store_initialize_uses_helper(capture_from_url):
    from src.dialog.session_store import DialogSessionStore

    s = DialogSessionStore()
    s.initialize(redis_url="redis://x:6379")
    assert s._redis is capture_from_url["client"]


def test_correlation_runtime_initialize_uses_helper(capture_from_url):
    from src.correlation.runtime import CorrelationRuntimeConfig

    rt = CorrelationRuntimeConfig()
    rt.initialize(redis_url="redis://x:6379")
    assert rt._redis is capture_from_url["client"]


def test_store_degrades_when_helper_raises(monkeypatch):
    # A connection failure must degrade to in-memory (self._redis is None), never
    # propagate out of initialize() — each store keeps its own try/except.
    def boom(url, **kwargs):
        raise ConnectionError("no redis")

    monkeypatch.setattr(_redis_pkg, "from_url", boom)

    from src.correlation.risk_state import RiskStateStore
    from src.correlation.runtime import CorrelationRuntimeConfig
    from src.dialog.session_store import DialogSessionStore
    from src.guardrails.session_tracker import SessionDecompositionTracker

    for store, kwargs in (
        (RiskStateStore(), {}),
        (SessionDecompositionTracker(), {}),
        (DialogSessionStore(), {}),
        (CorrelationRuntimeConfig(), {}),
    ):
        store.initialize(redis_url="redis://x:6379", **kwargs)
        assert store._redis is None
        assert store._initialized is True


# --- namespace disjointness -------------------------------------------------


def test_store_key_prefixes_are_disjoint():
    """The four stores must not share a Redis key prefix.

    Distinct purposes, distinct namespaces: sharing a bootstrap must never imply
    sharing keys. Guards against a future rename accidentally colliding them.
    """
    from src.correlation import risk_state, runtime
    from src.dialog import session_store
    from src.guardrails import session_tracker

    prefixes = {
        "risk": risk_state._KEY_PREFIX,                # bulwark:risk
        "dialog": session_store._KEY_PREFIX,           # bulwark:dialog
        "session_cfg": session_tracker.RUNTIME_CONFIG_KEY,   # bulwark:session:config
        "correlation_cfg": runtime.RUNTIME_CONFIG_KEY,       # bulwark:correlation:config
    }
    values = list(prefixes.values())
    assert len(set(values)) == len(values), f"duplicate namespace: {prefixes}"

    # No prefix may be a prefix of another (would let one store's scan hit
    # another's keys).
    for a in values:
        for b in values:
            if a is b:
                continue
            assert not b.startswith(a + ":"), f"{b} nests under {a}"


def test_risk_and_dialog_digest_keys_never_collide():
    """Same logical input, different store ⇒ different Redis key.

    Both hash to a 16-hex digest; the per-store prefix is what keeps them apart.
    """
    from src.correlation.risk_state import RiskStateStore
    from src.dialog.session_store import DialogSessionStore

    risk_key = RiskStateStore._redis_key("session", "tenant-a:agent-b")
    dialog_key = DialogSessionStore._redis_key("tenant-a:agent-b")
    assert risk_key.startswith("bulwark:risk:")
    assert dialog_key.startswith("bulwark:dialog:")
    assert risk_key != dialog_key
