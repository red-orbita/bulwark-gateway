"""Virtual Keys — data-path enforcement tests.

These tests close the audit finding that the Virtual Keys subsystem was a
facade: a real encrypted vault existed, but the proxy request path NEVER
consulted it (backend auth came solely from static tokens in agents.yaml).

They prove the opposite is now true:

  1. ``_resolve_backend_auth`` (the exact function called inside the proxy
     backend loop) sources the credential from the encrypted vault when the
     backend declares a ``provider``, decrypts it, and builds the auth header.
  2. It fails closed when a provider is declared but no credential exists.
  3. End-to-end through the real proxy app, a request to a provider-backed
     agent forwards the *decrypted vault key* to the backend — and a missing
     key yields ``502 backend_credential_unavailable`` instead of an
     unauthenticated forward.

Positive AND negative cases are covered per project convention.
"""

from __future__ import annotations

import os

# Test-safe environment MUST be set before importing src.* modules.
os.environ.setdefault("BULWARK_JWT_SECRET", "test-secret-key-for-vk-dataplane-32chars!!")
os.environ.setdefault("BULWARK_API_KEYS_ENABLED", "true")
os.environ.setdefault("BULWARK_API_KEYS", "test-vk-dataplane-key")
os.environ.setdefault("BULWARK_RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("BULWARK_DEBUG", "true")
os.environ.setdefault("BULWARK_REDIS_URL", "")
os.environ.setdefault("BULWARK_BACKEND_URL", "http://backend.internal:11434")
# Mandatory for the virtual-key vault (Fernet key derivation).
os.environ.setdefault("BULWARK_KEY_ENCRYPTION_KEY", "vk-dataplane-encryption-key-32-chars!")

from dataclasses import dataclass

import pytest

import src.routes.proxy as proxy
import src.services.virtual_keys as vk_module
from src.routes.proxy import _resolve_backend_auth
from src.services.agent_registry import AgentBackend

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


@dataclass
class _FakeBackend:
    """Minimal stand-in for AgentBackend used by the unit tests."""

    provider: str | None = None
    auth_header: str | None = None
    auth_token: str | None = None
    auth_scheme: str = "Bearer "


@pytest.fixture()
def fresh_vault():
    """Reset the vault singleton so the encryption key is deterministic."""
    vk_module._manager = None
    mgr = vk_module.get_virtual_key_manager()
    yield mgr
    vk_module._manager = None


# --------------------------------------------------------------------------- #
# Unit tests: _resolve_backend_auth (the data-path function)
# --------------------------------------------------------------------------- #


class TestResolveBackendAuthUnit:
    def test_vault_key_takes_precedence_and_is_decrypted(self, fresh_vault):
        """A provider-backed backend uses the DECRYPTED vault key, not config."""
        real_key = "sk-openai-REAL-secret-abc123"
        fresh_vault.create_key(
            tenant_id="acme", provider="openai", backend_api_key=real_key
        )

        backend = _FakeBackend(
            provider="openai",
            auth_header="Authorization",
            auth_token="Bearer sk-STALE-static-token",  # noqa: S106 - test fixture, must be ignored
            auth_scheme="Bearer ",
        )
        headers, error = _resolve_backend_auth(backend, "acme")

        assert error is None
        # The decrypted vault key must be present — proving the vault is on path.
        assert headers["Authorization"] == f"Bearer {real_key}"
        assert "STALE" not in headers["Authorization"]

    def test_custom_auth_scheme_is_applied(self, fresh_vault):
        """Azure-style ``api-key`` header with empty scheme works."""
        fresh_vault.create_key(
            tenant_id="acme", provider="azure", backend_api_key="azure-secret-xyz"
        )
        backend = _FakeBackend(
            provider="azure", auth_header="api-key", auth_scheme=""
        )
        headers, error = _resolve_backend_auth(backend, "acme")

        assert error is None
        assert headers["api-key"] == "azure-secret-xyz"

    def test_migration_fallback_to_static_token(self, fresh_vault):
        """Provider declared but no vault key yet → honor static token (migration)."""
        backend = _FakeBackend(
            provider="openai",
            auth_header="Authorization",
            auth_token="Bearer sk-static-during-migration",  # noqa: S106 - test fixture
        )
        headers, error = _resolve_backend_auth(backend, "no-vault-tenant")

        assert error is None
        assert headers["Authorization"] == "Bearer sk-static-during-migration"

    def test_fail_closed_when_provider_declared_but_no_credential(self, fresh_vault):
        """Provider declared, no vault key, no static token → hard error."""
        backend = _FakeBackend(provider="openai", auth_header=None, auth_token=None)
        headers, error = _resolve_backend_auth(backend, "empty-tenant")

        assert error is not None
        assert "openai" in error
        assert headers == {}

    def test_legacy_no_provider_uses_static_auth(self, fresh_vault):
        """No provider → legacy static behavior, no vault lookup, no error."""
        backend = _FakeBackend(
            provider=None,
            auth_header="Authorization",
            auth_token="Bearer legacy-static",  # noqa: S106 - test fixture
        )
        headers, error = _resolve_backend_auth(backend, "acme")

        assert error is None
        assert headers["Authorization"] == "Bearer legacy-static"

    def test_legacy_no_provider_no_token_is_unauthenticated_but_ok(self, fresh_vault):
        """No provider and no token → empty headers, no error (open backend)."""
        backend = _FakeBackend(provider=None, auth_header=None, auth_token=None)
        headers, error = _resolve_backend_auth(backend, "acme")

        assert error is None
        assert headers == {}

    def test_vault_unavailable_without_encryption_key(self, monkeypatch):
        """If the encryption key is unset, the vault must never crash the path."""
        monkeypatch.delenv("BULWARK_KEY_ENCRYPTION_KEY", raising=False)
        # Provider declared, no static token → fail closed (no key resolvable).
        backend = _FakeBackend(provider="openai")
        headers, error = _resolve_backend_auth(backend, "acme")
        assert error is not None
        assert headers == {}


# --------------------------------------------------------------------------- #
# End-to-end: through the real proxy app
# --------------------------------------------------------------------------- #


class _CapturingResponse:
    status_code = 200
    headers: dict[str, str] = {}
    content = b"{}"

    def json(self):
        return {
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "Hello!"},
                    "finish_reason": "stop",
                }
            ],
        }


class _CapturingClient:
    """Fake shared httpx client that records the outgoing backend headers."""

    def __init__(self, sink: dict):
        self._sink = sink

    async def post(self, url, json=None, headers=None):
        self._sink["url"] = url
        self._sink["headers"] = dict(headers or {})
        return _CapturingResponse()


@pytest.fixture(scope="module")
def app_client():
    """Module-scoped app + client.

    The lifespan is entered exactly once for the module. Re-entering the
    ASGI lifespan across multiple TestClient instances in the same module
    rebinds module-level async singletons (telemetry queue) to a fresh event
    loop and raises at teardown — so we share a single client instead.
    """
    import hashlib

    from fastapi.testclient import TestClient

    import src.middleware.auth as auth
    import src.telemetry.exporter as _tele_exporter
    import src.telemetry.queue as _tele_queue
    from src.main import create_app

    # Deterministic auth: bind our API key to the "default" tenant directly.
    # Env-based BULWARK_API_KEYS is unreliable here because another test module
    # may have already fixed it via setdefault before our module was imported.
    key_hash = hashlib.sha256(b"test-vk-dataplane-key").hexdigest()
    _added = key_hash not in auth._API_KEY_BINDINGS
    auth._API_KEY_BINDINGS[key_hash] = "default"

    # Reset telemetry singletons so the async queue/exporter are (re)created on
    # THIS module's TestClient portal loop. Otherwise a queue built during an
    # earlier module's lifespan is torn down here on a different event loop,
    # raising "Queue is bound to a different event loop" at teardown.
    _tele_exporter._exporter = None
    _tele_queue._queue = None

    app = create_app()
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            yield app, client
    finally:
        if _added:
            auth._API_KEY_BINDINGS.pop(key_hash, None)
        # Leave clean singletons for any module that runs afterwards.
        _tele_exporter._exporter = None
        _tele_queue._queue = None


def _auth_headers(tenant: str, agent: str) -> dict[str, str]:
    return {
        "Authorization": "Bearer test-vk-dataplane-key",
        "X-Tenant-ID": tenant,
        "X-Agent-ID": agent,
        "Content-Type": "application/json",
    }


def _benign_body() -> dict:
    return {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Hello there, how are you today?"}],
        "stream": False,
    }


class TestProxyForwardsVaultKey:
    def test_proxy_injects_decrypted_vault_key_into_backend_request(
        self, app_client, fresh_vault, monkeypatch
    ):
        """E2E: proxy forwards the decrypted vault key to the backend."""
        app, client = app_client
        real_key = "sk-e2e-REAL-vault-secret-999"
        # The API key without a ``:tenant`` suffix binds to the "default" tenant
        # (see auth middleware CRIT-01), so the vault + agent live under "default".
        fresh_vault.create_key(
            tenant_id="default", provider="openai", backend_api_key=real_key
        )

        # Register a provider-backed agent on the live registry.
        app.state.agent_registry.register(
            "default",
            "vk-chat",
            AgentBackend(
                backend_url="http://backend.internal:11434",
                path_prefix="/v1",
                provider="openai",
                auth_header="Authorization",
                auth_scheme="Bearer ",
            ),
        )

        # Isolate the vault behavior from the (unrelated) SSRF DNS check, which
        # would otherwise fail-closed on a non-resolvable test hostname.
        async def _no_ssrf(*a, **k):
            return False

        monkeypatch.setattr(proxy, "_async_is_ssrf_target", _no_ssrf)

        sink: dict = {}
        monkeypatch.setattr(
            proxy, "_get_shared_client", lambda timeout=120.0: _CapturingClient(sink)
        )
        monkeypatch.setattr(
            app.state.agent_registry, "_file_changed", lambda: False
        )

        resp = client.post(
            "/v1/chat/completions",
            json=_benign_body(),
            headers=_auth_headers("default", "vk-chat"),
        )

        assert resp.status_code == 200, resp.text
        # The backend received the DECRYPTED vault key — the vault is on the path.
        assert sink["headers"].get("Authorization") == f"Bearer {real_key}"

    def test_proxy_fails_closed_when_no_credential(
        self, app_client, fresh_vault, monkeypatch
    ):
        """E2E: provider declared but no key → 502, never an unauth forward."""
        app, client = app_client

        app.state.agent_registry.register(
            "default",
            "vk-nokey",
            AgentBackend(
                backend_url="http://backend.internal:11434",
                path_prefix="/v1",
                provider="openai",
                auth_header="Authorization",
                auth_scheme="Bearer ",
            ),
        )

        called = {"posted": False}

        class _NeverCalledClient:
            async def post(self, *a, **k):
                called["posted"] = True
                return _CapturingResponse()

        async def _no_ssrf(*a, **k):
            return False

        monkeypatch.setattr(proxy, "_async_is_ssrf_target", _no_ssrf)
        monkeypatch.setattr(
            proxy, "_get_shared_client", lambda timeout=120.0: _NeverCalledClient()
        )
        monkeypatch.setattr(
            app.state.agent_registry, "_file_changed", lambda: False
        )

        resp = client.post(
            "/v1/chat/completions",
            json=_benign_body(),
            headers=_auth_headers("default", "vk-nokey"),
        )

        assert resp.status_code == 502, resp.text
        body = resp.json()
        assert body["error"]["code"] == "backend_credential_unavailable"
        # Critically: we must NOT have forwarded an unauthenticated request.
        assert called["posted"] is False
