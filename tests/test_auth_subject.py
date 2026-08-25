"""Auth middleware — subject propagation (F3 blast-radius).

The correlation engine hardens on the *most-specific authenticated identity* so a
single abusive actor is blocked without penalising every user sharing the agent.
That requires the auth middleware to derive a server-side ``subject_id`` and attach
it to ``request.state`` — never from a client header, never logged/exported.

These tests pin:

* ``_validate_api_key`` returns ``(tenant, stable-digest)`` and rejects bad keys.
* The middleware attaches ``request.state.subject_id`` for both the API-key path
  (a stable per-key digest) and the JWT path (the ``sub`` claim).
* An anonymous/legacy caller (no ``sub``) yields ``subject_id is None`` — the
  correlation engine then falls back to the session scope.
* The subject digest is NOT the raw key (irreversibility / no secret leakage).

No credential-like literals are hardcoded — keys are generated at runtime.
"""

from __future__ import annotations

import hashlib
import secrets
import time

import jwt
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

import src.middleware.auth as auth
from src.config import settings
from src.middleware.auth import AuthMiddleware


def _echo_app() -> Starlette:
    async def echo(request):
        return JSONResponse(
            {
                "tenant_id": getattr(request.state, "tenant_id", None),
                "subject_id": getattr(request.state, "subject_id", None),
            }
        )

    app = Starlette(routes=[Route("/v1/echo", echo, methods=["POST"])])
    app.add_middleware(AuthMiddleware)
    return app


# ─── _validate_api_key contract ─────────────────────────────────────────────


def test_validate_api_key_returns_tenant_and_stable_digest(monkeypatch):
    key = secrets.token_hex(24)
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    monkeypatch.setitem(auth._API_KEY_BINDINGS, key_hash, "acme")
    try:
        mw = AuthMiddleware(app=None)  # type: ignore[arg-type]
        result = mw._validate_api_key(key)
        assert result is not None
        tenant, subject_digest = result
        assert tenant == "acme"
        # Stable, fixed-length, non-reversible: exactly the SHA-256[:16] of the key.
        assert subject_digest == key_hash[:16]
        assert len(subject_digest) == 16
        # NOT the raw key.
        assert subject_digest != key
        assert key not in subject_digest
        # Deterministic across calls.
        assert mw._validate_api_key(key) == result
    finally:
        auth._API_KEY_BINDINGS.pop(key_hash, None)


def test_validate_api_key_rejects_unknown_and_short(monkeypatch):
    mw = AuthMiddleware(app=None)  # type: ignore[arg-type]
    key = secrets.token_hex(24)
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    monkeypatch.setitem(auth._API_KEY_BINDINGS, key_hash, "acme")
    try:
        assert mw._validate_api_key(secrets.token_hex(24)) is None  # unknown
        assert mw._validate_api_key("short") is None  # < 16 chars
    finally:
        auth._API_KEY_BINDINGS.pop(key_hash, None)


# ─── middleware attaches request.state.subject_id ───────────────────────────


def test_api_key_subject_propagates_to_request_state(monkeypatch):
    monkeypatch.setattr(settings, "api_keys_enabled", True, raising=False)
    key = secrets.token_hex(24)
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    monkeypatch.setitem(auth._API_KEY_BINDINGS, key_hash, "acme")
    try:
        client = TestClient(_echo_app(), raise_server_exceptions=False)
        resp = client.post(
            "/v1/echo",
            headers={"Authorization": f"Bearer {key}", "X-Tenant-ID": "ignored"},
        )
        assert resp.status_code == 200
        body = resp.json()
        # CRIT-01: tenant is the bound tenant, not the header.
        assert body["tenant_id"] == "acme"
        # F3: subject is the stable per-key digest.
        assert body["subject_id"] == key_hash[:16]
    finally:
        auth._API_KEY_BINDINGS.pop(key_hash, None)


def _encode_jwt(secret: str, *, sub: str | None, tenant: str = "acme") -> str:
    claims = {
        "tenant_id": tenant,
        "aud": getattr(settings, "jwt_audience", "bulwark-proxy"),
        "iss": getattr(settings, "jwt_issuer", "bulwark-gateway"),
        "exp": int(time.time()) + 300,
        "jti": secrets.token_hex(8),
    }
    if sub is not None:
        claims["sub"] = sub
    return jwt.encode(claims, secret, algorithm="HS256")


def test_jwt_sub_propagates_as_subject(monkeypatch):
    secret = secrets.token_hex(24)  # 48 chars, passes the 32+ length gate
    monkeypatch.setattr(settings, "api_keys_enabled", True, raising=False)
    monkeypatch.setattr(settings, "jwt_secret", secret, raising=False)
    monkeypatch.setattr(settings, "jwt_algorithm", "HS256", raising=False)
    # Revocation is fail-closed without Redis (C-04); this test isolates subject
    # propagation, so stub the revocation check to "not revoked".
    monkeypatch.setattr(auth, "_is_token_revoked", lambda jti: False)

    token = _encode_jwt(secret, sub="user-77")
    client = TestClient(_echo_app(), raise_server_exceptions=False)
    resp = client.post("/v1/echo", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["tenant_id"] == "acme"
    assert body["subject_id"] == "user-77"


def test_jwt_without_sub_yields_anonymous_subject(monkeypatch):
    secret = secrets.token_hex(24)
    monkeypatch.setattr(settings, "api_keys_enabled", True, raising=False)
    monkeypatch.setattr(settings, "jwt_secret", secret, raising=False)
    monkeypatch.setattr(settings, "jwt_algorithm", "HS256", raising=False)
    monkeypatch.setattr(auth, "_is_token_revoked", lambda jti: False)

    token = _encode_jwt(secret, sub=None)
    client = TestClient(_echo_app(), raise_server_exceptions=False)
    resp = client.post("/v1/echo", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    # No sub claim → no subject → correlation falls back to session scope.
    assert resp.json()["subject_id"] is None
