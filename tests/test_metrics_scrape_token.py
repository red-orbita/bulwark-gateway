"""Auth tests for the dedicated Prometheus metrics scrape token.

The metrics endpoint (/admin/health/metrics) must be scrapeable by Prometheus
without a user session, but MUST NOT become an open endpoint. It accepts either:

  * a normal admin:read JWT/session (unchanged behaviour), or
  * a dedicated static bearer token (METRICS_SCRAPE_TOKEN) compared in constant
    time, scoped to this endpoint only.

Security properties proven here (per project convention: positive + negative +
bypass attempts):
  * correct token  -> 200 (happy path)
  * wrong token    -> 401 (no fallback session) — bypass attempt rejected
  * token prefix   -> 401 — constant-time full-match, not a prefix match
  * token unset    -> scrape path is inert (no insecure default); JWT required
  * no credentials -> 401
  * valid JWT      -> 200 via the fallback path (endpoint still works normally)
"""

from __future__ import annotations

import os

# Test-safe environment MUST be set before importing admin.* modules.
os.environ.setdefault("ADMIN_DEBUG", "true")
os.environ.setdefault("ADMIN_JWT_SECRET", "metrics-token-test-secret-32chars-min!!!")
os.environ.setdefault("BULWARK_JWT_SECRET", "metrics-token-test-secret-32chars-min!!!")
os.environ.setdefault("BULWARK_KEY_ENCRYPTION_KEY", "metrics-token-test-encryption-32chars-mn")

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from admin.main import app
from admin.models.auth import TokenPayload, UserRole
from admin.services import auth_service

_METRICS_PATH = "/admin/health/metrics"
_GOOD_TOKEN = "a" * 64  # shaped like `openssl rand -hex 32`


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def with_token(monkeypatch):
    """Configure a known scrape token for the duration of a test."""
    monkeypatch.setattr(auth_service, "METRICS_SCRAPE_TOKEN", _GOOD_TOKEN)
    return _GOOD_TOKEN


def _fake_user(role: UserRole) -> TokenPayload:
    now = datetime.now(timezone.utc)
    return TokenPayload(sub=f"test-{role.value}", role=role,
                        exp=now + timedelta(hours=1), iat=now)


# ── Positive: correct token scrapes successfully ──────────────────────────
def test_correct_token_grants_scrape(client, with_token):
    r = client.get(_METRICS_PATH, headers={"Authorization": f"Bearer {with_token}"})
    assert r.status_code == 200
    assert "bulwark_" in r.text


# ── Negative / bypass: wrong or partial token is rejected ─────────────────
def test_wrong_token_rejected(client, with_token):
    r = client.get(_METRICS_PATH, headers={"Authorization": "Bearer " + ("b" * 64)})
    assert r.status_code == 401


def test_token_prefix_does_not_match(client, with_token):
    # Constant-time FULL comparison: a correct prefix must not authenticate.
    r = client.get(_METRICS_PATH, headers={"Authorization": f"Bearer {_GOOD_TOKEN[:32]}"})
    assert r.status_code == 401


def test_empty_bearer_rejected(client, with_token):
    r = client.get(_METRICS_PATH, headers={"Authorization": "Bearer "})
    assert r.status_code == 401


# ── No insecure default: unset token disables the scrape path entirely ────
def test_unset_token_disables_scrape_path(client, monkeypatch):
    monkeypatch.setattr(auth_service, "METRICS_SCRAPE_TOKEN", "")
    # Even presenting *some* bearer must not authenticate when disabled.
    r = client.get(_METRICS_PATH, headers={"Authorization": f"Bearer {_GOOD_TOKEN}"})
    assert r.status_code == 401


def test_no_credentials_rejected(client, with_token):
    r = client.get(_METRICS_PATH)
    assert r.status_code == 401


# ── Fallback: a genuine admin:read session still works via JWT path ───────
def test_valid_session_still_scrapes(client, with_token, monkeypatch):
    # The fallback path calls get_current_user directly (not via Depends), so
    # patch the module global to simulate a validated admin session.
    async def _fake_current_user(request, credentials=None):
        return _fake_user(UserRole.ADMIN)

    monkeypatch.setattr(auth_service, "get_current_user", _fake_current_user)
    r = client.get(_METRICS_PATH)  # no scrape token header -> JWT fallback
    assert r.status_code == 200
    assert "bulwark_" in r.text


def test_valid_session_without_permission_rejected(client, with_token, monkeypatch):
    # A validated session that lacks admin:read must still be rejected 403.
    async def _fake_current_user(request, credentials=None):
        return _fake_user(UserRole.VIEWER)

    # Temporarily strip admin:read from VIEWER to prove the permission gate runs.
    from admin.models.auth import ROLE_PERMISSIONS
    original = ROLE_PERMISSIONS.get(UserRole.VIEWER, set())
    monkeypatch.setitem(ROLE_PERMISSIONS, UserRole.VIEWER, original - {"admin:read"})
    monkeypatch.setattr(auth_service, "get_current_user", _fake_current_user)
    r = client.get(_METRICS_PATH)
    assert r.status_code == 403


def test_scrape_token_unit_returns_service_principal():
    """The scrape-token branch returns a synthetic, low-privilege principal."""
    import asyncio

    from fastapi.security import HTTPAuthorizationCredentials

    auth_service.METRICS_SCRAPE_TOKEN = _GOOD_TOKEN
    try:
        dep = auth_service.require_permission_or_scrape_token("admin:read")
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=_GOOD_TOKEN)
        payload = asyncio.run(dep(request=None, credentials=creds))
        assert payload.sub == "prometheus-scraper"
        assert payload.role == UserRole.VIEWER
    finally:
        auth_service.METRICS_SCRAPE_TOKEN = ""
