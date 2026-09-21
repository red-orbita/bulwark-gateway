"""Attachment ownership through real authentication and application middleware."""

import asyncio
import hashlib
import secrets
import time
from types import SimpleNamespace

import httpx
import jwt
import pytest

from src.attachments import runtime
from src.attachments.service import AttachmentService
from src.config import settings
from src.guardrails.attachments import AttachmentPolicy
from src.guardrails.tool_policy import AgentPolicy, ToolPolicyEngine
from src.middleware import auth, quotas, rate_limit


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """No admin database writes for API tests."""


@pytest.fixture
async def client(tmp_path, monkeypatch):
    from src.main import create_app

    for key, value in {
        "api_keys_enabled": True, "jwt_algorithm": "HS256", "jwt_secret": secrets.token_hex(32),
        "cors_origins": ["https://chat.example"], "redis_url": None, "dedicated_tenants": [],
        "attachment_service_enabled": True, "workers": 1, "rate_limit_enabled": False,
        "siem_request_audit_enabled": False,
    }.items():
        monkeypatch.setattr(settings, key, value)
    monkeypatch.setattr(auth, "_ALLOWED_TENANTS", set())
    monkeypatch.setattr(auth, "_API_KEY_BINDINGS", {})
    monkeypatch.setattr(quotas, "_tenant_quotas", {})
    # Only the revocation dependency is stubbed; signing and claims are real.
    monkeypatch.setattr(auth, "_is_token_revoked", lambda jti: jti == "revoked")
    url_file = tmp_path / "url"
    url_file.write_text(f"sqlite:///{tmp_path / 'attachments.db'}")
    monkeypatch.setattr(settings, "attachment_service_db_url_file", url_file)

    async def parked(self):
        await asyncio.Event().wait()

    monkeypatch.setattr(AttachmentService, "_run", parked)
    app = create_app()
    engine = ToolPolicyEngine()
    for tenant in ("tenant-a", "tenant-b"):
        engine.register_policy(AgentPolicy(tenant_id=tenant, agent_id="agent-a", attachments=AttachmentPolicy(async_enabled=True)))
    app.state.policy_loader = SimpleNamespace(engine=engine)
    service = await runtime.start_attachment_service(app, settings)
    app.state.attachment_service = service
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as http:
            yield http, service
    finally:
        await service.stop()


def token(sub="user-a", **overrides):
    claims = dict(sub=sub, tenant_id="tenant-a", agent_id="agent-a", iss=settings.jwt_issuer,
                  aud=settings.jwt_audience, exp=int(time.time()) + 300, jti=secrets.token_hex(16))
    claims.update(overrides)
    return jwt.encode(claims, settings.jwt_secret, algorithm="HS256")


def headers(credential):
    return {"Authorization": f"Bearer {credential}", "Content-Type": "text/plain", "X-Agent-ID": "agent-a"}


@pytest.mark.parametrize("method", ["POST", "GET", "DELETE"])
async def test_real_application_cors_preflight_and_unauthenticated_request(client, method):
    http, _ = client
    response = await http.options("/v1/attachments", headers={
        "Origin": "https://chat.example", "Access-Control-Request-Method": method,
        "Access-Control-Request-Headers": "authorization,content-type,x-agent-id",
    })
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://chat.example"
    response = await http.request(method, "/v1/attachments", headers={"Origin": "https://chat.example"})
    assert response.status_code == 401
    assert response.headers["access-control-allow-origin"] == "https://chat.example"
    rejected = await http.options("/v1/attachments", headers={
        "Origin": "https://evil.example", "Access-Control-Request-Method": method,
    })
    assert rejected.status_code == 400 and "access-control-allow-origin" not in rejected.headers


@pytest.mark.parametrize("claims", [{"exp": 1}, {"aud": "admin"}, {"iss": "other"}, {"jti": "revoked"},
                                   {"sub": None}, {"tenant_id": []}, {"agent_id": {}}, {"tenant_id": "tenant-a\n"}])
async def test_invalid_claims_never_admit_upload(client, claims):
    http, service = client
    response = await http.post("/v1/attachments", content="report", headers=headers(token(**claims)))
    assert response.status_code in (400, 401)
    assert not await service.process_once()


@pytest.mark.parametrize("identity", ["long_sub", "key_namespace", "tenant"])
async def test_distinct_owners_cannot_access_same_document(client, identity, monkeypatch):
    http, service = client
    if identity == "long_sub":
        first, second = token("x" * 128 + "first"), token("x" * 128 + "second")
    elif identity == "key_namespace":
        first = secrets.token_hex(24)
        digest = hashlib.sha256(first.encode()).hexdigest()
        monkeypatch.setitem(auth._API_KEY_BINDINGS, digest, "tenant-a")
        second = token(digest[:16])
    else:
        first, second = token(), token(tenant_id="tenant-b")
    response = await http.post("/v1/attachments", content="Quarterly report", headers=headers(first))
    assert response.status_code == 202, response.text
    doc = response.json()
    await service.process_once()
    path = f"/v1/attachments/{doc['id']}"
    assert (await http.get(path, headers=headers(first))).json()["state"] == "approved"
    forged = {**headers(second), "X-Tenant-ID": "tenant-a", "X-Subject-ID": "user-a", "X-Attachment-Owner": "user-a"}
    assert (await http.get(path, headers=forged)).status_code == 404
    assert (await http.delete(path, headers=forged)).status_code == 404
    assert (await http.delete(path, headers=headers(first))).status_code == 204


async def test_development_auth_mode_does_not_authorize_attachments(client, monkeypatch):
    http, _ = client
    monkeypatch.setattr(settings, "api_keys_enabled", False)
    response = await http.post("/v1/attachments", content="report", headers=headers(token()))
    assert response.status_code == 401


async def test_attachment_quota_bounded_stream_and_model_budget_independence(client, monkeypatch):
    http, _ = client
    quotas.register_tenant_quotas("tenant-a", quotas.TenantQuotaConfig(
        max_request_size_bytes=5, allowed_models=["permitted-model"], max_tokens_per_day=1,
    ))
    monkeypatch.setattr(quotas.TokenBudgetTracker, "get_remaining", lambda *args: 0)
    consumed = []

    async def chunks():
        consumed.append(1)
        yield b"123456"
        pytest.fail("quota rejection must stop receiving body")

    response = await http.post("/v1/attachments", content=chunks(), headers=headers(token()))
    assert response.status_code == 413 and consumed == [1]
    accepted = await http.post("/v1/attachments", content="hello", headers=headers(token()))
    assert accepted.status_code == 202
    doc = accepted.json()
    # Exhausting the LLM token budget must not prevent deleting private uploads.
    assert (await http.delete(f"/v1/attachments/{doc['id']}", headers=headers(token()))).status_code == 204


async def test_attachment_routes_keep_rate_limit(client, monkeypatch):
    http, _ = client
    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    monkeypatch.setattr(rate_limit.InMemoryTokenBucket, "consume", lambda *args, **kwargs: False)
    response = await http.post("/v1/attachments", content="report", headers=headers(token()))
    assert response.status_code == 429


async def test_readiness_tracks_worker_without_credentials(client):
    http, service = client
    assert (await http.get("/ready/attachments")).status_code == 200
    service.ready = False
    response = await http.get("/ready/attachments")
    assert response.status_code == 503 and response.json() == {"status": "not_ready"}
