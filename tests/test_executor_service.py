"""Isolated ASGI tests: no sockets, databases, models, or external tool effects."""

import asyncio
import json
import time
from unittest.mock import AsyncMock

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import HTTPException
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_serializer,
    field_validator,
    model_serializer,
)

from src.executor.app import (
    ExecutorSettings,
    RegisteredTool,
    action_digest,
    create_app,
)
from src.executor.replay import MemoryReplayStore, RedisReplayStore
from src.guardrails.output_filter import OutputFilter
from src.guardrails.tool_policy import AgentPolicy, ToolPolicy, ToolPolicyEngine
from src.models import GuardrailResult, Verdict


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Override admin DB fixture: this standalone service never uses the admin DB."""


class LookupArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    item: str = Field(min_length=1, max_length=100)


class Harness:
    def __init__(self, **overrides):
        self.key = Ed25519PrivateKey.generate()
        self.settings = ExecutorSettings(
            public_key_pem=self.key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(),
            issuer="corporate-issuer", audience="dedicated-executor", development=True,
            **overrides,
        )
        self.calls = []

        async def lookup(arguments, context):
            self.calls.append((arguments, context))
            return "Public item information"

        self.tool = RegisteredTool(LookupArgs, lookup)
        self.policy = AgentPolicy(tenant_id="corp", agent_id="assistant", sandbox_level="strict",
                                  allowed_tools=["lookup"], max_tool_calls_per_request=1)
        self.store = MemoryReplayStore()
        self.principals = frozenset({("corp", "assistant", "operator")})
        self.body = {"request_id": "action-1", "tool": "lookup", "arguments": {"item": "public-item"}}

    def app(self, **overrides):
        kwargs = dict(settings=self.settings, tools={"lookup": self.tool}, policies=[self.policy],
                      principals=self.principals, replay_store=self.store)
        kwargs.update(overrides)
        return create_app(**kwargs)

    def claims(self, body=None, **overrides):
        body = body or self.body
        now = int(time.time())
        claims = dict(iss="corporate-issuer", aud="dedicated-executor", sub="operator", tenant_id="corp",
                      agent_id="assistant", jti="token-1", iat=now, exp=now + 120,
                      request_id=body["request_id"], action_sha256=action_digest(body["tool"], body["arguments"]))
        claims.update(overrides)
        return claims

    def headers(self, body=None, **overrides):
        return {"Authorization": "Bearer " + jwt.encode(self.claims(body, **overrides), self.key, algorithm="EdDSA")}


@pytest.fixture
def harness():
    return Harness()


async def post(app, body, headers):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="https://executor.test") as client:
        return await client.post("/execute", json=body, headers=headers)


@pytest.mark.asyncio
async def test_happy_path_context_is_authenticated(harness):
    response = await post(harness.app(), harness.body,
                          {**harness.headers(), "X-Tenant-ID": "attacker", "X-Agent-ID": "evil"})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {"request_id": "action-1", "status": "completed", "output": "Public item information"}
    args, context = harness.calls[0]
    assert args.item == "public-item"
    assert (context.tenant_id, context.agent_id, context.subject) == ("corp", "assistant", "operator")
    assert not hasattr(context, "token")


@pytest.mark.asyncio
@pytest.mark.parametrize("claim,value", [
    ("iss", "other"), ("aud", "bulwark-proxy"), ("aud", ["dedicated-executor"]),
    ("sub", ""), ("sub", "other"), ("tenant_id", "other"), ("agent_id", "other"),
    ("exp", 1), ("exp", "9999999999"), ("iat", True), ("iat", 1),
    ("jti", "a:b"), ("jti", "x" * 129), ("tenant_id", "corp:assistant"),
    ("tenant_id", "c\u043erp"), ("request_id", "other"), ("action_sha256", "0" * 64),
])
async def test_invalid_or_unbound_identity_never_executes(harness, claim, value):
    response = await post(harness.app(), harness.body, harness.headers(**{claim: value}))
    assert response.status_code in {401, 403}
    assert not harness.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["iss", "aud", "sub", "tenant_id", "agent_id", "jti", "exp", "iat",
                                      "request_id", "action_sha256"])
async def test_required_claims(harness, missing):
    claims = harness.claims()
    del claims[missing]
    token = jwt.encode(claims, harness.key, algorithm="EdDSA")
    response = await post(harness.app(), harness.body, {"Authorization": "Bearer " + token})
    assert response.status_code == 401
    assert not harness.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["none", "wrong-key", "hmac", "missing", "large", "duplicate"])
async def test_signature_bypasses(harness, mode):
    if mode == "none":
        headers = {"Authorization": "Bearer " + jwt.encode(harness.claims(), "", algorithm="none")}
    elif mode == "wrong-key":
        headers = {"Authorization": "Bearer " + jwt.encode(harness.claims(), Ed25519PrivateKey.generate(), algorithm="EdDSA")}
    elif mode == "hmac":
        headers = {"Authorization": "Bearer " + jwt.encode(harness.claims(), "x" * 32, algorithm="HS256")}
    elif mode == "large":
        headers = {"Authorization": "Bearer " + "x" * 9000}
    elif mode == "duplicate":
        headers = list(harness.headers().items()) * 2
    else:
        headers = {}
    response = await post(harness.app(), harness.body, headers)
    assert response.status_code == 401
    assert not harness.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["tenant_id", "agent_id", "sub", "credentials", "calls", "handler", "url"])
async def test_no_body_identity_credentials_dispatch_or_batch(harness, field):
    body = {**harness.body, field: "private-agent-data"}
    response = await post(harness.app(), body, harness.headers())
    assert response.status_code == 422
    assert "private-agent-data" not in response.text
    assert not harness.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", ["web_search", "bash", "__import__", "lookup.upper", "Lookup", "lo\u200bokup"])
async def test_registry_is_closed_even_with_signed_token(harness, tool):
    body = {**harness.body, "tool": tool}
    response = await post(harness.app(), body, harness.headers(body))
    assert response.status_code in {403, 422}
    assert not harness.calls


@pytest.mark.asyncio
async def test_empty_explicit_allowlist_denies_safe_named_tool(harness):
    harness.policy.allowed_tools = []
    response = await post(harness.app(), harness.body, harness.headers())
    assert response.status_code == 403
    assert not harness.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("arguments", [
    {"item": 1}, {"item": "ok", "api_key": "secret"}, {}, {"item": "x" * 101},
    {"item": "../../.ssh/id_rsa"}, {"item": "http://169.254.169.254/latest"},
    {"item": "password=actual-private-credential-value"},
])
async def test_argument_validation_policy_and_dlp(harness, arguments):
    body = {**harness.body, "arguments": arguments}
    response = await post(harness.app(), body, harness.headers(body))
    assert response.status_code in {403, 422}
    assert not harness.calls


@pytest.mark.asyncio
async def test_tool_policy_specific_constraint(harness):
    harness.policy.tool_policies["lookup"] = ToolPolicy(name="lookup", denied_arguments={"item": ["public"]})
    response = await post(harness.app(), harness.body, harness.headers())
    assert response.status_code == 403
    assert not harness.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("allowed,budget", [(True, 0), (False, 1)])
async def test_tool_specific_deny_and_zero_budget(harness, allowed, budget):
    harness.policy.tool_policies["lookup"] = ToolPolicy(name="lookup", allowed=allowed, max_calls_per_request=budget)
    response = await post(harness.app(), harness.body, harness.headers())
    assert response.status_code == 403
    assert not harness.calls


@pytest.mark.asyncio
async def test_handler_http_exception_is_not_a_response_channel(harness):
    async def handler(arguments, context):
        harness.calls.append(context)
        raise HTTPException(200, "private-backend-secret", headers={"X-Secret": "private-backend-secret"})

    harness.tool = RegisteredTool(LookupArgs, handler)
    app = harness.app()
    response = await post(app, harness.body, harness.headers())
    assert response.status_code == 503
    assert "private-backend-secret" not in response.text
    assert "x-secret" not in response.headers
    assert response.headers["cache-control"] == "no-store"
    assert (await post(app, harness.body, harness.headers())).status_code == 409


@pytest.mark.asyncio
async def test_policy_snapshot_not_mutable_by_caller(harness):
    app = harness.app()
    harness.policy.allowed_tools.clear()
    assert (await post(app, harness.body, harness.headers())).status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["same", "new-jti", "new-action", "changed-body"])
async def test_replays_and_ambiguous_rebinding_never_repeat(harness, mode):
    app = harness.app()
    assert (await post(app, harness.body, harness.headers())).status_code == 200
    body = dict(harness.body)
    overrides = {}
    if mode == "new-jti":
        overrides["jti"] = "another-token"
    elif mode == "new-action":
        body["request_id"] = "action-2"
    elif mode == "changed-body":
        body["arguments"] = {"item": "another-item"}
    response = await post(app, body, harness.headers(body, **overrides))
    assert response.status_code == 409
    assert len(harness.calls) == 1


@pytest.mark.asyncio
async def test_concurrent_replay(harness):
    app = harness.app()
    async with asyncio.timeout(3):
        results = await asyncio.gather(*(post(app, harness.body, harness.headers()) for _ in range(4)))
    assert sorted(r.status_code for r in results) == [200, 409, 409, 409]
    assert len(harness.calls) == 1


@pytest.mark.asyncio
async def test_new_authorized_action_can_execute(harness):
    app = harness.app()
    assert (await post(app, harness.body, harness.headers())).status_code == 200
    body = {**harness.body, "request_id": "action-2", "arguments": {"item": "other-public-item"}}
    assert (await post(app, body, harness.headers(body, jti="token-2"))).status_code == 200
    assert len(harness.calls) == 2


@pytest.mark.asyncio
async def test_cross_tenant_action_ids_do_not_collide(harness):
    other = AgentPolicy(tenant_id="other", agent_id="assistant", allowed_tools=["lookup"], sandbox_level="strict")
    app = harness.app(policies=[harness.policy, other], principals=harness.principals | {("other", "assistant", "operator")})
    assert (await post(app, harness.body, harness.headers())).status_code == 200
    response = await post(app, harness.body, harness.headers(tenant_id="other", jti="token-2"))
    assert response.status_code == 200
    assert harness.calls[1][1].tenant_id == "other"


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["store", "policy", "dlp", "handler", "handler-validation"])
async def test_fail_closed_and_generic_errors(harness, monkeypatch, failure):
    error = RuntimeError("private credential and internal path")
    if failure == "store":
        harness.store.reserve = AsyncMock(side_effect=error)
    elif failure == "policy":
        monkeypatch.setattr(ToolPolicyEngine, "evaluate_tool_call", lambda *a, **k: (_ for _ in ()).throw(error))
    elif failure == "dlp":
        monkeypatch.setattr(OutputFilter, "inspect_and_redact", lambda *a, **k: (_ for _ in ()).throw(error))
    else:
        async def broken(arguments, context):
            harness.calls.append(context)
            if failure == "handler-validation":
                LookupArgs.model_validate({})
            raise error
        harness.tool = RegisteredTool(LookupArgs, broken)
    app = harness.app()
    response = await post(app, harness.body, harness.headers())
    assert response.status_code == 503
    assert "private" not in response.text
    assert "do not retry" in response.text
    if failure.startswith("handler"):
        assert (await post(app, harness.body, harness.headers())).status_code == 409
        assert len(harness.calls) == 1
    else:
        assert not harness.calls


@pytest.mark.asyncio
async def test_handler_timeout_burns_action(harness):
    harness.settings = harness.settings.model_copy(update={"execution_timeout_seconds": 0.01})

    async def slow(arguments, context):
        harness.calls.append(context)
        await asyncio.Event().wait()

    harness.tool = RegisteredTool(LookupArgs, slow)
    app = harness.app()
    response = await post(app, harness.body, harness.headers())
    assert response.status_code == 503
    assert "outcome unknown" in response.text
    assert (await post(app, harness.body, harness.headers())).status_code == 409
    assert len(harness.calls) == 1


@pytest.mark.asyncio
async def test_cancelled_request_keeps_reservation(harness):
    entered = asyncio.Event()

    async def held(arguments, context):
        harness.calls.append(context)
        entered.set()
        await asyncio.Event().wait()

    harness.tool = RegisteredTool(LookupArgs, held)
    app = harness.app()
    async with asyncio.timeout(3):
        task = asyncio.create_task(post(app, harness.body, harness.headers()))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert (await post(app, harness.body, harness.headers())).status_code == 409
    assert len(harness.calls) == 1


@pytest.mark.asyncio
async def test_storage_timeout_never_executes(harness):
    harness.settings = harness.settings.model_copy(update={"replay_timeout_seconds": 0.01})

    async def slow(*args):
        await asyncio.Event().wait()

    harness.store.reserve = slow
    response = await post(harness.app(), harness.body, harness.headers())
    assert response.status_code == 503
    assert not harness.calls


@pytest.mark.asyncio
async def test_token_expiring_during_reservation_never_executes(harness, monkeypatch):
    original = harness.store.reserve

    async def delayed(*args):
        accepted = await original(*args)
        monkeypatch.setattr("src.executor.app.time.time", lambda: 9999999999)
        return accepted

    harness.store.reserve = delayed
    response = await post(harness.app(), harness.body, harness.headers())
    assert response.status_code == 401
    assert not harness.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("output", [
    "password=actual-private-credential-value", "user@corporate.example", "AKIAZYXWVUTSRQPONMLK",
    "opaque-operator-secret", "x" * 16385, {"credentials": "not-a-string"},
])
async def test_output_withheld_no_automatic_reexecution(harness, output):
    async def handler(arguments, context):
        harness.calls.append(context)
        return output

    harness.tool = RegisteredTool(LookupArgs, handler, (SecretStr("opaque-operator-secret"),))
    app = harness.app()
    response = await post(app, harness.body, harness.headers())
    assert response.status_code in {502, 503}
    assert "do not retry" in response.text
    assert "opaque-operator-secret" not in response.text
    assert (await post(app, harness.body, harness.headers())).status_code == 409
    assert len(harness.calls) == 1


@pytest.mark.asyncio
async def test_warn_output_cannot_leak_unredactable_secret(harness, monkeypatch):
    original = OutputFilter.inspect_and_redact

    def inspect_output(self, text, *args):
        if text == "Public item information":
            return GuardrailResult(verdict=Verdict.WARN)
        return original(self, text, *args)

    monkeypatch.setattr(OutputFilter, "inspect_and_redact", inspect_output)
    response = await post(harness.app(), harness.body, harness.headers())
    assert response.status_code == 502


@pytest.mark.asyncio
async def test_server_secret_not_accepted_as_argument(harness):
    harness.tool = RegisteredTool(LookupArgs, harness.tool.handler, (SecretStr("opaque-operator-secret"),))
    body = {**harness.body, "arguments": {"item": "opaque-operator-secret"}}
    response = await post(harness.app(), body, harness.headers(body))
    assert response.status_code == 403
    assert not harness.calls


@pytest.mark.asyncio
async def test_rate_limit_is_not_per_token(harness):
    harness.settings = harness.settings.model_copy(update={"requests_per_minute": 1})
    app = harness.app()
    assert (await post(app, harness.body, harness.headers())).status_code == 200
    body = {**harness.body, "request_id": "action-2"}
    assert (await post(app, body, harness.headers(body, jti="token-2"))).status_code == 429
    assert len(harness.calls) == 1


@pytest.mark.asyncio
async def test_invalid_requests_cannot_exhaust_authenticated_budget(harness):
    harness.settings = harness.settings.model_copy(update={
        "global_requests_per_minute": 1, "unauthenticated_requests_per_minute": 1,
    })
    app = harness.app()
    assert (await post(app, harness.body, {})).status_code == 401
    assert (await post(app, harness.body, {"Authorization": "Bearer invalid"})).status_code == 429
    assert (await post(app, harness.body, harness.headers(sub="unknown"))).status_code == 429
    assert (await post(app, harness.body, harness.headers())).status_code == 200
    body = {**harness.body, "request_id": "action-2"}
    assert (await post(app, body, harness.headers(body, jti="token-2"))).status_code == 429
    assert len(harness.calls) == 1


@pytest.mark.asyncio
async def test_concurrency_limit_rejects_without_waiting(harness):
    harness.settings = harness.settings.model_copy(update={"max_concurrency": 1})
    entered, release = asyncio.Event(), asyncio.Event()

    async def held(arguments, context):
        harness.calls.append(context)
        entered.set()
        await release.wait()
        return "Public result"

    harness.tool = RegisteredTool(LookupArgs, held)
    app = harness.app()
    async with asyncio.timeout(3):
        first = asyncio.create_task(post(app, harness.body, harness.headers()))
        try:
            await entered.wait()
            body = {**harness.body, "request_id": "action-2"}
            second = await post(app, body, harness.headers(body, jti="token-2"))
            assert second.status_code == 429
        finally:
            release.set()
            await first
    assert len(harness.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["huge-body", "huge-args", "deep", "nodes", "invalid-json", "encoding", "content-type"])
async def test_ingress_budgets(harness, mode):
    body = dict(harness.body)
    if mode in {"huge-body", "huge-args"}:
        body["arguments"] = {"item": "x" * (70000 if mode == "huge-body" else 17000)}
    elif mode == "deep":
        value = "hidden"
        for _ in range(10):
            value = {"nested": value}
        body["arguments"] = {"item": value}
    elif mode == "nodes":
        body["arguments"] = {"item": [0] * 1100}
    headers = {**harness.headers(body), "Content-Type": "application/json"}
    content = json.dumps(body)
    if mode == "invalid-json":
        content = "{invalid"
    elif mode == "encoding":
        headers["Content-Encoding"] = "gzip"
    elif mode == "content-type":
        headers["Content-Type"] = "text/plain"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(harness.app()), base_url="https://executor.test") as client:
        response = await client.post("/execute", content=content, headers=headers)
    assert response.status_code in {413, 415, 422}
    assert not harness.calls


@pytest.mark.asyncio
async def test_body_read_timeout(harness):
    harness.settings = harness.settings.model_copy(update={"body_timeout_seconds": 0.01})

    async def chunks():
        yield b"{"
        await asyncio.Event().wait()

    async with httpx.AsyncClient(transport=httpx.ASGITransport(harness.app()), base_url="https://executor.test") as client:
        response = await client.post("/execute", content=chunks(),
                                     headers={**harness.headers(), "Content-Type": "application/json"})
    assert response.status_code == 408
    assert not harness.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/docs", "/openapi.json", "/admin", "/execute/lookup"])
async def test_no_other_public_surface(harness, path):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(harness.app()), base_url="https://executor.test") as client:
        assert (await client.get(path)).status_code == 404


def test_unconfigured_factory_fails_even_with_debug_env(monkeypatch):
    monkeypatch.setenv("BULWARK_DEBUG", "true")
    with pytest.raises(ValueError, match="Explicit"):
        create_app()


def test_memory_not_accepted_in_production(harness):
    with pytest.raises(ValueError, match="durable"):
        harness.app(settings=harness.settings.model_copy(update={"development": False}))


@pytest.mark.parametrize("field,value", [("workers", 2), ("replicas", 2), ("max_concurrency", 0),
                                         ("requests_per_minute", 0), ("max_token_seconds", 1000)])
def test_unsupported_config_rejected(harness, field, value):
    with pytest.raises(ValidationError):
        ExecutorSettings.model_validate({**harness.settings.model_dump(), field: value})


@pytest.mark.parametrize("mode", ["empty-registry", "unknown-policy-tool", "standard-policy", "zero-calls",
                                    "duplicate-policy", "unknown-principal", "sync-handler", "open-schema",
                                    "bad-name", "bad-secret"])
def test_bad_operator_wiring_fails_startup(harness, mode):
    override = {}
    if mode == "empty-registry":
        override["tools"] = {}
    elif mode == "unknown-policy-tool":
        harness.policy.allowed_tools = ["arbitrary"]
    elif mode == "standard-policy":
        harness.policy.sandbox_level = "standard"
    elif mode == "zero-calls":
        harness.policy.max_tool_calls_per_request = 0
    elif mode == "duplicate-policy":
        override["policies"] = [harness.policy, harness.policy]
    elif mode == "unknown-principal":
        override["principals"] = frozenset({("unknown", "assistant", "operator")})
    elif mode == "sync-handler":
        harness.tool = RegisteredTool(LookupArgs, lambda a, c: "result")
    elif mode == "open-schema":
        harness.tool = RegisteredTool(BaseModel, harness.tool.handler)
    elif mode == "bad-name":
        override["tools"] = {"Lookup": harness.tool}
    elif mode == "bad-secret":
        harness.tool = RegisteredTool(LookupArgs, harness.tool.handler, (SecretStr(""),))
    with pytest.raises(ValueError):
        harness.app(**override)


@pytest.mark.asyncio
async def test_memory_capacity_fails_closed_and_expiry(monkeypatch):
    store = MemoryReplayStore(capacity=2)
    assert await store.reserve("token-1", "action-1", 10)
    assert not await store.reserve("token-1", "action-2", 10)
    with pytest.raises(RuntimeError):
        await store.reserve("token-2", "action-2", 10)
    monkeypatch.setattr("src.executor.replay.time.monotonic", lambda: 999999999999)
    assert await store.reserve("token-2", "action-2", 10)


@pytest.mark.asyncio
@pytest.mark.parametrize("results,expected", [([True, True], True), ([False], False), ([True, False], False)])
async def test_redis_reservations_mock_only(results, expected):
    client = AsyncMock()
    client.set.side_effect = results
    store = RedisReplayStore(client, durability_confirmed=True)
    assert await store.reserve("token", "action", 600) is expected
    assert client.set.await_count == len(results)
    client.set.assert_any_await("token", "reserved", nx=True, ex=600)


@pytest.mark.asyncio
async def test_redis_error_does_not_fallback_or_rollback():
    client = AsyncMock()
    client.set.side_effect = [True, ConnectionError("lost storage")]
    store = RedisReplayStore(client, durability_confirmed=True)
    with pytest.raises(ConnectionError):
        await store.reserve("token", "action", 600)
    client.delete.assert_not_called()


def test_redis_requires_durability_attestation():
    with pytest.raises(ValueError):
        RedisReplayStore(AsyncMock())


def test_invalid_memory_capacity():
    with pytest.raises(ValueError):
        MemoryReplayStore(capacity=1)


def test_non_ed25519_key_rejected(harness):
    from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key

    key = generate_private_key(SECP256R1()).public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(ValueError, match="Ed25519"):
        harness.app(settings=harness.settings.model_copy(update={"public_key_pem": key.decode()}))


@pytest.mark.asyncio
async def test_model_defaults_are_authorized_before_execution(harness):
    class WithDefault(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        item: str = "../../.ssh/id_rsa"

    harness.tool = RegisteredTool(WithDefault, harness.tool.handler)
    body = {**harness.body, "arguments": {}}
    response = await post(harness.app(), body, harness.headers(body))
    assert response.status_code == 403
    assert not harness.calls


@pytest.mark.asyncio
async def test_huge_model_default_is_bounded(harness):
    class WithDefault(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        item: str = "x" * 17000

    harness.tool = RegisteredTool(WithDefault, harness.tool.handler)
    body = {**harness.body, "arguments": {}}
    response = await post(harness.app(), body, harness.headers(body))
    assert response.status_code == 413
    assert not harness.calls


@pytest.mark.asyncio
async def test_lifespan_does_not_start_external_resources(harness):
    app = harness.app()
    async with app.router.lifespan_context(app):
        assert not harness.calls


@pytest.mark.asyncio
async def test_rate_window_expires(harness, monkeypatch):
    from src.executor.app import BoundaryMiddleware

    middleware = BoundaryMiddleware(harness.app(), settings=harness.settings,
                                    principals=harness.principals, key=harness.key.public_key())
    middleware._rate((), 1)
    with pytest.raises(HTTPException):
        middleware._rate((), 1)
    monkeypatch.setattr("src.executor.app.time.monotonic", lambda: 999999999999)
    middleware._rate((), 1)


def test_operator_redis_wiring_mock_only(monkeypatch):
    from unittest.mock import Mock

    from config.examples import executor_operator

    monkeypatch.setenv("BULWARK_EXECUTOR_REDIS_HOST", "redis.internal.example")
    monkeypatch.setenv("BULWARK_EXECUTOR_REDIS_USERNAME", "executor")
    monkeypatch.setenv("BULWARK_EXECUTOR_REDIS_PASSWORD_FILE", "/operator-mounted/password")
    monkeypatch.setenv("BULWARK_EXECUTOR_REDIS_CA_FILE", "/operator-mounted/ca.pem")
    monkeypatch.setattr(executor_operator.Path, "read_text", lambda *a, **k: "ephemeral-test-password")
    client = Mock()
    monkeypatch.setattr("redis.asyncio.Redis", client)
    assert executor_operator.get_redis_client() is client.return_value
    options = client.call_args.kwargs
    assert options["ssl"] is True
    assert options["ssl_check_hostname"] is True
    assert options["ssl_cert_reqs"] == "required"
    assert options["socket_timeout"] == 1.0
    assert options["socket_connect_timeout"] == 1.0
    assert options["retry_on_timeout"] is False


@pytest.mark.asyncio
async def test_operator_factory_wiring_and_cleanup_mock_only(harness, monkeypatch):
    from config.examples import executor_operator

    monkeypatch.setenv("BULWARK_EXECUTOR_PUBLIC_KEY_FILE", "/operator-mounted/public.pem")
    monkeypatch.setenv("BULWARK_EXECUTOR_ISSUER", "corporate-issuer")
    monkeypatch.setenv("BULWARK_EXECUTOR_AUDIENCE", "dedicated-executor")
    monkeypatch.setenv("BULWARK_EXECUTOR_REPLAY_DURABILITY_CONFIRMED", "true")
    monkeypatch.setattr(executor_operator.Path, "read_text", lambda *a, **k: harness.settings.public_key_pem)
    monkeypatch.setattr(executor_operator, "TOOLS", {"lookup": harness.tool})
    monkeypatch.setattr(executor_operator, "POLICIES", [harness.policy])
    monkeypatch.setattr(executor_operator, "PRINCIPALS", harness.principals)
    client = AsyncMock()
    client.set.return_value = True
    monkeypatch.setattr(executor_operator, "get_redis_client", lambda: client)
    app = executor_operator.create_executor()
    async with app.router.lifespan_context(app):
        assert (await post(app, harness.body, harness.headers())).status_code == 200
    client.aclose.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["exclude", "field-serializer", "model-serializer", "nested-exclude",
                                  "nested-serializer", "default-exclude"])
async def test_lossy_security_representation_is_rejected(harness, mode):
    class Excluded(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        item: str = Field(default="../../.ssh/id_rsa", exclude=True)

    class FieldSerialized(LookupArgs):
        @field_serializer("item")
        def hide(self, value):
            return "public-item"

    class ModelSerialized(LookupArgs):
        @model_serializer
        def hide(self):
            return {"item": "public-item"}

    class NestedExcluded(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        nested: Excluded

    class NestedSerialized(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        nested: FieldSerialized

    models = {"exclude": Excluded, "field-serializer": FieldSerialized, "model-serializer": ModelSerialized,
              "nested-exclude": NestedExcluded, "nested-serializer": NestedSerialized, "default-exclude": Excluded}
    arguments = {"item": "../../.ssh/id_rsa"}
    if mode.startswith("nested"):
        arguments = {"nested": arguments}
    elif mode == "default-exclude":
        arguments = {}
    harness.tool = RegisteredTool(models[mode], harness.tool.handler)
    harness.store.reserve = AsyncMock()
    body = {**harness.body, "arguments": arguments}
    response = await post(harness.app(), body, harness.headers(body))
    assert response.status_code == 422
    assert "id_rsa" not in response.text
    assert not harness.calls
    harness.store.reserve.assert_not_awaited()


@pytest.mark.asyncio
async def test_validator_normalized_value_reaches_policy(harness):
    class Normalized(LookupArgs):
        @field_validator("item")
        @classmethod
        def normalize(cls, value):
            return "../../.ssh/id_rsa"

    harness.tool = RegisteredTool(Normalized, harness.tool.handler)
    response = await post(harness.app(), harness.body, harness.headers())
    assert response.status_code == 403
    assert not harness.calls


@pytest.mark.asyncio
async def test_lossless_serializer_and_safe_normalization_are_allowed(harness):
    class Normalized(LookupArgs):
        @field_validator("item")
        @classmethod
        def normalize(cls, value):
            return value.strip()

        @field_serializer("item")
        def unchanged(self, value):
            return value

    harness.tool = RegisteredTool(Normalized, harness.tool.handler)
    body = {**harness.body, "arguments": {"item": " public-item "}}
    response = await post(harness.app(), body, harness.headers(body))
    assert response.status_code == 200
    assert harness.calls[0][0].item == "public-item"


@pytest.mark.asyncio
@pytest.mark.parametrize("secret", ['violet"orchid', "violet\\orchid", "violet\norchid", "violet\x00orchid"])
@pytest.mark.parametrize("location", ["value", "key", "default", "embedded", "output"])
async def test_protected_values_checked_after_json_decoding(harness, secret, location):
    class Structured(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        data: dict[str, str] = Field(default_factory=lambda: {"item": secret})

    async def handler(arguments, context):
        harness.calls.append(context)
        return json.dumps({"public": secret})

    body = dict(harness.body)
    if location in {"key", "default"}:
        harness.tool = RegisteredTool(Structured, harness.tool.handler, (SecretStr(secret),))
        body["arguments"] = {} if location == "default" else {"data": {secret: "public"}}
    else:
        harness.tool = RegisteredTool(LookupArgs, handler if location == "output" else harness.tool.handler,
                                      (SecretStr(secret),))
        if location != "output":
            body["arguments"] = {"item": json.dumps({"public": secret}) if location == "embedded" else secret}
    app = harness.app()
    response = await post(app, body, harness.headers(body))
    assert response.status_code == (502 if location == "output" else 403)
    if location == "output":
        assert len(harness.calls) == 1
        assert (await post(app, body, harness.headers(body))).status_code == 409
    else:
        assert not harness.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("location", ["object", "embedded", "nested-embedded", "output", "output-duplicate"])
async def test_structured_password_dlp(harness, location):
    secret_json = '{"password":"violet-orchid-cabin"}'

    class CredentialArgs(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        password: str = Field(max_length=100)

    async def handler(arguments, context):
        harness.calls.append(context)
        if location == "output-duplicate":
            return '{"password":"violet-orchid-cabin","password":"public"}'
        return secret_json

    body = dict(harness.body)
    if location == "object":
        harness.tool = RegisteredTool(CredentialArgs, harness.tool.handler)
        body["arguments"] = json.loads(secret_json)
    elif location.startswith("output"):
        harness.tool = RegisteredTool(LookupArgs, handler)
    else:
        body["arguments"] = {"item": json.dumps({"data": secret_json}) if location == "nested-embedded" else secret_json}
    response = await post(harness.app(), body, harness.headers(body))
    assert response.status_code == (502 if location.startswith("output") else 403)
    assert "violet-orchid-cabin" not in response.text
    if not location.startswith("output"):
        assert not harness.calls


@pytest.mark.asyncio
async def test_benign_structured_input_and_output_allowed(harness):
    async def handler(arguments, context):
        harness.calls.append(context)
        return '{"status":"public","count":2}'

    harness.tool = RegisteredTool(LookupArgs, handler)
    body = {**harness.body, "arguments": {"item": '{"label":"orchid","enabled":true}'}}
    response = await post(harness.app(), body, harness.headers(body))
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_embedded_json_depth_budget_fails_closed(harness):
    class TextArgs(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        item: str = Field(max_length=1000)

    harness.tool = RegisteredTool(TextArgs, harness.tool.handler)
    body = {**harness.body, "arguments": {"item": "[" * 10 + '"public"' + "]" * 10}}
    response = await post(harness.app(), body, harness.headers(body))
    assert response.status_code == 403
    assert not harness.calls
