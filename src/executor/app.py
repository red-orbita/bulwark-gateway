"""Standalone ASGI executor, with no proxy/admin lifespan or plugin discovery."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import hmac
import inspect
import json
import re
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Annotated, Literal

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from src.executor.replay import ReplayStore
from src.guardrails.output_filter import OutputFilter
from src.guardrails.tool_policy import AgentPolicy, ToolPolicyEngine
from src.models import ToolCall, Verdict

Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")]
ToolName = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")]
MAX_BODY_BYTES = 65536
MAX_ARGUMENT_BYTES = 16384
MAX_OUTPUT_BYTES = 16384
MAX_REGISTRY = 128
MAX_PRINCIPALS = 1024


class ExecutorSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    public_key_pem: str = Field(min_length=32, max_length=4096, repr=False)
    issuer: str = Field(min_length=1, max_length=256)
    audience: str = Field(min_length=1, max_length=256)
    development: bool = False
    workers: Literal[1] = 1
    replicas: Literal[1] = 1
    max_concurrency: int = Field(default=8, ge=1, le=128)
    requests_per_minute: int = Field(default=60, ge=1, le=10000)
    global_requests_per_minute: int = Field(default=600, ge=1, le=100000)
    unauthenticated_requests_per_minute: int = Field(default=600, ge=1, le=100000)
    max_token_seconds: int = Field(default=300, ge=1, le=300)
    replay_ttl_seconds: int = Field(default=86400, ge=600, le=604800)
    body_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    execution_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    replay_timeout_seconds: float = Field(default=2.0, gt=0, le=10)


class ExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    request_id: Identifier
    tool: ToolName
    arguments: dict[str, object]


class ActionClaims(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    iss: str = Field(min_length=1, max_length=256)
    aud: str = Field(min_length=1, max_length=256)
    sub: Identifier
    tenant_id: Identifier
    agent_id: Identifier
    jti: Identifier
    request_id: Identifier
    action_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    iat: int
    exp: int


class ExecutionContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    subject: Identifier
    tenant_id: Identifier
    agent_id: Identifier
    request_id: Identifier


@dataclass(frozen=True)
class RegisteredTool:
    """Only operator code creates these; credentials belong in handler closures.

    Arguments must be a strict Pydantic model with extra='forbid'. Handlers must
    be cooperative async functions returning bounded public text, not objects,
    headers, streams or credentials. They must not spawn background work.
    """

    arguments_model: type[BaseModel]
    handler: Callable[[BaseModel, ExecutionContext], Awaitable[str]]
    protected_values: tuple[SecretStr, ...] = field(default=(), repr=False)


def action_digest(tool: str, arguments: dict[str, object]) -> str:
    """Issuer/client binding format: UTF-8, sorted JSON, no NaN, compact, ASCII."""
    payload = json.dumps({"tool": tool, "arguments": arguments}, sort_keys=True,
                         separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def _ledger_key(kind: str, *parts: str) -> str:
    digest = hashlib.sha256(json.dumps(parts, separators=(",", ":")).encode()).hexdigest()
    return f"bulwark:executor:{kind}:{digest}"


def _security_arguments(arguments: BaseModel) -> dict[str, object]:
    """Inspect actual fields, never a serializer's potentially lossy projection."""
    nodes = 0

    def snapshot(value: object, depth: int) -> object:
        nonlocal nodes
        nodes += 1
        if depth > 8 or nodes > 1024:
            raise HTTPException(422, "Invalid arguments")
        if isinstance(value, BaseModel):
            value = {name: getattr(value, name) for name in type(value).model_fields}
        if isinstance(value, dict):
            if len(value) > 1024 or any(type(key) is not str for key in value):
                raise HTTPException(422, "Invalid arguments")
            return {key: snapshot(child, depth + 1) for key, child in value.items()}
        if isinstance(value, list):
            if len(value) > 1024:
                raise HTTPException(422, "Invalid arguments")
            return [snapshot(child, depth + 1) for child in value]
        if value is None or type(value) in (str, int, float, bool):
            return value
        raise HTTPException(422, "Arguments must have a lossless JSON representation")

    canonical = snapshot(arguments, 0)
    if not isinstance(canonical, dict):
        raise HTTPException(422, "Invalid arguments")
    text = json.dumps(canonical, sort_keys=True, ensure_ascii=True, allow_nan=False)
    if len(text) > MAX_ARGUMENT_BYTES:
        raise HTTPException(413, "Arguments too large")
    serialized = json.dumps(arguments.model_dump(mode="json"), sort_keys=True,
                            ensure_ascii=True, allow_nan=False)
    if text != serialized:
        raise HTTPException(422, "Arguments must have a lossless JSON representation")
    return canonical


def _dlp_allows(value: object, tool: RegisteredTool, detector: OutputFilter,
                tenant_id: str, agent_id: str) -> bool:
    """Bounded decoded key/value DLP, including complete JSON embedded in text.

    This does not parse arbitrary prose/code or identify arbitrary business secrets.
    Key=value candidates preserve the shared detector's credential-name context.
    """
    pending: list[tuple[object, int]] = [(value, 0)]
    nodes = size = 0

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, child in pairs:
            if key in result:
                raise ValueError("Ambiguous JSON object")
            result[key] = child
        return result

    while pending:
        current, depth = pending.pop()
        nodes += 1
        if depth > 8 or nodes + len(pending) > 1024:
            return False
        if isinstance(current, dict):
            if len(current) * 3 + nodes + len(pending) > 1024:
                return False
            for key, child in current.items():
                pending.extend(((key, depth + 1), (child, depth + 1)))
                if isinstance(child, (str, int, float, bool)):
                    pending.append((f"{key}={child}", depth + 1))
        elif isinstance(current, list):
            if len(current) + nodes + len(pending) > 1024:
                return False
            pending.extend((child, depth + 1) for child in current)
        elif current is not None:
            text = str(current)
            size += len(text.encode("utf-8"))
            if len(text) > MAX_OUTPUT_BYTES or size > MAX_OUTPUT_BYTES * 8:
                return False
            if any(secret.get_secret_value() in text for secret in tool.protected_values):
                return False
            result = detector.inspect_and_redact(text, tenant_id, agent_id)
            if result.verdict != Verdict.ALLOW or result.events:
                return False
            if text.lstrip().startswith(("{", "[", '"')):
                try:
                    decoded = json.loads(text, object_pairs_hook=unique_object)
                except json.JSONDecodeError:
                    continue  # Non-JSON text was still scanned above.
                except (ValueError, RecursionError):
                    return False
                pending.append((decoded, depth + 1))
    return True


class BoundaryMiddleware:
    """Authenticate before buffering; bound ingress, rate and active requests.

    Local counters have no await between test and reservation. One event loop,
    worker and replica is an explicit deployment requirement, not an HA claim.
    """

    def __init__(self, app: ASGIApp, *, settings: ExecutorSettings,
                 principals: frozenset[tuple[str, str, str]], key: Ed25519PublicKey) -> None:
        self.app, self.settings, self.principals, self.key = app, settings, principals, key
        self.active = 0
        self.rates: dict[tuple[str, ...], tuple[float, int]] = {}

    def _rate(self, identity: tuple[str, ...], limit: int) -> None:
        now = time.monotonic()
        start, count = self.rates.get(identity, (now, 0))
        if now - start >= 60:
            start, count = now, 0
        if count >= limit:
            raise HTTPException(429, "Rate limit exceeded")
        self.rates[identity] = (start, count + 1)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        acquired = False
        started = False
        authenticated = False

        async def private_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                message["headers"] = [(k, v) for k, v in message.get("headers", [])
                                      if k.lower() != b"cache-control"] + [(b"cache-control", b"no-store")]
            await send(message)

        try:
            if scope["path"] != "/execute" or scope["method"] != "POST":
                raise HTTPException(404, "Not found")
            headers = scope.get("headers", [])
            auth = [v for k, v in headers if k.lower() == b"authorization"]
            if len(auth) != 1 or len(auth[0]) > 8192 or not auth[0].startswith(b"Bearer "):
                raise HTTPException(401, "Authentication failed")
            try:
                raw = jwt.decode(auth[0][7:].decode("ascii"), self.key, algorithms=["EdDSA"],
                                 issuer=self.settings.issuer, audience=self.settings.audience,
                                 options={"require": list(ActionClaims.model_fields), "strict_aud": True})
                claims = ActionClaims.model_validate(raw)
                if not 0 < claims.exp - claims.iat <= self.settings.max_token_seconds:
                    raise ValueError("Invalid token lifetime")
            except (jwt.PyJWTError, ValidationError, ValueError, UnicodeError):
                raise HTTPException(401, "Authentication failed") from None
            identity = (claims.tenant_id, claims.agent_id, claims.sub)
            if identity not in self.principals:
                raise HTTPException(403, "Execution denied")
            authenticated = True
            self._rate(identity, self.settings.requests_per_minute)
            self._rate((), self.settings.global_requests_per_minute)
            if self.active >= self.settings.max_concurrency:
                raise HTTPException(429, "Executor busy")
            self.active += 1
            acquired = True
            if any(k.lower() == b"content-encoding" for k, _ in headers):
                raise HTTPException(415, "Unsupported encoding")
            content_types = [v for k, v in headers if k.lower() == b"content-type"]
            if len(content_types) != 1 or content_types[0].split(b";", 1)[0].strip() != b"application/json":
                raise HTTPException(415, "JSON required")
            body = bytearray()
            async with asyncio.timeout(self.settings.body_timeout_seconds):
                while True:
                    message = await receive()
                    if message["type"] != "http.request":
                        raise HTTPException(400, "Invalid request")
                    chunk = message.get("body", b"")
                    if len(body) + len(chunk) > MAX_BODY_BYTES:
                        raise HTTPException(413, "Request too large")
                    body.extend(chunk)
                    if not message.get("more_body", False):
                        break
            scope.setdefault("state", {})["executor_claims"] = claims

            async def bounded_receive() -> Message:
                return {"type": "http.request", "body": bytes(body), "more_body": False}

            await self.app(scope, bounded_receive, private_send)
        except HTTPException as exc:
            status_code, detail = exc.status_code, exc.detail
            if not authenticated:
                try:
                    self._rate(("unauthenticated",), self.settings.unauthenticated_requests_per_minute)
                except HTTPException as limited:
                    status_code, detail = limited.status_code, limited.detail
            await JSONResponse({"detail": detail}, status_code=status_code,
                               headers={"Cache-Control": "no-store"})(scope, receive, send)
        except TimeoutError:
            await JSONResponse({"detail": "Request timed out"}, status_code=408)(scope, receive, send)
        except Exception:
            if not started:
                await JSONResponse({"detail": "Execution unavailable; do not retry"}, status_code=503,
                                   headers={"Cache-Control": "no-store"})(scope, receive, send)
            else:
                raise RuntimeError("Executor response failed") from None
        finally:
            if acquired:
                self.active -= 1


def create_app(*, settings: ExecutorSettings | None = None,
               tools: Mapping[str, RegisteredTool] | None = None,
               policies: list[AgentPolicy] | None = None,
               principals: frozenset[tuple[str, str, str]] | None = None,
               replay_store: ReplayStore | None = None) -> FastAPI:
    """Operator wrapper factory for uvicorn --factory; unconfigured use is fatal."""
    if settings is None or tools is None or policies is None or not principals or replay_store is None:
        raise ValueError("Explicit executor configuration is required")
    if not settings.development and replay_store.durable is not True:
        raise ValueError("Production requires a durable replay store")
    key = load_pem_public_key(settings.public_key_pem.encode("ascii"))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("An Ed25519 verification key is required")
    if not 0 < len(tools) <= MAX_REGISTRY or not 0 < len(principals) <= MAX_PRINCIPALS:
        raise ValueError("Registry or principal budget exceeded")
    registry = dict(tools)
    for name, tool in registry.items():
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name):
            raise ValueError("Invalid tool name")
        if not inspect.iscoroutinefunction(tool.handler):
            raise ValueError("Handlers must be trusted async functions")
        if (not issubclass(tool.arguments_model, BaseModel)
                or tool.arguments_model.model_config.get("extra") != "forbid"
                or tool.arguments_model.model_config.get("strict") is not True):
            raise ValueError("Tools require strict, closed argument models")
        if len(tool.protected_values) > 32 or any(
            not isinstance(secret, SecretStr) or not 1 <= len(secret.get_secret_value()) <= 4096
            for secret in tool.protected_values
        ):
            raise ValueError("Invalid server-side secret protection configuration")
    engine = ToolPolicyEngine()
    if not 0 < len(policies) <= MAX_PRINCIPALS:
        raise ValueError("Policy budget exceeded")
    for policy in copy.deepcopy(policies):
        if (policy.sandbox_level != "strict" or policy.max_tool_calls_per_request < 1
                or any(name not in registry for name in policy.allowed_tools)
                or engine.get_policy(policy.tenant_id, policy.agent_id) is not None):
            raise ValueError("Explicit strict policies and registered tools are required")
        engine.register_policy(policy)
    for tenant, agent, subject in principals:
        if (not all(re.fullmatch(r"[A-Za-z0-9_-]{1,128}", v) for v in (tenant, agent, subject))
                or engine.get_policy(tenant, agent) is None):
            raise ValueError("Principals require explicit tenant/agent policies")
    output_filter = OutputFilter(redact_email=True, redact_phone=True)
    app = FastAPI(debug=False, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(BoundaryMiddleware, settings=settings, principals=frozenset(principals), key=key)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError) -> JSONResponse:
        # FastAPI's default validation response includes rejected input values.
        return JSONResponse({"detail": "Invalid request"}, status_code=422)

    @app.post("/execute")
    async def execute(body: ExecuteRequest, request: Request) -> JSONResponse:
        claims = request.state.executor_claims
        reserved = False
        try:
            if (body.request_id != claims.request_id
                    or not hmac.compare_digest(action_digest(body.tool, body.arguments), claims.action_sha256)):
                raise HTTPException(403, "Action binding failed")
            policy = engine.get_policy(claims.tenant_id, claims.agent_id)
            if policy is None or body.tool not in policy.allowed_tools or body.tool not in registry:
                raise HTTPException(403, "Execution denied")
            if len(json.dumps(body.arguments, ensure_ascii=True, allow_nan=False)) > MAX_ARGUMENT_BYTES:
                raise HTTPException(413, "Arguments too large")
            # Depth is below ToolPolicyEngine's traversal bound; reject, never truncate.
            pending: list[tuple[object, int]] = [(body.arguments, 0)]
            nodes = 0
            while pending:
                value, depth = pending.pop()
                nodes += 1
                if depth > 8 or nodes + len(pending) > 1024:
                    raise HTTPException(422, "Invalid arguments")
                if isinstance(value, dict):
                    pending.extend((v, depth + 1) for v in value.values())
                elif isinstance(value, list):
                    pending.extend((v, depth + 1) for v in value)
            tool = registry[body.tool]
            tool_policy = policy.tool_policies.get(body.tool)
            if tool_policy is not None and (not tool_policy.allowed or tool_policy.max_calls_per_request < 1):
                raise HTTPException(403, "Execution denied")
            try:
                arguments = tool.arguments_model.model_validate(body.arguments, strict=True)
            except ValidationError:
                raise HTTPException(422, "Invalid arguments") from None
            canonical = _security_arguments(arguments)
            result = engine.evaluate_tool_call(ToolCall(name=body.tool, arguments=canonical),
                                              claims.tenant_id, claims.agent_id, call_count=0)
            if result.verdict != Verdict.ALLOW:
                raise HTTPException(403, "Execution denied")
            if not all(_dlp_allows(value, tool, output_filter, claims.tenant_id, claims.agent_id)
                       for value in (body.arguments, canonical)):
                raise HTTPException(403, "Arguments denied by DLP")
            context = ExecutionContext(subject=claims.sub, tenant_id=claims.tenant_id,
                                       agent_id=claims.agent_id, request_id=claims.request_id)
            async with asyncio.timeout(settings.replay_timeout_seconds):
                accepted = await replay_store.reserve(
                    _ledger_key("token", settings.issuer, claims.jti),
                    _ledger_key("action", settings.issuer, claims.tenant_id, claims.agent_id, claims.request_id),
                    settings.replay_ttl_seconds)
            if not accepted:
                raise HTTPException(409, "Action already reserved; do not retry")
            reserved = True
            # Recheck expiry after queue/storage latency, immediately before invocation.
            if claims.exp <= time.time():
                raise HTTPException(401, "Authentication expired")
            async with asyncio.timeout(settings.execution_timeout_seconds):
                try:
                    output = await tool.handler(arguments, context)
                except Exception:
                    # Handler HTTPException/validation errors are untrusted output too.
                    raise RuntimeError("Handler failed") from None
            if not isinstance(output, str) or len(output) > MAX_OUTPUT_BYTES or len(output.encode()) > MAX_OUTPUT_BYTES:
                raise ValueError("Invalid handler output")
            # Withhold all findings: WARN may mean encoded secrets cannot be redacted.
            if not _dlp_allows(output, tool, output_filter, claims.tenant_id, claims.agent_id):
                raise HTTPException(502, "Output withheld; action may have completed; do not retry")
            return JSONResponse({"request_id": body.request_id, "status": "completed", "output": output},
                                headers={"Cache-Control": "no-store"})
        except HTTPException:
            raise
        except Exception:
            detail = ("Action outcome unknown; do not retry" if reserved
                      else "Execution unavailable; do not retry")
            raise HTTPException(503, detail) from None

    return app
