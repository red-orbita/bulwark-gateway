"""Framing, lease fencing and real middleware regressions, with no services."""

import asyncio
import json
import threading
from unittest.mock import AsyncMock

import anyio
import httpx
import pytest
from fastapi import FastAPI, Request
from starlette.responses import Response, StreamingResponse

from src.middleware import quotas
from src.routes import proxy
from tests.test_proxy_independent_review import Wire, consume, event
from tests.test_proxy_security_coverage import isolated_proxy as isolated_proxy


@pytest.mark.parametrize("prefix", [b"data:", b"data: ", b"data:  ", b"data:\t"])
@pytest.mark.parametrize("multiline", [False, True])
async def test_all_valid_data_fields_reach_tool_gate(prefix, multiline):
    raw = event({"name": "weather", "arguments": '{"key":"AKIAIOSFODNN7EXAMPLE"}'}, "tool_calls")[6:-2]
    if multiline:
        raw = raw.replace(b', "finish_reason"', b'\ndata: "finish_reason"')
        # Preserve the comma before a JSON whitespace/newline boundary.
        raw = raw.replace(b'\ndata:', b',\ndata:')
    output, policy = await consume(Wire([prefix + raw + b"\n\n", b"data: [DONE]\n\n"]))
    assert "security_violation" in output
    assert "AKIA" not in output
    assert '"tool_calls":' not in output
    policy.evaluate_tool_calls.assert_not_called()


@pytest.mark.parametrize("wire", [
    b'data:{"choices":\n\ndata: []}\n\n',
    b'data:not-json\n\n',
    b'data:{"tool_calls":[]}\n\n',
    b'data:[{"choices":[]}]\n\n',
    b'event: executable\ndata:{"choices":[]}\n\n',
    b'data\n\n',
    b'data: {"choices":[]}\n',
])
async def test_malformed_executable_events_never_pass_through(wire):
    output, _ = await consume(Wire([wire]))
    assert "security_violation" in output
    assert '"choices":' not in output


async def test_complete_multiline_event_crlf_and_comments_are_canonicalized():
    raw = event({"name": "weather", "arguments": "{}"}, "tool_calls")[6:-2]
    raw = raw.replace(b', "finish_reason"', b',\r\ndata:"finish_reason"')
    wire = b": comment\r\nid: opaque\r\nevent: message\r\ndata:" + raw + b"\r\n\r\ndata:[DONE]\r\n\r\n"
    output, policy = await consume(Wire([bytes([byte]) for byte in wire]))
    policy.evaluate_tool_calls.assert_called_once()
    assert "security_violation" not in output
    assert ": comment" not in output and "id: opaque" not in output
    assert output.count('"tool_calls":') == 1


@pytest.mark.parametrize("later", [
    event({"name": "second", "arguments": "{}"}, "tool_calls"),
    b'data:{"choices":[{"delta":{"content":"uninspected"}}]}\n\n',
    b'data:{"choices":[{"delta":{"role":"assistant"}}]}\n\n',
    event(finish="tool_calls"),
])
async def test_terminal_choice_cannot_reset_tool_policy_budget(later):
    output, policy = await consume(Wire([
        event({"name": "first", "arguments": "{}"}, "tool_calls"), later, b"data:[DONE]\n\n",
    ]))
    policy.evaluate_tool_calls.assert_called_once()
    assert "security_violation" in output
    assert '"tool_calls":' in output  # Only the first authorized batch was emitted.
    assert '"second"' not in output and "uninspected" not in output


async def test_usage_and_done_after_terminal_choice_are_supported():
    usage = b'data:{"choices":[],"usage":{"total_tokens":12}}\n\n'
    output, policy = await consume(Wire([
        event({"name": "first", "arguments": "{}"}, "tool_calls"), usage, b"data:[DONE]\n\n",
    ]))
    policy.evaluate_tool_calls.assert_called_once()
    assert '"total_tokens": 12' in output
    assert "security_violation" not in output


@pytest.mark.parametrize("combined", [False, True])
@pytest.mark.parametrize("text", ["Public test response", "Public " * 90, "AWS key AKIAIOSFODNN7EXAMPLE"])
async def test_buffered_content_precedes_finish_reason(combined, text):
    def chunk(content, finish=None):
        return ("data: " + json.dumps({"choices": [{"index": 0, "delta": {"content": content} if content else {},
                                                 "finish_reason": finish}]}) + "\n\n").encode()

    frames = [chunk(text, "stop")] if combined else [chunk(text), chunk(None, "stop")]
    output, _ = await consume(Wire([*frames, b"data: [DONE]\n\n"]))
    assert "security_violation" not in output
    assert "AKIAIOSFODNN7EXAMPLE" not in output
    payloads = [e[6:] for e in output.split("\n\n") if e.startswith("data: ")]
    assert payloads[-1] == "[DONE]"
    finished = False
    content = ""
    finishes = 0
    for payload in payloads[:-1]:
        for choice in json.loads(payload).get("choices", []):
            delta = choice.get("delta", {}).get("content") or ""
            assert not (finished and delta)
            content += delta
            if choice.get("finish_reason") is not None:
                finished = True
                finishes += 1
    assert finished and finishes == 1
    if "AKIA" in text:
        assert "REDACTED" in content
    else:
        assert content == text


async def test_blocked_terminal_buffer_never_emits_success_finish(monkeypatch):
    monkeypatch.setattr(proxy, "_filter_chunk", lambda *args: None)
    raw = b'data: {"choices":[{"index":0,"delta":{"content":"unsafe"},"finish_reason":"stop"}]}\n\n'
    output, _ = await consume(Wire([raw, b"data: [DONE]\n\n"]))
    assert "security_violation" in output
    assert "unsafe" not in output and '"finish_reason": "stop"' not in output


@pytest.mark.parametrize("combined", [False, True])
async def test_content_precedes_terminal_tool_calls(combined):
    content = b'data: {"choices":[{"index":0,"delta":{"content":"Checking weather"},"finish_reason":null}]}\n\n'
    frames = [content, event({"name": "weather", "arguments": "{}"}, "tool_calls" if combined else None)]
    if not combined:
        frames.append(event(finish="tool_calls"))
    output, policy = await consume(Wire([*frames, b"data: [DONE]\n\n"]))
    policy.evaluate_tool_calls.assert_called_once()
    assert "security_violation" not in output
    assert output.index("Checking weather") < output.index('"finish_reason": "tool_calls"')


async def test_final_delta_content_removed_from_metadata_but_other_metadata_checked():
    frame = b'data: {"id":"AKIAIOSFODNN7EXAMPLE","choices":[{"index":0,"delta":{"content":"public"},"finish_reason":"stop"}]}\n\n'
    output, _ = await consume(Wire([frame, b"data: [DONE]\n\n"]))
    assert "security_violation" in output
    assert "AKIAIOSFODNN7EXAMPLE" not in output and '"finish_reason": "stop"' not in output


class LeaseRedis:
    """Atomic sorted-set script model, not a Redis server or Lua interpreter."""

    def __init__(self):
        self.now = 0
        self.sets = {}
        self.lock = threading.Lock()
        self.releases = []

    def eval(self, script, count, tenant, global_key, member, *args):
        assert count == 2
        with self.lock:
            if script == proxy._STREAM_LEASE_RELEASE:
                self.releases.append(member)
                for key in (tenant, global_key):
                    self.sets.get(key, {}).pop(member, None)
                return 1
            assert script == proxy._STREAM_LEASE_ACQUIRE
            tenant_limit, global_limit, ttl = args
            for key in (tenant, global_key):
                self.sets[key] = {token: expiry for token, expiry in self.sets.get(key, {}).items() if expiry > self.now}
            if len(self.sets[tenant]) >= tenant_limit:
                return 429
            if len(self.sets[global_key]) >= global_limit:
                return 503
            for key in (tenant, global_key):
                self.sets[key][member] = self.now + ttl
            return 200


def chat_request(app):
    body = b'{"messages":[{"role":"user","content":"hello"}],"stream":true}'
    return Request({"type": "http", "method": "POST", "path": "/v1/chat/completions", "headers": [], "app": app},
                   AsyncMock(return_value={"type": "http.request", "body": body}))


async def test_expired_old_response_cannot_remove_recreated_lease(isolated_proxy, monkeypatch):
    app, _, _, streaming = isolated_proxy
    redis = LeaseRedis()
    monkeypatch.setattr(proxy, "_get_stream_redis", lambda: redis)
    monkeypatch.setattr(proxy, "_stream_semaphore", asyncio.Semaphore(10))
    monkeypatch.setattr(proxy, "_MAX_STREAMS_PER_TENANT", 1)
    async def body():
        yield "data: [DONE]\n\n"
    streaming.side_effect = lambda *args, **kwargs: StreamingResponse(body())
    old = await proxy.chat_completions(chat_request(app))
    denied = await proxy.chat_completions(chat_request(app))
    assert denied.status_code == 429
    redis.now += proxy._MAX_STREAM_DURATION_SECONDS + proxy._STREAM_LEASE_MARGIN_SECONDS + 1
    current = await proxy.chat_completions(chat_request(app))
    assert isinstance(current, proxy._CapacityStreamingResponse)
    before = {key: dict(value) for key, value in redis.sets.items()}
    await old._release_capacity()
    assert redis.sets == before
    denied = await proxy.chat_completions(chat_request(app))
    assert denied.status_code == 429
    await current._release_capacity()
    assert all(not value for value in redis.sets.values())
    await old._release_capacity()  # Idempotent cleanup, no negative counters.
    assert len(redis.releases) == 2


async def test_atomic_lease_admission_race(isolated_proxy, monkeypatch):
    app, _, _, streaming = isolated_proxy
    redis = LeaseRedis()
    monkeypatch.setattr(proxy, "_get_stream_redis", lambda: redis)
    monkeypatch.setattr(proxy, "_MAX_STREAMS_PER_TENANT", 1)
    monkeypatch.setattr(proxy, "_stream_semaphore", asyncio.Semaphore(20))
    async def body():
        yield "data: [DONE]\n\n"
    streaming.side_effect = lambda *args, **kwargs: StreamingResponse(body())
    responses = await asyncio.gather(*(proxy.chat_completions(chat_request(app)) for _ in range(8)))
    admitted = [response for response in responses if isinstance(response, proxy._CapacityStreamingResponse)]
    assert len(admitted) == 1
    assert all(response.status_code == 429 for response in responses if response not in admitted)
    await admitted[0]._release_capacity()


@pytest.mark.parametrize("worker_error", [False, True])
@pytest.mark.parametrize("repeated_cancel", [False, True])
async def test_direct_cancel_drains_admission_before_exact_token_cleanup(
    isolated_proxy, monkeypatch, worker_error, repeated_cancel,
):
    app, _, _, streaming = isolated_proxy
    entered = threading.Event()
    allow_commit = threading.Event()
    removing = threading.Event()
    allow_remove = threading.Event()
    order = []

    class PausedRedis(LeaseRedis):
        def eval(self, script, count, tenant, global_key, member, *args):
            if script == proxy._STREAM_LEASE_ACQUIRE:
                entered.set()
                assert allow_commit.wait(5), "Test did not release admission worker"
                result = super().eval(script, count, tenant, global_key, member, *args)
                assert result == 200
                # Another live lease must survive this response's cleanup.
                with self.lock:
                    for key in (tenant, global_key):
                        self.sets[key]["other-response"] = 1000
                order.append(("committed", member))
                if worker_error:
                    raise RuntimeError("Reply lost after commit")
                return result
            removing.set()
            assert allow_remove.wait(5), "Test did not release cleanup worker"
            result = super().eval(script, count, tenant, global_key, member, *args)
            order.append(("removed", member))
            return result

    redis = PausedRedis()
    monkeypatch.setattr(proxy, "_get_stream_redis", lambda: redis)
    monkeypatch.setattr(proxy, "_stream_semaphore", asyncio.Semaphore(1))
    monkeypatch.setattr(proxy, "_tenant_stream_counts", {})
    handler = asyncio.create_task(proxy.chat_completions(chat_request(app)))

    async def wait_for_thread(signal):
        async with asyncio.timeout(2):
            while not signal.is_set():
                await asyncio.sleep(0.001)

    async def cancel_and_check_pending():
        handler.cancel()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert not handler.done(), "Handler abandoned an in-flight Redis worker"

    try:
        await wait_for_thread(entered)
        await cancel_and_check_pending()
        if repeated_cancel:
            await cancel_and_check_pending()
            await cancel_and_check_pending()
        assert not redis.releases  # Removal before commit would leave a late lease.
        allow_commit.set()
        await wait_for_thread(removing)
        if repeated_cancel:
            await cancel_and_check_pending()
            await cancel_and_check_pending()
        allow_remove.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(handler, 2)
    finally:
        allow_commit.set()
        allow_remove.set()
        await asyncio.gather(handler, return_exceptions=True)

    token = order[0][1]
    assert order == [("committed", token), ("removed", token)]
    assert redis.releases == [token]
    assert all(value == {"other-response": 1000} for value in redis.sets.values())
    assert not proxy._stream_semaphore.locked()
    assert proxy._tenant_stream_counts == {}
    streaming.assert_not_awaited()


async def test_redis_admission_error_never_degrades_to_permissive_local(isolated_proxy, monkeypatch):
    app, _, _, streaming = isolated_proxy
    class FailedRedis:
        def eval(self, *args):
            raise RuntimeError("unavailable")
    monkeypatch.setattr(proxy, "_get_stream_redis", FailedRedis)
    response = await proxy.chat_completions(chat_request(app))
    assert response.status_code == 503
    streaming.assert_not_awaited()


async def test_configured_but_unavailable_redis_rejects_stream(isolated_proxy, monkeypatch):
    app, _, _, streaming = isolated_proxy
    monkeypatch.setattr(proxy.settings, "redis_url", "redis://unavailable.invalid")
    monkeypatch.setattr(proxy, "_get_stream_redis", lambda: None)
    response = await proxy.chat_completions(chat_request(app))
    assert response.status_code == 503
    streaming.assert_not_awaited()


@pytest.mark.parametrize("kind", ["fields", "bytes"])
async def test_unterminated_event_has_aggregate_budget(monkeypatch, kind):
    if kind == "fields":
        chunks = [b":comment\n" * 1025]
    else:
        monkeypatch.setattr(proxy, "_MAX_SSE_LINE_BYTES", 64)
        chunks = [b"data:" + b" " * 32 + b"\n"] * 2
    output, _ = await consume(Wire(chunks))
    assert "security_violation" in output


@pytest.mark.parametrize("cancel_kind", ["disconnect", "outer_cancel", "deadline"])
@pytest.mark.parametrize("distributed", [False, True])
async def test_real_base_middleware_cancellation_closes_backend_and_capacity(
    isolated_proxy, monkeypatch, cancel_kind, distributed,
):
    app, _, _, _ = isolated_proxy
    monkeypatch.setattr(proxy, "_handle_streaming", ORIGINAL_STREAM_HANDLER)
    monkeypatch.setattr(proxy, "_stream_semaphore", asyncio.Semaphore(1))
    monkeypatch.setattr(proxy, "_tenant_stream_counts", {})
    redis = LeaseRedis()
    monkeypatch.setattr(proxy, "_get_stream_redis", (lambda: redis) if distributed else lambda: None)
    monkeypatch.setattr(proxy.settings, "redis_url", None)
    if cancel_kind == "deadline":
        monkeypatch.setattr(proxy, "_MAX_STREAM_DURATION_SECONDS", 0.04)
    entered = anyio.Event()
    closed = []
    class LiveWire(Wire):
        async def __aiter__(self):
            yield b'data:{"choices":[{"delta":{"role":"assistant"}}]}\n\n'
            entered.set()
            await anyio.sleep_forever()
        async def aclose(self):
            await anyio.sleep(0)  # Cancellation checkpoint must be shielded.
            closed.append(True)
    @app.middleware("http")
    async def actual_base_http_middleware(request, call_next):
        return await call_next(request)
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, stream=LiveWire([])))) as client:
        monkeypatch.setattr(proxy, "_get_shared_client", lambda **kwargs: client)
        request_sent = False
        async def receive():
            nonlocal request_sent
            if not request_sent:
                request_sent = True
                return {"type": "http.request", "body": b'{"messages":[{"role":"user","content":"hello"}],"stream":true}'}
            await entered.wait()
            if cancel_kind == "disconnect":
                return {"type": "http.disconnect"}
            await anyio.sleep_forever()
        async def send(message):
            if cancel_kind == "deadline" and message["type"] == "http.response.body":
                await anyio.sleep(0.15)
                # Outer BaseHTTPMiddleware owns this downstream send, but the
                # backend and its admission must already be closed by deadline.
                assert closed == [True]
                assert not proxy._stream_semaphore.locked()
                raise OSError("downstream disconnected")
        scope = {"type": "http", "method": "POST", "path": "/v1/chat/completions", "headers": [],
                 "query_string": b"", "http_version": "1.1", "asgi": {"spec_version": "2.0"}}
        with anyio.move_on_after(0.1 if cancel_kind == "outer_cancel" else 1) as cancellation:
            try:
                await app(scope, receive, send)
            except (TimeoutError, ExceptionGroup, OSError):
                assert cancel_kind == "deadline"
        assert cancellation.cancel_called == (cancel_kind == "outer_cancel")
    assert closed == [True]
    assert not proxy._stream_semaphore.locked()
    assert proxy._tenant_stream_counts == {}
    if distributed:
        assert len(redis.releases) == 1
        assert all(not value for value in redis.sets.values())


ORIGINAL_STREAM_HANDLER = proxy._handle_streaming


@pytest.mark.parametrize("mode", ["chunked", "lying", "oversized_header", "timeout", "bad_json", "clean", "denied_model"])
@pytest.mark.parametrize("model_only", [False, True])
async def test_real_quota_middleware_bounds_and_replays_request(monkeypatch, mode, model_only):
    monkeypatch.setattr(quotas.settings, "redis_url", None)
    monkeypatch.setattr(quotas, "_MAX_BUFFERED_REQUEST_BYTES", 64)
    monkeypatch.setattr(quotas, "_REQUEST_BODY_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(quotas, "_tenant_quotas", {"tenant": quotas.TenantQuotaConfig(
        max_request_size_bytes=0 if model_only else 64, allowed_models=["allowed"],
    )})
    app = FastAPI()
    seen = []
    @app.post("/v1/chat/completions")
    async def endpoint(request: Request):
        seen.append(await request.body())
        return Response(seen[-1], media_type="application/json")
    app.add_middleware(quotas.QuotaMiddleware)
    @app.middleware("http")
    async def identity(request, call_next):
        request.state.tenant_id = "tenant"
        return await call_next(request)
    reads = 0
    clean = b'{ "model" : "allowed", "messages": [] }'
    async def receive():
        nonlocal reads
        reads += 1
        if mode == "timeout":
            await anyio.sleep_forever()
        if mode in ("chunked", "lying"):
            assert reads <= 3
            return {"type": "http.request", "body": b"x" * 32, "more_body": True}
        if reads == 1:
            payload = b"not json" if mode == "bad_json" else b'{"model":"denied"}' if mode == "denied_model" else clean
            return {"type": "http.request", "body": payload}
        await anyio.sleep_forever()
    messages = []
    async def send(message):
        messages.append(message)
    headers = [(b"content-length", b"1")] if mode == "lying" else []
    if mode == "oversized_header":
        headers = [(b"content-length", b"65")]
    scope = {"type": "http", "method": "POST", "path": "/v1/chat/completions", "headers": headers,
             "query_string": b"", "http_version": "1.1", "asgi": {"spec_version": "2.0"}}
    with anyio.fail_after(1):
        await app(scope, receive, send)
    expected = {"clean": 200, "timeout": 408, "bad_json": 400, "denied_model": 403}.get(mode, 413)
    assert messages[0]["status"] == expected
    assert seen == ([clean] if mode == "clean" else [])
    if mode == "oversized_header":
        assert reads == 0
