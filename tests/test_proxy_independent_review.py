"""Independent-review regressions, entirely in-process and without services."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from fastapi import Request
from fastapi.responses import StreamingResponse

from src.models import GuardrailResult, Verdict
from src.routes import proxy
from tests.test_proxy_security_coverage import isolated_proxy as isolated_proxy


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """The proxy boundary tests do not need an admin database."""


class Wire(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            yield chunk

    async def aclose(self):
        self.closed = True


def event(function=None, finish=None):
    delta = {} if function is None else {"tool_calls": [{"index": 0, "function": function}]}
    return ("data: " + json.dumps({"choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}) + "\n\n").encode()


async def consume(wire, *, token=None, status=200, headers=None):
    policy = MagicMock()
    policy.evaluate_tool_calls.return_value = GuardrailResult(verdict=Verdict.ALLOW)
    ioc = MagicMock()
    ioc.check_content.return_value = []
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        lambda request: httpx.Response(status, stream=wire, headers=headers),
    )) as client:
        response = await proxy._handle_streaming(
            client, "https://backend.example", {}, {}, "tenant", "agent", None, ioc, policy, token_jti=token,
        )
        output = "".join([part async for part in response.body_iterator])
    assert wire.closed
    return output, policy


@pytest.mark.parametrize("second_name", ["weather", "different", "", None])
@pytest.mark.parametrize("combined", [False, True])
async def test_repeated_nonempty_name_never_replayed(second_name, combined):
    second = {"arguments": "}"}
    if second_name is not None:
        second["name"] = second_name
    chunks = [event({"name": "weather", "arguments": "{"}),
              event(second, "tool_calls" if combined else None)]
    if not combined:
        chunks.append(event(finish="tool_calls"))
    chunks.append(b"data: [DONE]\n\n")
    output, policy = await consume(Wire(chunks))
    if second_name:
        assert "security_violation" in output
        assert '"tool_calls":' not in output
        policy.evaluate_tool_calls.assert_not_called()
    else:
        assert output == b"".join(chunks).decode()
        assert policy.evaluate_tool_calls.call_args.args[0][0].name == "weather"


@pytest.mark.parametrize("blank", [b"\n", b"\r\n", b"\r"])
@pytest.mark.parametrize("reason", ["duration", "revocation", "bytes"])
async def test_blank_stream_enforces_all_limits(monkeypatch, blank, reason):
    now = [0.0]
    monkeypatch.setattr(proxy, "time", SimpleNamespace(monotonic=lambda: now[0]))
    revoked = MagicMock(return_value=True)
    monkeypatch.setattr(proxy, "_is_token_revoked", revoked)
    monkeypatch.setattr(proxy, "_MAX_STREAM_BYTES", 2)
    class BlankWire(Wire):
        async def __aiter__(self):
            for _ in range(4):
                now[0] += {"duration": 301, "revocation": 31, "bytes": 0}[reason]
                yield blank
            pytest.fail("Blank stream must terminate without requesting more data")
    output, _ = await consume(BlankWire([]), token="test-jti" if reason == "revocation" else None)
    assert "security_violation" in output
    if reason == "revocation":
        revoked.assert_called_once_with("test-jti")


async def test_nonrevoked_token_and_blank_keepalives_remain_supported(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(proxy, "time", SimpleNamespace(monotonic=lambda: now[0]))
    revoked = MagicMock(return_value=False)
    monkeypatch.setattr(proxy, "_is_token_revoked", revoked)
    class KeepaliveWire(Wire):
        async def __aiter__(self):
            yield b"\n"
            now[0] = 31
            yield b"\r\n"
            yield b"data: [DONE]\n\n"
    output, _ = await consume(KeepaliveWire([]), token="test-jti")
    assert output == "data: [DONE]\n\n"
    revoked.assert_called_once_with("test-jti")


@pytest.mark.parametrize("chunks", [[b"x" * 65], [b"x" * 32, b"x" * 33], [b"x" * 64, b"x\n"]])
async def test_unterminated_line_is_bounded_before_assembly(monkeypatch, chunks):
    monkeypatch.setattr(proxy, "_MAX_SSE_LINE_BYTES", 64)
    output, _ = await consume(Wire(chunks))
    assert "security_violation" in output
    assert "x" * 32 not in output


async def test_idle_stream_has_absolute_timeout(monkeypatch):
    monkeypatch.setattr(proxy, "_MAX_STREAM_DURATION_SECONDS", 0.01)
    class IdleWire(Wire):
        async def __aiter__(self):
            await asyncio.Event().wait()
            yield b"unreachable"
    output, _ = await asyncio.wait_for(consume(IdleWire([])), timeout=1)
    assert "Request timed out" in output


@pytest.mark.parametrize("separator", [b"\n", b"\r", b"\r\n"])
async def test_fragmented_utf8_and_line_endings_still_work(separator):
    wire = 'data: {"choices":[{"delta":{"content":"caf\u00e9"}}]}'.encode() + separator * 2
    wire += b"data: [DONE]" + separator * 2
    output, _ = await consume(Wire([bytes([byte]) for byte in wire]))
    content = [json.loads(line[6:])["choices"][0]["delta"]["content"]
               for line in output.splitlines() if line.startswith("data: {")]
    assert content == ["caf\u00e9"]
    assert output.endswith("data: [DONE]\n\n")


@pytest.mark.parametrize("status,headers", [(503, None), (200, {"Content-Encoding": "gzip"})])
async def test_unneeded_or_compressed_body_is_not_read(status, headers):
    class UnreadableWire(Wire):
        async def __aiter__(self):
            pytest.fail("Must not buffer error bodies or decompress SSE")
            yield b"unreachable"
    output, _ = await consume(UnreadableWire([]), status=status, headers=headers)
    assert '"error"' in output


@pytest.mark.parametrize("declared", [None, "1"])
async def test_chunked_chat_body_rejected_before_full_read(isolated_proxy, declared):
    app, _, backend, streaming = isolated_proxy
    reads = 0
    async def receive():
        nonlocal reads
        reads += 1
        assert reads <= 11
        return {"type": "http.request", "body": b"x" * (1024 * 1024), "more_body": True}
    headers = [] if declared is None else [(b"content-length", declared.encode())]
    request = Request({"type": "http", "method": "POST", "path": "/v1/chat/completions",
                       "headers": headers, "app": app}, receive)
    response = await proxy.chat_completions(request)
    assert response.status_code == 413
    assert reads == 11
    backend.post.assert_not_awaited()
    streaming.assert_not_awaited()


@pytest.mark.parametrize("ending", ["complete", "error", "cancel", "disconnect", "send_error"])
@pytest.mark.parametrize("redis", [False, True])
async def test_stream_capacity_held_until_asgi_completion(isolated_proxy, monkeypatch, ending, redis):
    app, _, _, streaming = isolated_proxy
    semaphore = asyncio.Semaphore(1)
    monkeypatch.setattr(proxy, "_stream_semaphore", semaphore)
    monkeypatch.setattr(proxy, "_tenant_stream_counts", {})
    counters = MagicMock()
    counters.eval.return_value = 200
    if redis:
        monkeypatch.setattr(proxy, "_get_stream_redis", lambda: counters)
    entered = asyncio.Event()
    closed = []
    async def body():
        try:
            assert semaphore.locked()
            entered.set()
            yield "data: start\n\n"
            if ending == "error":
                raise RuntimeError("test failure")
            if ending in ("cancel", "disconnect"):
                await asyncio.Event().wait()
        finally:
            closed.append(True)
    streaming.return_value = StreamingResponse(body())
    payload = json.dumps({"messages": [{"role": "user", "content": "hello"}], "stream": True}).encode()
    request = Request({"type": "http", "method": "POST", "path": "/v1/chat/completions",
                       "headers": [], "app": app}, AsyncMock(return_value={"type": "http.request", "body": payload}))
    response = await proxy.chat_completions(request)
    assert semaphore.locked()
    assert counters.eval.call_count == (1 if redis else 0)
    if not redis:
        assert proxy._tenant_stream_counts == {"default": 1}
    async def receive():
        await entered.wait()
        if ending == "disconnect":
            return {"type": "http.disconnect"}
        await asyncio.Event().wait()
    async def send(message):
        if ending == "send_error" and message["type"] == "http.response.body":
            raise OSError("disconnected")
    task = asyncio.create_task(response({"type": "http", "asgi": {"spec_version": "2.0"}}, receive, send))
    if ending == "cancel":
        await entered.wait()
        task.cancel()
    try:
        await asyncio.wait_for(task, timeout=1)
    except (Exception, asyncio.CancelledError):
        assert ending in ("error", "cancel", "send_error")
    assert closed == [True]
    assert not semaphore.locked()
    assert proxy._tenant_stream_counts == {}
    if redis:
        assert counters.eval.call_count == 2
        assert counters.eval.call_args.args[0] == proxy._STREAM_LEASE_RELEASE


@pytest.mark.parametrize("cancel", [False, True])
async def test_stream_setup_failure_releases_admission(isolated_proxy, monkeypatch, cancel):
    app, _, _, streaming = isolated_proxy
    semaphore = asyncio.Semaphore(1)
    monkeypatch.setattr(proxy, "_stream_semaphore", semaphore)
    monkeypatch.setattr(proxy, "_tenant_stream_counts", {})
    entered = asyncio.Event()
    async def setup(*args, **kwargs):
        assert semaphore.locked()
        entered.set()
        if cancel:
            await asyncio.Event().wait()
        raise RuntimeError("test setup failure")
    streaming.side_effect = setup
    payload = json.dumps({"messages": [{"role": "user", "content": "hello"}], "stream": True}).encode()
    request = Request({"type": "http", "method": "POST", "path": "/v1/chat/completions",
                       "headers": [], "app": app}, AsyncMock(return_value={"type": "http.request", "body": payload}))
    task = asyncio.create_task(proxy.chat_completions(request))
    if cancel:
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        with pytest.raises(RuntimeError, match="test setup failure"):
            await task
    assert not semaphore.locked()
    assert proxy._tenant_stream_counts == {}
