"""Backend and quota response bounds with real HTTPX streaming, no network."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest
from starlette.responses import StreamingResponse

from src.middleware import quotas
from src.routes import proxy
from tests.test_proxy_security_coverage import isolated_proxy as isolated_proxy


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """No application databases needed."""


class Wire(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks, self.closed, self.reads = chunks, False, 0

    async def __aiter__(self):
        for chunk in self.chunks:
            self.reads += 1
            yield chunk

    async def aclose(self):
        self.closed = True


async def read(wire, status=200, headers=None):
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        lambda request: httpx.Response(status, headers=headers, stream=wire),
    )) as client:
        return await proxy._post_bounded_json(client, "https://backend.example", {}, {}, timeout=1)


async def test_valid_fragmented_json_and_exact_limit(monkeypatch):
    data = b'{"choices":[]}'
    monkeypatch.setattr(proxy, "_MAX_JSON_RESPONSE_BYTES", len(data))
    wire = Wire([data[:3], data[3:]])
    assert (await read(wire, headers={"Content-Length": str(len(data))})).json() == {"choices": []}
    assert wire.closed


@pytest.mark.parametrize("headers", [{"Content-Length": "999"}, {"Content-Length": "no"},
                                     {"Content-Encoding": "gzip"}, {"Content-Encoding": "br"}])
async def test_reject_before_consuming_compressed_or_oversized_response(monkeypatch, headers):
    monkeypatch.setattr(proxy, "_MAX_JSON_RESPONSE_BYTES", 16)
    wire = Wire([b"private"])
    with pytest.raises(proxy.HTTPException) as exc:
        await read(wire, headers=headers)
    assert exc.value.status_code == 502
    assert wire.closed and wire.reads == 0


async def test_undeclared_overflow_stops_before_next_chunk(monkeypatch):
    monkeypatch.setattr(proxy, "_MAX_JSON_RESPONSE_BYTES", 16)
    wire = Wire([b"x" * 8, b"y" * 9, b"must not read"])
    with pytest.raises(proxy.HTTPException):
        await read(wire)
    assert wire.closed and wire.reads == 2


@pytest.mark.parametrize("status", [400, 429, 500, 503])
async def test_error_body_never_consumed(status):
    wire = Wire([b"private diagnostics"])
    response = await read(wire, status=status)
    assert response.status_code == status and response.content == b""
    assert wire.closed and wire.reads == 0


async def test_truncated_body_rejected():
    wire = Wire([b"{}"])
    with pytest.raises(proxy.HTTPException, match="Incomplete"):
        await read(wire, headers={"Content-Length": "3"})
    assert wire.closed


async def test_total_deadline_closes_slow_body(monkeypatch):
    monkeypatch.setattr(proxy, "_MAX_JSON_RESPONSE_SECONDS", .01)
    class Slow(Wire):
        async def __aiter__(self):
            yield b"{"
            await asyncio.sleep(10)
    wire = Slow([])
    with pytest.raises(proxy.HTTPException) as exc:
        await read(wire)
    assert exc.value.status_code == 504 and wire.closed


@pytest.mark.parametrize("body", [b'[]', b'{"choices":{},"choices":[]}', b'{"choices":[null]}',
                                  b'{"choices":[{"message":[]}]}',
                                  b'{"choices":[{"message":{"tool_calls":null}}]}',
                                  b'{"choices":[],"usage":[1]}',
                                  b'{"choices":[],"model":[],"usage":{"total_tokens":1}}',
                                  b'{"choices":[],"usage":{"total_tokens":-1}}',
                                  b'{"choices":[{"message":{"content":{}}}]}',
                                  b'{"choices":[{"message":{"tool_calls":[{}]}}]}'])
async def test_invalid_response_shape_fails_closed_at_chat(isolated_proxy, body):
    app, _, backend, _ = isolated_proxy
    backend.post.return_value = httpx.Response(200, content=body)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/v1/chat/completions", json={
            "model": "test", "messages": [{"role": "user", "content": "Hello"}],
        })
    assert response.status_code == 502


async def test_accepted_response_timeout_never_replayed(isolated_proxy, monkeypatch):
    app, _, _, _ = isolated_proxy
    backend = app.state.agent_registry.resolve.return_value
    backend.fallback_backends = [SimpleNamespace(backend_url="https://fallback.example", path_prefix="/v1", timeout=1)]
    calls = []
    class Broken(Wire):
        async def __aiter__(self):
            yield b'{"choices":'
            raise httpx.ReadTimeout("private error")
    wire = Broken([])
    def upstream(request):
        calls.append(str(request.url))
        return httpx.Response(200, stream=wire)
    async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as backend_client:
        monkeypatch.setattr(proxy, "_get_shared_client", lambda **kwargs: backend_client)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/v1/chat/completions", json={
                "model": "test", "messages": [{"role": "user", "content": "Hello"}],
            })
    assert response.status_code == 504 and "private" not in response.text
    assert len(calls) == 1 and calls[0].startswith("https://backend.example/")
    assert wire.closed


@pytest.mark.parametrize("mode", ["oversize", "timeout", "error", "valid"])
async def test_quota_response_does_not_release_partial_or_excessive_body(monkeypatch, mode):
    monkeypatch.setattr(quotas, "_MAX_BUFFERED_RESPONSE_BYTES", 64)
    monkeypatch.setattr(quotas, "_RESPONSE_BODY_TIMEOUT_SECONDS", .01)
    closed = []
    async def chunks():
        try:
            yield b'{"usage":'
            if mode == "oversize":
                yield b" " * 65
            elif mode == "timeout":
                await asyncio.sleep(10)
            elif mode == "error":
                raise RuntimeError("private backend error")
            else:
                yield b'{"total_tokens":3}}'
        finally:
            closed.append(True)
    response = StreamingResponse(chunks(), media_type="application/json")
    middleware = object.__new__(quotas.QuotaMiddleware)
    tracker = Mock(increment=Mock(return_value=3))
    middleware._token_tracker = tracker
    result = await middleware._track_token_usage(response, "tenant", SimpleNamespace(max_tokens_per_day=10))
    assert closed
    if mode == "valid":
        assert result.status_code == 200 and json.loads(result.body)["usage"]["total_tokens"] == 3
        tracker.increment.assert_called_once_with("tenant", 3)
    else:
        assert result.status_code == 502 and b"private" not in result.body
        tracker.increment.assert_not_called()
