"""Exercise the real SSE generator with a mocked transport, without services."""

import json
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from src.guardrails.output_filter import OutputFilter
from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict
from src.routes import proxy
from src.sdk.guard import Guard, ScanResult, SecurityError

SECRET = "AKIAIOSFODNN7EXAMPLE"


def event(delta, finish=None, index=0):
    return "data: " + json.dumps({"choices": [{"index": index, "delta": delta, "finish_reason": finish}]}) + "\n\n"


@pytest.mark.parametrize("kind", ["secret", "escaped", "duplicate", "malformed", "ioc", "clean", "incomplete", "choice", "combined", "denied", "nonobject", "nan", "metadata", "eof", "password", "numeric_pii", "final_secret"])
async def test_stream_tool_egress_gate(monkeypatch, kind):
    raw = json.dumps({"city": "Madrid"})
    if kind == "secret":
        raw = json.dumps({"key": SECRET})
    elif kind == "escaped":
        raw = '{"key":"' + "".join(f"\\u{ord(c):04x}" for c in SECRET) + '"}'
    elif kind == "duplicate":
        raw = '{"city":"Madrid","city":"Paris"}'
    elif kind == "malformed":
        raw = '{"city":'
    elif kind == "ioc":
        raw = '{"url":"https://blocked.example"}'
    elif kind == "nonobject":
        raw = '["Madrid"]'
    elif kind == "nan":
        raw = '{"value":NaN}'
    elif kind == "password":
        raw = '{"password":"R8!mQ2#vL9"}'
    elif kind == "numeric_pii":
        raw = '{"credit_card":4111111111111111}'
    split = len(raw) // 2
    first = event({"tool_calls": [{"index": 0, "id": SECRET if kind == "metadata" else "call_1", "type": "function", "function": {
        "name": "weather", "arguments": raw[:split],
    }}]}, index=1 if kind == "choice" else 0)
    second = event({"tool_calls": [{"index": 0, "function": {"arguments": raw[split:]}}]},
                   finish="tool_calls" if kind == "combined" else None)
    ending = "" if kind in ("incomplete", "combined", "eof") else event({}, finish="tool_calls")
    if kind == "final_secret":
        ending = "data: " + json.dumps({"id": SECRET, "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}) + "\n\n"
    wire = first + second + ending + ("" if kind == "eof" else "data: [DONE]\n\n")
    policy = MagicMock()
    policy.evaluate_tool_calls.return_value = GuardrailResult(verdict=Verdict.BLOCK if kind == "denied" else Verdict.ALLOW)
    ioc = MagicMock()
    ioc.check_content.side_effect = lambda text: ["domain:blocked.example"] if "blocked.example" in text else []
    monkeypatch.setattr(proxy, "_log_events", AsyncMock())
    monkeypatch.setattr(proxy, "_fire_webhook_alert", AsyncMock())
    monkeypatch.setattr(proxy, "_push_recent_block", MagicMock())
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, text=wire))) as client:
        response = await proxy._handle_streaming(client, "https://backend.example", {}, {}, "tenant", "agent", None, ioc, policy)
        output = "".join([part async for part in response.body_iterator])
    if kind in ("clean", "combined"):
        assert output == wire
        assert policy.evaluate_tool_calls.call_args.args[0][0].arguments == {"city": "Madrid"}
    else:
        assert "security_violation" in output
        assert '"tool_calls":' not in output
        assert SECRET not in output


@pytest.mark.parametrize("warning", ["encoded", "dangerous"])
def test_output_warning_does_not_undo_redaction(monkeypatch, warning):
    engine = OutputFilter()
    findings = [SecurityEvent(tenant_id="t", agent_id="a", verdict=Verdict.WARN,
                              category=ThreatCategory.POLICY_VIOLATION,
                              description="warning", source="test", severity="medium")]
    name = "_check_encoded_secrets" if warning == "encoded" else "_check_dangerous_output"
    monkeypatch.setattr(engine, name, lambda *args: findings)
    result = engine.inspect_and_redact(SECRET, "t", "a")
    assert result.verdict == Verdict.REDACT
    assert SECRET not in result.modified_content


@pytest.mark.parametrize("replacement", ["[REDACTED]", ""])
@pytest.mark.parametrize("shape", ["positional", "keyword", "messages"])
async def test_sdk_never_forwards_original_after_redaction(replacement, shape):
    guard = Guard()
    guard._initialized = True
    guard.scan_input = AsyncMock(return_value=ScanResult(verdict=Verdict.REDACT, modified_content=replacement))
    guard.scan_output = AsyncMock(return_value=ScanResult(verdict=Verdict.ALLOW))
    backend = AsyncMock(return_value="safe")
    if shape == "messages":
        with pytest.raises(SecurityError):
            await guard.wrap(backend, messages=[{"role": "user", "content": SECRET}])
        backend.assert_not_awaited()
    elif shape == "keyword":
        await guard.wrap(backend, prompt=SECRET)
        backend.assert_awaited_once_with(prompt=replacement)
    else:
        await guard.wrap(backend, SECRET)
        backend.assert_awaited_once_with(replacement)


@pytest.mark.parametrize("response", ["private", {"content": "private"}, {"text": "private"},
                                      {"choices": [{"message": {"content": "private"}}]},
                                      {"choices": [{"message": {"content": "private"}}], "content": "ok"}])
async def test_sdk_empty_output_redaction_never_returns_original(response):
    guard = Guard()
    guard._initialized = True
    guard.scan_input = AsyncMock(return_value=ScanResult(verdict=Verdict.ALLOW))
    guard.scan_output = AsyncMock(return_value=ScanResult(verdict=Verdict.REDACT, modified_content=""))
    backend = AsyncMock(return_value=response)
    if isinstance(response, dict) and "choices" in response:
        with pytest.raises(SecurityError):
            await guard.wrap(backend, "hi")
    else:
        result = await guard.wrap(backend, "hi")
        assert "private" not in str(result)


async def test_real_stream_does_not_restore_redacted_overlap(monkeypatch):
    text = "x" * 180 + " " + SECRET + " " + "y" * 100
    wire = event({"content": text}) + "data: [DONE]\n\n"
    monkeypatch.setattr(proxy, "_schedule_streaming_telemetry", MagicMock())
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, text=wire))) as client:
        response = await proxy._handle_streaming(
            client, "https://backend.example", {}, {}, "tenant", "agent", None, MagicMock(), MagicMock(),
        )
        output = "".join([part async for part in response.body_iterator])
    content = "".join(
        json.loads(line[6:])["choices"][0]["delta"].get("content", "")
        for line in output.splitlines() if line.startswith("data: {")
    )
    expected = OutputFilter().inspect_and_redact(text, "tenant", "agent").modified_content
    assert content == expected
    assert SECRET not in content


def test_stream_redaction_without_replacement_blocks(monkeypatch):
    monkeypatch.setattr(proxy.output_filter, "inspect_and_redact", lambda *args: GuardrailResult(verdict=Verdict.REDACT))
    assert proxy._filter_chunk("private", "tenant", "agent", None) is None


async def test_legacy_function_stream_never_reaches_client():
    wire = event({"function_call": {"name": "forbidden", "arguments": "{}"}}) + "data: [DONE]\n\n"
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, text=wire))) as client:
        response = await proxy._handle_streaming(
            client, "https://backend.example", {}, {}, "tenant", "agent", None, MagicMock(), MagicMock(),
        )
        output = "".join([part async for part in response.body_iterator])
    assert "security_violation" in output
    assert "forbidden" not in output
