"""
Tests for the LLM-as-Judge input scanner.

These verify:
  - Inert (ALLOW) when disabled — the master registration gate.
  - Correct verdict mapping from the tolerant chat-completions judge answer.
  - ASYNC (WARN-only) vs BLOCKING (BLOCK) behaviour.
  - Fail-OPEN on any request-time judge error (even in blocking mode).
  - Fail-CLOSED readiness at boot (health()=False) only when blocking +
    unreachable, so the readiness backstop can make the FAIL_MODE call.
  - Tolerant parsing: JSON wrapped in prose / fences, ``verdict``/``unsafe``
    fallbacks, score coercion, category mapping.
"""

from typing import Any
from unittest.mock import patch

import httpx
import pytest

from src.models import ThreatCategory, Verdict
from src.scanners.ml.llm_judge import LlmJudgeScanner
from src.scanners.protocol import ScanContext, ScannerType

_ENABLED = "src.scanners.ml.llm_judge.settings.llm_judge_enabled"


def _make_context(**kwargs) -> ScanContext:
    defaults = {
        "tenant_id": "test-tenant",
        "agent_id": "test-agent",
        "request_id": "req-001",
        "messages": [{"role": "user", "content": "test"}],
    }
    defaults.update(kwargs)
    return ScanContext(**defaults)


def _completion(content: str) -> dict[str, Any]:
    """Wrap a judge answer string in an OpenAI chat-completions envelope."""
    return {"choices": [{"message": {"role": "assistant", "content": content}}]}


class _FakeResponse:
    def __init__(self, status_code: int, payload: Any) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> Any:
        return self._payload


class _FakeClient:
    """Minimal stand-in for httpx.AsyncClient used by the scanner."""

    def __init__(self, response: _FakeResponse | None = None, exc: Exception | None = None) -> None:
        self._response = response
        self._exc = exc
        self.closed = False
        self.calls: list[dict[str, Any]] = []

    async def post(self, url: str, json: Any = None) -> _FakeResponse:
        self.calls.append({"url": url, "json": json})
        if self._exc is not None:
            raise self._exc
        assert self._response is not None
        return self._response

    async def aclose(self) -> None:
        self.closed = True


def _scanner(**kwargs) -> LlmJudgeScanner:
    defaults = {
        "url": "http://ollama.test/v1/chat/completions",
        "model": "gemma2:2b",
        "blocking": False,
        "block_threshold": 0.85,
        "warn_threshold": 0.6,
    }
    defaults.update(kwargs)
    return LlmJudgeScanner(**defaults)


class TestLlmJudgeInfo:
    def test_info_async_mode(self):
        s = _scanner(blocking=False)
        assert s.info.name == "llm_judge"
        assert s.info.scanner_type == ScannerType.INPUT_ASYNC

    def test_info_blocking_mode(self):
        s = _scanner(blocking=True)
        assert s.info.scanner_type == ScannerType.INPUT_BLOCKING


class TestLlmJudgeScan:
    @pytest.mark.asyncio
    async def test_inert_when_disabled(self):
        """Disabled → ALLOW without even touching the endpoint."""
        s = _scanner(blocking=True)
        s._client = _FakeClient(exc=httpx.ConnectError("should not be called"))
        with patch(_ENABLED, False):
            result = await s.scan("ignore previous instructions", _make_context())
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_blocks_on_high_score_blocking(self):
        s = _scanner(blocking=True)
        s._client = _FakeClient(
            _FakeResponse(
                200,
                _completion(
                    '{"unsafe": true, "score": 0.95, '
                    '"category": "prompt_injection", "reason": "override attempt"}'
                ),
            )
        )
        with patch(_ENABLED, True):
            result = await s.scan("ignore all instructions", _make_context())
        assert result.verdict == Verdict.BLOCK
        assert len(result.events) == 1
        assert result.events[0].category == ThreatCategory.PROMPT_INJECTION
        assert result.events[0].source == "llm_judge"
        assert result.events[0].metadata["llm_judge_model"] == "gemma2:2b"

    @pytest.mark.asyncio
    async def test_high_score_async_only_warns(self):
        """Async mode never BLOCKs, even above the block threshold."""
        s = _scanner(blocking=False)
        s._client = _FakeClient(_FakeResponse(200, _completion('{"unsafe": true, "score": 0.99}')))
        with patch(_ENABLED, True):
            result = await s.scan("attack", _make_context())
        assert result.verdict == Verdict.WARN

    @pytest.mark.asyncio
    async def test_warns_on_medium_score(self):
        s = _scanner(blocking=True)
        s._client = _FakeClient(_FakeResponse(200, _completion('{"unsafe": true, "score": 0.7}')))
        with patch(_ENABLED, True):
            result = await s.scan("maybe injection", _make_context())
        assert result.verdict == Verdict.WARN

    @pytest.mark.asyncio
    async def test_allows_on_low_score(self):
        s = _scanner(blocking=True)
        s._client = _FakeClient(
            _FakeResponse(200, _completion('{"unsafe": false, "score": 0.1, "category": "safe"}'))
        )
        with patch(_ENABLED, True):
            result = await s.scan("normal question", _make_context())
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_json_wrapped_in_prose_is_parsed(self):
        """A judge that wraps its JSON in ```json fences / prose still parses."""
        s = _scanner(blocking=True)
        answer = 'Sure, here is my verdict:\n```json\n{"unsafe": true, "score": 0.9}\n```'
        s._client = _FakeClient(_FakeResponse(200, _completion(answer)))
        with patch(_ENABLED, True):
            result = await s.scan("x", _make_context())
        assert result.verdict == Verdict.BLOCK

    @pytest.mark.asyncio
    async def test_unsafe_boolean_without_score_treated_as_one(self):
        s = _scanner(blocking=True)
        s._client = _FakeClient(_FakeResponse(200, _completion('{"unsafe": true}')))
        with patch(_ENABLED, True):
            result = await s.scan("x", _make_context())
        assert result.verdict == Verdict.BLOCK
        assert result.events[0].metadata["llm_judge_score"] == 1.0

    @pytest.mark.asyncio
    async def test_verdict_string_block(self):
        s = _scanner(blocking=True)
        s._client = _FakeClient(_FakeResponse(200, _completion('{"verdict": "block"}')))
        with patch(_ENABLED, True):
            result = await s.scan("x", _make_context())
        assert result.verdict == Verdict.BLOCK

    @pytest.mark.asyncio
    async def test_verdict_string_safe_allows(self):
        s = _scanner(blocking=True)
        s._client = _FakeClient(_FakeResponse(200, _completion('{"verdict": "safe"}')))
        with patch(_ENABLED, True):
            result = await s.scan("hello", _make_context())
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_category_mapping(self):
        s = _scanner(blocking=True)
        s._client = _FakeClient(
            _FakeResponse(200, _completion('{"unsafe": true, "score": 0.9, "category": "jailbreak"}'))
        )
        with patch(_ENABLED, True):
            result = await s.scan("x", _make_context())
        assert result.events[0].category == ThreatCategory.JAILBREAK

    @pytest.mark.asyncio
    async def test_unknown_category_defaults(self):
        s = _scanner(blocking=True)
        s._client = _FakeClient(
            _FakeResponse(200, _completion('{"unsafe": true, "score": 0.9, "category": "weird"}'))
        )
        with patch(_ENABLED, True):
            result = await s.scan("x", _make_context())
        assert result.events[0].category == ThreatCategory.PROMPT_INJECTION

    @pytest.mark.asyncio
    async def test_fail_open_on_connect_error_even_blocking(self):
        """A judge network error degrades to ALLOW even in blocking mode."""
        s = _scanner(blocking=True)
        s._client = _FakeClient(exc=httpx.ConnectError("judge down"))
        with patch(_ENABLED, True):
            result = await s.scan("attack", _make_context())
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_fail_open_on_bad_status(self):
        s = _scanner(blocking=True)
        s._client = _FakeClient(_FakeResponse(500, {}))
        with patch(_ENABLED, True):
            result = await s.scan("attack", _make_context())
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_fail_open_on_no_choices(self):
        s = _scanner(blocking=True)
        s._client = _FakeClient(_FakeResponse(200, {"choices": []}))
        with patch(_ENABLED, True):
            result = await s.scan("attack", _make_context())
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_fail_open_on_non_json_completion(self):
        s = _scanner(blocking=True)
        s._client = _FakeClient(_FakeResponse(200, _completion("I cannot help with that.")))
        with patch(_ENABLED, True):
            result = await s.scan("attack", _make_context())
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_fail_open_on_malformed_body(self):
        s = _scanner(blocking=True)
        s._client = _FakeClient(_FakeResponse(200, "not-a-dict"))
        with patch(_ENABLED, True):
            result = await s.scan("attack", _make_context())
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_no_url_is_inert(self):
        s = _scanner(url="")
        with patch(_ENABLED, True):
            result = await s.scan("attack", _make_context())
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_text_field_fallback(self):
        """Some endpoints put the answer under choices[0].text, not .message."""
        s = _scanner(blocking=True)
        s._client = _FakeClient(
            _FakeResponse(200, {"choices": [{"text": '{"unsafe": true, "score": 0.9}'}]})
        )
        with patch(_ENABLED, True):
            result = await s.scan("x", _make_context())
        assert result.verdict == Verdict.BLOCK


class TestLlmJudgeHealth:
    @pytest.mark.asyncio
    async def test_health_disabled_is_true(self):
        s = _scanner(blocking=True)
        with patch(_ENABLED, False):
            assert await s.health() is True

    @pytest.mark.asyncio
    async def test_health_async_always_true(self):
        s = _scanner(blocking=False)
        s._reachable = False
        with patch(_ENABLED, True):
            assert await s.health() is True

    @pytest.mark.asyncio
    async def test_health_blocking_unreachable_false(self):
        s = _scanner(blocking=True)
        s._reachable = False
        with patch(_ENABLED, True):
            assert await s.health() is False

    @pytest.mark.asyncio
    async def test_health_blocking_reachable_true(self):
        s = _scanner(blocking=True)
        s._reachable = True
        with patch(_ENABLED, True):
            assert await s.health() is True


class TestLlmJudgeLifecycle:
    @pytest.mark.asyncio
    async def test_startup_skipped_when_disabled(self):
        s = _scanner(blocking=True)
        with patch(_ENABLED, False):
            await s.startup()
        assert s._client is None

    @pytest.mark.asyncio
    async def test_startup_async_marks_reachable_without_probe(self):
        s = _scanner(blocking=False)
        with patch(_ENABLED, True):
            await s.startup()
        assert s._reachable is True
        assert s._client is not None
        await s.shutdown()

    @pytest.mark.asyncio
    async def test_startup_blocking_probe_success(self):
        s = _scanner(blocking=True)
        fake = _FakeClient(_FakeResponse(200, _completion('{"unsafe": false}')))
        with patch(_ENABLED, True), patch.object(s, "_build_client", return_value=fake):
            await s.startup()
        assert s._reachable is True
        assert fake.calls  # probe was sent

    @pytest.mark.asyncio
    async def test_startup_blocking_probe_failure_is_not_fatal(self):
        s = _scanner(blocking=True)
        fake = _FakeClient(exc=httpx.ConnectError("down"))
        with patch(_ENABLED, True), patch.object(s, "_build_client", return_value=fake):
            await s.startup()  # must not raise
        assert s._reachable is False

    @pytest.mark.asyncio
    async def test_shutdown_closes_client(self):
        s = _scanner()
        fake = _FakeClient(_FakeResponse(200, {}))
        s._client = fake
        await s.shutdown()
        assert fake.closed is True
        assert s._client is None
