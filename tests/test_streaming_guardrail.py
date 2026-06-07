"""
Tests for streaming response guardrails.

Tests the chunk-level output filtering in the SSE streaming path.
"""

import json

import pytest

from src.routes.proxy import _filter_chunk, _make_content_event, _make_error_event


class TestFilterChunk:
    """Test the chunk-level output filter helper."""

    def test_clean_content_passes_through(self):
        result = _filter_chunk("Hello, how can I help you?", "test", "agent1", None)
        assert result == "Hello, how can I help you?"

    def test_redacts_aws_key(self):
        content = "Here's your key: AKIAIOSFODNN7EXAMPLE"
        result = _filter_chunk(content, "test", "agent1", None)
        assert result is not None
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "[REDACTED" in result

    def test_redacts_private_key(self):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK..."
        result = _filter_chunk(content, "test", "agent1", None)
        assert result is not None
        assert "BEGIN RSA PRIVATE KEY" not in result

    def test_clean_code_passes(self):
        content = "def hello():\n    return 'world'\n"
        result = _filter_chunk(content, "test", "agent1", None)
        assert result == content


class TestMakeContentEvent:
    """Test SSE content event formatting."""

    def test_creates_valid_sse(self):
        event = _make_content_event("hello")
        assert event.startswith("data: ")
        assert event.endswith("\n\n")
        data = json.loads(event[6:].strip())
        assert data["choices"][0]["delta"]["content"] == "hello"
        assert data["choices"][0]["finish_reason"] is None

    def test_preserves_special_chars(self):
        event = _make_content_event("line1\nline2")
        data = json.loads(event[6:].strip())
        assert data["choices"][0]["delta"]["content"] == "line1\nline2"


class TestMakeErrorEvent:
    """Test SSE error event formatting."""

    def test_creates_error_with_done(self):
        event = _make_error_event("blocked")
        assert "data: [DONE]" in event
        # First data line is the error
        lines = [l for l in event.split("\n") if l.startswith("data: ")]
        error_data = json.loads(lines[0][6:])
        assert error_data["error"]["type"] == "security_violation"
        assert error_data["error"]["message"] == "blocked"
