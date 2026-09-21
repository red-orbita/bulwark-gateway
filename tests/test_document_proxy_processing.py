"""Document processing failures are distinct from security detections."""

import base64
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from src.guardrails import attachments
from src.guardrails.document_extraction import ExtractionError
from src.models import SecurityEvent, ThreatCategory, Verdict
from src.routes import proxy
from src.scanners.builtin.regex_scanner import RegexInputScanner

# Shared isolated HTTP fixture: no external services, no production app lifespan.
from tests.test_proxy_security_coverage import isolated_proxy as _isolated_proxy

isolated_proxy = _isolated_proxy


@pytest.mark.parametrize("kind,status", [("no_text", 422), ("incomplete", 422), ("timeout", 503), ("unavailable", 503)])
async def test_processing_failure_is_not_an_attack(isolated_proxy, monkeypatch, tmp_path, kind, status):
    app, pipeline, backend, streaming = isolated_proxy
    pipeline.register(RegexInputScanner())
    monkeypatch.setattr(proxy.settings, "attachment_guard_enabled", True)
    monkeypatch.setattr(proxy.settings, "attachment_extract_documents", True)
    monkeypatch.setattr(proxy.settings, "attachment_parser_isolation_confirmed", True)
    monkeypatch.setattr(proxy.settings, "attachment_extraction_work_dir", tmp_path)
    monkeypatch.setattr(attachments, "extract_document", AsyncMock(side_effect=ExtractionError(kind)))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/v1/chat/completions", json={"model": "test", "messages": [{
            "role": "user", "content": [{"type": "image_url", "image_url": {
                "url": "data:image/png;base64," + base64.b64encode(b"synthetic").decode(),
            }}],
        }]})
    assert response.status_code == status
    assert response.json()["error"]["type"] == "document_processing_error"
    backend.post.assert_not_awaited()
    streaming.assert_not_awaited()


async def test_processing_event_does_not_accrue_origin_risk(monkeypatch):
    queue = SimpleNamespace(enqueue=AsyncMock(return_value=True))
    tap = MagicMock()
    monkeypatch.setattr(proxy, "get_telemetry_queue", lambda: queue)
    monkeypatch.setattr(proxy, "get_event_tap", lambda: tap)
    monkeypatch.setattr(proxy.settings, "correlation_enabled", True)
    event = SecurityEvent(
        tenant_id="tenant", agent_id="agent", verdict=Verdict.BLOCK,
        category=ThreatCategory.POLICY_VIOLATION, severity="high", description="processing unavailable",
        source="attachment_guard", metadata={"reason": "inspection_unavailable", "extraction_reason": "no_text"},
    )
    await proxy._log_events([event])
    tap.publish.assert_not_called()
    record = queue.enqueue.await_args.args[0]
    assert record.event.kind == "event"
    assert record.bulwark.verdict == "not_evaluated"
    assert record.labels == {"reason": "no_text"}


async def test_long_benign_extraction_survives_whole_request_dlp(isolated_proxy, monkeypatch, tmp_path):
    app, pipeline, backend, _ = isolated_proxy
    pipeline.register(RegexInputScanner())
    pipeline._all_scanners["regex_input"].scanner._engine.messages_budget_seconds = 10
    monkeypatch.setattr(proxy.settings, "attachment_guard_enabled", True)
    monkeypatch.setattr(proxy.settings, "attachment_extract_documents", True)
    monkeypatch.setattr(proxy.settings, "attachment_parser_isolation_confirmed", True)
    monkeypatch.setattr(proxy.settings, "attachment_extraction_work_dir", tmp_path)
    monkeypatch.setattr(proxy.settings, "input_dlp_enabled", True)
    text = "Public weather observations for the local area. " * 460
    assert 16384 < len(text) < 32768
    monkeypatch.setattr(attachments, "extract_document", AsyncMock(return_value=text))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/v1/chat/completions", json={"model": "test", "messages": [{
            "role": "user", "content": [{"type": "file", "file": {"filename": "public.pdf",
                "file_data": "data:application/pdf;base64," + base64.b64encode(b"synthetic").decode()}}],
        }]})
    assert response.status_code == 418
    assert text in backend.post.await_args.kwargs["json"]["messages"][0]["content"][0]["text"]
