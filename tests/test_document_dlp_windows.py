"""Extracted document admission followed by whole-request DLP, without native tools."""

import base64
import copy
from unittest.mock import AsyncMock, Mock

import pytest

from src.guardrails import attachments, input_dlp
from src.guardrails.attachments import AttachmentPolicy, inspect_chat_attachments
from src.guardrails.input_dlp import InputDlpPolicy, inspect_request
from src.models import GuardrailResult, Verdict

PARAGRAPH = (
    "The quarterly report describes progress on the community garden. "
    "Volunteers planted vegetables, repaired the fence, and discussed the next meeting. "
    "The public schedule includes a weekend workshop and a review of the spring harvest.\n\n"
)


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Pure attachment tests do not initialize the admin database."""


@pytest.mark.parametrize("mock_detector", [True, False])
@pytest.mark.parametrize("length", [20480, 32768])
async def test_long_image_text_survives_whole_request_dlp(monkeypatch, tmp_path, mock_detector, length):
    text = (PARAGRAPH * 150)[:length]
    assert len(text) == length
    extractor = AsyncMock(return_value=text)
    monkeypatch.setattr(attachments, "extract_document", extractor)
    scanned = []
    if mock_detector:
        def scan(self, content, tenant, agent):
            scanned.append(content)
            return GuardrailResult(verdict=Verdict.ALLOW)

        monkeypatch.setattr(input_dlp.OutputFilter, "inspect_and_redact", scan)
    body = {"model": "local", "messages": [{"role": "user", "content": [{
        "type": "image_url", "image_url": {
            "url": "data:image/png;base64," + base64.b64encode(b"synthetic image").decode(),
        },
    }]}]}
    original = copy.deepcopy(body)
    image_ref = body["messages"][0]["content"][0]
    guard = Mock(max_scan_bytes=16000, max_input_size=4096,
                 inspect=Mock(return_value=GuardrailResult(verdict=Verdict.ALLOW)))
    result = await inspect_chat_attachments(
        body, "tenant", "agent", "request", policy=AttachmentPolicy(enabled=True, extract_documents=True),
        input_guardrail=guard, parser_isolation_confirmed=True, extraction_work_dir=tmp_path,
    )
    assert result.guardrail_result.verdict == Verdict.ALLOW
    sanitized = result.sanitized_body
    assert sanitized is not None
    sanitized_original = copy.deepcopy(sanitized)
    sanitized_ref = sanitized["messages"][0]["content"][0]
    assert sanitized_ref == {"type": "text", "text": attachments.DOCUMENT_PROVENANCE + text}
    final = inspect_request(sanitized, "tenant", "agent", "request")
    assert final.verdict == Verdict.ALLOW
    assert body == original
    assert body["messages"][0]["content"][0] is image_ref
    assert sanitized == sanitized_original
    assert sanitized["messages"][0]["content"][0] is sanitized_ref
    if mock_detector:
        assert len(scanned) > 2
        assert all(len(window.encode()) <= 16384 for window in scanned)


@pytest.mark.parametrize("restricted", [False, True])
async def test_long_document_tail_dlp_never_approved(monkeypatch, tmp_path, restricted):
    marker = "Project Falcon" if restricted else "AKIAIOSFODNN7EXAMPLE"
    text = PARAGRAPH * 90 + marker
    assert len(text) > 20000
    monkeypatch.setattr(attachments, "extract_document", AsyncMock(return_value=text))
    body = {"messages": [{"role": "user", "content": [{
        "type": "file", "file": {"filename": "report.pdf", "file_data":
                                   "data:application/pdf;base64,c3ludGhldGlj"},
    }]}]}
    original = copy.deepcopy(body)
    result = await inspect_chat_attachments(
        body, "tenant", "agent", "request", policy=AttachmentPolicy(enabled=True, extract_documents=True),
        input_guardrail=Mock(max_scan_bytes=16000, max_input_size=4096,
                             inspect=Mock(return_value=GuardrailResult(verdict=Verdict.ALLOW))),
        parser_isolation_confirmed=True, extraction_work_dir=tmp_path,
        dlp_options=InputDlpPolicy(blocked_terms=(marker,) if restricted else ()),
    )
    assert result.guardrail_result.verdict == Verdict.BLOCK
    assert result.guardrail_result.events[-1].metadata == {"reason": "input_dlp"}
    assert result.sanitized_body is None
    assert marker not in result.guardrail_result.model_dump_json()
    assert body == original
