"""Tests for the ArtifactOutputScanner (OUTPUT_ASYNC, insecure-output / LLM02).

The scanner decodes inline base64 blobs / data: URIs from an LLM response and
runs the shared stdlib pickle-opcode engine over the bytes. It is DETECTIVE:
it emits WARN events but never blocks or rewrites the response, and — like the
underlying engine — it NEVER deserializes the payload.

All malicious fixtures are built here at test time; none are ever unpickled.
"""

from __future__ import annotations

import base64
import os
import pickle

import pytest

from src.models import ThreatCategory, Verdict
from src.scanners.output.artifact_scanner import ArtifactOutputScanner
from src.scanners.protocol import ScannerType


def _make_context():
    from src.scanners.protocol import ScanContext

    return ScanContext(
        tenant_id="test-tenant",
        agent_id="test-agent",
        request_id="req-artifact",
        messages=[{"role": "user", "content": "give me the model"}],
    )


class _OsSystemRCE:
    def __reduce__(self):
        return (os.system, ("id",))


def _b64_pickle_rce() -> str:
    return base64.b64encode(pickle.dumps(_OsSystemRCE())).decode()


def _b64_benign_pickle() -> str:
    return base64.b64encode(
        pickle.dumps({"weights": [1, 2, 3], "name": "model"})
    ).decode()


def _b64_fake_image() -> str:
    # JPEG magic + filler — a common benign base64 blob in responses.
    return base64.b64encode(b"\xff\xd8\xff\xe0" + b"JFIF-fake-image-bytes" * 40).decode()


class TestArtifactOutputScanner:
    @pytest.mark.asyncio
    async def test_info_is_output_async(self):
        scanner = ArtifactOutputScanner()
        assert scanner.info.name == "artifact_output_scanner"
        assert scanner.info.scanner_type == ScannerType.OUTPUT_ASYNC

    @pytest.mark.asyncio
    async def test_detects_base64_pickle_rce(self):
        scanner = ArtifactOutputScanner()
        blob = _b64_pickle_rce()
        result = await scanner.scan(f"Here is your model: {blob}", _make_context())

        assert result.verdict == Verdict.WARN
        assert len(result.events) == 1
        ev = result.events[0]
        assert ev.category == ThreatCategory.INSECURE_OUTPUT
        assert ev.matched_pattern == "BWK-ART-PICKLE-RCE"
        assert ev.source == "artifact_output_scanner"

    @pytest.mark.asyncio
    async def test_detects_data_uri_pickle_rce(self):
        scanner = ArtifactOutputScanner()
        blob = _b64_pickle_rce()
        content = f"model attached: data:application/octet-stream;base64,{blob}"
        result = await scanner.scan(content, _make_context())

        assert result.verdict == Verdict.WARN
        assert result.events[0].matched_pattern == "BWK-ART-PICKLE-RCE"

    @pytest.mark.asyncio
    async def test_benign_pickle_is_allowed(self):
        scanner = ArtifactOutputScanner()
        result = await scanner.scan(f"cache: {_b64_benign_pickle()}", _make_context())
        assert result.verdict == Verdict.ALLOW
        assert result.events == []

    @pytest.mark.asyncio
    async def test_benign_base64_image_is_not_flagged(self):
        """A decoded image is a 'malformed pickle' (low) — must NOT surface as WARN."""
        scanner = ArtifactOutputScanner()
        content = f"data:image/jpeg;base64,{_b64_fake_image()}"
        result = await scanner.scan(content, _make_context())
        assert result.verdict == Verdict.ALLOW
        assert result.events == []

    @pytest.mark.asyncio
    async def test_plain_text_is_allowed(self):
        scanner = ArtifactOutputScanner()
        result = await scanner.scan(
            "This is a normal answer with no artifacts at all.", _make_context()
        )
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_empty_content_is_allowed(self):
        scanner = ArtifactOutputScanner()
        result = await scanner.scan("", _make_context())
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_short_base64_ignored(self):
        """A short base64 token (below the min length) is not decoded/scanned."""
        scanner = ArtifactOutputScanner()
        result = await scanner.scan("token=YWJj123", _make_context())
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_scanner_never_executes_payload(self, tmp_path):
        """Regression: scanning must NEVER deserialize/run the pickle payload."""
        marker = tmp_path / "pwned"
        klass = type(
            "Marker",
            (),
            {"__reduce__": lambda self: (os.system, (f"touch {marker}",))},
        )
        blob = base64.b64encode(pickle.dumps(klass())).decode()
        result = await scanner_scan(blob)
        assert result.verdict == Verdict.WARN
        assert not marker.exists(), "scanner executed the pickle payload!"

    @pytest.mark.asyncio
    async def test_health_is_true(self):
        scanner = ArtifactOutputScanner()
        assert await scanner.health() is True


async def scanner_scan(blob: str):
    scanner = ArtifactOutputScanner()
    return await scanner.scan(f"payload: {blob}", _make_context())


class TestArtifactOutputScannerConfig:
    def test_flag_defaults_off(self):
        from src.config import settings

        assert settings.artifact_output_scanning_enabled is False
