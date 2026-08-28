"""
Wiring tests for the multilingual + multimodal per-agent policy integration.

These are NOT unit tests of the LanguageDetector / ImageHygieneScanner detection
logic (those live in tests/test_multilingual_multimodal.py). They pin the *wiring*
that makes an agent's opt-in language / image policy reachable from a real request:

  1. The `multilingual_enabled` / `image_hygiene_scanning_enabled` /
     `vision_scanning_enabled` flags are off by default (opt-in).
  2. `AgentPolicy.allowed_languages`, `block_unknown_language`, and `multimodal`
     are parsed from policy YAML by the loader.
  3. The proxy's `_get_agent_policy` accessor resolves a tenant/agent policy from
     app state and degrades to None (never raises) when the loader/engine is
     absent — so the hot path stays fail-safe.
  4. The exact ScanContext the proxy builds (policy `allowed_languages` /
     `multimodal` threaded into `metadata`) drives real BLOCK / ALLOW verdicts
     through `run_input_blocking` — i.e. an agent's policy actually reaches the
     scanner's enforcement branch. Before this wiring the scanners read these keys
     from metadata but the loader never parsed them and the proxy never threaded
     them, so enforcement silently failed open.

No mocks: the LanguageDetector runs its real script-heuristic detection and the
ImageHygieneScanner runs its real deterministic policy gate.
"""

from __future__ import annotations

import base64
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.config import Settings
from src.models import Verdict
from src.policies.loader import PolicyLoader
from src.routes.proxy import _get_agent_policy
from src.scanners.multilingual.language_detector import LanguageDetector
from src.scanners.multimodal.image_hygiene_scanner import ImageHygieneScanner
from src.scanners.pipeline import ScannerPipeline
from src.scanners.protocol import ScanContext, ScannerType


# ==============================================================================
# 1. Flags are opt-in (default off)
# ==============================================================================
def test_multilingual_flag_defaults_off():
    settings = Settings(jwt_secret="x" * 40)
    assert settings.multilingual_enabled is False


def test_image_hygiene_flag_defaults_off():
    settings = Settings(jwt_secret="x" * 40)
    assert settings.image_hygiene_scanning_enabled is False


def test_vision_flag_defaults_off():
    settings = Settings(jwt_secret="x" * 40)
    assert settings.vision_scanning_enabled is False


def test_multilingual_flag_can_be_enabled(monkeypatch):
    monkeypatch.setenv("BULWARK_MULTILINGUAL_ENABLED", "true")
    settings = Settings(jwt_secret="x" * 40)
    assert settings.multilingual_enabled is True


def test_image_hygiene_flag_can_be_enabled(monkeypatch):
    monkeypatch.setenv("BULWARK_IMAGE_HYGIENE_SCANNING_ENABLED", "true")
    settings = Settings(jwt_secret="x" * 40)
    assert settings.image_hygiene_scanning_enabled is True


# ==============================================================================
# 2. Loader parses allowed_languages / block_unknown_language / multimodal
# ==============================================================================
_POLICY_YAML = textwrap.dedent(
    """
    tenant: acme
    agents:
      - id: english-only
        sandbox_level: strict
        allowed_tools: [read_kb]
        allowed_languages: [en]
        block_unknown_language: true
        multimodal:
          allow_images: false
          max_image_size_mb: 2
          ocr_scan: true
      - id: chatbot
        allowed_tools: [web_search]
    """
)


@pytest.mark.asyncio
async def test_loader_parses_multilingual_multimodal(tmp_path: Path):
    (tmp_path / "acme.yaml").write_text(_POLICY_YAML)
    loader = PolicyLoader(tmp_path)
    await loader.load_all()

    policy = loader.engine.get_policy("acme", "english-only")
    assert policy is not None
    assert policy.allowed_languages == ["en"]
    assert policy.block_unknown_language is True
    assert policy.multimodal["allow_images"] is False
    assert policy.multimodal["max_image_size_mb"] == 2
    assert policy.multimodal["ocr_scan"] is True


@pytest.mark.asyncio
async def test_loader_defaults_multilingual_multimodal_empty(tmp_path: Path):
    """An agent without language/multimodal blocks gets inert defaults."""
    (tmp_path / "acme.yaml").write_text(_POLICY_YAML)
    loader = PolicyLoader(tmp_path)
    await loader.load_all()

    chatbot = loader.engine.get_policy("acme", "chatbot")
    assert chatbot is not None
    assert chatbot.allowed_languages == []
    assert chatbot.block_unknown_language is False
    assert chatbot.multimodal == {}


# ==============================================================================
# 3. Proxy `_get_agent_policy` accessor is None-safe
# ==============================================================================
@pytest.mark.asyncio
async def test_get_agent_policy_returns_policy(tmp_path: Path):
    (tmp_path / "acme.yaml").write_text(_POLICY_YAML)
    loader = PolicyLoader(tmp_path)
    await loader.load_all()

    request = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(policy_loader=loader))
    )
    policy = _get_agent_policy(request, "acme", "english-only")
    assert policy is not None
    assert policy.allowed_languages == ["en"]


def test_get_agent_policy_none_when_loader_missing():
    """No policy_loader on app.state → None, never AttributeError."""
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))
    assert _get_agent_policy(request, "acme", "english-only") is None


def test_get_agent_policy_none_when_engine_none():
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(policy_loader=SimpleNamespace(engine=None))
        )
    )
    assert _get_agent_policy(request, "acme", "english-only") is None


def test_get_agent_policy_none_for_unknown_agent(tmp_path: Path):
    loader = PolicyLoader(tmp_path)  # empty dir → no policies registered
    request = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(policy_loader=loader))
    )
    assert _get_agent_policy(request, "acme", "ghost") is None


# ==============================================================================
# 4a. End-to-end: the input ScanContext drives real LanguageDetector verdicts
# ==============================================================================
def _proxy_in_context(
    allowed_languages: list[str] | None,
    block_unknown: bool = False,
    multimodal: dict | None = None,
    image_contents: list | None = None,
) -> ScanContext:
    """Build the same input ScanContext the proxy constructs (see proxy.py).

    The proxy threads the agent's `allowed_languages` / `block_unknown_language`
    only when `allowed_languages` is non-empty, and `multimodal` only when
    non-empty; otherwise those metadata keys are absent (scanner fails open).
    """
    metadata: dict = {}
    if allowed_languages:
        metadata["allowed_languages"] = allowed_languages
        metadata["block_unknown_language"] = block_unknown
    if multimodal:
        metadata["multimodal"] = multimodal
    if image_contents is not None:
        metadata["image_contents"] = image_contents
    return ScanContext(
        tenant_id="acme",
        agent_id="english-only",
        request_id="req-1",
        messages=[{"role": "user", "content": "x"}],
        metadata=metadata,
    )


async def _run_language(
    allowed_languages: list[str] | None, content: str, block_unknown: bool = False
):
    detector = LanguageDetector()
    pipeline = ScannerPipeline()
    pipeline.register(detector)
    await pipeline.startup()
    # Pin the deterministic script heuristic regardless of whether an optional
    # lingua/fasttext backend happens to be installed in the test environment.
    detector._backend = "heuristic"
    detector._lingua_detector = None
    detector._fasttext_model = None
    ctx = _proxy_in_context(allowed_languages, block_unknown=block_unknown)
    return await pipeline.run_input_blocking(content, ctx)


# Pure Han script → detected "zh" at high confidence by every backend.
_CHINESE = "这是一个测试请求用来验证语言检测的功能是否正常运作良好"


def test_language_detector_is_input_blocking():
    assert LanguageDetector().info.scanner_type == ScannerType.INPUT_BLOCKING


@pytest.mark.asyncio
async def test_disallowed_language_blocks_via_policy():
    """zh input + allowed=[en], high confidence → BLOCK from the policy branch."""
    result = await _run_language(["en"], _CHINESE)
    assert result.verdict == Verdict.BLOCK
    assert result.events
    assert result.events[0].source == "language_detector"


@pytest.mark.asyncio
async def test_allowed_language_passes_via_policy():
    """zh input + allowed=[zh] → ALLOW (detected language is permitted)."""
    result = await _run_language(["zh"], _CHINESE)
    assert result.verdict == Verdict.ALLOW


@pytest.mark.asyncio
async def test_inert_when_agent_has_no_allowed_languages():
    """No allowed_languages threaded → no enforcement, ALLOW regardless of lang."""
    result = await _run_language(None, _CHINESE)
    assert result.verdict == Verdict.ALLOW
    assert result.events == []


# ==============================================================================
# 4b. End-to-end: the input ScanContext drives real ImageHygiene verdicts
# ==============================================================================
def _png_data_uri() -> str:
    """A tiny but structurally valid PNG (magic bytes) as a data URI."""
    png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 24
    return "data:image/png;base64," + base64.b64encode(png_bytes).decode()


async def _run_image(multimodal: dict | None, image_contents: list):
    scanner = ImageHygieneScanner(blocking=True)
    pipeline = ScannerPipeline()
    pipeline.register(scanner)
    await pipeline.startup()
    ctx = _proxy_in_context(None, multimodal=multimodal, image_contents=image_contents)
    return await pipeline.run_input_blocking("look at this", ctx)


@pytest.mark.asyncio
async def test_images_blocked_when_policy_disallows():
    """multimodal.allow_images=False → BLOCK the moment an image is present."""
    result = await _run_image({"allow_images": False}, [_png_data_uri()])
    assert result.verdict == Verdict.BLOCK
    assert result.events
    assert result.events[0].source == "image_hygiene_scanner"


@pytest.mark.asyncio
async def test_images_allowed_when_policy_permits():
    """allow_images defaults True → a valid small image passes (ALLOW)."""
    result = await _run_image({"allow_images": True}, [_png_data_uri()])
    assert result.verdict == Verdict.ALLOW


@pytest.mark.asyncio
async def test_inert_when_agent_has_no_multimodal_policy():
    """No multimodal policy threaded → allow_images defaults True → not blocked.

    Proves the BLOCK in test_images_blocked_when_policy_disallows is driven by
    the threaded policy, not by the presence of an image alone.
    """
    result = await _run_image(None, [_png_data_uri()])
    assert result.verdict == Verdict.ALLOW
