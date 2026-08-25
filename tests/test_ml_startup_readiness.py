"""
Tests for the P0 ML startup-readiness fix (the "blocking scanner without a model
blocks all traffic" landmine).

Covers three units, all without loading real ONNX models:
  1. model_files_present()           — registration-time provisioning gate
  2. ScannerPipeline.unhealthy_blocking_scanners() — post-startup detection
  3. resolve_blocking_readiness()     — fail-mode decision policy

These are the pieces that convert a silent total outage (an ML scanner whose
model failed to load fails-closed and BLOCKs every request) into either an
explicit boot-time refusal (fail_mode=closed) or a loud graceful degradation
(fail_mode=open).
"""

from __future__ import annotations

import pytest

from src.models import GuardrailResult, Verdict
from src.scanners.ml.model_manager import model_files_present
from src.scanners.pipeline import (
    ScannerPipeline,
    resolve_blocking_readiness,
)
from src.scanners.protocol import (
    InputScanner,
    OutputScanner,
    ScanContext,
    ScannerInfo,
    ScannerType,
)

# === Fixtures / fakes ===============================================


class _HealthScanner(InputScanner):
    """Input scanner whose health() and scanner_type are configurable."""

    def __init__(
        self,
        name: str,
        healthy: bool,
        scanner_type: ScannerType = ScannerType.INPUT_BLOCKING,
    ) -> None:
        self._name = name
        self._healthy = healthy
        self._type = scanner_type

    @property
    def info(self) -> ScannerInfo:
        return ScannerInfo(name=self._name, version="1.0.0", scanner_type=self._type)

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        return GuardrailResult(verdict=Verdict.ALLOW)

    async def health(self) -> bool:
        return self._healthy


class _HealthOutputScanner(OutputScanner):
    """Output scanner with a configurable health()."""

    def __init__(self, name: str, healthy: bool) -> None:
        self._name = name
        self._healthy = healthy

    @property
    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name=self._name, version="1.0.0", scanner_type=ScannerType.OUTPUT_BLOCKING
        )

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        return GuardrailResult(verdict=Verdict.ALLOW)

    async def health(self) -> bool:
        return self._healthy


class _RaisingHealthScanner(InputScanner):
    """Blocking scanner whose health() raises — must be treated as unhealthy."""

    @property
    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="raiser", version="1.0.0", scanner_type=ScannerType.INPUT_BLOCKING
        )

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        return GuardrailResult(verdict=Verdict.ALLOW)

    async def health(self) -> bool:
        raise RuntimeError("model manager exploded")


# === model_files_present() ==========================================


def test_model_files_present_true_when_both_files_exist(tmp_path):
    sub = tmp_path / "injection-classifier"
    sub.mkdir()
    (sub / "model.onnx").write_bytes(b"\x00")
    (sub / "tokenizer.json").write_text("{}")
    assert model_files_present("injection-classifier", model_dir=tmp_path) is True


def test_model_files_present_false_when_onnx_missing(tmp_path):
    sub = tmp_path / "intent-classifier"
    sub.mkdir()
    (sub / "tokenizer.json").write_text("{}")  # only tokenizer, no model.onnx
    assert model_files_present("intent-classifier", model_dir=tmp_path) is False


def test_model_files_present_false_when_tokenizer_missing(tmp_path):
    sub = tmp_path / "topic-classifier"
    sub.mkdir()
    (sub / "model.onnx").write_bytes(b"\x00")  # only model, no tokenizer
    assert model_files_present("topic-classifier", model_dir=tmp_path) is False


def test_model_files_present_false_when_dir_missing(tmp_path):
    # Directory does not exist at all (the topic/intent real-world case).
    assert model_files_present("does-not-exist", model_dir=tmp_path) is False


def test_model_files_present_blocks_path_traversal(tmp_path):
    # A malicious subdir must never escape the model directory.
    assert model_files_present("../../etc", model_dir=tmp_path) is False


# === unhealthy_blocking_scanners() ==================================


@pytest.mark.asyncio
async def test_unhealthy_blocking_detected():
    pipeline = ScannerPipeline()
    pipeline.register(_HealthScanner("ml_ok", healthy=True))
    pipeline.register(_HealthScanner("ml_broken", healthy=False))

    degraded = await pipeline.unhealthy_blocking_scanners()
    assert degraded == ["ml_broken"]


@pytest.mark.asyncio
async def test_unhealthy_blocking_all_healthy_returns_empty():
    pipeline = ScannerPipeline()
    pipeline.register(_HealthScanner("regex", healthy=True))
    pipeline.register(_HealthScanner("ml_ok", healthy=True))

    assert await pipeline.unhealthy_blocking_scanners() == []


@pytest.mark.asyncio
async def test_unhealthy_output_blocking_detected():
    pipeline = ScannerPipeline()
    pipeline.register(_HealthOutputScanner("out_broken", healthy=False))
    assert await pipeline.unhealthy_blocking_scanners() == ["out_broken"]


@pytest.mark.asyncio
async def test_unhealthy_ignores_async_scanners():
    # Async (non-blocking) scanners must NOT trigger the readiness gate even if
    # unhealthy — they never block a request.
    pipeline = ScannerPipeline()
    pipeline.register(
        _HealthScanner("ml_async", healthy=False, scanner_type=ScannerType.INPUT_ASYNC)
    )
    assert await pipeline.unhealthy_blocking_scanners() == []


@pytest.mark.asyncio
async def test_unhealthy_ignores_disabled_scanners():
    pipeline = ScannerPipeline()
    pipeline.register(_HealthScanner("ml_broken", healthy=False))
    pipeline.disable("ml_broken")
    assert await pipeline.unhealthy_blocking_scanners() == []


@pytest.mark.asyncio
async def test_unhealthy_health_exception_is_unhealthy():
    pipeline = ScannerPipeline()
    pipeline.register(_RaisingHealthScanner())
    assert await pipeline.unhealthy_blocking_scanners() == ["raiser"]


# === resolve_blocking_readiness() ===================================


def test_resolve_ok_when_nothing_degraded():
    action, message = resolve_blocking_readiness([], "closed")
    assert action == "ok"
    assert message == ""


def test_resolve_closed_refuses_to_start():
    action, message = resolve_blocking_readiness(["ml_intent_detector"], "closed")
    assert action == "refuse"
    assert "ml_intent_detector" in message
    assert "BLOCK ALL traffic" in message


def test_resolve_open_degrades():
    action, message = resolve_blocking_readiness(["ml_intent_detector"], "open")
    assert action == "degrade"
    assert "ml_intent_detector" in message


def test_resolve_message_lists_all_degraded_sorted():
    action, message = resolve_blocking_readiness(["z_scanner", "a_scanner"], "closed")
    assert action == "refuse"
    # Names are sorted for stable, readable operator output.
    assert message.index("a_scanner") < message.index("z_scanner")
