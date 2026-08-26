"""Scanner maturity tier tests (Fase 0 — honesty governance).

Maturity is an HONESTY signal, not a functional gate: it tells operators how
much to trust a scanner's verdicts today so the product never overstates its
own coverage. These tests pin the declared tier of each shipped scanner and
verify the tier propagates through the introspection API (list_scanners) that
feeds the admin UI and the /internal/scanners/status endpoint.

No models are loaded — scanner constructors are lazy, so ``.info`` is cheap and
reflects the statically declared ScannerInfo.maturity.
"""

from __future__ import annotations

import pytest

from src.models import GuardrailResult, Verdict
from src.scanners.builtin.output_redaction_scanner import OutputRedactionScanner
from src.scanners.builtin.regex_scanner import RegexInputScanner
from src.scanners.builtin.tool_policy_scanner import ToolPolicyScanner
from src.scanners.ml.injection_classifier import InjectionClassifier
from src.scanners.ml.toxicity_scanner import ToxicityScanner
from src.scanners.multimodal.vision_scanner import VisionScanner
from src.scanners.output.grounding_scanner import GroundingScanner
from src.scanners.output.hallucination_scanner import HallucinationScanner
from src.scanners.output.relevance_scanner import RelevanceScanner
from src.scanners.output.schema_validator import SchemaValidator
from src.scanners.pipeline import ScannerPipeline
from src.scanners.protocol import (
    InputScanner,
    MaturityTier,
    ScanContext,
    ScannerInfo,
    ScannerType,
)


def test_default_maturity_is_experimental():
    """Anything not explicitly promoted must default to EXPERIMENTAL.

    This guarantees new or third-party plugin scanners never masquerade as GA.
    """
    info = ScannerInfo(
        name="unspecified",
        version="1.0.0",
        scanner_type=ScannerType.INPUT_BLOCKING,
    )
    assert info.maturity is MaturityTier.EXPERIMENTAL


@pytest.mark.parametrize(
    "scanner_cls, expected",
    [
        # GA — deterministic, tested, production-proven builtins
        (RegexInputScanner, MaturityTier.GA),
        (OutputRedactionScanner, MaturityTier.GA),
        (ToolPolicyScanner, MaturityTier.GA),
        # Beta — real model + tests, efficacy not yet benchmark-validated
        (InjectionClassifier, MaturityTier.BETA),
        (ToxicityScanner, MaturityTier.BETA),
        # Beta — model-free, deterministic, tested; jsonschema is a core dep.
        # Not wired into the default proxy pipeline (opt-in per agent).
        (SchemaValidator, MaturityTier.BETA),
        # Beta — real `sentence-embeddings` ONNX model provisioned (manifest +
        # download-models.py --embeddings), mean-pool + cosine logic verified by
        # measured forward-pass tests. Opt-in (BULWARK_RELEVANCE_SCANNING_ENABLED).
        (RelevanceScanner, MaturityTier.BETA),
        # Experimental — real decision logic but the required model/deps are NOT
        # provisioned by default, so these scanners are INERT (return ALLOW) in
        # the shipped distribution. They must never masquerade as GA/BETA until a
        # model is provisioned + real-inference tests land (see ROADMAP §3.4/§4).
        (HallucinationScanner, MaturityTier.EXPERIMENTAL),
        (GroundingScanner, MaturityTier.EXPERIMENTAL),
        (VisionScanner, MaturityTier.EXPERIMENTAL),
    ],
)
def test_declared_maturity_tiers(scanner_cls, expected):
    """Each shipped scanner declares its approved maturity tier."""
    scanner = scanner_cls()
    assert scanner.info.maturity is expected


def test_unprovisioned_model_scanners_are_never_ga():
    """Scanners whose ONNX model / native deps are NOT provisioned in the default
    distribution must stay EXPERIMENTAL — they are inert (return ALLOW) until a
    model is provisioned, so a GA/BETA claim would overstate real coverage."""
    for cls in (HallucinationScanner, GroundingScanner, VisionScanner):
        assert cls().info.maturity is MaturityTier.EXPERIMENTAL


def test_ml_scanners_are_never_ga():
    """ML scanners must not claim GA — their efficacy is unproven vs an
    adaptive adversary until Fase 1 benchmarking lands."""
    for cls in (InjectionClassifier, ToxicityScanner):
        assert cls().info.maturity is not MaturityTier.GA


class _FakeGAScanner(InputScanner):
    @property
    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="fake_ga",
            version="1.0.0",
            scanner_type=ScannerType.INPUT_BLOCKING,
            maturity=MaturityTier.GA,
        )

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        return GuardrailResult(verdict=Verdict.ALLOW)


def test_list_scanners_exposes_maturity():
    """The introspection API (feeds admin UI + /internal/scanners/status) must
    surface the maturity tier so operators can triage by trust level."""
    pipeline = ScannerPipeline()
    pipeline.register(_FakeGAScanner())

    rows = pipeline.list_scanners()
    row = next(r for r in rows if r["name"] == "fake_ga")

    assert "maturity" in row
    assert row["maturity"] == "ga"


def test_list_scanners_maturity_is_always_valid():
    """Every emitted maturity value must be a real MaturityTier member —
    guards against typos leaking into the UI / SIEM triage fields."""
    valid = {t.value for t in MaturityTier}
    pipeline = ScannerPipeline()
    pipeline.register(RegexInputScanner())
    pipeline.register(_FakeGAScanner())

    for row in pipeline.list_scanners():
        assert row["maturity"] in valid
