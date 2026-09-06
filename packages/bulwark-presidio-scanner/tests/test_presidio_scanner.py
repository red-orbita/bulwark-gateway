"""Tests for the Bulwark Presidio PII scanner plugin.

These tests run WITHOUT `presidio-analyzer` installed. They cover:
  * the inert / fail-open path when Presidio is not provisioned;
  * env-driven configuration parsing (entities / threshold / language);
  * scanner metadata + entry-point contract;
  * detection + redaction logic against a FAKE analyzer (so the splicing,
    verdict, event shaping, and severity are validated deterministically).

The package src dir is added to sys.path so the module imports without a pip
install and without the heavy Presidio/spaCy stack.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

# Make the in-repo package importable without installing it.
_PKG_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_PKG_SRC) not in sys.path:
    sys.path.insert(0, str(_PKG_SRC))

from bulwark_presidio_scanner import scanner as mod  # noqa: E402
from bulwark_presidio_scanner.scanner import (  # noqa: E402
    PresidioInputScanner,
    PresidioOutputScanner,
    _PresidioEngine,
)

from src.models import Verdict  # noqa: E402
from src.scanners.protocol import ScanContext, ScannerType  # noqa: E402

# ─── fakes ────────────────────────────────────────────────────────────────────


@dataclass
class _FakeResult:
    """Mimics presidio_analyzer.RecognizerResult (the fields we use)."""

    entity_type: str
    start: int
    end: int
    score: float = 0.9


def _ctx() -> ScanContext:
    return ScanContext(
        tenant_id="t1",
        agent_id="a1",
        request_id="r1",
        messages=[{"role": "user", "content": "hi"}],
    )


@pytest.fixture(autouse=True)
def _reset_singleton_and_env(monkeypatch):
    """Reset the process-wide engine singleton + env between tests."""
    _PresidioEngine._instance = None
    for var in (
        "BULWARK_PRESIDIO_ENTITIES",
        "BULWARK_PRESIDIO_SCORE_THRESHOLD",
        "BULWARK_PRESIDIO_LANGUAGE",
        "BULWARK_PRESIDIO_SPACY_MODEL",
    ):
        monkeypatch.delenv(var, raising=False)
    yield
    _PresidioEngine._instance = None


# ─── config parsing ───────────────────────────────────────────────────────────


def test_default_entities_used_when_unset():
    assert mod._parse_entities() == list(mod._DEFAULT_ENTITIES)


def test_star_entities_means_all_recognizers(monkeypatch):
    monkeypatch.setenv("BULWARK_PRESIDIO_ENTITIES", "*")
    assert mod._parse_entities() is None


def test_custom_entities_parsed_uppercased(monkeypatch):
    monkeypatch.setenv("BULWARK_PRESIDIO_ENTITIES", "person, email_address ,us_ssn")
    assert mod._parse_entities() == ["PERSON", "EMAIL_ADDRESS", "US_SSN"]


def test_threshold_parsed_and_clamped(monkeypatch):
    monkeypatch.setenv("BULWARK_PRESIDIO_SCORE_THRESHOLD", "0.7")
    assert mod._parse_threshold() == 0.7
    monkeypatch.setenv("BULWARK_PRESIDIO_SCORE_THRESHOLD", "5")
    assert mod._parse_threshold() == 1.0
    monkeypatch.setenv("BULWARK_PRESIDIO_SCORE_THRESHOLD", "-1")
    assert mod._parse_threshold() == 0.0


def test_bad_threshold_falls_back(monkeypatch):
    monkeypatch.setenv("BULWARK_PRESIDIO_SCORE_THRESHOLD", "not-a-number")
    assert mod._parse_threshold() == 0.5


# ─── metadata / entry-point contract ──────────────────────────────────────────


def test_output_scanner_metadata():
    info = PresidioOutputScanner().info
    assert info.name == "presidio_pii_output"
    assert info.scanner_type == ScannerType.OUTPUT_BLOCKING
    assert info.maturity.value == "beta"


def test_input_scanner_metadata():
    info = PresidioInputScanner().info
    assert info.name == "presidio_pii_input"
    assert info.scanner_type == ScannerType.INPUT_ASYNC


def test_scanners_are_valid_scanner_subclasses():
    from src.scanners.discovery import _is_valid_scanner_class

    assert _is_valid_scanner_class(PresidioOutputScanner)
    assert _is_valid_scanner_class(PresidioInputScanner)


# ─── inert / fail-open path (Presidio not installed) ──────────────────────────


async def test_output_inert_when_unavailable():
    scanner = PresidioOutputScanner()
    # Force the engine to report unavailable (mirrors presidio not installed).
    scanner._engine._available = False
    result = await scanner.scan("My name is Jane Doe, SSN 123-45-6789", _ctx())
    assert result.verdict == Verdict.ALLOW
    assert result.modified_content is None
    assert result.events == []
    assert await scanner.health() is False


async def test_input_inert_when_unavailable():
    scanner = PresidioInputScanner()
    scanner._engine._available = False
    result = await scanner.scan("email me at a@b.com", _ctx())
    assert result.verdict == Verdict.ALLOW
    assert result.events == []


def test_missing_presidio_marks_unavailable(monkeypatch):
    """_try_build must degrade to unavailable (never raise) when import fails."""
    real_import = __import__

    def _blocked_import(name, *args, **kwargs):
        if name.startswith("presidio_analyzer"):
            raise ImportError("no presidio")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", _blocked_import)
    engine = _PresidioEngine()
    assert engine.available is False


# ─── detection + redaction (fake analyzer) ────────────────────────────────────


def _wire_fake_analyzer(scanner, results):
    """Make the scanner's engine 'available' and return canned results."""
    engine = scanner._engine
    engine._available = True
    engine._analyzer = object()  # non-None sentinel
    engine.analyze = lambda text: results  # type: ignore[method-assign]


async def test_output_redacts_detected_pii():
    scanner = PresidioOutputScanner()
    text = "Contact Jane at jane@corp.com now"
    # "jane@corp.com" spans indices 16..29
    start = text.index("jane@corp.com")
    end = start + len("jane@corp.com")
    _wire_fake_analyzer(scanner, [_FakeResult("EMAIL_ADDRESS", start, end)])

    result = await scanner.scan(text, _ctx())
    assert result.verdict == Verdict.REDACT
    assert "jane@corp.com" not in result.modified_content
    assert "[REDACTED:EMAIL_ADDRESS]" in result.modified_content
    assert len(result.events) == 1
    assert result.events[0].category.value == "pii_leak"


async def test_output_high_severity_for_ssn():
    scanner = PresidioOutputScanner()
    text = "SSN 123-45-6789"
    start = text.index("123-45-6789")
    end = start + len("123-45-6789")
    _wire_fake_analyzer(scanner, [_FakeResult("US_SSN", start, end)])

    result = await scanner.scan(text, _ctx())
    assert result.events[0].severity == "high"


async def test_output_allows_clean_content():
    scanner = PresidioOutputScanner()
    _wire_fake_analyzer(scanner, [])
    result = await scanner.scan("nothing sensitive here", _ctx())
    assert result.verdict == Verdict.ALLOW
    assert result.modified_content is None


async def test_input_warns_but_does_not_modify():
    scanner = PresidioInputScanner()
    text = "my number is 555-123-4567"
    start = text.index("555-123-4567")
    end = start + len("555-123-4567")
    _wire_fake_analyzer(scanner, [_FakeResult("PHONE_NUMBER", start, end)])

    result = await scanner.scan(text, _ctx())
    assert result.verdict == Verdict.WARN
    assert result.modified_content is None
    assert len(result.events) == 1


def test_redact_splices_multiple_spans_right_to_left():
    text = "a AAAA b BBBB c"
    results = [
        _FakeResult("PERSON", 2, 6),   # AAAA
        _FakeResult("PERSON", 9, 13),  # BBBB
    ]
    out = _PresidioEngine.redact(text, results)
    assert out == "a [REDACTED:PERSON] b [REDACTED:PERSON] c"


def test_redact_ignores_out_of_range_spans():
    text = "short"
    out = _PresidioEngine.redact(text, [_FakeResult("PERSON", 0, 999)])
    assert out == "short"  # invalid span skipped, text untouched


def test_entity_counts_and_severity_helpers():
    results = [
        _FakeResult("PERSON", 0, 1),
        _FakeResult("PERSON", 2, 3),
        _FakeResult("EMAIL_ADDRESS", 4, 5),
    ]
    counts = mod._entity_counts(results)
    assert counts == {"PERSON": 2, "EMAIL_ADDRESS": 1}
    assert mod._severity_for(counts) == "medium"
    assert mod._severity_for({"US_SSN": 1}) == "high"
