"""Quantified FP/FN of the correlation confidence gate — audit finding F5.

The correlator's WARN→BLOCK escalation is gated by
``src.correlation.confidence.correlation_confidence`` reaching
``confidence_block_threshold`` (shipped default 0.5). Because clearing that gate
turns a legitimate response into a 403, F5 requires its error rate to be
*measured* against a labelled corpus rather than assumed.

These tests turn that requirement into an evidence-closed contract:

* **No false positives** — zero benign co-occurrences hard-block at the default
  threshold (blocking a legitimate user is the worst outcome).
* **High block-recall on real credential leaks** — a genuine high-entropy secret
  leaving the gateway reliably clears the gate.
* **Clean separation** — every credential leak scores above every benign sample.
* **Bulk-PII recall (R6)** — a dump of several distinct *structured* identifiers
  (SSNs, emails, phones, cards) trips the PII-multiplicity signal and clears the
  block gate end-to-end, without costing a single benign false positive.
* **Honest residual false-negatives** — leaks of purely *unstructured* PII (street
  addresses, dates of birth) carry no regex-recognisable identifier and stay WARN
  by design, but are *not* silently passed:
  :meth:`InputOutputCorrelator.evaluate` still emits a WARN incident and accrues
  origin risk (repetition escalates to a BLOCK via the adaptive path).
* **Threshold/FP tradeoff** — lowering the tunable threshold below the benign
  band reintroduces false positives; the shipped 0.5 default is defended by data.

Targets (asserted below):

| Metric                         | Target        |
|--------------------------------|---------------|
| Benign false-positive rate     | == 0          |
| Credential leak block-recall   | >= 0.90       |
| Bulk-PII leak block-recall     | >= 0.70       |
| Credential↔benign separation   | > 0           |
"""

from __future__ import annotations

import pytest

from src.correlation.incident import InputOutputCorrelator
from src.correlation.risk_state import RiskStateStore
from src.models import SecurityEvent, ThreatCategory, Verdict
from tests.data.correlation_corpus import (
    DEFAULT_BLOCK_THRESHOLD,
    corpus,
    evaluate_corpus,
    score,
)

# ─── Acceptance targets (documented in the audit doc, finding F5 + R6) ─────────

_MAX_BENIGN_FALSE_POSITIVES = 0
_MIN_CREDENTIAL_BLOCK_RECALL = 0.90
_MIN_PII_BLOCK_RECALL = 0.70


def test_corpus_threshold_matches_shipped_default():
    """The corpus is measured at exactly the production default (drift guard)."""
    from src.config import Settings

    assert DEFAULT_BLOCK_THRESHOLD == Settings().correlation_confidence_block_threshold


def test_corpus_is_labelled_and_non_trivial():
    """Enough samples on both sides to make the FP/FN numbers meaningful."""
    samples = corpus()
    benign = [s for s in samples if not s.is_exfiltration]
    attacks = [s for s in samples if s.is_exfiltration]
    assert len(benign) >= 15
    assert len(attacks) >= 15
    # Every sample carries a ground-truth label and a subset tag.
    assert all(s.subset in {"benign", "attack_credential", "attack_pii"} for s in samples)


def test_no_false_positives_on_benign_corpus(capsys):
    """Zero benign co-occurrences hard-block at the shipped threshold."""
    report = evaluate_corpus()
    with capsys.disabled():
        print("\n" + report.render())
    assert report.false_positives == _MAX_BENIGN_FALSE_POSITIVES
    assert report.false_positive_rate == 0.0
    # The worst benign case stays strictly under the threshold.
    assert report.benign.max_score < DEFAULT_BLOCK_THRESHOLD


def test_credential_leaks_meet_block_recall_target():
    """Genuine high-entropy secret leaks reliably clear the block gate."""
    report = evaluate_corpus()
    assert report.credential_recall >= _MIN_CREDENTIAL_BLOCK_RECALL


def test_clean_separation_between_credential_and_benign():
    """Every credential leak scores above every benign co-occurrence."""
    report = evaluate_corpus()
    assert report.separation_margin > 0.0
    assert report.attack_credential.min_score >= DEFAULT_BLOCK_THRESHOLD


def test_every_credential_sample_carries_runtime_secret_not_a_literal():
    """The credential outputs get their entropy from a fresh runtime token.

    Two independent builds of the corpus must differ (proves the secret is
    generated, never a committed literal — secure-coding compliance).
    """
    from tests.data.correlation_corpus import _ATTACK_CREDENTIAL

    build_a = [s.output_text for s in _ATTACK_CREDENTIAL]
    import importlib

    import tests.data.correlation_corpus as mod

    reloaded = importlib.reload(mod)
    build_b = [s.output_text for s in reloaded._ATTACK_CREDENTIAL]
    # Same leading prose, different secret tail ⇒ generated, not hardcoded.
    assert build_a != build_b


def test_lowering_threshold_below_benign_band_introduces_fp():
    """Data-backed defence of the 0.5 default: dropping below it FP-s.

    The shipped default leaves only a small headroom above the hardest benign
    sample (an output that trips a credential *category* by wording). Tuning the
    knob down into that band starts blocking legitimate users — this pins that
    tradeoff so nobody lowers it blindly.
    """
    report = evaluate_corpus()
    floor = report.min_fp_free_threshold
    # At/above the benign band: still zero FP at the default.
    assert evaluate_corpus(DEFAULT_BLOCK_THRESHOLD).false_positives == 0
    # Just below the hardest benign score: false positives appear.
    below = round(floor - 0.05, 2)
    assert evaluate_corpus(below).false_positives >= 1
    # The default must sit above the FP-free floor.
    assert DEFAULT_BLOCK_THRESHOLD > floor


# ─── End-to-end: the measured heuristic drives real enforcement ────────────────


def _event(category: ThreatCategory) -> SecurityEvent:
    return SecurityEvent(
        tenant_id="acme",
        agent_id="bot",
        verdict=Verdict.WARN,
        category=category,
        description="test",
        source="test",
        severity="high",
    )


@pytest.fixture
def blocking_correlator(monkeypatch):
    """A correlator with blocking ON and a fresh in-memory risk store."""
    from src.config import settings

    monkeypatch.setattr(settings, "correlation_enabled", True, raising=False)
    monkeypatch.setattr(settings, "correlation_blocking", True, raising=False)
    monkeypatch.setattr(
        settings, "correlation_confidence_block_threshold",
        DEFAULT_BLOCK_THRESHOLD, raising=False,
    )
    c = InputOutputCorrelator()
    store = RiskStateStore(decay_seconds=900.0)
    store.initialize(redis_url=None)
    c._risk = store
    return c


def test_end_to_end_credential_leak_blocks(blocking_correlator):
    """A corpus credential leak, run through evaluate(), hard-BLOCKs."""
    sample = next(
        s for s in corpus() if s.subset == "attack_credential" and s.critical
    )
    assert score(sample) >= DEFAULT_BLOCK_THRESHOLD  # precondition from the corpus
    incident = blocking_correlator.evaluate(
        input_events=[_event(ThreatCategory.PROMPT_INJECTION)],
        output_events=[_event(ThreatCategory.CREDENTIAL_ACCESS)],
        tenant_id="acme",
        agent_id="bot",
        input_text=sample.input_text,
        output_text=sample.output_text,
        subject_id="user-1",
    )
    assert incident is not None
    assert incident.verdict == Verdict.BLOCK


def test_end_to_end_benign_stays_warn(blocking_correlator):
    """A benign co-occurrence, run through evaluate() with blocking ON, only WARNs."""
    sample = next(s for s in corpus() if s.subset == "benign" and s.critical)
    assert score(sample) < DEFAULT_BLOCK_THRESHOLD  # precondition from the corpus
    incident = blocking_correlator.evaluate(
        input_events=[_event(ThreatCategory.PROMPT_INJECTION)],
        output_events=[_event(ThreatCategory.CREDENTIAL_ACCESS)],
        tenant_id="acme",
        agent_id="bot",
        input_text=sample.input_text,
        output_text=sample.output_text,
        subject_id="user-1",
    )
    assert incident is not None  # correlation still fires…
    assert incident.verdict == Verdict.WARN  # …but does not hard-block a legit user


def test_bulk_pii_leaks_meet_block_recall_target():
    """R6: a corpus of bulk structured-PII dumps clears the block gate at target.

    The PII-multiplicity signal lifts genuine multi-identifier dumps over the
    threshold. This pins the recall gain as data (>= 0.70) so a future weight
    change that silently regresses it fails CI — while the FP test above proves
    the gain costs zero benign false positives.
    """
    report = evaluate_corpus()
    assert report.pii_block_recall >= _MIN_PII_BLOCK_RECALL


def test_bulk_structured_pii_leak_blocks_end_to_end(blocking_correlator):
    """A bulk structured-PII dump, run through evaluate(), hard-BLOCKs (R6)."""
    # Selected by score, not by name, so the test tracks the shipped heuristic.
    sample = next(
        s
        for s in corpus()
        if s.subset == "attack_pii" and score(s) >= DEFAULT_BLOCK_THRESHOLD
    )
    incident = blocking_correlator.evaluate(
        input_events=[_event(ThreatCategory.EXFILTRATION)],
        output_events=[_event(ThreatCategory.PII_LEAK)],
        tenant_id="acme",
        agent_id="bot",
        input_text=sample.input_text,
        output_text=sample.output_text,
        subject_id="user-8",
    )
    assert incident is not None
    assert incident.verdict == Verdict.BLOCK


def test_unstructured_pii_leak_is_warn_tier_not_silently_passed(blocking_correlator):
    """An unstructured-PII leak stays WARN (residual FN) yet still accrues risk."""
    report = evaluate_corpus()
    # Honest limit: recall is strong but not perfect — some unstructured PII
    # (addresses, DoB) has no regex-recognisable identifier to count.
    assert report.pii_block_recall < 1.0

    # Selected by score: a genuine PII leak that the gate does NOT hard-block.
    sample = next(
        s
        for s in corpus()
        if s.subset == "attack_pii" and score(s) < DEFAULT_BLOCK_THRESHOLD
    )
    before = blocking_correlator._risk.get("subject", "acme:user-9")
    incident = blocking_correlator.evaluate(
        input_events=[_event(ThreatCategory.EXFILTRATION)],
        output_events=[_event(ThreatCategory.PII_LEAK)],
        tenant_id="acme",
        agent_id="bot",
        input_text=sample.input_text,
        output_text=sample.output_text,
        subject_id="user-9",
    )
    # Not silently passed: a WARN incident is emitted and risk is accrued so that
    # repeated PII exfiltration escalates to a BLOCK via the adaptive path.
    assert incident is not None
    assert incident.verdict == Verdict.WARN
    after = blocking_correlator._risk.get("subject", "acme:user-9")
    assert after > before
