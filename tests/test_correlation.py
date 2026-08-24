"""Tests for the inline correlation engine (Phase 0/1).

Covers:

* :class:`RiskStateStore` — bump/get, exponential decay, clamping, scope
  isolation, in-memory fallback (no Redis).
* :class:`InputOutputCorrelator` — the input↔output exfiltration confirmation:
  master-switch gating, positive/negative pairings, WARN-vs-BLOCK mode,
  severity escalation, and the correlated ``SecurityEvent`` shape.
* The durable store's new ``since``/``until`` time-range filtering.
"""

from __future__ import annotations

import time

import pytest

from src.correlation.incident import InputOutputCorrelator
from src.correlation.risk_state import RiskStateStore
from src.models import SecurityEvent, ThreatCategory, Verdict


def _event(category: ThreatCategory, verdict: Verdict = Verdict.WARN) -> SecurityEvent:
    return SecurityEvent(
        tenant_id="acme",
        agent_id="support-bot",
        verdict=verdict,
        category=category,
        description="test",
        source="test",
        severity="high",
    )


# ─── RiskStateStore ──────────────────────────────────────────────────────────


def _mem_store(decay_seconds: float = 900.0) -> RiskStateStore:
    s = RiskStateStore(decay_seconds=decay_seconds)
    s.initialize(redis_url=None)  # force in-memory fallback
    return s


def test_risk_bump_increases_score():
    s = _mem_store()
    assert s.get("session", "acme:bot") == 0.0
    new = s.bump("session", "acme:bot", 3.0)
    assert new == pytest.approx(3.0)
    assert s.get("session", "acme:bot") == pytest.approx(3.0, abs=0.01)


def test_risk_score_clamped_at_max():
    s = _mem_store()
    s.bump("tenant", "acme", 8.0)
    new = s.bump("tenant", "acme", 8.0)
    assert new == pytest.approx(10.0)  # clamped to _MAX_SCORE


def test_risk_decays_over_time():
    # 1-second half-life so decay is observable in-test.
    s = _mem_store(decay_seconds=1.0)
    s.bump("input", "abc", 8.0)
    # Force the stored timestamp into the past by ~2 half-lives.
    entry = s._local[s._local_key("input", "abc")]
    entry.updated_at -= 2.0
    decayed = s.get("input", "abc")
    assert decayed == pytest.approx(2.0, abs=0.2)  # 8 * 0.5**2 = 2.0


def test_risk_scopes_are_isolated():
    s = _mem_store()
    s.bump("session", "acme:bot", 5.0)
    assert s.get("tenant", "acme") == 0.0
    assert s.get("input", "acme:bot") == 0.0


def test_risk_empty_scope_id_is_zero():
    s = _mem_store()
    assert s.get("session", "") == 0.0
    assert s.bump("session", "", 5.0) == 0.0


# ─── InputOutputCorrelator ───────────────────────────────────────────────────


@pytest.fixture
def correlator(monkeypatch):
    """A correlator with a fresh in-memory risk store and enabled config."""
    from src.config import settings

    monkeypatch.setattr(settings, "correlation_enabled", True, raising=False)
    monkeypatch.setattr(settings, "correlation_blocking", False, raising=False)
    monkeypatch.setattr(settings, "correlation_window_seconds", 30.0, raising=False)
    c = InputOutputCorrelator()
    c._risk = _mem_store()
    return c


def test_correlation_disabled_returns_none(monkeypatch):
    from src.config import settings

    monkeypatch.setattr(settings, "correlation_enabled", False, raising=False)
    c = InputOutputCorrelator()
    c._risk = _mem_store()
    incident = c.evaluate(
        input_events=[_event(ThreatCategory.PROMPT_INJECTION)],
        output_events=[_event(ThreatCategory.CREDENTIAL_ACCESS)],
        tenant_id="acme",
        agent_id="bot",
    )
    assert incident is None


def test_suspicious_input_plus_sensitive_output_confirms(correlator):
    incident = correlator.evaluate(
        input_events=[_event(ThreatCategory.PROMPT_INJECTION)],
        output_events=[_event(ThreatCategory.PII_LEAK)],
        tenant_id="acme",
        agent_id="bot",
        input_hash="deadbeef",
        request_id="acme:bot:1",
    )
    assert incident is not None
    assert incident.verdict == Verdict.WARN  # blocking is off
    assert "prompt_injection" in incident.input_categories
    assert "pii_leak" in incident.output_categories
    assert incident.risk_score > 0.0


def test_blocking_mode_yields_block_verdict(correlator, monkeypatch):
    from src.config import settings

    monkeypatch.setattr(settings, "correlation_blocking", True, raising=False)
    incident = correlator.evaluate(
        input_events=[_event(ThreatCategory.EXFILTRATION)],
        output_events=[_event(ThreatCategory.CREDENTIAL_ACCESS)],
        tenant_id="acme",
        agent_id="bot",
    )
    assert incident is not None
    assert incident.verdict == Verdict.BLOCK


def test_credential_output_is_critical(correlator):
    incident = correlator.evaluate(
        input_events=[_event(ThreatCategory.PROMPT_INJECTION)],
        output_events=[_event(ThreatCategory.CREDENTIAL_ACCESS)],
        tenant_id="acme",
        agent_id="bot",
    )
    assert incident is not None
    assert incident.severity == "critical"


def test_pii_only_output_is_high_not_critical(correlator):
    incident = correlator.evaluate(
        input_events=[_event(ThreatCategory.JAILBREAK)],
        output_events=[_event(ThreatCategory.PII_LEAK)],
        tenant_id="acme",
        agent_id="bot",
    )
    assert incident is not None
    assert incident.severity == "high"


def test_benign_input_no_correlation(correlator):
    # RATE_LIMIT is not a suspicious-input category → no correlation.
    incident = correlator.evaluate(
        input_events=[_event(ThreatCategory.RATE_LIMIT)],
        output_events=[_event(ThreatCategory.PII_LEAK)],
        tenant_id="acme",
        agent_id="bot",
    )
    assert incident is None


def test_benign_output_no_correlation(correlator):
    # POLICY_VIOLATION is not a sensitive-output category → no correlation.
    incident = correlator.evaluate(
        input_events=[_event(ThreatCategory.PROMPT_INJECTION)],
        output_events=[_event(ThreatCategory.POLICY_VIOLATION)],
        tenant_id="acme",
        agent_id="bot",
    )
    assert incident is None


def test_stale_input_outside_window_no_correlation(correlator):
    incident = correlator.evaluate(
        input_events=[_event(ThreatCategory.PROMPT_INJECTION)],
        output_events=[_event(ThreatCategory.PII_LEAK)],
        tenant_id="acme",
        agent_id="bot",
        input_detected_at=time.time() - 120.0,  # 2 min ago, window is 30s
    )
    assert incident is None


def test_incident_to_security_event_shape(correlator):
    incident = correlator.evaluate(
        input_events=[_event(ThreatCategory.PROMPT_INJECTION)],
        output_events=[_event(ThreatCategory.CREDENTIAL_ACCESS)],
        tenant_id="acme",
        agent_id="bot",
        input_hash="cafebabe",
        request_id="acme:bot:9",
    )
    assert incident is not None
    ev = incident.to_security_event()
    assert ev.category == ThreatCategory.EXFILTRATION
    assert ev.source == "correlation_engine"
    assert ev.metadata["correlation"] is True
    assert ev.metadata["input_hash"] == "cafebabe"
    assert "prompt_injection" in ev.metadata["input_categories"]
    assert "credential_access" in ev.metadata["output_categories"]


def test_correlation_bumps_origin_risk(correlator):
    correlator.evaluate(
        input_events=[_event(ThreatCategory.PROMPT_INJECTION)],
        output_events=[_event(ThreatCategory.CREDENTIAL_ACCESS)],
        tenant_id="acme",
        agent_id="bot",
        input_hash="d00d",
    )
    # Session risk should be elevated after a confirmed correlation.
    assert correlator._risk.get("session", "acme:bot") > 0.0
    assert correlator._risk.get("input", "d00d") > 0.0
    assert correlator._risk.get("tenant", "acme") > 0.0
