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


# ─── CorrelationRuntimeConfig (Phase 2) ──────────────────────────────────────


class _RuntimeFakeRedis:
    """Minimal decode_responses Redis: a single config HASH + ping."""

    def __init__(self, hashes: dict | None = None, fail: bool = False):
        self.hashes = hashes or {}
        self.fail = fail

    def ping(self):
        if self.fail:
            raise ConnectionError("no redis")
        return True

    def hgetall(self, key):
        if self.fail:
            raise ConnectionError("no redis")
        return dict(self.hashes.get(key, {}))


def _runtime():
    from src.correlation.runtime import CorrelationRuntimeConfig

    return CorrelationRuntimeConfig()


def test_runtime_defaults_match_settings(monkeypatch):
    from src.config import settings

    monkeypatch.setattr(settings, "correlation_blocking", False, raising=False)
    monkeypatch.setattr(settings, "correlation_risk_block_threshold", 7.0, raising=False)
    monkeypatch.setattr(settings, "correlation_risk_warn_threshold", 4.0, raising=False)
    cfg = _runtime().get()
    assert cfg.blocking is False
    assert cfg.risk_block_threshold == 7.0
    assert cfg.risk_warn_threshold == 4.0
    # Built-in scoring weights (no settings counterpart).
    assert cfg.event_bump_warn == 0.5
    assert cfg.event_bump_block == 1.0
    assert cfg.severity_high_mult == 1.5
    assert cfg.severity_critical_mult == 2.0


def test_runtime_no_redis_is_defaults():
    rt = _runtime()
    rt.initialize(redis_url=None)  # no redis
    assert rt.override_state() == {}


def test_runtime_override_applies_and_clamps():
    rt = _runtime()
    rt._redis = _RuntimeFakeRedis({
        "bulwark:correlation:config": {
            "blocking": "true",
            "risk_block_threshold": "999",   # clamped to 10.0
            "risk_warn_threshold": "2.5",
            "event_bump_warn": "0.9",
        }
    })
    rt._last_refresh = 0.0
    cfg = rt.get()
    assert cfg.blocking is True
    assert cfg.risk_block_threshold == 10.0  # clamped to max
    assert cfg.risk_warn_threshold == 2.5
    assert cfg.event_bump_warn == 0.9


def test_runtime_refresh_is_throttled():
    rt = _runtime()
    rt._redis = _RuntimeFakeRedis({
        "bulwark:correlation:config": {"risk_warn_threshold": "1.0"}
    })
    rt._last_refresh = time.time()  # just refreshed → skip
    cfg = rt.get()
    assert cfg.risk_warn_threshold != 1.0  # not applied (throttled)
    rt._last_refresh = 0.0
    assert rt.get().risk_warn_threshold == 1.0


def test_runtime_malformed_override_ignored():
    rt = _runtime()
    rt._redis = _RuntimeFakeRedis({
        "bulwark:correlation:config": {
            "risk_block_threshold": "not-a-number",
            "window_seconds": "45",
        }
    })
    rt._last_refresh = 0.0
    cfg = rt.get()
    assert cfg.window_seconds == 45.0          # valid applied
    assert cfg.risk_block_threshold == 7.0     # malformed dropped → default


def test_runtime_redis_failure_degrades_to_defaults():
    rt = _runtime()
    rt._redis = _RuntimeFakeRedis(fail=True)
    rt._last_refresh = 0.0
    cfg = rt.get()  # must not raise
    assert cfg.risk_block_threshold == 7.0


def test_numeric_bounds_shape():
    from src.correlation.runtime import TUNABLE_FIELDS, numeric_field_bounds

    bounds = numeric_field_bounds()
    assert bounds["risk_block_threshold"] == (0.1, 10.0)
    assert "blocking" in TUNABLE_FIELDS
    assert "blocking" not in bounds  # boolean handled separately


# ─── CorrelationEventTap (Phase 2) ───────────────────────────────────────────


def _tap(monkeypatch, blocking=False):
    """A tap wired to a fresh in-memory risk store and a default runtime."""
    from src.config import settings
    from src.correlation.event_tap import CorrelationEventTap
    from src.correlation.runtime import CorrelationRuntimeConfig

    monkeypatch.setattr(settings, "correlation_blocking", blocking, raising=False)
    t = CorrelationEventTap()
    t._risk = _mem_store()
    t._runtime = CorrelationRuntimeConfig()  # no redis → static defaults
    return t


def test_tap_apply_bumps_session_and_tenant(monkeypatch):
    t = _tap(monkeypatch)
    # WARN high: 0.5 * 1.5 = 0.75 session; tenant fraction 0.25 → 0.1875
    t._apply(("acme", "bot", "warn", "high"))
    assert t._risk.get("session", "acme:bot") == pytest.approx(0.75, abs=0.01)
    assert t._risk.get("tenant", "acme") == pytest.approx(0.1875, abs=0.01)
    assert t.processed == 1


def test_tap_block_bumps_more_than_warn(monkeypatch):
    t = _tap(monkeypatch)
    warn = t._bump_amount("warn", "medium")   # 0.5 * 1.0
    block = t._bump_amount("block", "medium")  # 1.0 * 1.0
    crit = t._bump_amount("block", "critical")  # 1.0 * 2.0
    assert block > warn
    assert crit == pytest.approx(2.0)


def test_tap_apply_without_agent_only_tenant(monkeypatch):
    t = _tap(monkeypatch)
    t._apply(("acme", "", "block", "medium"))
    assert t._risk.get("session", "acme:") == 0.0
    assert t._risk.get("tenant", "acme") > 0.0


async def test_tap_publish_filters_and_counts(monkeypatch):
    import asyncio

    t = _tap(monkeypatch)
    t._queue = asyncio.Queue(maxsize=100)  # bind a queue without the consumer

    # ALLOW → skipped
    t.publish(_event(ThreatCategory.PROMPT_INJECTION, Verdict.ALLOW))
    # correlation-engine output → skipped (no amplification)
    own = SecurityEvent(
        tenant_id="acme", agent_id="bot", verdict=Verdict.BLOCK,
        category=ThreatCategory.POLICY_VIOLATION, description="x",
        source="correlation_engine", severity="high",
    )
    t.publish(own)
    # metadata.correlation → skipped
    tagged = SecurityEvent(
        tenant_id="acme", agent_id="bot", verdict=Verdict.WARN,
        category=ThreatCategory.PROMPT_INJECTION, description="x",
        source="test", severity="high", metadata={"correlation": True},
    )
    t.publish(tagged)
    # WARN, legitimate → enqueued
    t.publish(_event(ThreatCategory.PROMPT_INJECTION, Verdict.WARN))

    assert t.published == 1
    assert t._queue.qsize() == 1


async def test_tap_publish_no_queue_is_noop(monkeypatch):
    t = _tap(monkeypatch)  # never started → _queue is None
    t.publish(_event(ThreatCategory.PROMPT_INJECTION, Verdict.WARN))
    assert t.published == 0


def test_tap_stats_shape(monkeypatch):
    t = _tap(monkeypatch)
    stats = t.stats()
    assert set(stats) == {"running", "published", "dropped", "processed", "queue_depth"}
    assert stats["running"] is False


# ─── evaluate_origin_risk (Phase 2 adaptive enforcement) ─────────────────────


def test_origin_risk_below_warn_returns_none(correlator):
    # No accumulated risk → no hardening.
    assert correlator.evaluate_origin_risk(tenant_id="acme", agent_id="bot") is None


def test_origin_risk_warn_between_thresholds(correlator, monkeypatch):
    from src.config import settings

    monkeypatch.setattr(settings, "correlation_blocking", False, raising=False)
    correlator._risk.bump("session", "acme:bot", 5.0)  # >=4 warn, <7 block
    a = correlator.evaluate_origin_risk(tenant_id="acme", agent_id="bot", request_id="r1")
    assert a is not None
    assert a.verdict == Verdict.WARN
    assert a.score == pytest.approx(5.0, abs=0.05)
    assert a.request_id == "r1"


def test_origin_risk_block_when_blocking_enabled(correlator, monkeypatch):
    from src.config import settings

    monkeypatch.setattr(settings, "correlation_blocking", True, raising=False)
    correlator._risk.bump("session", "acme:bot", 8.0)  # >=7 block
    a = correlator.evaluate_origin_risk(tenant_id="acme", agent_id="bot")
    assert a is not None
    assert a.verdict == Verdict.BLOCK


def test_origin_risk_high_score_warns_when_blocking_off(correlator, monkeypatch):
    from src.config import settings

    # Over the block threshold but blocking disabled → hardened to WARN, not BLOCK.
    monkeypatch.setattr(settings, "correlation_blocking", False, raising=False)
    correlator._risk.bump("session", "acme:bot", 9.0)
    a = correlator.evaluate_origin_risk(tenant_id="acme", agent_id="bot")
    assert a is not None
    assert a.verdict == Verdict.WARN


def test_origin_risk_uses_session_not_tenant(correlator, monkeypatch):
    from src.config import settings

    monkeypatch.setattr(settings, "correlation_blocking", False, raising=False)
    # Tenant score is high but the specific session is clean → no hardening.
    correlator._risk.bump("tenant", "acme", 9.0)
    assert correlator.evaluate_origin_risk(tenant_id="acme", agent_id="bot") is None


def test_origin_risk_assessment_to_security_event(correlator, monkeypatch):
    from src.config import settings

    monkeypatch.setattr(settings, "correlation_blocking", False, raising=False)
    correlator._risk.bump("session", "acme:bot", 5.0)
    correlator._risk.bump("tenant", "acme", 2.0)
    a = correlator.evaluate_origin_risk(tenant_id="acme", agent_id="bot", request_id="r9")
    ev = a.to_security_event()
    assert ev.category == ThreatCategory.POLICY_VIOLATION
    assert ev.source == "correlation_engine"
    assert ev.metadata["correlation"] is True
    assert ev.metadata["adaptive_enforcement"] is True
    assert ev.request_id == "r9"
