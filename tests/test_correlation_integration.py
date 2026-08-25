"""Integration / feedback-loop tests for the correlation engine (Phase 4c).

The Phase 0-2 unit tests (``test_correlation.py``) exercise each component in
isolation against an in-memory risk store. This suite covers the *wiring* those
unit tests cannot:

* **Redis-backed risk state** — the actual ``hgetall`` / pipelined ``hset`` +
  ``expire`` code path (not just the in-memory fallback), including decay through
  Redis, scope isolation, TTL, backend-failure degradation, and Redis↔memory
  parity.
* **The adaptive feedback loop end-to-end** — the same enforcement path the proxy
  runs (minus HTTP transport): the event tap folds WARN/BLOCK security events into
  a *shared* risk store, and :meth:`InputOutputCorrelator.evaluate_origin_risk`
  reads that accrued, decayed score back and hardens a later request to WARN or
  BLOCK. This is the cross-request loop the proxy wires at PHASE 1r.
* **The async consumer** (``CorrelationEventTap._run``) draining its queue and
  surviving a poisoned item without dying.

No network and no real Redis: a fake implementing Redis HASH + pipeline semantics
stands in, so the tests are deterministic and hermetic while still driving the
real backend code path.
"""

from __future__ import annotations

import time

import pytest

from src.correlation.event_tap import CorrelationEventTap
from src.correlation.incident import InputOutputCorrelator
from src.correlation.risk_state import RiskStateStore
from src.correlation.runtime import CorrelationRuntimeConfig
from src.models import SecurityEvent, ThreatCategory, Verdict

# ─── Fake Redis (HASH + pipeline semantics, decode_responses) ────────────────


class _FakePipeline:
    """Buffers hset/expire and applies them on execute (like redis-py)."""

    def __init__(self, backend: "_FakeRedisHash") -> None:
        self._backend = backend
        self._ops: list[tuple] = []

    def hset(self, key: str, mapping: dict | None = None):
        self._ops.append(("hset", key, mapping))
        return self

    def expire(self, key: str, ttl: int):
        self._ops.append(("expire", key, ttl))
        return self

    def execute(self) -> list:
        for op in self._ops:
            if op[0] == "hset":
                self._backend.hset(op[1], mapping=op[2])
            elif op[0] == "expire":
                self._backend.expire(op[1], op[2])
        self._ops = []
        return []


class _FakeRedisHash:
    """Minimal decode_responses Redis: HASH ops + pipeline + ttl bookkeeping.

    Values are stored as strings to mirror ``decode_responses=True``.
    """

    def __init__(self, fail: bool = False) -> None:
        self.store: dict[str, dict[str, str]] = {}
        self.ttls: dict[str, int] = {}
        self.fail = fail

    def ping(self) -> bool:
        if self.fail:
            raise ConnectionError("no redis")
        return True

    def hgetall(self, key: str) -> dict:
        if self.fail:
            raise ConnectionError("no redis")
        return dict(self.store.get(key, {}))

    def hset(self, key: str, mapping: dict | None = None) -> int:
        if self.fail:
            raise ConnectionError("no redis")
        h = self.store.setdefault(key, {})
        for k, v in (mapping or {}).items():
            h[str(k)] = str(v)
        return len(mapping or {})

    def expire(self, key: str, ttl: int) -> bool:
        self.ttls[key] = ttl
        return True

    def pipeline(self) -> _FakePipeline:
        if self.fail:
            raise ConnectionError("no redis")
        return _FakePipeline(self)


def _redis_store(decay_seconds: float = 900.0, fail: bool = False) -> RiskStateStore:
    """A risk store wired to a fake Redis (drives the real Redis code path)."""
    s = RiskStateStore(decay_seconds=decay_seconds)
    s._redis = _FakeRedisHash(fail=fail)  # type: ignore[assignment]
    s._initialized = True
    return s


def _mem_store(decay_seconds: float = 900.0) -> RiskStateStore:
    s = RiskStateStore(decay_seconds=decay_seconds)
    s.initialize(redis_url=None)  # in-memory fallback
    return s


# ─── Redis-backed RiskStateStore integration ─────────────────────────────────


def test_redis_bump_then_get_roundtrip():
    s = _redis_store()
    assert s.get("session", "acme:bot") == 0.0
    new = s.bump("session", "acme:bot", 3.0)
    assert new == pytest.approx(3.0)
    # Read back through the Redis hgetall path.
    assert s.get("session", "acme:bot") == pytest.approx(3.0, abs=0.01)


def test_redis_bump_accumulates():
    s = _redis_store()
    s.bump("tenant", "acme", 2.0)
    total = s.bump("tenant", "acme", 2.5)
    assert total == pytest.approx(4.5, abs=0.05)


def test_redis_score_clamped_at_max():
    s = _redis_store()
    s.bump("tenant", "acme", 8.0)
    assert s.bump("tenant", "acme", 8.0) == pytest.approx(10.0)


def test_redis_decay_applied_on_read():
    # 1-second half-life so decay is observable by rewinding the stored timestamp.
    s = _redis_store(decay_seconds=1.0)
    s.bump("input", "abc", 8.0)
    key = RiskStateStore._redis_key("input", "abc")
    # Rewind the stored ts by ~2 half-lives: 8 * 0.5**2 = 2.0.
    s._redis.store[key]["ts"] = str(time.time() - 2.0)
    assert s.get("input", "abc") == pytest.approx(2.0, abs=0.2)


def test_redis_scopes_isolated_by_key():
    s = _redis_store()
    s.bump("session", "acme:bot", 5.0)
    # Distinct scope/id → distinct Redis key → no bleed.
    assert s.get("tenant", "acme") == 0.0
    assert s.get("input", "acme:bot") == 0.0
    assert len(s._redis.store) == 1


def test_redis_bump_sets_ttl():
    s = _redis_store(decay_seconds=100.0)
    s.bump("session", "acme:bot", 1.0)
    key = RiskStateStore._redis_key("session", "acme:bot")
    # TTL is a few half-lives out: int(decay*8)+60.
    assert s._redis.ttls[key] == int(100.0 * 8) + 60


def test_redis_failure_degrades_to_memory_never_raises():
    s = _redis_store()
    # Flip the backend to failing after wiring — bump/get must not raise and must
    # fall back to the in-memory map.
    s._redis.fail = True
    new = s.bump("session", "acme:bot", 4.0)  # must not raise
    assert new == pytest.approx(4.0)
    assert s.get("session", "acme:bot") == pytest.approx(4.0, abs=0.01)


def test_redis_and_memory_backends_agree():
    """Identical bump sequences yield the same score on both backends."""
    r = _redis_store(decay_seconds=10_000.0)
    m = _mem_store(decay_seconds=10_000.0)
    for amt in (1.0, 2.0, 0.5, 3.0):
        r.bump("session", "acme:bot", amt)
        m.bump("session", "acme:bot", amt)
    assert r.get("session", "acme:bot") == pytest.approx(
        m.get("session", "acme:bot"), abs=0.05
    )


# ─── Adaptive feedback loop (tap → shared risk store → enforcement) ──────────


def _event(
    category: ThreatCategory,
    verdict: Verdict = Verdict.WARN,
    severity: str = "high",
    source: str = "input_guardrail",
    metadata: dict | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        tenant_id="acme",
        agent_id="bot",
        verdict=verdict,
        category=category,
        description="test",
        source=source,
        severity=severity,
        metadata=metadata or {},
    )


def _wired(monkeypatch, *, blocking: bool, decay: float = 900.0):
    """A tap and a correlator sharing one risk store — the proxy's wiring.

    Returns ``(tap, correlator, store)``. The tap's runtime and the singleton
    runtime used by ``evaluate_origin_risk`` both read ``settings`` live (no
    Redis), so the monkeypatched blocking flag governs both sides.
    """
    from src.config import settings

    monkeypatch.setattr(settings, "correlation_enabled", True, raising=False)
    monkeypatch.setattr(settings, "correlation_blocking", blocking, raising=False)
    monkeypatch.setattr(settings, "correlation_risk_block_threshold", 7.0, raising=False)
    monkeypatch.setattr(settings, "correlation_risk_warn_threshold", 4.0, raising=False)

    store = RiskStateStore(decay_seconds=decay)
    store.initialize(redis_url=None)

    tap = CorrelationEventTap()
    tap._risk = store
    tap._runtime = CorrelationRuntimeConfig()  # static defaults, no redis

    correlator = InputOutputCorrelator()
    correlator._risk = store
    return tap, correlator, store


async def _drain(tap: CorrelationEventTap) -> None:
    """Wait for the consumer to process everything currently queued."""
    assert tap._queue is not None
    await tap._queue.join()


async def test_feedback_loop_warn_events_accrue_to_block(monkeypatch):
    """Repeated suspicious events accrue origin risk until a later request BLOCKs."""
    tap, correlator, _ = _wired(monkeypatch, blocking=True)
    tap.start()
    try:
        # 5 BLOCK/critical events: 1.0 (block) * 2.0 (critical) = 2.0 each → 10.0.
        for _ in range(5):
            tap.publish(
                _event(ThreatCategory.PROMPT_INJECTION, Verdict.BLOCK, "critical")
            )
        await _drain(tap)
    finally:
        await tap.stop()

    assessment = correlator.evaluate_origin_risk(tenant_id="acme", agent_id="bot")
    assert assessment is not None
    assert assessment.verdict == Verdict.BLOCK
    assert assessment.score >= 7.0


async def test_feedback_loop_accrues_to_warn_between_thresholds(monkeypatch):
    """A moderate amount of accrued risk hardens a later request to WARN only."""
    tap, correlator, _ = _wired(monkeypatch, blocking=True)
    tap.start()
    try:
        # 5 WARN/critical events: 0.5 * 2.0 = 1.0 each → 5.0 (>=4 warn, <7 block).
        for _ in range(5):
            tap.publish(
                _event(ThreatCategory.PROMPT_INJECTION, Verdict.WARN, "critical")
            )
        await _drain(tap)
    finally:
        await tap.stop()

    assessment = correlator.evaluate_origin_risk(tenant_id="acme", agent_id="bot")
    assert assessment is not None
    assert assessment.verdict == Verdict.WARN
    assert 4.0 <= assessment.score < 7.0


async def test_feedback_loop_no_amplification_from_correlation_events(monkeypatch):
    """Correlation-engine output published back must not accrue any risk."""
    tap, correlator, store = _wired(monkeypatch, blocking=True)
    tap.start()
    try:
        # Both of these must be filtered by publish() → nothing enqueued.
        tap.publish(
            _event(
                ThreatCategory.EXFILTRATION,
                Verdict.BLOCK,
                "critical",
                source="correlation_engine",
            )
        )
        tap.publish(
            _event(
                ThreatCategory.EXFILTRATION,
                Verdict.BLOCK,
                "critical",
                metadata={"correlation": True},
            )
        )
        await _drain(tap)
    finally:
        await tap.stop()

    assert store.get("session", "acme:bot") == 0.0
    assert correlator.evaluate_origin_risk(tenant_id="acme", agent_id="bot") is None


async def test_feedback_loop_allow_events_do_not_accrue(monkeypatch):
    """ALLOW verdicts carry no risk signal and must not accrue."""
    tap, correlator, store = _wired(monkeypatch, blocking=True)
    tap.start()
    try:
        for _ in range(10):
            tap.publish(
                _event(ThreatCategory.PROMPT_INJECTION, Verdict.ALLOW, "critical")
            )
        await _drain(tap)
    finally:
        await tap.stop()

    assert store.get("session", "acme:bot") == 0.0
    assert correlator.evaluate_origin_risk(tenant_id="acme", agent_id="bot") is None


def test_feedback_loop_decayed_risk_stops_hardening(monkeypatch):
    """Accrued risk that has since decayed below WARN yields no hardening."""
    _, correlator, store = _wired(monkeypatch, blocking=True, decay=1.0)
    # Accrue directly into the shared store, then rewind so it decays to ~0.
    store.bump("session", "acme:bot", 6.0)
    entry = store._local[store._local_key("session", "acme:bot")]
    entry.updated_at -= 20.0  # ~20 half-lives → negligible
    assert correlator.evaluate_origin_risk(tenant_id="acme", agent_id="bot") is None


def test_feedback_loop_session_scoped_not_tenant_wide(monkeypatch):
    """A noisy session does not escalate a *different* session of the same tenant."""
    tap, correlator, store = _wired(monkeypatch, blocking=True)
    # Accrue heavily on bot-1's session and the tenant scope.
    store.bump("session", "acme:bot-1", 9.0)
    store.bump("tenant", "acme", 9.0)
    # bot-2 shares the tenant but has a clean session → no hardening.
    assert correlator.evaluate_origin_risk(tenant_id="acme", agent_id="bot-2") is None


# ─── Async consumer (_run) robustness ────────────────────────────────────────


async def test_run_consumer_processes_and_counts(monkeypatch):
    """The background consumer drains the queue and increments processed."""
    tap, _, store = _wired(monkeypatch, blocking=False)
    tap.start()
    try:
        tap.publish(_event(ThreatCategory.PROMPT_INJECTION, Verdict.WARN, "high"))
        tap.publish(_event(ThreatCategory.JAILBREAK, Verdict.BLOCK, "critical"))
        await _drain(tap)
    finally:
        await tap.stop()

    assert tap.processed == 2
    assert store.get("session", "acme:bot") > 0.0


async def test_run_consumer_survives_poisoned_item(monkeypatch):
    """A raising ``_apply`` must not kill the loop — later items still process."""
    tap, _, _ = _wired(monkeypatch, blocking=False)

    calls: list[tuple] = []
    original_apply = tap._apply

    def _flaky_apply(item):
        calls.append(item)
        if len(calls) == 1:
            raise RuntimeError("poisoned item")
        return original_apply(item)

    monkeypatch.setattr(tap, "_apply", _flaky_apply)
    tap.start()
    try:
        tap.publish(_event(ThreatCategory.PROMPT_INJECTION, Verdict.WARN, "high"))
        tap.publish(_event(ThreatCategory.JAILBREAK, Verdict.WARN, "high"))
        await _drain(tap)
    finally:
        await tap.stop()

    # Both items were handed to _apply; the loop survived the first one raising.
    assert len(calls) == 2
