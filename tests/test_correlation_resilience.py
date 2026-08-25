"""R2 / finding F2 — Redis resilience of the inline risk path.

Audit finding closed here (see ``docs/audits/correlation-maturity.md`` F2): the
per-request origin-risk enforcement read was two separate Redis round-trips
(session + tenant), and every call went to Redis with a 1s socket timeout and no
circuit breaker — so a slow/down Redis multiplied user latency by the number of
calls. Two fixes:

  * ``get_many`` pipelines the enforcement reads into a single round-trip.
  * a circuit breaker opens after N consecutive Redis errors and short-circuits
    straight to the in-memory fallback (no socket touch) until a cooldown probe.

Coverage per project convention — positive AND negative AND adversarial AND
fail-closed.
"""

from __future__ import annotations

import os

os.environ.setdefault("BULWARK_JWT_SECRET", "corr-resilience-test-secret-32-chars!!!")

import time

import pytest

from src.correlation.risk_state import (
    _CB_COOLDOWN_SECONDS,
    _CB_FAIL_THRESHOLD,
    RiskStateStore,
    _apply_bump,
)

# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #


class _SpyPipe:
    def __init__(self, backend: "_SpyRedis") -> None:
        self._backend = backend
        self._keys: list[str] = []

    def hgetall(self, key: str):
        self._keys.append(key)
        return self

    def execute(self) -> list:
        return [dict(self._backend.store.get(k, {})) for k in self._keys]


class _SpyRedis:
    """Counts pipeline round-trips + direct hgetall calls; hash-only backing."""

    def __init__(self, seed: dict | None = None) -> None:
        self.store: dict[str, dict] = seed or {}
        self.pipeline_count = 0
        self.hgetall_count = 0

    def pipeline(self) -> _SpyPipe:
        self.pipeline_count += 1
        return _SpyPipe(self)

    def hgetall(self, key: str):
        self.hgetall_count += 1
        return dict(self.store.get(key, {}))


class _FlakyRedis:
    """Fails every op with ConnectionError; counts how many times it is hit.

    Lets a test prove the breaker *stops* calling Redis once open (the calls
    counter freezes) instead of paying a timeout on every request.
    """

    def __init__(self) -> None:
        self.calls = 0
        self.store: dict[str, dict] = {}
        self.healthy = False

    def register_script(self, _src: str):
        def _script(keys, args):
            self.calls += 1
            if not self.healthy:
                raise ConnectionError("redis down")
            key = keys[0]
            now = float(args[0])
            cur = self.store.get(key, {})
            prev_score = float(cur.get("score", 0.0) or 0.0)
            prev_ts = float(cur.get("ts", now) or now)
            new_score = _apply_bump(prev_score, prev_ts, now, float(args[1]), float(args[2]), float(args[3]))
            self.store[key] = {"score": str(new_score), "ts": str(now)}
            return str(new_score)

        return _script

    def pipeline(self):
        self.calls += 1
        raise ConnectionError("redis down")

    def hgetall(self, key: str):
        self.calls += 1
        if not self.healthy:
            raise ConnectionError("redis down")
        return dict(self.store.get(key, {}))


def _store_with(redis_obj) -> RiskStateStore:
    s = RiskStateStore(decay_seconds=10_000.0)
    s._redis = redis_obj  # type: ignore[assignment]
    s._initialized = True
    return s


# --------------------------------------------------------------------------- #
# get_many — one round-trip, order-preserving, fail-closed
# --------------------------------------------------------------------------- #


def test_get_many_single_pipeline_round_trip():
    """Two enforcement reads collapse to exactly one pipeline (positive)."""
    now = time.time()
    seed = {
        RiskStateStore._redis_key("session", "acme:bot"): {"score": "5.0", "ts": str(now)},
        RiskStateStore._redis_key("tenant", "acme"): {"score": "2.0", "ts": str(now)},
    }
    spy = _SpyRedis(seed)
    s = _store_with(spy)

    scores = s.get_many([("session", "acme:bot"), ("tenant", "acme")])
    assert scores == pytest.approx([5.0, 2.0], abs=0.01)
    assert spy.pipeline_count == 1       # one round-trip, not two
    assert spy.hgetall_count == 0        # not the per-key path


def test_get_many_preserves_order_and_zero_fills_absent():
    """Order matches input; unseen origins read as 0.0 (positive + negative)."""
    now = time.time()
    seed = {RiskStateStore._redis_key("tenant", "acme"): {"score": "3.0", "ts": str(now)}}
    s = _store_with(_SpyRedis(seed))

    scores = s.get_many([("session", "acme:bot"), ("tenant", "acme"), ("input", "deadbeef")])
    assert scores[0] == 0.0
    assert scores[1] == pytest.approx(3.0, abs=0.01)
    assert scores[2] == 0.0


def test_get_many_empty_is_empty():
    s = _store_with(_SpyRedis())
    assert s.get_many([]) == []


def test_get_many_degrades_to_memory_on_error():
    """A pipeline failure falls back to the in-memory map, never raises."""
    s = _store_with(_FlakyRedis())  # pipeline() raises
    # Seed the local fallback so we can observe the degraded read return it.
    s._bump_local("session", "acme:bot", 4.0, time.time())
    scores = s.get_many([("session", "acme:bot"), ("tenant", "acme")])
    assert scores[0] == pytest.approx(4.0, abs=0.05)
    assert scores[1] == 0.0


# --------------------------------------------------------------------------- #
# Circuit breaker — opens, stops hitting Redis, half-open probe recovers
# --------------------------------------------------------------------------- #


def test_breaker_opens_after_threshold_and_stops_calling_redis():
    """Adversarial: once open, further calls do NOT touch Redis (no timeout pileup)."""
    flaky = _FlakyRedis()
    s = _store_with(flaky)

    # Drive exactly the threshold number of failures.
    for _ in range(_CB_FAIL_THRESHOLD):
        s.bump("session", "acme:bot", 1.0)  # each fails → in-memory fallback
    assert s.circuit_open is True
    calls_at_open = flaky.calls

    # Subsequent calls must short-circuit — Redis untouched.
    for _ in range(10):
        s.bump("session", "acme:bot", 1.0)
        s.get("session", "acme:bot")
    assert flaky.calls == calls_at_open  # frozen: breaker is protecting the path

    # And the risk still accrues via the in-memory fallback (never lost).
    assert s.get("session", "acme:bot") > 0.0


def test_breaker_half_open_probe_recovers_when_redis_healthy():
    """After cooldown a probe re-tests Redis; success closes the breaker."""
    flaky = _FlakyRedis()
    s = _store_with(flaky)
    for _ in range(_CB_FAIL_THRESHOLD):
        s.bump("session", "acme:bot", 1.0)
    assert s.circuit_open is True

    # Simulate cooldown elapsing and Redis coming back.
    s._cb_opened_at = time.time() - _CB_COOLDOWN_SECONDS - 1.0
    flaky.healthy = True
    assert s.circuit_open is False  # half-open: probe allowed

    out = s.bump("session", "acme:bot", 1.0)  # probe hits Redis, succeeds
    assert out > 0.0
    assert s.circuit_open is False
    assert s._cb_failures == 0  # breaker fully closed after success


def test_breaker_success_resets_failure_counter():
    """A success below the threshold clears accumulated failures (no latent trip)."""
    flaky = _FlakyRedis()
    s = _store_with(flaky)
    for _ in range(_CB_FAIL_THRESHOLD - 1):  # one short of opening
        s.bump("session", "acme:bot", 1.0)
    assert s.circuit_open is False
    assert s._cb_failures == _CB_FAIL_THRESHOLD - 1

    flaky.healthy = True
    s.bump("session", "acme:bot", 1.0)  # success
    assert s._cb_failures == 0  # reset, so the next failures start from zero


# --------------------------------------------------------------------------- #
# evaluate_origin_risk uses a single round-trip (integration with the correlator)
# --------------------------------------------------------------------------- #


def test_evaluate_origin_risk_uses_single_round_trip(monkeypatch):
    """The enforcement read is one pipeline, not two per-key hgetall calls."""
    import dataclasses

    from src.correlation.incident import InputOutputCorrelator
    from src.correlation.runtime import get_correlation_runtime

    now = time.time()
    seed = {
        RiskStateStore._redis_key("session", "acme:bot"): {"score": "8.0", "ts": str(now)},
        RiskStateStore._redis_key("tenant", "acme"): {"score": "1.0", "ts": str(now)},
    }
    spy = _SpyRedis(seed)
    store = _store_with(spy)

    # Force blocking-on with a low block threshold so we exercise the full path.
    rc = dataclasses.replace(
        get_correlation_runtime().get(),
        blocking=True,
        risk_block_threshold=5.0,
        risk_warn_threshold=3.0,
    )
    monkeypatch.setattr(get_correlation_runtime(), "get", lambda: rc)

    corr = InputOutputCorrelator()
    corr._risk = store  # inject the spy-backed store

    assessment = corr.evaluate_origin_risk(tenant_id="acme", agent_id="bot")
    assert assessment is not None
    assert assessment.score == pytest.approx(8.0, abs=0.01)
    assert spy.pipeline_count == 1   # exactly one round-trip
    assert spy.hgetall_count == 0
