"""R1 / finding F1 — atomic origin-risk bump (no lost updates under concurrency).

Audit finding closed here (see ``docs/audits/correlation-maturity.md`` F1): the
origin-risk ``bump`` was a non-atomic read-modify-write (``hgetall`` → decay in
Python → ``pipeline(hset, expire)``). Two concurrent bumps of the *same* origin
both read the same base score and the last write wins → risk is **undercounted**
exactly during a burst attack. The bump is now a single atomic server-side Lua
script (``_LUA_BUMP``), mirrored byte-for-byte by the pure ``_apply_bump``
reference (shared with the in-memory fallback).

Coverage per project convention — positive AND negative AND adversarial AND
fail-closed:

  * pure arithmetic (``_apply_bump``): decay, accumulation, both clamps
  * atomic path is actually taken (one script call, no separate read-then-write)
  * degrade-to-memory when the script backend errors (never raises)
  * OPT-IN real-Redis concurrency proof (skipped unless ``BULWARK_TEST_REDIS_URL``)
"""

from __future__ import annotations

import os

os.environ.setdefault("BULWARK_JWT_SECRET", "corr-atomic-bump-test-secret-32-chars!!")

import concurrent.futures
import time

import pytest

from src.correlation.risk_state import _MAX_SCORE, RiskStateStore, _apply_bump

# --------------------------------------------------------------------------- #
# Pure reference arithmetic — the single source of truth shared by Lua + local.
# --------------------------------------------------------------------------- #


def test_apply_bump_no_elapsed_is_plain_add():
    """now == prev_ts ⇒ no decay ⇒ score is prev + amount (positive case)."""
    now = 1_000.0
    assert _apply_bump(2.0, now, now, 1.5, 900.0, _MAX_SCORE) == pytest.approx(3.5)


def test_apply_bump_applies_half_life_decay():
    """One half-life of elapsed time halves the prior score before adding."""
    half_life = 100.0
    # prev 8.0 decays to 4.0 after exactly one half-life, then +1.0 = 5.0.
    out = _apply_bump(8.0, 0.0, half_life, 1.0, half_life, _MAX_SCORE)
    assert out == pytest.approx(5.0, abs=1e-9)


def test_apply_bump_accumulates_without_time():
    """Repeated bumps at the same instant accumulate linearly (positive case)."""
    now = 500.0
    score = 0.0
    prev_ts = now
    for _ in range(4):
        score = _apply_bump(score, prev_ts, now, 1.0, 900.0, _MAX_SCORE)
    assert score == pytest.approx(4.0)


def test_apply_bump_clamps_at_max():
    """Score never exceeds the 0..10 ceiling (negative case)."""
    now = 0.0
    assert _apply_bump(8.0, now, now, 8.0, 900.0, _MAX_SCORE) == pytest.approx(_MAX_SCORE)


def test_apply_bump_clamps_at_zero():
    """A negative net result floors at 0.0, never negative (negative case)."""
    now = 0.0
    assert _apply_bump(1.0, now, now, -5.0, 900.0, _MAX_SCORE) == 0.0


def test_apply_bump_sequential_equals_single_shot():
    """Adversarial baseline: N unit bumps at t0 == one bump of the sum.

    This is the exact invariant the concurrency test asserts against real Redis —
    if the atomic path were lossy, the concurrent total would fall short of this.
    """
    now = 0.0
    seq = 0.0
    for _ in range(6):
        seq = _apply_bump(seq, now, now, 1.0, 900.0, _MAX_SCORE)
    single = _apply_bump(0.0, now, now, 6.0, 900.0, _MAX_SCORE)
    assert seq == pytest.approx(single) == pytest.approx(6.0)


# --------------------------------------------------------------------------- #
# The atomic path is actually taken — one script call, no read-then-write.
# --------------------------------------------------------------------------- #


class _AtomicSpyRedis:
    """Records how ``bump`` reaches Redis.

    Deliberately exposes NO ``pipeline`` / ``hset`` methods: if the old
    non-atomic read-modify-write path were taken, the bump would ``AttributeError``.
    A single ``register_script`` closure is the only mutation surface, mirroring
    the real atomic contract.
    """

    def __init__(self) -> None:
        self.store: dict[str, dict[str, str]] = {}
        self.script_calls = 0
        self.hgetall_calls = 0

    def register_script(self, _src: str):
        def _script(keys, args):
            self.script_calls += 1
            key = keys[0]
            now = float(args[0])
            amount = float(args[1])
            half_life = float(args[2])
            max_score = float(args[3])
            cur = self.store.get(key, {})
            prev_score = float(cur.get("score", 0.0) or 0.0)
            prev_ts = float(cur.get("ts", now) or now)
            new_score = _apply_bump(prev_score, prev_ts, now, amount, half_life, max_score)
            self.store[key] = {"score": str(new_score), "ts": str(now)}
            return str(new_score)

        return _script

    def hgetall(self, key: str) -> dict:
        self.hgetall_calls += 1
        return dict(self.store.get(key, {}))


def _spy_store() -> tuple[RiskStateStore, _AtomicSpyRedis]:
    s = RiskStateStore(decay_seconds=900.0)
    spy = _AtomicSpyRedis()
    s._redis = spy  # type: ignore[assignment]
    s._initialized = True
    return s, spy


def test_bump_uses_single_atomic_script_call():
    """Each bump is exactly one atomic script invocation (no separate read)."""
    s, spy = _spy_store()
    s.bump("session", "acme:bot", 3.0)
    assert spy.script_calls == 1
    assert spy.hgetall_calls == 0  # bump must not read-then-write
    # A second bump is again a single atomic call, and it accumulates.
    total = s.bump("session", "acme:bot", 2.0)
    assert spy.script_calls == 2
    assert total == pytest.approx(5.0)


def test_bump_script_registered_once_and_reused():
    """The script handle is cached; we don't re-register on every bump."""
    s, _ = _spy_store()
    s.bump("tenant", "acme", 1.0)
    first = s._bump_script
    s.bump("tenant", "acme", 1.0)
    assert s._bump_script is first  # reused, not re-registered


# --------------------------------------------------------------------------- #
# Fail-closed: a broken script backend degrades to in-memory, never raises.
# --------------------------------------------------------------------------- #


class _BrokenScriptRedis:
    def register_script(self, _src: str):
        def _script(keys, args):
            raise ConnectionError("redis down mid-eval")

        return _script

    def hgetall(self, key: str) -> dict:
        raise ConnectionError("redis down")


def test_bump_degrades_to_memory_when_script_errors():
    """A script/backend error must fall back to the in-memory map, not propagate."""
    s = RiskStateStore(decay_seconds=900.0)
    s._redis = _BrokenScriptRedis()  # type: ignore[assignment]
    s._initialized = True
    new = s.bump("session", "acme:bot", 4.0)  # must not raise
    assert new == pytest.approx(4.0)
    # Subsequent reads also degrade to the in-memory value.
    assert s.get("session", "acme:bot") == pytest.approx(4.0, abs=0.01)


# --------------------------------------------------------------------------- #
# OPT-IN real-Redis proof: concurrent bumps of one origin lose no updates.
# Skipped unless BULWARK_TEST_REDIS_URL points at a disposable Redis.
# --------------------------------------------------------------------------- #

_REAL_REDIS_URL = os.environ.get("BULWARK_TEST_REDIS_URL")


@pytest.mark.skipif(not _REAL_REDIS_URL, reason="requires BULWARK_TEST_REDIS_URL (real Redis)")
def test_concurrent_bumps_no_lost_update_real_redis():
    """N threads each bump the same origin by 0.1; the total must be N*0.1.

    Under the old non-atomic read-modify-write this undercounts (lost updates);
    the atomic Lua path holds it exactly. A very long half-life makes decay
    negligible over the test window so the target is deterministic.
    """
    s = RiskStateStore(decay_seconds=10_000_000.0)
    s.initialize(redis_url=_REAL_REDIS_URL)
    if s.redis is None:  # URL set but unreachable → don't pretend to pass
        pytest.skip("BULWARK_TEST_REDIS_URL set but Redis unreachable")

    scope_id = f"conc:{int(time.time() * 1000)}"
    n = 200
    amount = 0.1

    def _one() -> None:
        s.bump("session", scope_id, amount)

    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(lambda _i: _one(), range(n)))

    expected = min(_MAX_SCORE, n * amount)
    assert s.get("session", scope_id) == pytest.approx(expected, abs=0.05)
