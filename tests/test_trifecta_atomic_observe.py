"""S-21 — atomic runtime-trifecta observe (no lost updates / no double-fire).

Second-pass finding S-21: :meth:`TrifectaStateStore._observe_redis` was a
non-atomic read-modify-write (``HGETALL`` → prune/complete in Python → a separate
``HSET``/``HDEL``/``EXPIRE`` pipeline). Two concurrent output-path requests for the
*same* origin could each read a two-pillar state, each add the missing third, and
BOTH observe the ``newly_completed`` transition — a duplicate ``EXCESSIVE_AGENCY``
event plus a double risk bump — or a lost update could drop a pillar and *miss* the
completion entirely. The whole read→prune→stamp→ttl sequence is now one atomic
server-side Lua script (``_LUA_OBSERVE``), so exactly one caller ever sees the
completion.

Coverage per project convention — positive AND negative AND adversarial AND
fail-closed:

  * the atomic path is actually taken (one script call, no separate read/pipeline)
  * the script handle is registered once and reused
  * behaviour parity with the in-memory fallback (accumulate, complete once, prune)
  * degrade-to-memory when the script backend errors (never raises)
  * OPT-IN real-Redis proof: N concurrent completions fire the transition ONCE
    (skipped unless ``BULWARK_TEST_REDIS_URL`` points at a disposable Redis)
"""

from __future__ import annotations

import os

os.environ.setdefault("BULWARK_JWT_SECRET", "trifecta-observe-test-secret-32-chars!!")

import concurrent.futures
import time

import pytest

from src.correlation.trifecta_runtime import _TRIFECTA_SIZE, TrifectaStateStore

_DA = "data_access"
_UE = "untrusted_exposure"
_EX = "exfiltration"


# --------------------------------------------------------------------------- #
# A fake that emulates the Lua observe closure ATOMICALLY in Python.
#
# It deliberately exposes NO ``hgetall`` / ``pipeline`` / ``hset`` methods: if the
# old non-atomic read-modify-write path were taken, the observe would
# ``AttributeError``. The single ``register_script`` closure is the only mutation
# surface, mirroring the real atomic contract and the ``_LUA_OBSERVE`` algorithm
# byte-for-byte (prune stale, stamp new, return ``[newly, *live]``).
# --------------------------------------------------------------------------- #


class _ObserveSpyRedis:
    def __init__(self) -> None:
        self.store: dict[str, dict[str, str]] = {}
        self.script_calls = 0

    def register_script(self, _src: str):
        def _script(keys, args):
            self.script_calls += 1
            key = keys[0]
            now = float(args[0])
            window = float(args[1])
            # args[2] = ttl (unused by the fake), args[3] = trifecta size
            trifecta = int(args[3])
            new_pillars = [str(a) for a in args[4:]]
            cur = dict(self.store.get(key, {}))
            live: dict[str, bool] = {}
            live_before = 0
            stale: list[str] = []
            for pillar, ts in cur.items():
                try:
                    seen = float(ts)
                except (TypeError, ValueError):
                    stale.append(pillar)
                    continue
                if now - seen <= window:
                    live[pillar] = True
                    live_before += 1
                else:
                    stale.append(pillar)
            for pillar in stale:
                cur.pop(pillar, None)
            for pillar in new_pillars:
                cur[pillar] = str(now)
                live[pillar] = True
            self.store[key] = cur
            live_after = len(live)
            newly = "1" if (live_after == trifecta and live_before < trifecta) else "0"
            return [newly, *live.keys()]

        return _script


def _spy_store() -> tuple[TrifectaStateStore, _ObserveSpyRedis]:
    s = TrifectaStateStore()
    spy = _ObserveSpyRedis()
    s._redis = spy  # type: ignore[assignment]
    return s, spy


# --------------------------------------------------------------------------- #
# The atomic path is actually taken — one script call, no read-then-write.
# --------------------------------------------------------------------------- #


def test_observe_uses_single_atomic_script_call():
    """Each observe is exactly one atomic script invocation (no separate read)."""
    s, spy = _spy_store()
    s.observe("session", "acme:bot", {_DA}, 1800.0)
    assert spy.script_calls == 1
    # The spy exposes no hgetall/pipeline; reaching here proves the atomic path.
    assert not hasattr(spy, "hgetall")
    assert not hasattr(spy, "pipeline")
    s.observe("session", "acme:bot", {_UE}, 1800.0)
    assert spy.script_calls == 2


def test_observe_script_registered_once_and_reused():
    """The script handle is cached; we don't re-register on every observe."""
    s, _ = _spy_store()
    s.observe("session", "acme:bot", {_DA}, 1800.0)
    first = s._observe_script
    assert first is not None
    s.observe("session", "acme:bot", {_UE}, 1800.0)
    assert s._observe_script is first  # reused, not re-registered


# --------------------------------------------------------------------------- #
# Behaviour parity with the in-memory fallback.
# --------------------------------------------------------------------------- #


def test_observe_accumulates_and_completes_once_redis():
    """Pillars accrue across requests; completion fires exactly once."""
    s, _ = _spy_store()
    live, done = s.observe("session", "acme:bot", {_DA}, 1800.0)
    assert live == {_DA}
    assert done is False
    live, done = s.observe("session", "acme:bot", {_UE}, 1800.0)
    assert live == {_DA, _UE}
    assert done is False
    live, done = s.observe("session", "acme:bot", {_EX}, 1800.0)
    assert live == {_DA, _UE, _EX}
    assert len(live) == _TRIFECTA_SIZE
    assert done is True
    # An already-complete origin does NOT re-fire the transition.
    _live, done = s.observe("session", "acme:bot", {_EX}, 1800.0)
    assert done is False


def test_observe_single_request_all_three_completes_redis():
    """All three pillars in one observe completes on that call."""
    s, _ = _spy_store()
    live, done = s.observe("session", "acme:bot", {_DA, _UE, _EX}, 1800.0)
    assert live == {_DA, _UE, _EX}
    assert done is True


def test_observe_prunes_stale_pillars_redis():
    """Pillars older than the window decay out and do not complete the trifecta."""
    s, _ = _spy_store()
    s.observe("session", "acme:bot", {_DA, _UE}, 1800.0, now=1_000.0)
    # A tiny window means the earlier pillars have expired by the next observe.
    live, done = s.observe("session", "acme:bot", {_EX}, 10.0, now=5_000.0)
    assert live == {_EX}
    assert done is False


def test_observe_scopes_are_isolated_redis():
    """One origin's pillars never complete another origin's trifecta."""
    s, _ = _spy_store()
    s.observe("session", "acme:bot", {_DA, _UE}, 1800.0)
    live, done = s.observe("session", "acme:other", {_EX}, 1800.0)
    assert live == {_EX}
    assert done is False


# --------------------------------------------------------------------------- #
# Fail-closed: a broken script backend degrades to in-memory, never raises.
# --------------------------------------------------------------------------- #


class _BrokenScriptRedis:
    def register_script(self, _src: str):
        def _script(keys, args):
            raise ConnectionError("redis down mid-eval")

        return _script


def test_observe_degrades_to_memory_when_script_errors():
    """A script/backend error must fall back to the in-memory map, not propagate."""
    s = TrifectaStateStore()
    s._redis = _BrokenScriptRedis()  # type: ignore[assignment]
    # First two pillars via the fallback (must not raise).
    live, done = s.observe("session", "acme:bot", {_DA, _UE}, 1800.0)
    assert live == {_DA, _UE}
    assert done is False
    # The third completes via the same in-memory fallback.
    live, done = s.observe("session", "acme:bot", {_EX}, 1800.0)
    assert live == {_DA, _UE, _EX}
    assert done is True


# --------------------------------------------------------------------------- #
# OPT-IN real-Redis proof: N concurrent completions fire the transition ONCE.
# Skipped unless BULWARK_TEST_REDIS_URL points at a disposable Redis.
# --------------------------------------------------------------------------- #

_REAL_REDIS_URL = os.environ.get("BULWARK_TEST_REDIS_URL")


@pytest.mark.skipif(not _REAL_REDIS_URL, reason="requires BULWARK_TEST_REDIS_URL (real Redis)")
def test_concurrent_completion_fires_once_real_redis():
    """Two pillars pre-seeded; N threads each add the third concurrently.

    Under the old non-atomic read-modify-write, several threads could each read
    the two-pillar state and each observe the completion (duplicate event + double
    risk bump). The atomic Lua path guarantees exactly ONE ``newly_completed``.
    """
    s = TrifectaStateStore()
    s.initialize(redis_url=_REAL_REDIS_URL)
    if s._redis is None:  # URL set but unreachable → don't pretend to pass
        pytest.skip("BULWARK_TEST_REDIS_URL set but Redis unreachable")

    scope_id = f"conc:{int(time.time() * 1000)}"
    window = 100_000.0
    # Pre-seed the first two pillars so the trifecta is one pillar short.
    s.observe("session", scope_id, {_DA, _UE}, window)

    n = 64
    results: list[bool] = []

    def _one() -> bool:
        _live, done = s.observe("session", scope_id, {_EX}, window)
        return done

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _i: _one(), range(n)))

    assert sum(1 for d in results if d) == 1  # exactly one completion transition
