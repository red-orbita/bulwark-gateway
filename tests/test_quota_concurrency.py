"""Distributed per-tenant concurrency quota tests.

Audit finding closed here: ``max_concurrent_requests`` was enforced with a
per-process ``asyncio.Semaphore``. Under the shipped topology (2-10 proxy
replicas) that means the *global* limit was silently ``limit × replicas`` — a
noisy-neighbour / DoS control that did not actually hold. The limiter is now
backed by a Redis sorted set of in-flight tokens (atomic Lua acquire, stale
pruning for crashed pods) with the per-process semaphore demoted to an explicit
degraded fallback.

Both paths are covered:

  * fallback (no Redis): acquire up to the limit, reject beyond it, release
    frees a slot — same guarantee within a single process.
  * distributed (Redis): the limiter reserves/reads/releases slots via the
    shared sorted set, and stale in-flight tokens self-expire so a crashed
    replica cannot leak capacity forever.

Positive AND negative cases per project convention.
"""

from __future__ import annotations

import os

os.environ.setdefault("BULWARK_JWT_SECRET", "quota-concurrency-test-secret-32-chars!!")
os.environ.setdefault("BULWARK_KEY_ENCRYPTION_KEY", "quota-concurrency-enc-32-characters-min!")

import time

from src.middleware.quotas import DistributedConcurrencyLimiter

# --------------------------------------------------------------------------- #
# Minimal Redis double: enough of the sorted-set surface for the limiter.
# register_script returns a Python closure emulating the atomic acquire.
# --------------------------------------------------------------------------- #


class _FakeRedis:
    def __init__(self):
        self.zsets: dict[str, dict[str, float]] = {}

    def register_script(self, _src: str):
        def _script(keys, args):
            key = keys[0]
            now = float(args[0])
            limit = int(args[1])
            member = args[2]
            stale = float(args[3])
            z = self.zsets.setdefault(key, {})
            # prune stale members
            for m in [m for m, s in z.items() if s <= now - stale]:
                del z[m]
            if len(z) >= limit:
                return 0
            z[member] = now
            return 1

        return _script

    def zrem(self, key: str, member: str):
        self.zsets.get(key, {}).pop(member, None)

    def zcard(self, key: str) -> int:
        return len(self.zsets.get(key, {}))

    def zremrangebyscore(self, key: str, lo: float, hi: float):
        z = self.zsets.get(key, {})
        for m in [m for m, s in z.items() if lo <= s <= hi]:
            del z[m]


# --------------------------------------------------------------------------- #
# Fallback (no Redis) — per-process accounting.
# --------------------------------------------------------------------------- #


class TestLocalFallback:
    def test_reports_non_distributed(self):
        lim = DistributedConcurrencyLimiter(redis_client=None, stale_seconds=60)
        assert lim.distributed is False

    def test_enforces_limit_within_process(self):
        lim = DistributedConcurrencyLimiter(redis_client=None, stale_seconds=60)
        ok1, t1 = lim.try_acquire("acme", 2)
        ok2, t2 = lim.try_acquire("acme", 2)
        ok3, t3 = lim.try_acquire("acme", 2)
        assert ok1 and ok2
        assert ok3 is False and t3 is None
        assert lim.in_flight("acme") == 2

    def test_release_frees_a_slot(self):
        lim = DistributedConcurrencyLimiter(redis_client=None, stale_seconds=60)
        _, t1 = lim.try_acquire("acme", 1)
        blocked, _ = lim.try_acquire("acme", 1)
        assert blocked is False
        lim.release("acme", t1)
        regained, _ = lim.try_acquire("acme", 1)
        assert regained is True

    def test_release_none_is_safe(self):
        lim = DistributedConcurrencyLimiter(redis_client=None, stale_seconds=60)
        lim.release("acme", None)  # must not raise

    def test_tenants_are_isolated(self):
        lim = DistributedConcurrencyLimiter(redis_client=None, stale_seconds=60)
        lim.try_acquire("acme", 1)
        ok, _ = lim.try_acquire("globex", 1)
        assert ok is True  # globex has its own budget


# --------------------------------------------------------------------------- #
# Distributed (Redis) — global accounting shared across replicas.
# --------------------------------------------------------------------------- #


class TestDistributed:
    def test_reports_distributed(self):
        lim = DistributedConcurrencyLimiter(redis_client=_FakeRedis(), stale_seconds=60)
        assert lim.distributed is True

    def test_two_limiters_share_one_global_budget(self):
        """Simulates two replicas: the limit is global, not per-instance."""
        shared = _FakeRedis()
        pod_a = DistributedConcurrencyLimiter(redis_client=shared, stale_seconds=60)
        pod_b = DistributedConcurrencyLimiter(redis_client=shared, stale_seconds=60)

        ok_a, ta = pod_a.try_acquire("acme", 2)
        ok_b, tb = pod_b.try_acquire("acme", 2)
        assert ok_a and ok_b
        # Third acquire on EITHER pod must be rejected — global limit reached.
        ok_c, tc = pod_a.try_acquire("acme", 2)
        assert ok_c is False and tc is None
        ok_d, td = pod_b.try_acquire("acme", 2)
        assert ok_d is False and td is None
        assert pod_a.in_flight("acme") == 2

    def test_release_on_one_pod_frees_global_slot(self):
        shared = _FakeRedis()
        pod_a = DistributedConcurrencyLimiter(redis_client=shared, stale_seconds=60)
        pod_b = DistributedConcurrencyLimiter(redis_client=shared, stale_seconds=60)
        _, ta = pod_a.try_acquire("acme", 1)
        blocked, _ = pod_b.try_acquire("acme", 1)
        assert blocked is False
        pod_a.release("acme", ta)
        regained, _ = pod_b.try_acquire("acme", 1)
        assert regained is True

    def test_stale_slots_self_heal(self):
        """A crashed pod's in-flight token expires and frees capacity."""
        shared = _FakeRedis()
        # stale window of 1s; manually age the token to simulate a crash.
        lim = DistributedConcurrencyLimiter(redis_client=shared, stale_seconds=1)
        ok, token = lim.try_acquire("acme", 1)
        assert ok
        # Age the member well beyond the stale window.
        key = "bulwark:quota:concurrent:acme"
        shared.zsets[key][token[2:]] = time.time() - 10
        # Next acquire prunes the stale slot and succeeds despite limit=1.
        regained, _ = lim.try_acquire("acme", 1)
        assert regained is True

    def test_redis_token_prefix(self):
        lim = DistributedConcurrencyLimiter(redis_client=_FakeRedis(), stale_seconds=60)
        _, token = lim.try_acquire("acme", 5)
        assert token is not None and token.startswith("r:")

    def test_redis_failure_degrades_gracefully(self):
        """If Redis raises mid-flight, acquisition falls back to local counting."""

        class _BoomRedis(_FakeRedis):
            def register_script(self, _src):
                def _script(keys, args):
                    raise RuntimeError("redis down")
                return _script

        lim = DistributedConcurrencyLimiter(redis_client=_BoomRedis(), stale_seconds=60)
        assert lim.distributed is True  # script registered fine
        ok, token = lim.try_acquire("acme", 1)
        assert ok is True
        assert token == "l:"  # noqa: S105 - degraded to local accounting
        blocked, _ = lim.try_acquire("acme", 1)
        assert blocked is False
