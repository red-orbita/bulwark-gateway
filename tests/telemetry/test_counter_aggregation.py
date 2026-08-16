"""Unit tests for cross-worker counter aggregation in /health/stats.

The proxy runs with multiple uvicorn workers, so the in-process ``ProxyCounters``
only ever see one worker's slice of traffic. ``merge_global_counters`` overlays
the authoritative distributed totals from Redis (``bulwark:global:*``) so the
stats endpoint reports true cluster-wide numbers. These tests pin that contract.
"""

from src.telemetry.counters import ProxyCounters, merge_global_counters


class _FakeRedis:
    """Minimal duck-typed Redis exposing only mget (optionally raising)."""

    def __init__(self, values=None, raise_on_mget=False):
        self._values = values or {}
        self._raise = raise_on_mget

    def mget(self, *keys):
        if self._raise:
            raise ConnectionError("redis down")
        # redis-py accepts either *keys or a single iterable
        if len(keys) == 1 and isinstance(keys[0], (list, tuple)):
            keys = tuple(keys[0])
        return [self._values.get(k) for k in keys]


def _local_snapshot() -> dict:
    c = ProxyCounters()
    # Simulate this worker having seen a partial slice of traffic.
    c.record("block", 5.0)
    c.record("allow", 9.0)
    return c.snapshot()


class TestMergeGlobalCounters:
    def test_overlay_uses_redis_totals_when_available(self):
        """Redis global totals win over per-worker local counts; scope=global."""
        snap = _local_snapshot()
        assert snap["requests_total"] == 2  # local worker only saw 2
        r = _FakeRedis(
            {
                "bulwark:global:requests_total": b"34",
                "bulwark:global:block": b"21",
                "bulwark:global:allow": b"13",
                "bulwark:global:warn": b"0",
                "bulwark:global:redact": b"0",
            }
        )
        merged = merge_global_counters(snap, r)
        assert merged["scope"] == "global"
        assert merged["requests_total"] == 34
        assert merged["blocked"] == 21
        assert merged["allowed"] == 13
        assert merged["warned"] == 0
        assert merged["redacted"] == 0
        # requests_per_second recomputed from the authoritative total.
        assert merged["requests_per_second"] == round(34 / max(merged["uptime_seconds"], 1), 2)
        # Latency percentiles stay local (Redis does not track them).
        assert "latency_p95_ms" in merged

    def test_no_redis_falls_back_to_worker_scope(self):
        """Without Redis the local per-worker snapshot is returned untouched."""
        snap = _local_snapshot()
        merged = merge_global_counters(snap, None)
        assert merged["scope"] == "worker"
        assert merged["requests_total"] == 2  # unchanged local value

    def test_redis_error_falls_back_to_worker_scope(self):
        """A Redis failure must not break the stats endpoint (fail-soft)."""
        snap = _local_snapshot()
        merged = merge_global_counters(snap, _FakeRedis(raise_on_mget=True))
        assert merged["scope"] == "worker"
        assert merged["requests_total"] == 2

    def test_missing_global_key_falls_back_to_worker_scope(self):
        """If global counters are not yet populated, keep the worker-local view."""
        snap = _local_snapshot()
        # requests_total key absent → mget returns [None, ...]
        merged = merge_global_counters(snap, _FakeRedis({}))
        assert merged["scope"] == "worker"
        assert merged["requests_total"] == 2

    def test_partial_verdict_keys_coerce_missing_to_zero(self):
        """Missing individual verdict keys coerce to 0 without error."""
        snap = _local_snapshot()
        r = _FakeRedis({"bulwark:global:requests_total": b"7"})  # only total present
        merged = merge_global_counters(snap, r)
        assert merged["scope"] == "global"
        assert merged["requests_total"] == 7
        assert merged["blocked"] == 0
        assert merged["allowed"] == 0
