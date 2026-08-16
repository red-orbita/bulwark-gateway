"""Rate limiter resilience tests (H-08).

Regression coverage for the bug where a transient Redis failure at middleware
construction time (rolling deploy / cold DNS / 0.5s socket timeout) permanently
demoted the proxy to the per-process in-memory fallback with no reconnection,
causing spurious fail-closed 429s and inaccurate distributed limits.
"""

import redis

import src.middleware.rate_limit as rl


class _FakePipeline:
    """Minimal MULTI/EXEC pipeline stub."""

    def __init__(self, client):
        self.client = client

    # Chainable, no-op command recorders.
    def zremrangebyscore(self, *a, **k):
        return self

    def zadd(self, *a, **k):
        return self

    def zcard(self, *a, **k):
        return self

    def expire(self, *a, **k):
        return self

    def execute(self):
        if self.client.state["op_error"]:
            raise redis.exceptions.ConnectionError("simulated pipeline failure")
        # Results positionally mirror the real pipeline:
        # [zremrangebyscore, zadd, zcard, expire]
        return [0, 1, self.client.state["count"], True]


class _FakeRedis:
    """Controllable fake Redis client shared via a mutable state dict."""

    def __init__(self, state):
        self.state = state

    def ping(self):
        if self.state["down"]:
            raise redis.exceptions.ConnectionError("simulated down")
        return True

    def pipeline(self, transaction=True):
        return _FakePipeline(self)

    def zrem(self, *a, **k):
        if self.state["op_error"]:
            raise redis.exceptions.ConnectionError("simulated zrem failure")
        return 1


def _patch_from_url(monkeypatch, state):
    calls = {"n": 0}

    def fake_from_url(url, **kwargs):
        calls["n"] += 1
        return _FakeRedis(state)

    monkeypatch.setattr(rl.redis, "from_url", fake_from_url)
    return calls


def test_reconnects_after_transient_startup_failure(monkeypatch):
    """POSITIVE: a limiter that failed to connect at construction must
    self-heal once Redis becomes reachable again."""
    state = {"down": True, "op_error": False, "count": 1}
    _patch_from_url(monkeypatch, state)

    limiter = rl.RedisRateLimiter(rate_rpm=60, redis_url="redis://x:6379/0")
    # Startup ping failed → not available, on in-memory fallback.
    assert limiter.available is False

    # Redis recovers; force the reconnect throttle window open.
    state["down"] = False
    limiter._last_connect_attempt = 0.0

    assert limiter.available is True
    assert limiter.consume("ip:1.2.3.4") is True


def test_reconnect_attempts_are_throttled(monkeypatch):
    """NEGATIVE: while Redis stays down, the hot path must not attempt a new
    connection on every request — reconnects are throttled."""
    state = {"down": True, "op_error": False, "count": 1}
    calls = _patch_from_url(monkeypatch, state)

    limiter = rl.RedisRateLimiter(rate_rpm=60, redis_url="redis://x:6379/0")
    attempts_after_ctor = calls["n"]  # one attempt during __init__

    # Repeated checks within the throttle interval → no new connect attempts.
    for _ in range(10):
        assert limiter.available is False
    assert calls["n"] == attempts_after_ctor

    # After the throttle window elapses, exactly one more attempt is made.
    limiter._last_connect_attempt = 0.0
    assert limiter.available is False
    assert calls["n"] == attempts_after_ctor + 1


def test_consume_uses_transaction_not_eval(monkeypatch):
    """The limiter must NOT depend on server-side scripting (EVAL is disabled
    on hardened Redis). A client without eval() still works via MULTI/EXEC."""
    state = {"down": False, "op_error": False, "count": 1}
    _patch_from_url(monkeypatch, state)

    limiter = rl.RedisRateLimiter(rate_rpm=60, redis_url="redis://x:6379/0")
    # _FakeRedis deliberately has no eval() method — proves it isn't called.
    assert not hasattr(limiter._redis, "eval")
    assert limiter.consume("ip:1.2.3.4") is True


def test_consume_rejects_when_over_limit(monkeypatch):
    """NEGATIVE: when the window exceeds the limit, consume rejects (False) but
    keeps the Redis client (it's a limit hit, not a connection error)."""
    state = {"down": False, "op_error": False, "count": 61}  # > rpm 60
    _patch_from_url(monkeypatch, state)

    limiter = rl.RedisRateLimiter(rate_rpm=60, redis_url="redis://x:6379/0")
    assert limiter.consume("ip:1.2.3.4") is False
    assert limiter._redis is not None  # still connected, just rate-limited


def test_consume_fail_closed_marks_reconnect(monkeypatch):
    """A Redis error during consume() fails CLOSED (returns False) AND drops
    the client so the next throttled window re-establishes it."""
    state = {"down": False, "op_error": True, "count": 1}
    _patch_from_url(monkeypatch, state)

    limiter = rl.RedisRateLimiter(rate_rpm=60, redis_url="redis://x:6379/0")
    assert limiter._redis is not None  # connected at startup

    assert limiter.consume("ip:1.2.3.4") is False  # fail-closed
    assert limiter._redis is None  # marked for reconnect

    # Redis recovers → limiter heals on the next window.
    state["op_error"] = False
    limiter._last_connect_attempt = 0.0
    assert limiter.available is True


def test_no_redis_url_defers_to_caller_fallback():
    """Without a Redis URL the limiter is unavailable and consume() returns
    True so the caller applies the in-memory fallback."""
    limiter = rl.RedisRateLimiter(rate_rpm=60, redis_url=None)
    assert limiter.available is False
    assert limiter.consume("ip:1.2.3.4") is True


def test_in_memory_token_bucket_allows_burst_then_blocks(monkeypatch):
    """POSITIVE + NEGATIVE: the fallback bucket allows up to burst, then blocks."""
    monkeypatch.setenv("BULWARK_WORKERS", "1")  # deterministic (no worker division)
    bucket = rl.InMemoryTokenBucket(rate=600 / 60.0, burst=5)  # 10 tok/s, burst 5

    # Fired in a tight loop; refill is negligible → first 5 pass.
    assert all(bucket.consume("ip:9.9.9.9") for _ in range(5))
    # 6th is blocked (bucket exhausted).
    assert bucket.consume("ip:9.9.9.9") is False
