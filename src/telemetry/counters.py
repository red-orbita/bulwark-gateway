"""Simple in-memory request counters for the proxy hot path.

Thread-safe via GIL (single-process asyncio). Exposed via /health/stats.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field


@dataclass
class ProxyCounters:
    """Lightweight counters — no external deps, zero-alloc hot path."""

    _start: float = field(default_factory=time.time)
    requests_total: int = 0
    blocked: int = 0
    warned: int = 0
    allowed: int = 0
    redacted: int = 0
    errors: int = 0
    _latencies: deque = field(default_factory=lambda: deque(maxlen=2000))

    def record(self, verdict: str, latency_ms: float) -> None:
        self.requests_total += 1
        self._latencies.append(latency_ms)
        if verdict == "block":
            self.blocked += 1
        elif verdict == "warn":
            self.warned += 1
        elif verdict == "redact":
            self.redacted += 1
        elif verdict == "allow":
            self.allowed += 1

    def record_error(self) -> None:
        self.requests_total += 1
        self.errors += 1

    def snapshot(self) -> dict:
        latencies = sorted(self._latencies) if self._latencies else [0.0]
        n = len(latencies)
        uptime = time.time() - self._start
        return {
            "uptime_seconds": round(uptime, 1),
            "requests_total": self.requests_total,
            "requests_per_second": round(self.requests_total / max(uptime, 1), 2),
            "blocked": self.blocked,
            "warned": self.warned,
            "allowed": self.allowed,
            "redacted": self.redacted,
            "errors": self.errors,
            "latency_p50_ms": round(latencies[int(n * 0.5)], 2),
            "latency_p95_ms": round(latencies[int(n * 0.95)], 2),
            "latency_p99_ms": round(latencies[int(n * 0.99)], 2),
        }


def merge_global_counters(snapshot: dict, redis_client) -> dict:
    """Overlay authoritative cross-worker verdict totals from Redis.

    In-process ``ProxyCounters`` are per-worker: the proxy runs with multiple
    uvicorn workers (``--workers N``), so ``/health/stats`` served by any single
    worker only sees that worker's slice of traffic. The proxy hot path also
    increments distributed ``bulwark:global:*`` counters in Redis, which hold the
    true aggregate across every worker and replica (and survive restarts).

    This overlays those authoritative totals onto a local snapshot when Redis is
    reachable, and tags the result with ``scope`` so operators know whether the
    numbers are cluster-wide (``"global"``) or a single worker (``"worker"``).

    Latency percentiles, ``errors`` and ``uptime_seconds`` remain per-worker
    best-effort (Redis does not track them); ``requests_per_second`` is therefore
    derived from the serving worker's uptime. ``redis_client`` is duck-typed
    (only ``.mget`` is used) to keep this module dependency-free.
    """
    if redis_client is None:
        snapshot["scope"] = "worker"
        return snapshot
    try:
        raw = redis_client.mget(
            "bulwark:global:requests_total",
            "bulwark:global:block",
            "bulwark:global:allow",
            "bulwark:global:warn",
            "bulwark:global:redact",
        )
    except Exception:
        snapshot["scope"] = "worker"
        return snapshot
    # requests_total missing → counters not yet populated; keep worker-local view.
    if not raw or raw[0] is None:
        snapshot["scope"] = "worker"
        return snapshot
    snapshot["requests_total"] = int(raw[0])
    snapshot["blocked"] = int(raw[1] or 0)
    snapshot["allowed"] = int(raw[2] or 0)
    snapshot["warned"] = int(raw[3] or 0)
    snapshot["redacted"] = int(raw[4] or 0)
    uptime = snapshot.get("uptime_seconds") or 0
    snapshot["requests_per_second"] = round(snapshot["requests_total"] / max(uptime, 1), 2)
    snapshot["scope"] = "global"
    return snapshot


# Singleton
_counters: ProxyCounters | None = None


def get_counters() -> ProxyCounters:
    global _counters
    if _counters is None:
        _counters = ProxyCounters()
    return _counters
