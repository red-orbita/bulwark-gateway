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


# Singleton
_counters: ProxyCounters | None = None


def get_counters() -> ProxyCounters:
    global _counters
    if _counters is None:
        _counters = ProxyCounters()
    return _counters
