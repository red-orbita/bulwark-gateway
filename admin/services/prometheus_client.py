"""Prometheus metrics client — Exposes and collects metrics for dashboard."""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from ..models.metrics import MetricsSnapshot


@dataclass
class PrometheusMetrics:
    """In-process metrics collector. Also scrapeable via /admin/health/metrics."""

    _start_time: float = field(default_factory=time.time)
    _requests_total: int = 0
    _blocks_total: int = 0
    _warns_total: int = 0
    _allows_total: int = 0
    _latencies: deque = field(default_factory=lambda: deque(maxlen=1000))

    def record_request(self, verdict: str, latency_ms: float) -> None:
        self._requests_total += 1
        self._latencies.append(latency_ms)
        if verdict == "block":
            self._blocks_total += 1
        elif verdict == "warn":
            self._warns_total += 1
        else:
            self._allows_total += 1

    def snapshot(self) -> MetricsSnapshot:
        from datetime import datetime, timezone

        latencies = sorted(self._latencies) if self._latencies else [0]
        n = len(latencies)
        uptime = time.time() - self._start_time
        rps = self._requests_total / max(uptime, 1)

        total_decisions = self._blocks_total + self._warns_total + self._allows_total
        bypass_rate = 0.0  # TODO: compute from red team results
        fp_rate = 0.0  # TODO: compute from QA results

        return MetricsSnapshot(
            timestamp=datetime.now(timezone.utc),
            latency_p50_ms=latencies[int(n * 0.5)] if n else 0,
            latency_p95_ms=latencies[int(n * 0.95)] if n else 0,
            latency_p99_ms=latencies[int(n * 0.99)] if n else 0,
            requests_total=self._requests_total,
            requests_per_second=round(rps, 2),
            events_blocked=self._blocks_total,
            events_warned=self._warns_total,
            events_allowed=self._allows_total,
            bypass_rate=bypass_rate,
            false_positive_rate=fp_rate,
            active_tenants=0,  # TODO: from policy loader
            uptime_seconds=round(uptime, 1),
        )

    def to_prometheus_text(self) -> str:
        """Prometheus exposition format (text/plain)."""
        s = self.snapshot()
        lines = [
            "# HELP sentinel_requests_total Total requests processed",
            "# TYPE sentinel_requests_total counter",
            f"sentinel_requests_total {s.requests_total}",
            "# HELP sentinel_blocks_total Total requests blocked",
            "# TYPE sentinel_blocks_total counter",
            f"sentinel_blocks_total {s.events_blocked}",
            "# HELP sentinel_warns_total Total requests warned",
            "# TYPE sentinel_warns_total counter",
            f"sentinel_warns_total {s.events_warned}",
            "# HELP sentinel_latency_p95_ms Request latency p95 in ms",
            "# TYPE sentinel_latency_p95_ms gauge",
            f"sentinel_latency_p95_ms {s.latency_p95_ms:.2f}",
            "# HELP sentinel_latency_p99_ms Request latency p99 in ms",
            "# TYPE sentinel_latency_p99_ms gauge",
            f"sentinel_latency_p99_ms {s.latency_p99_ms:.2f}",
            "# HELP sentinel_uptime_seconds Uptime in seconds",
            "# TYPE sentinel_uptime_seconds gauge",
            f"sentinel_uptime_seconds {s.uptime_seconds}",
            "# HELP sentinel_queue_depth_memory Telemetry queue depth (memory)",
            "# TYPE sentinel_queue_depth_memory gauge",
            f"sentinel_queue_depth_memory {s.queue_depth_memory}",
            "# HELP sentinel_siem_export_errors SIEM export error count",
            "# TYPE sentinel_siem_export_errors counter",
            f"sentinel_siem_export_errors {s.siem_export_errors}",
        ]
        return "\n".join(lines) + "\n"


_metrics: Optional[PrometheusMetrics] = None


def get_metrics() -> PrometheusMetrics:
    global _metrics
    if _metrics is None:
        _metrics = PrometheusMetrics()
    return _metrics
