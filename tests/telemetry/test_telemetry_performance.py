"""
Load / Performance tests — Validate telemetry has zero impact on hot path.

Run with: pytest tests/telemetry/test_telemetry_performance.py -v
"""

import asyncio
import tempfile
import time

import pytest

from src.telemetry.schema import from_security_event
from src.telemetry.queue import TelemetryQueue


class TestTelemetryPerformance:
    """Validate enqueue overhead is ≤2ms p95 under load."""

    def test_enqueue_10k_events_under_2ms_p95(self):
        """Simulate 10k events (10 req/s * 1000s) and measure enqueue latency."""

        async def _test():
            with tempfile.TemporaryDirectory() as tmpdir:
                q = TelemetryQueue(max_size=10000, disk_path=f"{tmpdir}/perf.db")
                event = from_security_event(
                    verdict="block",
                    rule_id="PERF-001",
                    rule_description="Performance test event",
                    threat_category="test",
                    tenant_id="load-test",
                    agent_id="bench-agent",
                    guardrail_layer="input",
                    latency_ms=5.0,
                    source_ip="10.0.0.1",
                    raw_input="test payload for benchmarking",
                )

                latencies = []
                for _ in range(10000):
                    start = time.perf_counter()
                    q.enqueue_nowait(event)
                    elapsed_ms = (time.perf_counter() - start) * 1000
                    latencies.append(elapsed_ms)

                latencies.sort()
                p50 = latencies[5000]
                p95 = latencies[9500]
                p99 = latencies[9900]
                max_lat = latencies[-1]

                print(f"\n[TELEMETRY PERF] Enqueue 10k events:")
                print(f"  p50: {p50:.4f}ms")
                print(f"  p95: {p95:.4f}ms")
                print(f"  p99: {p99:.4f}ms")
                print(f"  max: {max_lat:.4f}ms")
                print(f"  Queue stats: {q.stats}")

                assert p95 < 2.0, f"Enqueue p95 = {p95:.3f}ms exceeds 2ms budget"
                assert q.stats["enqueued"] == 10000
                q.close()

        asyncio.run(_test())

    def test_overflow_performance(self):
        """When queue overflows to disk, enqueue should still be <2ms."""

        async def _test():
            with tempfile.TemporaryDirectory() as tmpdir:
                # Small queue to force overflow
                q = TelemetryQueue(max_size=100, disk_path=f"{tmpdir}/overflow.db")
                event = from_security_event(
                    verdict="warn",
                    rule_id="PERF-002",
                    rule_description="Overflow test",
                    threat_category="test",
                    tenant_id="t",
                    agent_id=None,
                    guardrail_layer="input",
                    latency_ms=1.0,
                )

                latencies = []
                for _ in range(1000):
                    start = time.perf_counter()
                    q.enqueue_nowait(event)
                    elapsed_ms = (time.perf_counter() - start) * 1000
                    latencies.append(elapsed_ms)

                latencies.sort()
                p95 = latencies[950]
                print(f"\n[OVERFLOW PERF] p95: {p95:.4f}ms, disk_spills: {q.stats['disk_spills']}")

                assert p95 < 2.0, f"Overflow enqueue p95 = {p95:.3f}ms exceeds 2ms"
                assert q.stats["disk_spills"] == 900  # 1000 - 100 in memory
                q.close()

        asyncio.run(_test())

    def test_proxy_latency_unaffected(self):
        """
        Simulate hot path: guardrail inspect + enqueue.
        Total must stay ≤40ms p95.
        """

        async def _test():
            from src.guardrails.input_guardrail import InputGuardrail

            with tempfile.TemporaryDirectory() as tmpdir:
                ig = InputGuardrail()
                q = TelemetryQueue(max_size=10000, disk_path=f"{tmpdir}/proxy.db")

                latencies = []
                for i in range(500):
                    start = time.perf_counter()

                    # Simulate hot path
                    result = ig.inspect(f"Normal user request number {i}", "tenant-1", "agent-1")

                    # Enqueue telemetry (non-blocking)
                    event = from_security_event(
                        verdict=result.verdict.value,
                        rule_id=result.events[0].rule_id if result.events else None,
                        rule_description=result.events[0].description if result.events else None,
                        threat_category=result.events[0].threat_category.value
                        if result.events
                        else None,
                        tenant_id="tenant-1",
                        agent_id="agent-1",
                        guardrail_layer="input",
                        latency_ms=(time.perf_counter() - start) * 1000,
                    )
                    q.enqueue_nowait(event)

                    elapsed_ms = (time.perf_counter() - start) * 1000
                    latencies.append(elapsed_ms)

                latencies.sort()
                p95 = latencies[int(len(latencies) * 0.95)]
                print(f"\n[PROXY+TELEMETRY] p95: {p95:.2f}ms (budget: 40ms)")

                assert p95 < 40.0, f"Proxy+telemetry p95 = {p95:.1f}ms exceeds 40ms"
                q.close()

        asyncio.run(_test())
