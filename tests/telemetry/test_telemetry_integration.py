"""
Integration tests — Mock SIEM receivers, format validation, end-to-end flow.
"""

import asyncio
import json
import tempfile
from typing import Any

import pytest

from src.telemetry.schema import SecurityTelemetryEvent, from_security_event
from src.telemetry.queue import TelemetryQueue
from src.telemetry.exporter import TelemetryExporter
from src.telemetry.transports.file_shipper import FileShipperConfig, FileShipperTransport


class MockTransport:
    """Mock transport that collects events for assertion."""

    name = "mock"

    def __init__(self, fail_count: int = 0):
        self.batches: list[list[SecurityTelemetryEvent]] = []
        self.call_count = 0
        self._fail_count = fail_count

    async def send_batch(self, events: list[SecurityTelemetryEvent]) -> bool:
        self.call_count += 1
        if self.call_count <= self._fail_count:
            return False
        self.batches.append(events)
        return True

    async def close(self) -> None:
        pass


class TestFileShipperIntegration:
    def test_write_and_read_ndjson(self):
        async def _test():
            with tempfile.TemporaryDirectory() as tmpdir:
                config = FileShipperConfig(path=f"{tmpdir}/events.ndjson")
                transport = FileShipperTransport(config)
                events = [
                    from_security_event(
                        verdict="block",
                        rule_id=f"R{i}",
                        rule_description=f"Rule {i}",
                        threat_category="injection",
                        tenant_id="example-corp",
                        agent_id=None,
                        guardrail_layer="input",
                        latency_ms=float(i),
                    )
                    for i in range(10)
                ]
                success = await transport.send_batch(events)
                assert success
                await transport.close()

                # Verify file content
                with open(f"{tmpdir}/events.ndjson") as f:
                    lines = f.readlines()
                assert len(lines) == 10
                for line in lines:
                    data = json.loads(line)
                    assert "@timestamp" in data
                    assert data["sentinel"]["verdict"] == "block"

        asyncio.run(_test())


class TestExporterIntegration:
    def test_exporter_flushes_to_transport(self):
        async def _test():
            import os

            os.environ["SENTINEL_TELEMETRY_ENABLED"] = "true"

            with tempfile.TemporaryDirectory() as tmpdir:
                queue = TelemetryQueue(max_size=1000, disk_path=f"{tmpdir}/q.db")
                exporter = TelemetryExporter(queue=queue)
                mock = MockTransport()
                exporter.add_transport(mock)

                # Enqueue events
                for i in range(50):
                    event = from_security_event(
                        verdict="block",
                        rule_id=f"R{i}",
                        rule_description="test",
                        threat_category="test",
                        tenant_id="t",
                        agent_id=None,
                        guardrail_layer="input",
                        latency_ms=1.0,
                    )
                    queue.enqueue_nowait(event)

                # Start exporter, wait for flush, stop
                await exporter.start()
                await asyncio.sleep(1.5)  # Wait for flush interval
                await exporter.stop()

                # Verify events were delivered
                total_events = sum(len(b) for b in mock.batches)
                assert total_events == 50
                assert exporter.stats["events_exported"] == 50

                os.environ.pop("SENTINEL_TELEMETRY_ENABLED", None)
                queue.close()

        asyncio.run(_test())

    def test_circuit_breaker_activation(self):
        async def _test():
            import os

            os.environ["SENTINEL_TELEMETRY_ENABLED"] = "true"

            with tempfile.TemporaryDirectory() as tmpdir:
                queue = TelemetryQueue(max_size=1000, disk_path=f"{tmpdir}/q.db")
                # batch_size=1 forces 1 event per flush cycle
                exporter = TelemetryExporter(queue=queue, batch_size=1, flush_interval=0.1)
                # Transport that fails first 6 times (exceeds threshold of 5)
                mock = MockTransport(fail_count=6)
                exporter.add_transport(mock)

                for i in range(10):
                    event = from_security_event(
                        verdict="block",
                        rule_id="R1",
                        rule_description="test",
                        threat_category="test",
                        tenant_id="t",
                        agent_id=None,
                        guardrail_layer="input",
                        latency_ms=1.0,
                    )
                    queue.enqueue_nowait(event)

                await exporter.start()
                await asyncio.sleep(3.0)
                await exporter.stop()

                # Circuit breaker should have opened after 5 failures
                assert exporter.stats["export_errors"] >= 5
                transport_stats = exporter.stats["transports"][0]
                assert transport_stats["circuit_stats"]["failures"] >= 5

                os.environ.pop("SENTINEL_TELEMETRY_ENABLED", None)
                queue.close()

        asyncio.run(_test())


class TestFormatValidation:
    """Validate output formats against schema expectations."""

    def _make_event(self) -> SecurityTelemetryEvent:
        return from_security_event(
            verdict="block",
            rule_id="PI-042",
            rule_description="Cross-agent injection via output",
            threat_category="cross_agent_injection",
            tenant_id="healthcare-corp",
            agent_id="medical-agent",
            guardrail_layer="input",
            latency_ms=4.7,
            source_ip="10.0.1.50",
            raw_input="inject payload for next agent",
        )

    def test_ecs_json_has_required_fields(self):
        event = self._make_event()
        ecs = event.to_ecs_json()
        # Required ECS fields
        assert "@timestamp" in ecs
        assert "event" in ecs
        assert ecs["event"]["category"] == "intrusion_detection"
        assert ecs["event"]["kind"] == "alert"
        assert "observer" in ecs
        assert ecs["observer"]["type"] == "sentinel-gateway"
        # Sentinel custom fields
        assert ecs["sentinel"]["verdict"] == "block"
        assert ecs["sentinel"]["rule_id"] == "PI-042"
        assert ecs["sentinel"]["input_hash"]  # Hash present
        assert "inject payload" not in json.dumps(ecs)  # Raw NOT present

    def test_cef_format_structure(self):
        event = self._make_event()
        cef = event.to_cef()
        parts = cef.split("|")
        assert parts[0] == "CEF:0"
        assert parts[1] == "SentinelGateway"
        assert parts[2] == "Guardrail"
        # parts[3]=version, parts[4]=signatureID, parts[5]=name, parts[6]=severity
        assert int(parts[6]) >= 0  # severity is numeric

    def test_leef_format_structure(self):
        event = self._make_event()
        leef = event.to_leef()
        assert leef.startswith("LEEF:2.0|SentinelGateway|")
        assert "action=block" in leef
        assert "tenantId=healthcare-corp" in leef
