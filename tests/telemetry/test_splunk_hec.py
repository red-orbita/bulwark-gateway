"""Splunk requires HEC envelopes, not bare ECS documents or JSON arrays."""

import json
from datetime import datetime

import httpx
import pytest

from src.telemetry.exporter import TelemetryExporter, _add_transport_from_config
from src.telemetry.schema import from_security_event
from src.telemetry.transports.http_rest import HttpRestTransport, HttpTransportConfig


@pytest.fixture
def events():
    return [from_security_event(
        verdict="block", rule_id="test", rule_description="Synthetic event\nsecond line",
        threat_category="prompt_injection", tenant_id="synthetic", agent_id="test-agent",
        guardrail_layer="input", latency_ms=0,
    ) for _ in range(2)]


def test_hec_batch_preserves_full_ecs_document(events):
    transport = HttpRestTransport(HttpTransportConfig(url="https://collector.example", format="splunk_hec"))
    body = transport._serialize_batch(events)
    envelopes = [json.loads(line) for line in body.splitlines()]
    assert len(envelopes) == 2
    for envelope, event in zip(envelopes, events, strict=True):
        assert envelope["event"] == event.to_ecs_json()
        assert envelope["source"] == "bulwark-gateway"
        assert envelope["time"] == datetime.fromisoformat(event.timestamp).timestamp()
        # Index and sourcetype inherit the operator's HEC token settings.
        assert "index" not in envelope and "sourcetype" not in envelope


@pytest.mark.parametrize("platform", ["splunk", "splunk_es"])
@pytest.mark.parametrize("auth_type", ["api_key", "bearer", "oauth2"])
def test_loader_selects_hec_framing_and_auth(platform, auth_type):
    exporter = TelemetryExporter()
    _add_transport_from_config(exporter, {
        "platform": platform, "transport_type": "http_rest", "endpoint": "https://collector.example/services/collector/event",
        "format": "ecs_json", "auth_type": auth_type, "auth_value": "synthetic-hec-token",
    })
    transport = exporter._transports[0].transport
    assert transport._config.format == "splunk_hec"
    assert transport._build_headers(b"")["Authorization"] == "Splunk synthetic-hec-token"


@pytest.mark.parametrize("status,payload,expected", [
    (200, {"code": 0}, True),
    (200, {"code": 5}, False),
    (200, {"code": False}, False),
    (200, {"code": "0"}, False),
    (200, {}, False),
    (200, [], False),
    (200, "invalid acknowledgement", False),
    (403, {"code": 4}, False),
    (503, {"code": 9}, False),
    (302, {"code": 0}, False),
])
async def test_hec_requires_success_code(events, monkeypatch, status, payload, expected):
    transport = HttpRestTransport(HttpTransportConfig(url="https://8.8.8.8/services/collector/event", format="splunk_hec"))
    def receiver(request):
        assert len(request.content.splitlines()) == 2
        return httpx.Response(status, json=payload)
    client_class = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: client_class(transport=httpx.MockTransport(receiver), **kwargs))
    assert await transport.send_batch(events) is expected


async def test_empty_hec_batch_does_not_connect(monkeypatch):
    def unexpected_client(**kwargs):
        pytest.fail("Empty batch must not connect")
    monkeypatch.setattr(httpx, "AsyncClient", unexpected_client)
    assert await HttpRestTransport(HttpTransportConfig(url="https://collector.example", format="splunk_hec")).send_batch([])
