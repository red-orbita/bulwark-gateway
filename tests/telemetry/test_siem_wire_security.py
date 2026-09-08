"""Protocol regression tests, not QRadar/ArcSight/Datadog product validation."""

import re

import httpx
import pytest

from src.telemetry.exporter import TelemetryExporter, _add_transport_from_config
from src.telemetry.schema import from_security_event
from src.telemetry.transports.http_rest import HttpAuthMethod, HttpRestTransport, HttpTransportConfig


def event():
    return from_security_event(
        verdict="block", rule_id="pattern", rule_description="Description", threat_category="prompt_injection",
        tenant_id="test", agent_id="agent", guardrail_layer="input", latency_ms=1, request_id="request-test",
    )


def test_cef_delimiters_cannot_inject_fields_or_records():
    sample = event()
    sample.bulwark.rule_description = "fake|header\\suffix\nnewline"
    sample.tenant.id = "tenant act=allow\r\nCEF:0|fake"
    wire = sample.to_cef()
    assert len(re.split(r"(?<!\\)\|", wire, maxsplit=7)) == 8
    assert "tenant act\\=allow\\r\\nCEF:0|fake" in wire
    assert "fake\\|header\\\\suffix\\nnewline" in wire
    assert "\n" not in wire and "\r" not in wire
    assert f"externalId={sample.event.id}" in wire


def test_leef_declares_separator_and_rejects_attribute_injection():
    sample = event()
    sample.tenant.id = "test\taction=allow\nforged"
    header = sample.to_leef().split("|", 6)
    assert header[5] == "0x09"
    fields = dict(item.split("=", 1) for item in header[6].split("\t"))
    assert fields["action"] == "block"
    assert fields["tenantId"] == "test\\taction=allow\\nforged"
    assert fields["requestId"] == "request-test"
    assert fields["eventId"] == sample.event.id


@pytest.mark.parametrize("status,expected", [(202, True), (400, False), (401, False), (403, False), (413, False), (429, False), (503, False), (307, False)])
async def test_datadog_contract_and_failure_status(monkeypatch, status, expected):
    exporter = TelemetryExporter()
    _add_transport_from_config(exporter, {
        "platform": "datadog", "transport_type": "http_rest", "endpoint": "https://8.8.8.8/api/v2/logs",
        "auth_type": "api_key", "auth_value": "synthetic-key", "format": "ecs_json",
    })
    sample = event()
    def receiver(request):
        import json
        assert request.headers["DD-API-KEY"] == "synthetic-key"
        assert json.loads(request.content) == [sample.to_ecs_json()]
        return httpx.Response(status)
    client_class = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: client_class(transport=httpx.MockTransport(receiver), **kwargs))
    assert await exporter._transports[0].transport.send_batch([sample]) is expected


async def test_mtls_without_certificate_never_falls_back_to_server_only_tls(monkeypatch):
    def unexpected_client(**kwargs):
        pytest.fail("Missing mTLS credentials must never send")
    monkeypatch.setattr(httpx, "AsyncClient", unexpected_client)
    transport = HttpRestTransport(HttpTransportConfig(url="https://8.8.8.8", auth_method=HttpAuthMethod.MTLS))
    assert await transport.send_batch([event()]) is False


@pytest.mark.parametrize("address", ["::ffff:127.0.0.1", "::ffff:169.254.169.254", "::"])
def test_ssrf_ipv6_aliases_do_not_bypass_always_blocked_ranges(monkeypatch, address):
    from src.telemetry.transports import is_ssrf_target_host
    monkeypatch.setenv("BULWARK_SIEM_SSRF_ALLOW_PRIVATE", "true")
    assert is_ssrf_target_host(address, 443)


def test_ssrf_empty_dns_result_fails_closed(monkeypatch):
    import socket

    from src.telemetry.transports import is_ssrf_target_host
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [])
    assert is_ssrf_target_host("collector.example", 443)
