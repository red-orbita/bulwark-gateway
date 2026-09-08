"""Elasticsearch Bulk framing and per-document acknowledgement regressions."""

import json
import os
import secrets

import httpx
import pytest

from src.telemetry.exporter import TelemetryExporter, _add_transport_from_config
from src.telemetry.schema import from_security_event
from src.telemetry.transports.http_rest import HttpRestTransport, HttpTransportConfig


@pytest.fixture
def events():
    return [from_security_event(
        verdict="block", rule_id="test-injection", rule_description="Synthetic test",
        threat_category="prompt_injection", tenant_id="test-tenant", agent_id="test-agent",
        guardrail_layer="input", latency_ms=1.0,
    ) for _ in range(2)]


def test_bulk_framing_preserves_ids_and_ecs(events):
    transport = HttpRestTransport(HttpTransportConfig(url="https://collector.example/index/_bulk", format="elastic_bulk"))
    body = transport._serialize_batch(events)
    lines = [json.loads(line) for line in body.splitlines()]
    assert body.endswith(b"\n")
    assert len(lines) == 4
    for pos, event in enumerate(events):
        assert lines[pos * 2] == {"index": {"_id": event.event.id}}
        assert lines[pos * 2 + 1] == event.to_ecs_json()
    assert transport._build_headers(body)["Content-Type"] == "application/x-ndjson"


@pytest.mark.parametrize("platform,path,fmt,expected", [
    ("elastic", "/index/_bulk", "ecs_json", "elastic_bulk"),
    ("elastic_elk", "/index/_bulk?refresh=true", "ndjson", "elastic_bulk"),
    ("elastic", "/logstash", "ecs_json", "json"),
    ("custom", "/index/_bulk", "elastic_bulk", "elastic_bulk"),
    ("custom", "/collector", "ndjson", "ndjson"),
])
def test_loader_selects_bulk_without_changing_logstash(platform, path, fmt, expected):
    exporter = TelemetryExporter()
    _add_transport_from_config(exporter, {
        "transport_type": "http_rest", "platform": platform,
        "endpoint": "https://collector.example" + path, "format": fmt,
    })
    assert exporter._transports[0].transport._config.format == expected


@pytest.mark.parametrize("status,payload,expected", [
    (200, {"errors": False, "items": [{"index": {"status": 201}}, {"index": {"status": 200}}]}, True),
    (200, {"errors": True, "items": [{"index": {"status": 201}}, {"index": {"status": 400}}]}, False),
    (200, {"errors": False, "items": [{"index": {"status": 201}}, {"index": {"status": 429}}]}, False),
    (200, {"errors": False, "items": []}, False),
    (200, {}, False),
    (200, [], False),
    (200, "not a Bulk acknowledgement", False),
    (200, {"errors": False, "items": [None, None]}, False),
    (401, {}, False),
    (302, {}, False),
    (500, {}, False),
])
async def test_bulk_requires_successful_document_acknowledgements(events, monkeypatch, status, payload, expected):
    # A public numeric address avoids DNS and retains the real SSRF check.
    transport = HttpRestTransport(HttpTransportConfig(url="https://8.8.8.8/index/_bulk", format="elastic_bulk"))
    monkeypatch.delenv("BULWARK_SIEM_SSRF_ALLOW_PRIVATE", raising=False)

    def receiver(request):
        assert request.headers["Content-Type"] == "application/x-ndjson"
        assert len(request.content.splitlines()) == 4
        return httpx.Response(status, json=payload)

    client_class = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: client_class(transport=httpx.MockTransport(receiver), **kwargs))
    assert await transport.send_batch(events) is expected


async def test_bulk_loopback_blocked_even_with_private_opt_in(events, monkeypatch):
    monkeypatch.setenv("BULWARK_SIEM_SSRF_ALLOW_PRIVATE", "true")
    transport = HttpRestTransport(HttpTransportConfig(
        url="http://127.0.0.1:9200/index/_bulk", format="elastic_bulk",
    ))

    def unexpected_client(**kwargs):
        pytest.fail("SSRF-blocked destination must never open an HTTP client")

    monkeypatch.setattr(httpx, "AsyncClient", unexpected_client)
    assert await transport.send_batch(events) is False


async def test_live_elasticsearch_index_query_and_mapping_rejection(events, monkeypatch):
    """Opt-in: only use a disposable Elasticsearch, never a production cluster."""
    endpoint = os.getenv("BULWARK_TEST_ELASTIC_URL")
    if not endpoint:
        pytest.skip("BULWARK_TEST_ELASTIC_URL not set (disposable Elasticsearch required)")
    monkeypatch.setenv("BULWARK_SIEM_SSRF_ALLOW_PRIVATE", "true")
    index = "bulwark-test-" + secrets.token_hex(8)
    rejected_index = index + "-rejected"
    transport = HttpRestTransport(HttpTransportConfig(
        url=f"{endpoint}/{index}/_bulk", format="elastic_bulk",
    ))
    async with httpx.AsyncClient(base_url=endpoint, timeout=15, follow_redirects=False) as client:
        try:
            assert await transport.send_batch(events)
            # A repeat must update the same IDs, not duplicate them.
            assert await transport.send_batch(events)
            response = await client.post(f"/{index}/_refresh")
            response.raise_for_status()
            response = await client.get(f"/{index}/_search")
            response.raise_for_status()
            hits = response.json()["hits"]["hits"]
            assert len(hits) == len(events)
            assert {hit["_id"] for hit in hits} == {event.event.id for event in events}
            originals = {event.event.id: event.to_ecs_json() for event in events}
            for hit in hits:
                assert hit["_source"] == originals[hit["_id"]]

            # Bulk can return HTTP 200 with document-level mapping failures.
            response = await client.put(f"/{rejected_index}", json={
                "mappings": {"properties": {"message": {"type": "integer"}}},
            })
            response.raise_for_status()
            rejected = HttpRestTransport(HttpTransportConfig(
                url=f"{endpoint}/{rejected_index}/_bulk", format="elastic_bulk",
            ))
            response = await client.post(
                f"/{rejected_index}/_bulk", content=rejected._serialize_batch(events),
                headers={"Content-Type": "application/x-ndjson"},
            )
            assert response.status_code == 200
            assert response.json()["errors"] is True
            assert await rejected.send_batch(events) is False
        finally:
            await client.delete(f"/{index}")
            await client.delete(f"/{rejected_index}")
