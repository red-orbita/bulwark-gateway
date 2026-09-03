"""Tests for the MISP connector (lookup + case push).

Cover the pure helpers (attribute type mapping, TLP selection, verdict banding)
and the async REST flows against a mocked MISP server (``pytest_httpx``): version
probe, attribute ``restSearch`` lookup verdicts, event add/edit push with
idempotency, the TLP:RED data-sharing gate, and MISP's 200-body error envelope.
"""

from __future__ import annotations

import pytest

from admin.services.integrations.base import ConnectorError, TlpGateError
from admin.services.integrations.misp import (
    MispConnector,
    attribute_mapping,
    misp_verdict,
    select_event_tlp,
)

_BASE = "http://misp.test"


def _connector() -> MispConnector:
    return MispConnector(base_url=_BASE, api_key="tok")


def _obs(otype: str, value: str, *, is_ioc: bool = False, tlp: str = "amber") -> dict:
    return {"type": otype, "value": value, "is_ioc": is_ioc, "tlp": tlp}


def _attr(value: str, *, to_ids: bool = False, event_id: str = "1", tags=None) -> dict:
    attr: dict = {"type": "ip-dst", "value": value, "to_ids": to_ids, "event_id": event_id}
    if tags is not None:
        attr["Tag"] = [{"name": t} for t in tags]
    return attr


def _search(*attrs: dict) -> dict:
    return {"response": {"Attribute": list(attrs)}}


# ─── Pure helpers ────────────────────────────────────────────────────────────


def test_attribute_mapping_network_types():
    assert attribute_mapping(_obs("ip", "1.2.3.4")) == ("ip-dst", "Network activity")
    assert attribute_mapping(_obs("domain", "evil.test")) == ("domain", "Network activity")
    assert attribute_mapping(_obs("url", "http://evil.test/x")) == ("url", "Network activity")


def test_attribute_mapping_payload_types():
    assert attribute_mapping(_obs("email", "a@b.test")) == ("email-src", "Payload delivery")
    assert attribute_mapping(_obs("filename", "x.exe")) == ("filename", "Payload delivery")


def test_attribute_mapping_hash_by_length():
    assert attribute_mapping(_obs("hash", "a" * 32)) == ("md5", "Payload delivery")
    assert attribute_mapping(_obs("hash", "b" * 40)) == ("sha1", "Payload delivery")
    assert attribute_mapping(_obs("hash", "c" * 64)) == ("sha256", "Payload delivery")


def test_attribute_mapping_rejects_unmappable():
    assert attribute_mapping(_obs("hash", "d" * 50)) is None  # unknown hash length
    assert attribute_mapping(_obs("other", "x")) is None
    assert attribute_mapping(_obs("ip", "   ")) is None  # empty value


def test_select_event_tlp_picks_most_restrictive_non_red():
    obs = [_obs("ip", "1.1.1.1", tlp="white"), _obs("ip", "2.2.2.2", tlp="amber")]
    assert select_event_tlp(obs) == "amber"
    assert select_event_tlp([_obs("ip", "1.1.1.1", tlp="green")]) == "green"
    # red is excluded from the calculation; empty ⇒ conservative amber default.
    assert select_event_tlp([_obs("ip", "1.1.1.1", tlp="red")]) == "amber"
    assert select_event_tlp([]) == "amber"


def test_misp_verdict_bands():
    assert misp_verdict(found=False, actionable=False) == "not_found"
    assert misp_verdict(found=True, actionable=True) == "malicious"
    assert misp_verdict(found=True, actionable=False) == "suspicious"


# ─── test_connection ─────────────────────────────────────────────────────────


async def test_test_connection_ok(httpx_mock):
    httpx_mock.add_response(
        method="GET", url=f"{_BASE}/servers/getVersion", json={"version": "2.4.190"}
    )
    health = await _connector().test_connection()
    assert health.ok is True
    assert "2.4.190" in health.detail


async def test_test_connection_http_error(httpx_mock):
    httpx_mock.add_response(
        method="GET", url=f"{_BASE}/servers/getVersion", status_code=403, json={}
    )
    health = await _connector().test_connection()
    assert health.ok is False


# ─── lookup_observable ───────────────────────────────────────────────────────


async def test_lookup_malicious_when_to_ids(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=f"{_BASE}/attributes/restSearch",
        json=_search(
            _attr("1.2.3.4", to_ids=True, event_id="10", tags=["tlp:amber", "apt"]),
            _attr("1.2.3.4", to_ids=False, event_id="11"),
        ),
    )
    result = await _connector().lookup_observable(observable_type="ip", value="1.2.3.4")
    assert result["verdict"] == "malicious"
    assert result["is_malicious"] is True
    assert result["found"] is True
    assert result["attribute_count"] == 2
    assert result["event_count"] == 2
    assert result["to_ids_count"] == 1
    assert "apt" in result["tags"]


async def test_lookup_suspicious_when_context_only(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=f"{_BASE}/attributes/restSearch",
        json=_search(_attr("1.2.3.4", to_ids=False)),
    )
    result = await _connector().lookup_observable(observable_type="ip", value="1.2.3.4")
    assert result["verdict"] == "suspicious"
    assert result["is_malicious"] is False
    assert result["found"] is True


async def test_lookup_not_found_on_empty_response(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=f"{_BASE}/attributes/restSearch",
        json={"response": {"Attribute": []}},
    )
    result = await _connector().lookup_observable(observable_type="ip", value="9.9.9.9")
    assert result["verdict"] == "not_found"
    assert result["found"] is False
    assert result["attribute_count"] == 0


async def test_lookup_empty_value_short_circuits(httpx_mock):
    # No HTTP call should be made for a blank value.
    result = await _connector().lookup_observable(observable_type="ip", value="   ")
    assert result["verdict"] == "not_found"
    assert result["found"] is False
    assert len(httpx_mock.get_requests()) == 0


async def test_lookup_error_envelope_raises(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=f"{_BASE}/attributes/restSearch",
        json={"errors": "Invalid value"},
    )
    with pytest.raises(ConnectorError):
        await _connector().lookup_observable(observable_type="ip", value="1.2.3.4")


# ─── push_case ───────────────────────────────────────────────────────────────


def _case() -> dict:
    return {
        "case_id": "case-1",
        "title": "Suspicious beaconing",
        "severity": "high",
        "created_at": "2026-01-02T03:04:05Z",
        "tags": ["T1041", "beacon"],
    }


async def test_push_create_event(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=f"{_BASE}/events/add",
        json={"Event": {"id": "42", "uuid": "abc-uuid"}},
    )
    observables = [
        _obs("ip", "1.2.3.4", is_ioc=True, tlp="amber"),
        _obs("domain", "evil.test", is_ioc=False, tlp="green"),
    ]
    result = await _connector().push_case(_case(), observables, [])
    assert result.created is True
    assert result.remote_id == "abc-uuid"
    assert result.remote_url == f"{_BASE}/events/view/abc-uuid"

    request = httpx_mock.get_requests()[0]
    import json as _json

    sent = _json.loads(request.content)["Event"]
    assert sent["threat_level_id"] == "1"  # high
    assert len(sent["Attribute"]) == 2
    ioc_attr = next(a for a in sent["Attribute"] if a["value"] == "1.2.3.4")
    assert ioc_attr["to_ids"] is True
    assert ioc_attr["type"] == "ip-dst"
    tag_names = {t["name"] for t in sent["Tag"]}
    assert 'misp-galaxy:mitre-attack-pattern="T1041"' in tag_names
    assert "bulwark:beacon" in tag_names
    # Event TLP is the most-restrictive shareable marking (amber > green).
    assert "tlp:amber" in tag_names


async def test_push_update_event_is_idempotent(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=f"{_BASE}/events/edit/abc-uuid",
        json={"Event": {"id": "42", "uuid": "abc-uuid"}},
    )
    observables = [_obs("ip", "1.2.3.4", is_ioc=True)]
    result = await _connector().push_case(
        _case(), observables, [], remote_id="abc-uuid"
    )
    assert result.created is False
    assert result.remote_id == "abc-uuid"


async def test_push_excludes_tlp_red(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=f"{_BASE}/events/add",
        json={"Event": {"uuid": "abc-uuid"}},
    )
    observables = [
        _obs("ip", "1.2.3.4", is_ioc=True, tlp="amber"),
        _obs("ip", "5.6.7.8", is_ioc=True, tlp="red"),  # excluded
    ]
    result = await _connector().push_case(_case(), observables, [])
    assert result.created is True

    import json as _json

    sent = _json.loads(httpx_mock.get_requests()[0].content)["Event"]
    values = {a["value"] for a in sent["Attribute"]}
    assert values == {"1.2.3.4"}
    assert "1 TLP:RED excluded" in result.detail


async def test_push_all_red_refused_by_tlp_gate(httpx_mock):
    observables = [_obs("ip", "1.2.3.4", is_ioc=True, tlp="red")]
    with pytest.raises(TlpGateError):
        await _connector().push_case(_case(), observables, [])
    # The remote is never contacted for restricted data.
    assert len(httpx_mock.get_requests()) == 0


async def test_push_no_mappable_refused_by_tlp_gate(httpx_mock):
    observables = [_obs("other", "not-mappable", tlp="green")]
    with pytest.raises(TlpGateError):
        await _connector().push_case(_case(), observables, [])
    assert len(httpx_mock.get_requests()) == 0


async def test_push_create_missing_uuid_raises(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=f"{_BASE}/events/add", json={"Event": {}}
    )
    observables = [_obs("ip", "1.2.3.4", is_ioc=True)]
    with pytest.raises(ConnectorError):
        await _connector().push_case(_case(), observables, [])


# ─── report_sighting ─────────────────────────────────────────────────────────


async def test_report_sighting_success(httpx_mock):
    # MISP's success envelope carries a `name` — the tolerant parser must NOT
    # treat that as an error (unlike the attribute/event parser).
    httpx_mock.add_response(
        method="POST", url=f"{_BASE}/sightings/add",
        json={"name": "1 sighting successfully added.", "message": "1 sighting added."},
    )
    result = await _connector().report_sighting(value="1.2.3.4", observable_type="ip")
    assert result["reported"] is True
    assert result["connector"] == "misp"
    assert "sighting" in result["detail"].lower()

    import json as _json

    sent = _json.loads(httpx_mock.get_requests()[0].content)
    assert sent == {"value": "1.2.3.4"}


async def test_report_sighting_empty_value_short_circuits(httpx_mock):
    result = await _connector().report_sighting(value="   ")
    assert result["reported"] is False
    assert len(httpx_mock.get_requests()) == 0


async def test_report_sighting_error_envelope_raises(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=f"{_BASE}/sightings/add",
        json={"errors": "No matching attribute"},
    )
    with pytest.raises(ConnectorError):
        await _connector().report_sighting(value="9.9.9.9")


async def test_report_sighting_4xx_raises(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=f"{_BASE}/sightings/add", status_code=404, json={}
    )
    with pytest.raises(ConnectorError):
        await _connector().report_sighting(value="9.9.9.9")
