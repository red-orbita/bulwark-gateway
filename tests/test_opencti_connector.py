"""Tests for the OpenCTI lookup connector.

Cover the pure helpers (score→verdict banding, score coercion, label extraction)
and the async GraphQL flow against a mocked OpenCTI ``/graphql`` endpoint
(``pytest_httpx``). OpenCTI reports failures as an HTTP 200 body carrying an
``errors`` array, so that path is exercised explicitly alongside transport errors.
"""

from __future__ import annotations

import pytest

from admin.services.integrations.base import ConnectorError, TlpGateError
from admin.services.integrations.opencti import (
    OpenCTIConnector,
    _coerce_score,
    _indicator_pattern,
    _main_observable_type,
    _match_indicator_id,
    _node_labels,
    _observable_payload,
    _report_input,
    score_verdict,
    select_report_marking,
)

_URL = "http://opencti.test/graphql"


def _connector() -> OpenCTIConnector:
    return OpenCTIConnector(base_url="http://opencti.test", api_key="tok")


def _indicator(pattern: str, *, score: int = 0, revoked: bool = False, labels=None) -> dict:
    node: dict = {
        "pattern": pattern,
        "pattern_type": "stix",
        "revoked": revoked,
        "x_opencti_score": score,
    }
    if labels is not None:
        node["objectLabel"] = [{"value": lbl} for lbl in labels]
    return {"node": node}


def _edges(*nodes: dict) -> dict:
    return {"data": {"indicators": {"edges": list(nodes)}}}


# ─── Pure helpers ────────────────────────────────────────────────────────────

def test_score_verdict_bands():
    assert score_verdict(90, found=True) == "malicious"
    assert score_verdict(70, found=True) == "malicious"
    assert score_verdict(55, found=True) == "suspicious"
    assert score_verdict(40, found=True) == "suspicious"
    assert score_verdict(10, found=True) == "clean"
    assert score_verdict(0, found=True) == "clean"


def test_score_verdict_not_found_regardless_of_score():
    # ``found`` reflects an *active* match; when false the value is unknown.
    assert score_verdict(0, found=False) == "not_found"
    assert score_verdict(99, found=False) == "not_found"


def test_coerce_score_clamps_and_tolerates_garbage():
    assert _coerce_score(50) == 50
    assert _coerce_score("80") == 80
    assert _coerce_score(150) == 100
    assert _coerce_score(-5) == 0
    assert _coerce_score(None) == 0
    assert _coerce_score("nope") == 0


def test_node_labels_extracts_up_to_three():
    node = {"objectLabel": [{"value": "apt"}, {"value": "c2"}, {"value": "x"}, {"value": "y"}]}
    assert _node_labels(node) == ["apt", "c2", "x"]


def test_node_labels_tolerates_garbage():
    assert _node_labels({}) == []
    assert _node_labels({"objectLabel": None}) == []
    assert _node_labels({"objectLabel": [123, {"value": ""}, {"value": "ok"}]}) == ["ok"]


# ─── test_connection ─────────────────────────────────────────────────────────

async def test_test_connection_ok(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=_URL, json={"data": {"about": {"version": "6.2.0"}}}
    )
    health = await _connector().test_connection()
    assert health.ok is True
    assert "6.2.0" in health.detail


async def test_test_connection_graphql_error(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=_URL, json={"errors": [{"message": "unauthorized"}]}
    )
    health = await _connector().test_connection()
    assert health.ok is False
    assert "unauthorized" in health.detail


async def test_test_connection_http_error(httpx_mock):
    httpx_mock.add_response(method="POST", url=_URL, status_code=401, json={})
    health = await _connector().test_connection()
    assert health.ok is False


# ─── lookup_observable ───────────────────────────────────────────────────────

async def test_lookup_malicious(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=_URL,
        json=_edges(
            _indicator("[ipv4-addr:value = '1.2.3.4']", score=85, labels=["apt", "c2"]),
            _indicator("[ipv4-addr:value = '1.2.3.4']", score=30),
        ),
    )
    result = await _connector().lookup_observable(observable_type="ip", value="1.2.3.4")
    assert result["connector"] == "opencti"
    assert result["verdict"] == "malicious"
    assert result["is_malicious"] is True
    assert result["found"] is True
    assert result["score"] == 85
    assert result["indicator_count"] == 2
    assert result["labels"] == ["apt", "c2"]


async def test_lookup_suspicious(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=_URL,
        json=_edges(_indicator("[url:value = 'http://x.example/a']", score=50)),
    )
    result = await _connector().lookup_observable(
        observable_type="url", value="http://x.example/a"
    )
    assert result["verdict"] == "suspicious"
    assert result["is_malicious"] is False
    assert result["found"] is True


async def test_lookup_not_found(httpx_mock):
    httpx_mock.add_response(method="POST", url=_URL, json=_edges())
    result = await _connector().lookup_observable(observable_type="ip", value="8.8.8.8")
    assert result["verdict"] == "not_found"
    assert result["is_malicious"] is False
    assert result["found"] is False
    assert result["indicator_count"] == 0


async def test_lookup_fuzzy_match_dropped(httpx_mock):
    # OpenCTI ``search`` is fuzzy — an indicator that does not literally contain the
    # value is not a real match and must be discarded.
    httpx_mock.add_response(
        method="POST", url=_URL,
        json=_edges(_indicator("[ipv4-addr:value = '9.9.9.9']", score=90)),
    )
    result = await _connector().lookup_observable(observable_type="ip", value="1.2.3.4")
    assert result["found"] is False
    assert result["verdict"] == "not_found"


async def test_lookup_revoked_only_is_clean(httpx_mock):
    # A value known only via revoked indicators was an IOC but no longer is.
    httpx_mock.add_response(
        method="POST", url=_URL,
        json=_edges(_indicator("[ipv4-addr:value = '1.2.3.4']", score=95, revoked=True)),
    )
    result = await _connector().lookup_observable(observable_type="ip", value="1.2.3.4")
    assert result["found"] is True
    assert result["score"] == 0
    assert result["verdict"] == "clean"
    assert result["is_malicious"] is False


async def test_lookup_non_stix_pattern_skipped(httpx_mock):
    node = {"node": {
        "pattern": "rule x { condition: true }",
        "pattern_type": "yara",
        "x_opencti_score": 90,
    }}
    httpx_mock.add_response(
        method="POST", url=_URL, json={"data": {"indicators": {"edges": [node]}}}
    )
    result = await _connector().lookup_observable(observable_type="ip", value="1.2.3.4")
    assert result["found"] is False


async def test_lookup_empty_value_short_circuits(httpx_mock):
    # No HTTP call is registered — an empty value must not hit the network.
    result = await _connector().lookup_observable(observable_type="ip", value="   ")
    assert result["verdict"] == "not_found"
    assert result["found"] is False


async def test_lookup_graphql_error_raises(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=_URL, json={"errors": [{"message": "boom"}]}
    )
    with pytest.raises(ConnectorError):
        await _connector().lookup_observable(observable_type="ip", value="1.2.3.4")


async def test_lookup_transport_error_surfaces(httpx_mock):
    import httpx

    for _ in range(3):  # exhaust the retry budget
        httpx_mock.add_exception(httpx.ConnectError("down"))
    with pytest.raises(ConnectorError):
        await _connector().lookup_observable(observable_type="ip", value="1.2.3.4")


# ─── Push pure helpers ───────────────────────────────────────────────────────

def _obs(otype: str, value: str, *, tlp: str = "amber", is_ioc: bool = False, **extra) -> dict:
    node = {"type": otype, "value": value, "tlp": tlp, "is_ioc": is_ioc}
    node.update(extra)
    return node


def test_select_report_marking_picks_most_restrictive():
    assert select_report_marking([_obs("ip", "1.2.3.4", tlp="green"),
                                  _obs("domain", "x.test", tlp="amber")]) == "amber"
    assert select_report_marking([_obs("ip", "1.2.3.4", tlp="white"),
                                  _obs("domain", "x.test", tlp="green")]) == "green"
    assert select_report_marking([_obs("ip", "1.2.3.4", tlp="white")]) == "white"


def test_select_report_marking_excludes_red_and_defaults_amber():
    # red is skipped; with nothing else it defaults to amber.
    assert select_report_marking([_obs("ip", "1.2.3.4", tlp="red")]) == "amber"
    # unmarked observables default to amber.
    assert select_report_marking([{"type": "ip", "value": "1.2.3.4"}]) == "amber"


def test_observable_payload_maps_known_types():
    assert _observable_payload(_obs("ip", "1.2.3.4")) == (
        "IPv4-Addr", "IPv4Addr", {"value": "1.2.3.4"})
    assert _observable_payload(_obs("ip", "2001:db8::1")) == (
        "IPv6-Addr", "IPv6Addr", {"value": "2001:db8::1"})
    assert _observable_payload(_obs("domain", "evil.test")) == (
        "Domain-Name", "DomainName", {"value": "evil.test"})
    octype, var_key, payload = _observable_payload(_obs("hash", "d41d8cd98f00b204e9800998ecf8427e"))
    assert octype == "StixFile"
    assert payload == {"hashes": [{"algorithm": "MD5", "hash": "d41d8cd98f00b204e9800998ecf8427e"}]}


def test_observable_payload_unmappable_returns_none():
    assert _observable_payload(_obs("other", "whatever")) is None
    assert _observable_payload(_obs("ip", "   ")) is None
    assert _observable_payload(_obs("hash", "deadbeef")) is None  # no known algorithm length


def test_indicator_pattern_builds_and_escapes():
    assert _indicator_pattern(_obs("ip", "1.2.3.4")) == "[ipv4-addr:value = '1.2.3.4']"
    assert _indicator_pattern(_obs("domain", "evil.test")) == "[domain-name:value = 'evil.test']"
    # single quotes in the value are STIX-escaped.
    assert _indicator_pattern(_obs("url", "http://x/'a")) == "[url:value = 'http://x/\\'a']"
    assert _indicator_pattern(_obs("other", "x")) is None


def test_main_observable_type():
    assert _main_observable_type(_obs("ip", "1.2.3.4")) == "IPv4-Addr"
    assert _main_observable_type(_obs("ip", "2001:db8::1")) == "IPv6-Addr"
    assert _main_observable_type(_obs("domain", "x.test")) == "Domain-Name"
    assert _main_observable_type(_obs("other", "x")) == "Unknown"


def test_report_input_shape():
    case = {"case_id": "C-1", "title": "Intrusion", "summary": "bad",
            "updated_at": "2026-01-01T00:00:00Z"}
    got = _report_input(case, ["obs1", "ind1"], "marking-x")
    assert got["name"] == "Intrusion"
    assert got["published"] == "2026-01-01T00:00:00Z"
    assert got["objectMarking"] == ["marking-x"]
    assert got["objects"] == ["obs1", "ind1"]
    assert got["report_types"] == ["threat-report"]


# ─── push_case flow ──────────────────────────────────────────────────────────

def _gql(key: str, node: dict) -> dict:
    return {"data": {key: node}}


_CASE = {"case_id": "C-1", "title": "Intrusion", "summary": "bad guy",
         "updated_at": "2026-01-01T00:00:00Z"}


async def test_push_creates_report(httpx_mock):
    # ip (IOC) → obs + indicator + sighting; domain (non-IOC) → obs only; then report.
    httpx_mock.add_response(method="POST", url=_URL,
                            json=_gql("stixCyberObservableAdd", {"id": "obs1"}))
    httpx_mock.add_response(method="POST", url=_URL,
                            json=_gql("indicatorAdd", {"id": "ind1"}))
    httpx_mock.add_response(method="POST", url=_URL,
                            json=_gql("identityAdd", {"id": "id-bulwark"}))
    httpx_mock.add_response(method="POST", url=_URL,
                            json=_gql("stixSightingRelationshipAdd", {"id": "sig1"}))
    httpx_mock.add_response(method="POST", url=_URL,
                            json=_gql("stixCyberObservableAdd", {"id": "obs2"}))
    httpx_mock.add_response(method="POST", url=_URL,
                            json=_gql("reportAdd", {"id": "rep1"}))

    result = await _connector().push_case(
        _CASE,
        [_obs("ip", "1.2.3.4", is_ioc=True), _obs("domain", "evil.test")],
        [],
    )
    assert result.created is True
    assert result.remote_id == "rep1"
    assert "rep1" in result.remote_url
    assert "3 objects" in result.detail
    assert "1 indicators" in result.detail
    assert "1 sightings" in result.detail
    assert "0 TLP:RED excluded" in result.detail


async def test_push_excludes_tlp_red(httpx_mock):
    # red observable is dropped; only the amber domain is shared.
    httpx_mock.add_response(method="POST", url=_URL,
                            json=_gql("stixCyberObservableAdd", {"id": "obs1"}))
    httpx_mock.add_response(method="POST", url=_URL,
                            json=_gql("reportAdd", {"id": "rep1"}))

    result = await _connector().push_case(
        _CASE,
        [_obs("ip", "9.9.9.9", tlp="red", is_ioc=True), _obs("domain", "evil.test")],
        [],
    )
    assert result.created is True
    assert "1 TLP:RED excluded" in result.detail


async def test_push_all_red_raises_gate(httpx_mock):
    # everything is red → nothing shareable → refused with no remote call.
    with pytest.raises(TlpGateError):
        await _connector().push_case(
            _CASE, [_obs("ip", "9.9.9.9", tlp="red")], [],
        )


async def test_push_no_mappable_raises_gate(httpx_mock):
    # non-red but unmappable observable → still nothing to push.
    with pytest.raises(TlpGateError):
        await _connector().push_case(
            _CASE, [_obs("other", "freeform note")], [],
        )


async def test_push_sighting_failure_best_effort(httpx_mock):
    # sighting create fails (GraphQL errors body) but the push still completes.
    httpx_mock.add_response(method="POST", url=_URL,
                            json=_gql("stixCyberObservableAdd", {"id": "obs1"}))
    httpx_mock.add_response(method="POST", url=_URL,
                            json=_gql("indicatorAdd", {"id": "ind1"}))
    httpx_mock.add_response(method="POST", url=_URL,
                            json={"errors": [{"message": "sighting boom"}]})
    httpx_mock.add_response(method="POST", url=_URL,
                            json=_gql("reportAdd", {"id": "rep1"}))

    result = await _connector().push_case(
        _CASE, [_obs("ip", "1.2.3.4", is_ioc=True)], [],
    )
    assert result.created is True
    assert "1 indicators" in result.detail
    assert "0 sightings" in result.detail


async def test_push_update_patches_report(httpx_mock):
    # re-push: obs upsert, then report fieldPatch + relationAdd for the new ref.
    httpx_mock.add_response(method="POST", url=_URL,
                            json=_gql("stixCyberObservableAdd", {"id": "obs1"}))
    httpx_mock.add_response(method="POST", url=_URL,
                            json=_gql("reportEdit", {"fieldPatch": {"id": "rep-existing"}}))
    httpx_mock.add_response(method="POST", url=_URL,
                            json=_gql("reportEdit", {"relationAdd": {"id": "rel1"}}))

    result = await _connector().push_case(
        _CASE, [_obs("domain", "evil.test")], [], remote_id="rep-existing",
    )
    assert result.created is False
    assert result.remote_id == "rep-existing"
    assert "report updated" in result.detail


async def test_push_report_no_id_raises(httpx_mock):
    # a report create that returns no id is a hard failure.
    httpx_mock.add_response(method="POST", url=_URL,
                            json=_gql("stixCyberObservableAdd", {"id": "obs1"}))
    httpx_mock.add_response(method="POST", url=_URL, json=_gql("reportAdd", {}))

    with pytest.raises(ConnectorError):
        await _connector().push_case(
            _CASE, [_obs("domain", "evil.test")], [],
        )


# ─── _match_indicator_id (pure) ──────────────────────────────────────────────

def _sedge(pattern: str, *, iid: str = "ind-1", revoked: bool = False,
           ptype: str = "stix") -> dict:
    return {"node": {"id": iid, "pattern": pattern, "pattern_type": ptype,
                     "revoked": revoked}}


def test_match_indicator_id_returns_active_stix_match():
    edges = [_sedge("[ipv4-addr:value = '1.2.3.4']", iid="ind-42")]
    assert _match_indicator_id(edges, "1.2.3.4") == "ind-42"


def test_match_indicator_id_skips_revoked_and_non_stix_and_fuzzy():
    # revoked → skip; yara → skip; literal-miss (fuzzy) → skip.
    edges = [
        _sedge("[ipv4-addr:value = '1.2.3.4']", iid="r", revoked=True),
        _sedge("rule x {}", iid="y", ptype="yara"),
        _sedge("[ipv4-addr:value = '9.9.9.9']", iid="f"),
    ]
    assert _match_indicator_id(edges, "1.2.3.4") == ""


def test_match_indicator_id_tolerates_garbage_edges():
    assert _match_indicator_id(None, "1.2.3.4") == ""
    assert _match_indicator_id([{}, {"node": None}, "x"], "1.2.3.4") == ""


# ─── report_sighting flow ────────────────────────────────────────────────────

async def test_report_sighting_creates_sighting(httpx_mock):
    # lookup resolves an active indicator id, then the sighting mutation succeeds.
    httpx_mock.add_response(
        method="POST", url=_URL,
        json={"data": {"indicators": {"edges": [
            _sedge("[ipv4-addr:value = '1.2.3.4']", iid="ind-7")]}}},
    )
    httpx_mock.add_response(
        method="POST", url=_URL,
        json=_gql("identityAdd", {"id": "id-bulwark"}),
    )
    httpx_mock.add_response(
        method="POST", url=_URL,
        json=_gql("stixSightingRelationshipAdd", {"id": "sig-9"}),
    )
    result = await _connector().report_sighting(observable_type="ip", value="1.2.3.4")
    assert result["reported"] is True
    assert result["indicator_id"] == "ind-7"
    assert result["sighting_id"] == "sig-9"


async def test_report_sighting_noop_when_no_active_indicator(httpx_mock):
    # only a revoked indicator matches → nothing to sight, no mutation call made.
    httpx_mock.add_response(
        method="POST", url=_URL,
        json={"data": {"indicators": {"edges": [
            _sedge("[ipv4-addr:value = '1.2.3.4']", revoked=True)]}}},
    )
    result = await _connector().report_sighting(observable_type="ip", value="1.2.3.4")
    assert result["reported"] is False
    assert result["indicator_id"] == ""
    assert len(httpx_mock.get_requests()) == 1  # lookup only, no mutation


async def test_report_sighting_empty_value_short_circuits(httpx_mock):
    result = await _connector().report_sighting(observable_type="ip", value="   ")
    assert result["reported"] is False
    assert len(httpx_mock.get_requests()) == 0


async def test_report_sighting_transport_error_raises(httpx_mock):
    import httpx

    for _ in range(3):  # exhaust the retry budget on the lookup
        httpx_mock.add_exception(httpx.ConnectError("down"))
    with pytest.raises(ConnectorError):
        await _connector().report_sighting(observable_type="ip", value="1.2.3.4")
