"""Tests for the OpenCTI lookup connector.

Cover the pure helpers (score→verdict banding, score coercion, label extraction)
and the async GraphQL flow against a mocked OpenCTI ``/graphql`` endpoint
(``pytest_httpx``). OpenCTI reports failures as an HTTP 200 body carrying an
``errors`` array, so that path is exercised explicitly alongside transport errors.
"""

from __future__ import annotations

import pytest

from admin.services.integrations.base import ConnectorError
from admin.services.integrations.opencti import (
    OpenCTIConnector,
    _coerce_score,
    _node_labels,
    score_verdict,
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
