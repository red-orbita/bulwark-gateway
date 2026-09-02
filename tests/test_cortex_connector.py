"""Tests for the Cortex enrichment connector.

Cover the pure helpers (dataType mapping, taxonomy extraction, worst-level
folding) and the async submit→poll→report flow against a mocked Cortex REST API
(``pytest_httpx``). Polling is driven to instant by a zero interval so the
bounded loop is exercised without real sleeps.
"""

from __future__ import annotations

import pytest

from admin.services.integrations.base import ConnectorError
from admin.services.integrations.cortex import (
    CortexConnector,
    _extract_taxonomies,
    _worst_level,
    cortex_datatype,
)


def _connector() -> CortexConnector:
    return CortexConnector(
        base_url="http://cortex.test", api_key="tok",
        poll_interval=0.0, max_polls=5,
    )


def _tax(level: str, ns: str = "VT", pred: str = "GetReport", value: str = "5/70") -> dict:
    return {"level": level, "namespace": ns, "predicate": pred, "value": value}


# ─── Pure helpers ────────────────────────────────────────────────────────────

def test_cortex_datatype_mapping():
    assert cortex_datatype("ip") == "ip"
    assert cortex_datatype("email") == "mail"
    assert cortex_datatype("user") == "other"
    assert cortex_datatype("nonsense") == "other"


def test_extract_taxonomies_from_report_envelope():
    payload = {"report": {"summary": {"taxonomies": [_tax("malicious"), _tax("safe")]}}}
    tax = _extract_taxonomies(payload)
    assert len(tax) == 2
    assert tax[0]["level"] == "malicious"
    assert tax[0]["namespace"] == "VT"


def test_extract_taxonomies_tolerates_garbage():
    assert _extract_taxonomies({}) == []
    assert _extract_taxonomies({"report": None}) == []
    assert _extract_taxonomies({"report": {"summary": {"taxonomies": ["nope", 5]}}}) == []


def test_extract_taxonomies_normalizes_unknown_level():
    tax = _extract_taxonomies({"summary": {"taxonomies": [_tax("bogus")]}})
    assert tax[0]["level"] == "info"


def test_worst_level_folds_to_most_severe():
    assert _worst_level([_tax("safe"), _tax("malicious"), _tax("suspicious")]) == "malicious"
    assert _worst_level([_tax("safe"), _tax("info")]) == "safe"
    assert _worst_level([]) == "info"


# ─── test_connection ─────────────────────────────────────────────────────────

async def test_test_connection_ok(httpx_mock):
    httpx_mock.add_response(method="GET", url="http://cortex.test/api/analyzer", json=[])
    health = await _connector().test_connection()
    assert health.ok is True
    assert health.detail == "authenticated"


async def test_test_connection_failure(httpx_mock):
    httpx_mock.add_response(
        method="GET", url="http://cortex.test/api/analyzer", status_code=401, json={}
    )
    health = await _connector().test_connection()
    assert health.ok is False


# ─── list_analyzers ──────────────────────────────────────────────────────────

async def test_list_analyzers(httpx_mock):
    httpx_mock.add_response(
        method="GET", url="http://cortex.test/api/analyzer",
        json=[
            {"id": "VT_3_0", "name": "VirusTotal_GetReport", "dataTypeList": ["ip", "domain"]},
            {"_id": "AB_1_0", "name": "AbuseIPDB", "dataTypeList": ["ip"]},
            {"name": "no-id-dropped"},
        ],
    )
    analyzers = await _connector().list_analyzers()
    assert len(analyzers) == 2
    assert analyzers[0]["id"] == "VT_3_0"
    assert analyzers[0]["data_types"] == ["ip", "domain"]
    assert analyzers[1]["id"] == "AB_1_0"


# ─── enrich_observable (submit → poll → report) ──────────────────────────────

async def test_enrich_observable_malicious(httpx_mock):
    conn = _connector()
    # Submit → job InProgress.
    httpx_mock.add_response(
        method="POST", url="http://cortex.test/api/analyzer/VT_3_0/run",
        status_code=201, json={"id": "job1", "status": "InProgress"},
    )
    # Poll #1 still running, poll #2 success.
    httpx_mock.add_response(
        method="GET", url="http://cortex.test/api/job/job1", json={"id": "job1", "status": "InProgress"},
    )
    httpx_mock.add_response(
        method="GET", url="http://cortex.test/api/job/job1", json={"id": "job1", "status": "Success"},
    )
    # Report.
    httpx_mock.add_response(
        method="GET", url="http://cortex.test/api/job/job1/report",
        json={"report": {"summary": {"taxonomies": [_tax("malicious")]}}},
    )

    result = await conn.enrich_observable(
        observable_type="ip", value="1.2.3.4", analyzer_ids=["VT_3_0"],
    )
    assert result["connector"] == "cortex"
    assert result["data_type"] == "ip"
    assert result["verdict"] == "malicious"
    assert result["is_malicious"] is True
    assert len(result["analyzers"]) == 1
    entry = result["analyzers"][0]
    assert entry["job_id"] == "job1"
    assert entry["status"] == "Success"
    assert entry["level"] == "malicious"
    assert entry["error"] == ""


async def test_enrich_observable_job_failure_is_captured(httpx_mock):
    conn = _connector()
    httpx_mock.add_response(
        method="POST", url="http://cortex.test/api/analyzer/BAD/run",
        status_code=201, json={"id": "jobX", "status": "InProgress"},
    )
    httpx_mock.add_response(
        method="GET", url="http://cortex.test/api/job/jobX", json={"status": "Failure"},
    )
    result = await conn.enrich_observable(
        observable_type="domain", value="evil.example", analyzer_ids=["BAD"],
    )
    assert result["verdict"] == "info"
    assert result["is_malicious"] is False
    entry = result["analyzers"][0]
    assert entry["status"] == "Failure"
    assert "did not succeed" in entry["error"]


async def test_enrich_observable_multiple_analyzers_worst_wins(httpx_mock):
    conn = _connector()
    for aid, level in (("A1", "safe"), ("A2", "suspicious")):
        httpx_mock.add_response(
            method="POST", url=f"http://cortex.test/api/analyzer/{aid}/run",
            status_code=201, json={"id": f"job-{aid}", "status": "Success"},
        )
        httpx_mock.add_response(
            method="GET", url=f"http://cortex.test/api/job/job-{aid}",
            json={"status": "Success"},
        )
        httpx_mock.add_response(
            method="GET", url=f"http://cortex.test/api/job/job-{aid}/report",
            json={"report": {"summary": {"taxonomies": [_tax(level)]}}},
        )
    result = await conn.enrich_observable(
        observable_type="ip", value="9.9.9.9", analyzer_ids=["A1", "A2"],
    )
    assert result["verdict"] == "suspicious"
    assert len(result["analyzers"]) == 2


async def test_enrich_observable_submit_4xx_raises_captured(httpx_mock):
    conn = _connector()
    # A 4xx on submit fails fast inside _request → ConnectorError, captured per entry.
    httpx_mock.add_response(
        method="POST", url="http://cortex.test/api/analyzer/NOPE/run",
        status_code=404, json={"message": "no such analyzer"},
    )
    result = await conn.enrich_observable(
        observable_type="ip", value="1.2.3.4", analyzer_ids=["NOPE"],
    )
    entry = result["analyzers"][0]
    assert entry["error"]
    assert entry["taxonomies"] == []


async def test_poll_budget_exhausted_returns_last_status(httpx_mock):
    conn = CortexConnector(
        base_url="http://cortex.test", api_key="tok", poll_interval=0.0, max_polls=2,
    )
    httpx_mock.add_response(
        method="POST", url="http://cortex.test/api/analyzer/SLOW/run",
        status_code=201, json={"id": "jslow", "status": "InProgress"},
    )
    # Always in progress — poll budget (2) is spent, no report fetch happens.
    httpx_mock.add_response(
        method="GET", url="http://cortex.test/api/job/jslow", json={"status": "InProgress"},
    )
    httpx_mock.add_response(
        method="GET", url="http://cortex.test/api/job/jslow", json={"status": "InProgress"},
    )
    result = await conn.enrich_observable(
        observable_type="ip", value="1.2.3.4", analyzer_ids=["SLOW"],
    )
    entry = result["analyzers"][0]
    assert entry["status"] == "InProgress"
    assert "did not succeed" in entry["error"]


async def test_run_responder(httpx_mock):
    conn = _connector()
    httpx_mock.add_response(
        method="POST", url="http://cortex.test/api/responder/block/run",
        status_code=201, json={"id": "rjob", "status": "Success"},
    )
    httpx_mock.add_response(
        method="GET", url="http://cortex.test/api/job/rjob", json={"status": "Success"},
    )
    result = await conn.run_responder(
        responder_id="block", observable_type="ip", value="1.2.3.4",
    )
    assert result["responder"] == "block"
    assert result["job_id"] == "rjob"
    assert result["status"] == "Success"


async def test_transport_error_surfaces_as_connector_error(httpx_mock):
    import httpx

    conn = CortexConnector(
        base_url="http://cortex.test", api_key="tok", poll_interval=0.0, max_polls=1,
    )
    for _ in range(3):  # exhaust the retry budget
        httpx_mock.add_exception(httpx.ConnectError("boom"))
    with pytest.raises(ConnectorError):
        await conn.list_analyzers()
