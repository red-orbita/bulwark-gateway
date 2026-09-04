"""Tests for the TAXII 2.1 case-publish connector.

Cover the pure helpers (TLP selection, restriction, marking application) and the
async publish flow against a mocked TAXII collection ``objects`` endpoint
(``pytest_httpx``). The connector SSRF-validates the collection URL and stamps the
bundle with a standard STIX TLP marking-definition; ``TLP:RED`` observables are
never shared. Because ``taxii.py`` binds ``_validate_url_no_ssrf`` at import time,
the happy paths monkeypatch it *on the taxii module* (mirroring the feed tests) and
the SSRF-blocked paths use a ``localhost`` URL (short-circuited by the blocklist
before any DNS).
"""

from __future__ import annotations

import json

import httpx
import pytest

import admin.services.integrations.taxii as taxii_mod
from admin.services.integrations.base import ConnectorError, TlpGateError
from admin.services.integrations.taxii import (
    _TLP_MARKING_IDS,
    TaxiiConnector,
    _is_restricted,
    apply_tlp_markings,
    select_publish_tlp,
)

_URL = "http://taxii.test/api/root/collections/c1/objects/"
_INFO_URL = "http://taxii.test/api/root/collections/c1"

_CASE = {
    "case_id": "C-1",
    "title": "Intrusion",
    "summary": "bad guy",
    "tags": ["T1041"],
    "updated_at": "2026-01-01T00:00:00Z",
}


def _connector(url: str = _URL) -> TaxiiConnector:
    return TaxiiConnector(base_url=url, api_key="Bearer tok")


def _obs(otype: str, value: str, *, tlp: str = "amber", is_ioc: bool = False, **extra) -> dict:
    node = {"type": otype, "value": value, "tlp": tlp, "is_ioc": is_ioc}
    node.update(extra)
    return node


def _no_ssrf(monkeypatch) -> None:
    monkeypatch.setattr(taxii_mod, "_validate_url_no_ssrf", lambda url: None)


# ─── Pure helpers ────────────────────────────────────────────────────────────

def test_is_restricted_only_red():
    assert _is_restricted(_obs("ip", "1.2.3.4", tlp="red")) is True
    assert _is_restricted(_obs("ip", "1.2.3.4", tlp="amber")) is False
    assert _is_restricted(_obs("ip", "1.2.3.4", tlp="green")) is False
    assert _is_restricted(_obs("ip", "1.2.3.4", tlp="white")) is False
    # Unmarked observables default to amber (shareable).
    assert _is_restricted({"type": "ip", "value": "1.2.3.4"}) is False


def test_select_publish_tlp_picks_most_restrictive():
    assert select_publish_tlp([_obs("ip", "1.2.3.4", tlp="green"),
                               _obs("domain", "x.test", tlp="amber")]) == "amber"
    assert select_publish_tlp([_obs("ip", "1.2.3.4", tlp="white"),
                               _obs("domain", "x.test", tlp="green")]) == "green"
    assert select_publish_tlp([_obs("ip", "1.2.3.4", tlp="white")]) == "white"


def test_select_publish_tlp_excludes_red_and_defaults_amber():
    # red is skipped; with nothing else it defaults to amber.
    assert select_publish_tlp([_obs("ip", "1.2.3.4", tlp="red")]) == "amber"
    # unmarked observables default to amber.
    assert select_publish_tlp([{"type": "ip", "value": "1.2.3.4"}]) == "amber"
    assert select_publish_tlp([]) == "amber"


def test_apply_tlp_markings_prepends_definition_and_refs():
    bundle = {
        "type": "bundle",
        "id": "bundle--x",
        "objects": [
            {"type": "identity", "id": "identity--a"},
            {"type": "indicator", "id": "indicator--b"},
        ],
    }
    apply_tlp_markings(bundle, "green")
    objects = bundle["objects"]
    # The marking-definition is prepended.
    assert objects[0]["type"] == "marking-definition"
    assert objects[0]["id"] == _TLP_MARKING_IDS["green"]
    assert objects[0]["name"] == "TLP:GREEN"
    # Every non-marking object now references it.
    for obj in objects[1:]:
        assert obj["object_marking_refs"] == [_TLP_MARKING_IDS["green"]]


# ─── push_case flow ──────────────────────────────────────────────────────────

async def test_push_publishes_bundle(httpx_mock, monkeypatch):
    _no_ssrf(monkeypatch)
    httpx_mock.add_response(
        method="POST", url=_URL, status_code=202,
        json={"id": "status--1", "status": "complete"},
    )

    result = await _connector().push_case(
        _CASE,
        [_obs("ip", "1.2.3.4", is_ioc=True), _obs("domain", "evil.test")],
        [],
    )
    # ip → SCO + indicator; domain → SCO ⇒ 3 shared objects.
    assert result.created is True
    assert result.remote_id.startswith("bundle--")
    assert result.remote_url == _INFO_URL
    assert "3 STIX objects" in result.detail
    assert "TLP:AMBER" in result.detail
    assert "0 TLP:RED excluded" in result.detail
    assert "status complete" in result.detail

    # The published envelope carries a TLP marking-definition on every object.
    body = json.loads(httpx_mock.get_requests()[0].content)
    objects = body["objects"]
    types = [o["type"] for o in objects]
    assert objects[0]["type"] == "marking-definition"
    assert "report" in types and "indicator" in types
    for obj in objects:
        if obj["type"] == "marking-definition":
            continue
        assert obj["object_marking_refs"] == [_TLP_MARKING_IDS["amber"]]


async def test_push_idempotent_update(httpx_mock, monkeypatch):
    _no_ssrf(monkeypatch)
    httpx_mock.add_response(method="POST", url=_URL, status_code=202, json={})

    result = await _connector().push_case(
        _CASE, [_obs("domain", "evil.test")], [], remote_id="bundle--prior",
    )
    assert result.created is False
    assert result.remote_id == "bundle--prior"
    assert "re-published" in result.detail


async def test_push_excludes_tlp_red(httpx_mock, monkeypatch):
    _no_ssrf(monkeypatch)
    httpx_mock.add_response(method="POST", url=_URL, status_code=202, json={})

    result = await _connector().push_case(
        _CASE,
        [_obs("ip", "9.9.9.9", tlp="red", is_ioc=True), _obs("domain", "evil.test")],
        [],
    )
    assert result.created is True
    assert "1 TLP:RED excluded" in result.detail


async def test_push_all_red_raises_gate(monkeypatch):
    _no_ssrf(monkeypatch)
    # everything is red → nothing shareable → refused with no remote call.
    with pytest.raises(TlpGateError):
        await _connector().push_case(
            _CASE, [_obs("ip", "9.9.9.9", tlp="red")], [],
        )


async def test_push_no_observables_raises_gate(monkeypatch):
    _no_ssrf(monkeypatch)
    # a bundle of only identity+report has nothing to publish.
    with pytest.raises(TlpGateError):
        await _connector().push_case(_CASE, [], [])


async def test_push_ssrf_blocked_url():
    # localhost is short-circuited by the SSRF blocklist before any DNS/HTTP.
    conn = _connector("http://localhost:9000/collections/c/objects/")
    with pytest.raises(ConnectorError) as exc:
        await conn.push_case(_CASE, [_obs("domain", "evil.test")], [])
    assert "SSRF" in str(exc.value)


async def test_push_transport_error_surfaces(httpx_mock, monkeypatch):
    _no_ssrf(monkeypatch)
    # The bounded retry loop makes up to _MAX_ATTEMPTS attempts before failing.
    for _ in range(3):
        httpx_mock.add_exception(httpx.ConnectError("down"))
    with pytest.raises(ConnectorError):
        await _connector().push_case(_CASE, [_obs("domain", "evil.test")], [])


async def test_push_client_error_fails_fast(httpx_mock, monkeypatch):
    _no_ssrf(monkeypatch)
    httpx_mock.add_response(method="POST", url=_URL, status_code=400, text="bad")
    with pytest.raises(ConnectorError):
        await _connector().push_case(_CASE, [_obs("domain", "evil.test")], [])


# ─── test_connection ─────────────────────────────────────────────────────────

async def test_test_connection_ok(httpx_mock, monkeypatch):
    _no_ssrf(monkeypatch)
    httpx_mock.add_response(
        method="GET", url=_INFO_URL,
        json={"title": "Shared", "can_write": True},
    )
    health = await _connector().test_connection()
    assert health.ok is True
    assert "writable" in health.detail
    assert "Shared" in health.detail


async def test_test_connection_not_writable(httpx_mock, monkeypatch):
    _no_ssrf(monkeypatch)
    httpx_mock.add_response(
        method="GET", url=_INFO_URL,
        json={"title": "ReadOnly", "can_write": False},
    )
    health = await _connector().test_connection()
    assert health.ok is False
    assert "not writable" in health.detail


async def test_test_connection_http_error(httpx_mock, monkeypatch):
    _no_ssrf(monkeypatch)
    httpx_mock.add_response(method="GET", url=_INFO_URL, status_code=401, json={})
    health = await _connector().test_connection()
    assert health.ok is False
    assert "401" in health.detail


async def test_test_connection_ssrf_blocked():
    conn = _connector("http://localhost:9000/collections/c/objects/")
    health = await conn.test_connection()
    assert health.ok is False
    assert "SSRF" in health.detail
