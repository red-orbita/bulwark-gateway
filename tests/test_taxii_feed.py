"""Tests for the TAXII 2.1 collection feed client + IOCStore integration.

Covers the pure STIX-2.1 helpers (indicator atom extraction, confidence floor,
label carry-through), the bounded ``poll_collection`` transport (pagination via
``more``/``next``, error/SSRF handling, auth + Accept headers), and the
``IOCStore._fetch_taxii`` wiring (import, filtering, dedup, tag/severity mapping).

Like the OpenCTI feed, the transport uses synchronous ``httpx`` (it runs in an
executor in production); ``pytest_httpx``'s ``httpx_mock`` intercepts it. Because
``taxii.py`` binds ``_validate_url_no_ssrf`` at import time, the happy paths
monkeypatch it *on the taxii module* (not ``ioc_store``).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from admin.models.iocs import FeedCreate, FeedType, IOCType
from admin.services.integrations import taxii as taxii_mod
from admin.services.integrations.taxii import (
    TaxiiError,
    indicator_meets_confidence,
    poll_collection,
    stix_confidence_score,
    stix_indicator_iocs,
    stix_labels,
)
from admin.services.ioc_store import IOCStore

_URL = "http://taxii.test/api/root/collections/c1/objects/"


def _store(tmp_path: Path) -> IOCStore:
    return IOCStore(ioc_path=tmp_path / "iocs.json", feed_state_path=tmp_path / "feed_state.json")


def _taxii_feed(store: IOCStore, url: str = _URL, key: str = "Bearer tok", min_conf: float = 0.7):
    return store.create_feed(
        FeedCreate(
            name="taxii1", feed_type=FeedType.TAXII, url=url, api_key=key,
            auth_header="Authorization", min_confidence=min_conf,
        )
    )


def _indicator(pattern: str, **over) -> dict:
    sdo = {
        "type": "indicator",
        "spec_version": "2.1",
        "pattern": pattern,
        "pattern_type": "stix",
        "revoked": False,
        "confidence": 90,
        "labels": ["malicious-activity"],
    }
    sdo.update(over)
    return sdo


def _envelope(objects: list[dict], *, more: bool = False, nxt: str | None = None) -> dict:
    env: dict = {"objects": objects, "more": more}
    if nxt is not None:
        env["next"] = nxt
    return env


# ─── Pure STIX-2.1 helpers ───────────────────────────────────────────────────────


def test_stix_indicator_iocs_extracts_domain():
    sdo = _indicator("[domain-name:value = 'evil.example']")
    assert stix_indicator_iocs(sdo) == [(IOCType.DOMAIN, "evil.example")]


def test_stix_indicator_iocs_multi_atom():
    sdo = _indicator("[ipv4-addr:value = '1.2.3.4'] AND [domain-name:value = 'm.example']")
    atoms = stix_indicator_iocs(sdo)
    assert (IOCType.IP, "1.2.3.4") in atoms
    assert (IOCType.DOMAIN, "m.example") in atoms


def test_stix_indicator_iocs_skips_non_indicator():
    assert stix_indicator_iocs({"type": "malware", "pattern": "x"}) == []


def test_stix_indicator_iocs_skips_revoked():
    assert stix_indicator_iocs(_indicator("[url:value = 'http://x.example/y']", revoked=True)) == []


def test_stix_indicator_iocs_skips_non_stix_pattern():
    assert stix_indicator_iocs(_indicator("rule x {}", pattern_type="yara")) == []


def test_stix_indicator_iocs_skips_non_dict_and_empty():
    assert stix_indicator_iocs("not-a-dict") == []
    assert stix_indicator_iocs(_indicator("")) == []


def test_stix_confidence_score_present_absent_invalid():
    assert stix_confidence_score({"confidence": 80}) == 80
    assert stix_confidence_score({}) == 50  # neutral default
    assert stix_confidence_score({"confidence": "nope"}) == 50
    assert stix_confidence_score({"confidence": 250}) == 100  # clamped


def test_indicator_meets_confidence():
    # Absent confidence is kept (cannot be judged); present-but-low is dropped.
    assert indicator_meets_confidence({}, 0.7) is True
    assert indicator_meets_confidence({"confidence": 40}, 0.7) is False
    assert indicator_meets_confidence({"confidence": 80}, 0.7) is True
    assert indicator_meets_confidence({"confidence": "bad"}, 0.7) is True


def test_stix_labels_extracts_dedups_caps():
    sdo = {"labels": ["a", "a", "b", "c", "d"]}
    assert stix_labels(sdo) == ["a", "b", "c"]
    assert stix_labels({}) == []
    assert stix_labels({"labels": "not-a-list"}) == []


# ─── Transport: poll_collection ──────────────────────────────────────────────────


def test_poll_collection_single_page(httpx_mock, monkeypatch):
    monkeypatch.setattr(taxii_mod, "_validate_url_no_ssrf", lambda url: None)
    httpx_mock.add_response(
        method="GET",
        json=_envelope([_indicator("[domain-name:value = 'a.example']")]),
    )
    objs = list(poll_collection(url=_URL, api_key="Bearer tok"))
    assert len(objs) == 1
    req = httpx_mock.get_requests()[0]
    assert req.headers["Accept"] == "application/taxii+json;version=2.1"
    assert req.headers["Authorization"] == "Bearer tok"


def test_poll_collection_follows_pagination(httpx_mock, monkeypatch):
    monkeypatch.setattr(taxii_mod, "_validate_url_no_ssrf", lambda url: None)
    httpx_mock.add_response(
        method="GET",
        json=_envelope([_indicator("[domain-name:value = 'p1.example']")], more=True, nxt="cur2"),
    )
    httpx_mock.add_response(
        method="GET",
        json=_envelope([_indicator("[domain-name:value = 'p2.example']")], more=False),
    )
    objs = list(poll_collection(url=_URL, api_key="k"))
    assert len(objs) == 2
    # The second request must carry the cursor from the first page's ``next``.
    assert "next=cur2" in str(httpx_mock.get_requests()[1].url)


def test_poll_collection_stops_when_more_false(httpx_mock, monkeypatch):
    monkeypatch.setattr(taxii_mod, "_validate_url_no_ssrf", lambda url: None)
    httpx_mock.add_response(method="GET", json=_envelope([], more=False, nxt="ignored"))
    assert list(poll_collection(url=_URL)) == []
    assert len(httpx_mock.get_requests()) == 1


def test_poll_collection_non_200_raises(httpx_mock, monkeypatch):
    monkeypatch.setattr(taxii_mod, "_validate_url_no_ssrf", lambda url: None)
    httpx_mock.add_response(method="GET", status_code=503)
    with pytest.raises(TaxiiError, match="returned 503"):
        list(poll_collection(url=_URL))


def test_poll_collection_non_json_raises(httpx_mock, monkeypatch):
    monkeypatch.setattr(taxii_mod, "_validate_url_no_ssrf", lambda url: None)
    httpx_mock.add_response(method="GET", content=b"not json", headers={"Content-Type": "text/plain"})
    with pytest.raises(TaxiiError, match="non-JSON"):
        list(poll_collection(url=_URL))


def test_poll_collection_ssrf_blocked():
    # localhost is short-circuited by the SSRF blocklist before any DNS/HTTP.
    with pytest.raises(TaxiiError, match="SSRF protection"):
        list(poll_collection(url="http://localhost:9000/collections/c/objects/"))


# ─── IOCStore._fetch_taxii integration ───────────────────────────────────────────


def test_fetch_taxii_imports_and_filters(tmp_path, httpx_mock, monkeypatch):
    monkeypatch.setattr(taxii_mod, "_validate_url_no_ssrf", lambda url: None)
    store = _store(tmp_path)
    feed = _taxii_feed(store, min_conf=0.7)
    httpx_mock.add_response(
        method="GET",
        json=_envelope([
            _indicator("[domain-name:value = 'evil.example']", confidence=85,
                       labels=["apt", "c2"]),
            _indicator("[ipv4-addr:value = '198.51.100.9']", confidence=40),  # < floor
            _indicator("[url:value = 'http://revoked.example/x']", revoked=True),
            _indicator("rule x {}", pattern_type="yara"),
            {"type": "malware", "name": "not-an-indicator"},
        ]),
    )
    count = store._fetch_taxii(feed)
    assert count == 1

    entries, total = store.list_entries(source="taxii")
    assert total == 1
    entry = entries[0]
    assert entry.type == IOCType.DOMAIN
    assert entry.value == "evil.example"
    assert entry.severity.value == "critical"  # score 85
    assert entry.confidence == pytest.approx(0.85)
    assert set(entry.tags) == {"taxii", "apt", "c2"}


def test_fetch_taxii_dedups_against_store(tmp_path, httpx_mock, monkeypatch):
    monkeypatch.setattr(taxii_mod, "_validate_url_no_ssrf", lambda url: None)
    store = _store(tmp_path)
    feed = _taxii_feed(store)
    httpx_mock.add_response(
        method="GET",
        json=_envelope([
            _indicator("[domain-name:value = 'dup.example']"),
            _indicator("[domain-name:value = 'dup.example']"),
        ]),
    )
    assert store._fetch_taxii(feed) == 1


def test_fetch_taxii_requires_url(tmp_path):
    store = _store(tmp_path)
    feed = store.create_feed(
        FeedCreate(name="t2", feed_type=FeedType.TAXII, url="", api_key="k")
    )
    with pytest.raises(RuntimeError, match="collection URL required"):
        store._fetch_taxii(feed)


def test_fetch_taxii_ssrf_blocked(tmp_path):
    store = _store(tmp_path)
    feed = _taxii_feed(store, url="http://localhost:9000/collections/c/objects/")
    with pytest.raises(RuntimeError, match="SSRF protection"):
        store._fetch_taxii(feed)
