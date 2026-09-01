"""Tests for the OpenCTI IOC feed puller (admin IOCStore).

Covers the STIX-2 indicator pattern parser, score/severity mapping, and the
GraphQL pull path (import, confidence floor, revoked filtering, label→tag
carry-through, SSRF protection, GraphQL/HTTP error handling).

The pull path uses synchronous ``httpx.post`` (it runs in an executor in
production); ``pytest_httpx``'s ``httpx_mock`` intercepts it transparently.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from admin.models.iocs import FeedCreate, FeedType, IOCType
from admin.services import ioc_store as ioc_store_mod
from admin.services.ioc_store import (
    IOCStore,
    _opencti_labels,
    _parse_stix_indicator_pattern,
    _severity_from_score,
)


def _store(tmp_path: Path) -> IOCStore:
    return IOCStore(ioc_path=tmp_path / "iocs.json", feed_state_path=tmp_path / "feed_state.json")


def _opencti_feed(store: IOCStore, url: str = "http://opencti.test", key: str = "tok", min_conf: float = 0.7):
    return store.create_feed(
        FeedCreate(
            name="octi", feed_type=FeedType.OPENCTI, url=url, api_key=key,
            min_confidence=min_conf,
        )
    )


def _graphql(edges: list[dict]) -> dict:
    return {"data": {"indicators": {"edges": [{"node": n} for n in edges]}}}


# ─── STIX pattern parser (pure) ──────────────────────────────────────────────

def test_parse_stix_domain():
    assert _parse_stix_indicator_pattern("[domain-name:value = 'evil.example']") == [
        (IOCType.DOMAIN, "evil.example")
    ]


def test_parse_stix_ipv4_and_ipv6():
    assert _parse_stix_indicator_pattern("[ipv4-addr:value = '203.0.113.5']") == [
        (IOCType.IP, "203.0.113.5")
    ]
    assert _parse_stix_indicator_pattern("[ipv6-addr:value = '2001:db8::1']") == [
        (IOCType.IP, "2001:db8::1")
    ]


def test_parse_stix_url():
    assert _parse_stix_indicator_pattern("[url:value = 'http://evil.example/x']") == [
        (IOCType.URL, "http://evil.example/x")
    ]


def test_parse_stix_file_hashes():
    sha = "a" * 64
    md5 = "b" * 32
    assert _parse_stix_indicator_pattern(f"[file:hashes.'SHA-256' = '{sha}']") == [
        (IOCType.HASH_SHA256, sha)
    ]
    assert _parse_stix_indicator_pattern(f"[file:hashes.'MD5' = '{md5}']") == [
        (IOCType.HASH_MD5, md5)
    ]


def test_parse_stix_multi_atom():
    pattern = "[ipv4-addr:value = '1.2.3.4'] AND [domain-name:value = 'multi.example']"
    parsed = _parse_stix_indicator_pattern(pattern)
    assert (IOCType.IP, "1.2.3.4") in parsed
    assert (IOCType.DOMAIN, "multi.example") in parsed
    assert len(parsed) == 2


def test_parse_stix_skips_unknown_and_unsupported_hash():
    # Unknown object type and an unsupported hash algorithm are dropped, not guessed.
    assert _parse_stix_indicator_pattern("[email-addr:value = 'a@b.example']") == []
    assert _parse_stix_indicator_pattern("[file:hashes.'SHA-1' = 'deadbeef']") == []


def test_severity_from_score_bands():
    assert _severity_from_score(85).value == "critical"
    assert _severity_from_score(60).value == "high"
    assert _severity_from_score(20).value == "medium"


def test_opencti_labels_extracts_and_caps():
    node = {"objectLabel": [{"value": "malware"}, {"value": "apt29"}, {"value": "c2"}, {"value": "extra"}]}
    assert _opencti_labels(node) == ["malware", "apt29", "c2"]
    assert _opencti_labels({}) == []


# ─── GraphQL pull path ───────────────────────────────────────────────────────

def test_opencti_import_indicators(tmp_path, httpx_mock, monkeypatch):
    monkeypatch.setattr(ioc_store_mod, "_validate_url_no_ssrf", lambda url: None)
    store = _store(tmp_path)
    feed = _opencti_feed(store, min_conf=0.7)

    httpx_mock.add_response(
        method="POST",
        url="http://opencti.test/graphql",
        json=_graphql([
            {
                "pattern": "[domain-name:value = 'evil.example']",
                "pattern_type": "stix", "revoked": False,
                "confidence": 90, "x_opencti_score": 85,
                "objectLabel": [{"value": "malware"}, {"value": "apt"}],
            },
            {  # below confidence floor (score 40 < 70) → skipped
                "pattern": "[ipv4-addr:value = '198.51.100.9']",
                "pattern_type": "stix", "revoked": False,
                "confidence": 40, "x_opencti_score": 40, "objectLabel": [],
            },
            {  # revoked → skipped
                "pattern": "[url:value = 'http://revoked.example/x']",
                "pattern_type": "stix", "revoked": True,
                "confidence": 95, "x_opencti_score": 95, "objectLabel": [],
            },
            {  # non-STIX pattern (yara) → skipped
                "pattern": "rule x { condition: true }",
                "pattern_type": "yara", "revoked": False,
                "confidence": 90, "x_opencti_score": 90, "objectLabel": [],
            },
        ]),
    )

    count = store._fetch_opencti(feed)
    assert count == 1

    entries, total = store.list_entries(source="opencti")
    assert total == 1
    entry = entries[0]
    assert entry.type == IOCType.DOMAIN
    assert entry.value == "evil.example"
    assert entry.severity.value == "critical"  # score 85
    assert entry.confidence == pytest.approx(0.85)
    assert set(entry.tags) == {"opencti", "malware", "apt"}


def test_opencti_requires_url_and_key(tmp_path):
    store = _store(tmp_path)
    # URL present but empty API key.
    feed = store.create_feed(
        FeedCreate(name="octi2", feed_type=FeedType.OPENCTI, url="http://opencti.test", api_key="")
    )
    with pytest.raises(RuntimeError, match="URL and API key required"):
        store._fetch_opencti(feed)


def test_opencti_ssrf_blocked(tmp_path):
    # localhost is short-circuited by the SSRF blocklist before any DNS/HTTP.
    store = _store(tmp_path)
    feed = _opencti_feed(store, url="http://localhost:8080", key="tok")
    with pytest.raises(RuntimeError, match="SSRF protection"):
        store._fetch_opencti(feed)


def test_opencti_graphql_errors(tmp_path, httpx_mock, monkeypatch):
    monkeypatch.setattr(ioc_store_mod, "_validate_url_no_ssrf", lambda url: None)
    store = _store(tmp_path)
    feed = _opencti_feed(store)
    httpx_mock.add_response(
        method="POST", url="http://opencti.test/graphql",
        json={"errors": [{"message": "Field 'indicators' unauthorized"}]},
    )
    with pytest.raises(RuntimeError, match="GraphQL error"):
        store._fetch_opencti(feed)


def test_opencti_http_500(tmp_path, httpx_mock, monkeypatch):
    monkeypatch.setattr(ioc_store_mod, "_validate_url_no_ssrf", lambda url: None)
    store = _store(tmp_path)
    feed = _opencti_feed(store)
    httpx_mock.add_response(method="POST", url="http://opencti.test/graphql", status_code=500)
    with pytest.raises(RuntimeError, match="OpenCTI returned 500"):
        store._fetch_opencti(feed)
