"""Tests for per-tenant recent-blocks aggregation in admin.services.redis_sync.

Regression coverage for SGW-XT-002: the proxy writes one capped list per tenant
(``bulwark:recent_blocks:<tenant_id>``) so block metadata never leaks across
tenant boundaries. Admin readers previously read a single bare
``bulwark:recent_blocks`` key (always empty) — this suite locks in the SCAN +
pipeline aggregation contract of ``iter_recent_block_keys`` /
``fetch_recent_blocks``.
"""

from __future__ import annotations

import importlib
import json

import pytest


@pytest.fixture
def redis_sync():
    return importlib.import_module("admin.services.redis_sync")


class FakePipeline:
    """Minimal pipeline: records queued lrange keys, resolves from a data map."""

    def __init__(self, data: dict[str, list[str]]):
        self._data = data
        self._queued: list[str] = []

    def lrange(self, key, start, end):
        self._queued.append(key)
        return self

    def execute(self):
        return [self._data.get(k, []) for k in self._queued]


class FakeRedis:
    def __init__(self, data: dict[str, list[str]], *, scan_raises=False):
        self._data = data
        self._scan_raises = scan_raises

    def scan_iter(self, match=None, count=None):
        if self._scan_raises:
            raise RuntimeError("redis down")
        prefix = match.rstrip("*") if match else ""
        for key in self._data:
            if key.startswith(prefix):
                yield key

    def pipeline(self, transaction=True):
        return FakePipeline(self._data)

    def lrange(self, key, start, end):
        return self._data.get(key, [])


def _entry(tenant: str, ts: float, category: str = "prompt_injection") -> str:
    return json.dumps({"ts": ts, "tenant": tenant, "category": category, "description": "blocked"})


# ─── iter_recent_block_keys ──────────────────────────────────────────────────


def test_iter_keys_returns_only_per_tenant_lists(redis_sync):
    r = FakeRedis({
        "bulwark:recent_blocks:acme": [],
        "bulwark:recent_blocks:globex": [],
        "bulwark:guardrails:version": ["3"],  # must be excluded by SCAN match
    })
    keys = redis_sync.iter_recent_block_keys(r)
    assert set(keys) == {"bulwark:recent_blocks:acme", "bulwark:recent_blocks:globex"}


def test_iter_keys_swallows_scan_errors(redis_sync):
    """A failing SCAN degrades gracefully to an empty list (never raises)."""
    r = FakeRedis({}, scan_raises=True)
    assert redis_sync.iter_recent_block_keys(r) == []


# ─── fetch_recent_blocks (positive) ──────────────────────────────────────────


def test_fetch_merges_and_sorts_newest_first(redis_sync):
    r = FakeRedis({
        "bulwark:recent_blocks:acme": [_entry("acme", 100.0), _entry("acme", 300.0)],
        "bulwark:recent_blocks:globex": [_entry("globex", 200.0)],
    })
    events = redis_sync.fetch_recent_blocks(r)
    assert [e["ts"] for e in events] == [300.0, 200.0, 100.0]
    # Entries from both tenants are aggregated.
    assert {e["tenant"] for e in events} == {"acme", "globex"}


def test_fetch_truncates_to_max_items(redis_sync):
    r = FakeRedis({
        "bulwark:recent_blocks:acme": [_entry("acme", float(i)) for i in range(10)],
    })
    events = redis_sync.fetch_recent_blocks(r, max_items=3)
    assert len(events) == 3
    assert [e["ts"] for e in events] == [9.0, 8.0, 7.0]


def test_fetch_tenant_fast_path_reads_single_list(redis_sync):
    """With a tenant filter, only that tenant's list is read (no cross-tenant leak)."""
    r = FakeRedis({
        "bulwark:recent_blocks:acme": [_entry("acme", 100.0)],
        "bulwark:recent_blocks:globex": [_entry("globex", 200.0)],
    })
    events = redis_sync.fetch_recent_blocks(r, tenant="acme")
    assert len(events) == 1
    assert events[0]["tenant"] == "acme"


# ─── fetch_recent_blocks (negative / robustness) ─────────────────────────────


def test_fetch_empty_when_no_lists(redis_sync):
    assert redis_sync.fetch_recent_blocks(FakeRedis({})) == []


def test_fetch_skips_malformed_json(redis_sync):
    r = FakeRedis({
        "bulwark:recent_blocks:acme": ["{not valid json", _entry("acme", 50.0)],
    })
    events = redis_sync.fetch_recent_blocks(r)
    assert len(events) == 1
    assert events[0]["tenant"] == "acme"
