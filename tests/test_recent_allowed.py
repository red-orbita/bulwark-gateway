"""Tests for the opt-in ALLOWED-event feed (BULWARK_LOG_ALLOWED).

Two sides are covered:

* Producer — ``proxy._push_recent_allowed`` synthesises a privacy-safe, browsable
  record for a request that passed every guardrail. It is gated behind
  ``settings.log_allowed``, capped at ``settings.events_max_per_tenant``, and writes to a
  DEDICATED per-tenant key (``bulwark:recent_allowed:<tenant>``) so high-volume
  legitimate traffic never evicts security-relevant block/warn events.
* Reader — ``admin.services.redis_sync.{iter_recent_allowed_keys,fetch_recent_allowed}``
  aggregate those per-tenant lists newest-first, mirroring the recent-blocks reader.
"""

from __future__ import annotations

import hashlib
import importlib
import json

import pytest

from src.guardrails import dynamic_registry as registry_mod
from src.routes import proxy as proxy_mod

# ─── Producer: _push_recent_allowed ──────────────────────────────────────────


class _FakeRedis:
    """Minimal in-memory Redis stub capturing lpush/ltrim calls."""

    def __init__(self) -> None:
        self.lists: dict[str, list[str]] = {}

    def lpush(self, key: str, value: str) -> int:
        self.lists.setdefault(key, []).insert(0, value)
        return len(self.lists[key])

    def ltrim(self, key: str, start: int, end: int) -> bool:
        if key in self.lists:
            self.lists[key] = self.lists[key][start : end + 1]
        return True


@pytest.fixture
def fake_registry(monkeypatch):
    fake = _FakeRedis()

    class _Reg:
        _redis = fake

    monkeypatch.setattr(registry_mod, "get_pattern_registry", lambda: _Reg())
    return fake


@pytest.fixture
def log_allowed_on(monkeypatch):
    """Enable the opt-in allowed feed with a small cap for the duration of a test."""
    monkeypatch.setattr(proxy_mod.settings, "log_allowed", True, raising=False)
    monkeypatch.setattr(proxy_mod.settings, "events_max_per_tenant", 100, raising=False)


def test_disabled_by_default_is_noop(fake_registry, monkeypatch):
    """With ``log_allowed`` off (default), nothing is written — no feed at all."""
    monkeypatch.setattr(proxy_mod.settings, "log_allowed", False, raising=False)
    proxy_mod._push_recent_allowed("acme", "support-bot", snippet_source="hello there")
    assert fake_registry.lists == {}


def test_entry_written_to_dedicated_allowed_key(fake_registry, log_allowed_on):
    proxy_mod._push_recent_allowed(
        "acme", "support-bot", snippet_source="what is the weather today?"
    )

    # DEDICATED key — must NOT pollute the recent_blocks feed.
    key = "bulwark:recent_allowed:acme"
    assert key in fake_registry.lists
    assert "bulwark:recent_blocks:acme" not in fake_registry.lists

    entry = json.loads(fake_registry.lists[key][0])
    assert entry["tenant"] == "acme"
    assert entry["agent"] == "support-bot"
    assert entry["verdict"] == "allow"
    assert entry["category"] == "allowed"
    assert entry["severity"] == "info"


def test_request_id_is_persisted(fake_registry, log_allowed_on):
    proxy_mod._push_recent_allowed(
        "acme", "support-bot", snippet_source="hi", request_id="acme:support-bot:42"
    )
    entry = json.loads(fake_registry.lists["bulwark:recent_allowed:acme"][0])
    assert entry["request_id"] == "acme:support-bot:42"


def test_snippet_redacts_secrets(fake_registry, log_allowed_on):
    """Even a passed request must never persist raw secrets verbatim."""
    aws_key = "AKIAIOSFODNN7EXAMPLE"
    source = f"please store my key {aws_key} for later"
    proxy_mod._push_recent_allowed("acme", "support-bot", snippet_source=source)

    entry = json.loads(fake_registry.lists["bulwark:recent_allowed:acme"][0])
    assert aws_key not in entry["snippet"]
    # Correlation hash still covers the true original.
    expected = hashlib.sha256(source.encode("utf-8", "ignore")).hexdigest()[:16]
    assert entry["input_hash"] == expected


def test_cap_trims_to_events_max_per_tenant(fake_registry, monkeypatch):
    monkeypatch.setattr(proxy_mod.settings, "log_allowed", True, raising=False)
    monkeypatch.setattr(proxy_mod.settings, "events_max_per_tenant", 3, raising=False)
    for i in range(10):
        proxy_mod._push_recent_allowed("acme", "support-bot", snippet_source=f"msg {i}")
    # ltrim keeps only the newest ``cap`` entries.
    assert len(fake_registry.lists["bulwark:recent_allowed:acme"]) == 3


def test_missing_redis_is_noop(monkeypatch, log_allowed_on):
    class _Reg:
        _redis = None

    monkeypatch.setattr(registry_mod, "get_pattern_registry", lambda: _Reg())
    # Must not raise even with logging enabled but no Redis.
    proxy_mod._push_recent_allowed("acme", "support-bot", snippet_source="x")


# ─── Reader: fetch_recent_allowed / iter_recent_allowed_keys ─────────────────


@pytest.fixture
def redis_sync():
    return importlib.import_module("admin.services.redis_sync")


class _ReaderPipeline:
    def __init__(self, data: dict[str, list[str]]):
        self._data = data
        self._queued: list[str] = []

    def lrange(self, key, start, end):
        self._queued.append(key)
        return self

    def execute(self):
        return [self._data.get(k, []) for k in self._queued]


class _ReaderRedis:
    def __init__(self, data: dict[str, list[str]]):
        self._data = data

    def scan_iter(self, match=None, count=None):
        prefix = match.rstrip("*") if match else ""
        for key in self._data:
            if key.startswith(prefix):
                yield key

    def pipeline(self, transaction=True):
        return _ReaderPipeline(self._data)


def _entry(tenant: str, ts: float) -> str:
    return json.dumps({"ts": ts, "tenant": tenant, "verdict": "allow", "category": "allowed"})


def test_iter_allowed_keys_only_matches_allowed_prefix(redis_sync):
    r = _ReaderRedis({
        "bulwark:recent_allowed:acme": [],
        "bulwark:recent_allowed:globex": [],
        "bulwark:recent_blocks:acme": [],  # different feed — must be excluded
    })
    keys = redis_sync.iter_recent_allowed_keys(r)
    assert set(keys) == {"bulwark:recent_allowed:acme", "bulwark:recent_allowed:globex"}


def test_fetch_allowed_merges_newest_first(redis_sync):
    r = _ReaderRedis({
        "bulwark:recent_allowed:acme": [_entry("acme", 100.0), _entry("acme", 300.0)],
        "bulwark:recent_allowed:globex": [_entry("globex", 200.0)],
    })
    events = redis_sync.fetch_recent_allowed(r)
    assert [e["ts"] for e in events] == [300.0, 200.0, 100.0]
    assert {e["tenant"] for e in events} == {"acme", "globex"}


def test_fetch_allowed_tenant_fast_path(redis_sync):
    r = _ReaderRedis({
        "bulwark:recent_allowed:acme": [_entry("acme", 100.0)],
        "bulwark:recent_allowed:globex": [_entry("globex", 200.0)],
    })
    events = redis_sync.fetch_recent_allowed(r, tenant="acme")
    assert len(events) == 1
    assert events[0]["tenant"] == "acme"


def test_fetch_allowed_empty_when_no_lists(redis_sync):
    assert redis_sync.fetch_recent_allowed(_ReaderRedis({})) == []
