"""Tests for integration-managed IOC feeds (IOCStore + IntegrationConfig).

A connector of type ``opencti``/``misp`` can auto-provision an inbound IOC feed
(``int-<connector_id>``) that reuses its credential, eliminating a duplicate
feed configuration. These tests cover the model plumbing and the store's
upsert/remove helpers plus the read-only guard on the IOC feed CRUD surface.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from admin.models.iocs import FeedCreate, FeedType, FeedUpdate
from admin.services.integrations.registry import IntegrationConfig
from admin.services.ioc_store import IOCStore, ManagedFeedError


def _store(tmp_path: Path) -> IOCStore:
    return IOCStore(ioc_path=tmp_path / "iocs.json", feed_state_path=tmp_path / "feed_state.json")


# ─── IntegrationConfig model round-trip ──────────────────────────────────────


def test_integration_config_defaults_pull_off():
    cfg = IntegrationConfig(id="octi1", name="OpenCTI", type="opencti")
    assert cfg.pull_feed is False
    assert cfg.pull_interval_minutes == 1440
    assert cfg.pull_min_confidence == 0.7


def test_integration_config_pull_fields_round_trip():
    cfg = IntegrationConfig(
        id="octi1", name="OpenCTI", type="opencti",
        pull_feed=True, pull_interval_minutes=60, pull_min_confidence=0.9,
    )
    restored = IntegrationConfig.from_dict(cfg.to_dict())
    assert restored.pull_feed is True
    assert restored.pull_interval_minutes == 60
    assert restored.pull_min_confidence == 0.9


def test_integration_config_from_dict_missing_pull_fields():
    # Legacy configs (pre-managed-feed) load with pull disabled.
    restored = IntegrationConfig.from_dict({"id": "x", "name": "X", "type": "thehive"})
    assert restored.pull_feed is False
    assert restored.pull_interval_minutes == 1440
    assert restored.pull_min_confidence == 0.7


# ─── upsert_managed_feed ─────────────────────────────────────────────────────


def test_upsert_managed_feed_creates(tmp_path: Path):
    store = _store(tmp_path)
    feed = store.upsert_managed_feed(
        connector_id="octi1", feed_type=FeedType.OPENCTI, name="OpenCTI",
        url="http://opencti.test", api_key="tok", min_confidence=0.8,
    )
    assert feed.id == "int-octi1"
    assert feed.managed_by == "octi1"
    assert feed.feed_type == FeedType.OPENCTI
    assert feed.url == "http://opencti.test"
    assert feed.api_key_configured is True
    assert feed.min_confidence == 0.8
    # Surfaces through list_feeds too.
    assert any(f.id == "int-octi1" and f.managed_by == "octi1" for f in store.list_feeds())


def test_upsert_managed_feed_is_idempotent_and_preserves_runtime_state(tmp_path: Path):
    store = _store(tmp_path)
    store.upsert_managed_feed(
        connector_id="octi1", feed_type=FeedType.OPENCTI, name="OpenCTI",
        url="http://opencti.test", api_key="tok",
    )
    # Simulate a completed fetch cycle mutating runtime state.
    st = store._feed_state["feeds"]["int-octi1"]
    st["last_count"] = 42
    st["last_run"] = "2026-01-01T00:00:00+00:00"
    st["ioc_types"] = ["ip"]
    created_at = st["created_at"]

    updated = store.upsert_managed_feed(
        connector_id="octi1", feed_type=FeedType.OPENCTI, name="OpenCTI Renamed",
        url="http://opencti.test/new", api_key="",
    )
    assert updated.name == "OpenCTI Renamed"
    assert updated.url == "http://opencti.test/new"
    reloaded = store._feed_state["feeds"]["int-octi1"]
    assert reloaded["last_count"] == 42
    assert reloaded["last_run"] == "2026-01-01T00:00:00+00:00"
    assert reloaded["ioc_types"] == ["ip"]  # operator selection preserved
    assert reloaded["created_at"] == created_at
    assert reloaded["api_key"] == "tok"  # empty key leaves stored key intact


def test_upsert_managed_feed_empty_key_keeps_none_when_never_set(tmp_path: Path):
    store = _store(tmp_path)
    feed = store.upsert_managed_feed(
        connector_id="m1", feed_type=FeedType.MISP, name="MISP",
        url="http://misp.test", api_key="",
    )
    assert feed.api_key_configured is False


# ─── remove_managed_feed ─────────────────────────────────────────────────────


def test_remove_managed_feed(tmp_path: Path):
    store = _store(tmp_path)
    store.upsert_managed_feed(
        connector_id="octi1", feed_type=FeedType.OPENCTI, name="OpenCTI",
        url="http://opencti.test", api_key="tok",
    )
    assert store.remove_managed_feed("octi1") is True
    assert store.get_feed("int-octi1") is None
    # Idempotent.
    assert store.remove_managed_feed("octi1") is False


def test_remove_managed_feed_never_touches_unmanaged_feed(tmp_path: Path):
    store = _store(tmp_path)
    # A hand-made feed that happens to collide on the derived id.
    store._ensure_default_feeds()
    store._feed_state["feeds"]["int-octi1"] = {
        "id": "int-octi1", "name": "hand-made", "feed_type": "custom",
        "url": "", "auth_header": "", "api_key": "", "enabled": True,
        "interval_minutes": 1440, "min_confidence": 0.7,
        "ioc_types": ["ip"], "last_run": None, "last_count": 0,
        "last_error": "", "created_at": None,
    }
    assert store.remove_managed_feed("octi1") is False
    assert store.get_feed("int-octi1") is not None


# ─── read-only guard on the IOC feed CRUD surface ────────────────────────────


def test_managed_feed_update_is_blocked(tmp_path: Path):
    store = _store(tmp_path)
    store.upsert_managed_feed(
        connector_id="octi1", feed_type=FeedType.OPENCTI, name="OpenCTI",
        url="http://opencti.test", api_key="tok",
    )
    with pytest.raises(ManagedFeedError):
        store.update_feed("int-octi1", FeedUpdate(name="hijack"))


def test_managed_feed_delete_is_blocked(tmp_path: Path):
    store = _store(tmp_path)
    store.upsert_managed_feed(
        connector_id="octi1", feed_type=FeedType.OPENCTI, name="OpenCTI",
        url="http://opencti.test", api_key="tok",
    )
    with pytest.raises(ManagedFeedError):
        store.delete_feed("int-octi1")


def test_managed_feed_toggle_is_blocked(tmp_path: Path):
    store = _store(tmp_path)
    store.upsert_managed_feed(
        connector_id="octi1", feed_type=FeedType.OPENCTI, name="OpenCTI",
        url="http://opencti.test", api_key="tok",
    )
    with pytest.raises(ManagedFeedError):
        store.toggle_feed("int-octi1")


def test_unmanaged_feed_crud_still_works(tmp_path: Path):
    store = _store(tmp_path)
    feed = store.create_feed(
        FeedCreate(name="hand made", feed_type=FeedType.CUSTOM, url="http://x.test")
    )
    assert store.update_feed(feed.id, FeedUpdate(name="renamed")).name == "renamed"
    assert store.toggle_feed(feed.id).enabled is False
    assert store.delete_feed(feed.id) is True
