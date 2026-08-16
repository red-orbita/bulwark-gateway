"""Tests for the admin virtual keys surface (admin.services.virtual_keys_store).

Covers:
  - subsystem availability (encryption key present / absent)
  - create / list / rotate / revoke round-trip (in-memory path)
  - hydrate_tenant multi-process correctness with a fake Redis
  - rotate/revoke Redis persistence side-effects
  - audit trail retrieval
"""

from __future__ import annotations

import importlib
import json

import pytest


@pytest.fixture
def enc_key(monkeypatch):
    """Provide a deterministic encryption key for the manager."""
    monkeypatch.setenv("BULWARK_KEY_ENCRYPTION_KEY", "unit-test-key-0123456789abcdef-xyz")
    yield


@pytest.fixture
def store(enc_key):
    """Fresh admin store module with reset singletons."""
    import admin.services.virtual_keys_store as s

    importlib.reload(s)
    s._manager = None
    s._init_error = None
    yield s
    s._manager = None
    s._init_error = None


class FakeRedis:
    """Minimal in-memory Redis supporting the subset used by VirtualKeyManager."""

    def __init__(self):
        self.hashes: dict[str, dict[str, str]] = {}
        self.lists: dict[str, list[str]] = {}

    def hset(self, key, field, value):
        self.hashes.setdefault(key, {})[field] = value

    def hget(self, key, field):
        return self.hashes.get(key, {}).get(field)

    def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    def hdel(self, key, field):
        self.hashes.get(key, {}).pop(field, None)

    def lpush(self, key, value):
        self.lists.setdefault(key, []).insert(0, value)

    def ltrim(self, key, start, end):
        self.lists[key] = self.lists.get(key, [])[start : end + 1]

    def lrange(self, key, start, end):
        return self.lists.get(key, [])[start : end + 1]


class TestAvailability:
    def test_available_with_key(self, store):
        ok, reason = store.is_available()
        assert ok is True
        assert reason is None

    def test_unavailable_without_key(self, monkeypatch):
        monkeypatch.delenv("BULWARK_KEY_ENCRYPTION_KEY", raising=False)
        import admin.services.virtual_keys_store as s

        importlib.reload(s)
        s._manager = None
        s._init_error = None
        ok, reason = s.is_available()
        assert ok is False
        assert reason and "BULWARK_KEY_ENCRYPTION_KEY" in reason
        with pytest.raises(s.VirtualKeysUnavailable):
            s.list_keys("acme")
        # audit trail degrades gracefully to empty
        assert s.audit_trail() == []


class TestRoundTrip:
    def test_create_list_rotate_revoke(self, store):
        vk = store.create_key("acme", "openai", "sk-secret-12345", description="prod")
        assert vk["key_id"].startswith("vk_")
        assert vk["provider"] == "openai"
        assert vk["is_active"] is True
        # never leaks the secret
        assert "backend_api_key" not in vk
        assert "encrypted_key" not in vk

        keys = store.list_keys("acme")
        assert len(keys) == 1

        rotated = store.rotate_key("acme", "openai", "sk-new-67890abc")
        assert rotated is not None and rotated["is_active"] is True

        keys = store.list_keys("acme")
        active = [k for k in keys if k["is_active"]]
        assert len(keys) == 2
        assert len(active) == 1
        assert active[0]["key_id"] == rotated["key_id"]

        assert store.revoke_key("acme", rotated["key_id"]) is True
        assert store.revoke_key("acme", "vk_deadbeefdeadbeef") is False

    def test_audit_trail_empty_without_redis(self, store):
        store.create_key("acme", "openai", "sk-secret-12345")
        # No Redis wired → audit trail is empty (audit list lives in Redis)
        assert store.audit_trail() == []


class TestHydrationMultiProcess:
    """Simulate a second process (admin) reading keys a first process created."""

    def test_hydrate_makes_redis_keys_visible(self, enc_key):
        from src.services.virtual_keys import VirtualKeyManager

        shared = FakeRedis()

        # Process A: proxy creates a key
        mgr_a = VirtualKeyManager()
        mgr_a._redis = shared
        vk = mgr_a.create_key("acme", "openai", "sk-proc-a-secret")

        # Process B: admin has empty memory, must hydrate before listing
        mgr_b = VirtualKeyManager()
        mgr_b._redis = shared
        assert mgr_b.list_keys("acme") == []  # not hydrated yet
        mgr_b.hydrate_tenant("acme")
        keys = mgr_b.list_keys("acme")
        assert len(keys) == 1
        assert keys[0]["key_id"] == vk.key_id

        # Process B can decrypt via the shared schema (same derived key)
        assert mgr_b.get_backend_key("acme", "openai") == "sk-proc-a-secret"

    def test_rotate_persists_deactivation_to_redis(self, enc_key):
        from src.services.virtual_keys import VirtualKeyManager

        shared = FakeRedis()
        mgr = VirtualKeyManager()
        mgr._redis = shared
        old = mgr.create_key("acme", "openai", "sk-old-secret-1")
        mgr.rotate_key("acme", "openai", "sk-new-secret-2")

        # Old key's Redis record must now be marked inactive
        raw = shared.hget("bulwark:vkeys:acme", old.key_id)
        assert raw is not None
        assert json.loads(raw)["is_active"] is False

    def test_revoke_clears_active_pointer(self, enc_key):
        from src.services.virtual_keys import VirtualKeyManager

        shared = FakeRedis()
        mgr = VirtualKeyManager()
        mgr._redis = shared
        vk = mgr.create_key("acme", "openai", "sk-revoke-me-1")
        assert shared.hget("bulwark:vkeys:acme:active", "openai") == vk.key_id
        assert mgr.revoke_key("acme", vk.key_id) is True
        # active pointer cleared, key removed from hash
        assert shared.hget("bulwark:vkeys:acme:active", "openai") is None
        assert shared.hget("bulwark:vkeys:acme", vk.key_id) is None

    def test_hydrate_noop_without_redis(self, enc_key):
        from src.services.virtual_keys import VirtualKeyManager

        mgr = VirtualKeyManager()
        mgr._redis = None
        # Must not raise
        mgr.hydrate_tenant("ghost")
        assert mgr.list_keys("ghost") == []


class TestAuditTrailWithRedis:
    def test_audit_trail_returns_operations(self, store):
        shared = FakeRedis()
        # Wire the shared fake redis into the store's manager
        mgr = store._get_manager()
        mgr._redis = shared
        store.create_key("acme", "openai", "sk-audit-secret-1")
        entries = store.audit_trail(limit=10)
        assert any(e["action"] == "create" for e in entries)
        assert entries[0]["tenant_id"] == "acme"
