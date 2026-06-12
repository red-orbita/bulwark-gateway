"""Tests for response cache and virtual keys services."""

import json
import os
import time
from unittest.mock import patch, MagicMock

import pytest


# ═══════════════════════════════════════════════════════════════════════
# Response Cache Tests
# ═══════════════════════════════════════════════════════════════════════


class TestResponseCache:
    """Unit tests for ResponseCache."""

    def _make_cache(self, ttl=60, max_size=100, enabled=True):
        """Create a fresh cache instance (no Redis)."""
        from src.services.response_cache import ResponseCache
        cache = ResponseCache(ttl=ttl, max_size=max_size, enabled=enabled)
        cache._redis = None  # Force in-memory only for unit tests
        return cache

    def _sample_request(self, model="gpt-4", content="Hello"):
        return {
            "model": model,
            "messages": [{"role": "user", "content": content}],
            "temperature": 0.7,
        }

    def _sample_response(self, content="Hi there!", tokens=50):
        return {
            "id": "chatcmpl-123",
            "object": "chat.completion",
            "model": "gpt-4",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": tokens - 10,
                "total_tokens": tokens,
            },
        }

    def test_cache_disabled_returns_none(self):
        cache = self._make_cache(enabled=False)
        req = self._sample_request()
        resp = self._sample_response()
        cache.put(req, resp)
        assert cache.get(req) is None

    def test_cache_put_and_get(self):
        cache = self._make_cache()
        req = self._sample_request()
        resp = self._sample_response()
        cache.put(req, resp)
        result = cache.get(req)
        assert result is not None
        assert result["choices"][0]["message"]["content"] == "Hi there!"

    def test_cache_miss_different_content(self):
        cache = self._make_cache()
        req1 = self._sample_request(content="Hello")
        req2 = self._sample_request(content="Goodbye")
        resp = self._sample_response()
        cache.put(req1, resp)
        assert cache.get(req2) is None

    def test_cache_miss_different_model(self):
        cache = self._make_cache()
        req1 = self._sample_request(model="gpt-4")
        req2 = self._sample_request(model="gpt-3.5-turbo")
        resp = self._sample_response()
        cache.put(req1, resp)
        assert cache.get(req2) is None

    def test_cache_miss_different_temperature(self):
        cache = self._make_cache()
        req1 = {"model": "gpt-4", "messages": [{"role": "user", "content": "Hi"}], "temperature": 0.0}
        req2 = {"model": "gpt-4", "messages": [{"role": "user", "content": "Hi"}], "temperature": 1.0}
        resp = self._sample_response()
        cache.put(req1, resp)
        assert cache.get(req2) is None

    def test_cache_hit_ignores_stream_field(self):
        """stream field should NOT affect cache key (same query = same answer)."""
        cache = self._make_cache()
        req1 = self._sample_request()
        req1["stream"] = False
        req2 = self._sample_request()
        req2["stream"] = True
        resp = self._sample_response()
        cache.put(req1, resp)
        # Same content, different stream flag — should still hit
        result = cache.get(req2)
        assert result is not None

    def test_cache_hit_ignores_max_tokens(self):
        """max_tokens shouldn't affect cache key."""
        cache = self._make_cache()
        req1 = self._sample_request()
        req1["max_tokens"] = 100
        req2 = self._sample_request()
        req2["max_tokens"] = 500
        resp = self._sample_response()
        cache.put(req1, resp)
        assert cache.get(req2) is not None

    def test_cache_expiration(self):
        cache = self._make_cache(ttl=1)
        req = self._sample_request()
        resp = self._sample_response()
        cache.put(req, resp)
        assert cache.get(req) is not None
        # Manually expire the entry
        key = cache._compute_key(req)
        cache._lru[key].created_at = time.time() - 10
        assert cache.get(req) is None

    def test_cache_does_not_store_errors(self):
        cache = self._make_cache()
        req = self._sample_request()
        error_resp = {"error": {"message": "Rate limit exceeded", "type": "rate_limit"}}
        cache.put(req, error_resp)
        assert cache.get(req) is None

    def test_cache_does_not_store_empty_choices(self):
        cache = self._make_cache()
        req = self._sample_request()
        empty_resp = {"choices": []}
        cache.put(req, empty_resp)
        assert cache.get(req) is None

    def test_cache_invalidate(self):
        cache = self._make_cache()
        req = self._sample_request()
        resp = self._sample_response()
        cache.put(req, resp)
        assert cache.get(req) is not None
        removed = cache.invalidate(req)
        assert removed is True
        assert cache.get(req) is None

    def test_cache_invalidate_nonexistent(self):
        cache = self._make_cache()
        req = self._sample_request()
        removed = cache.invalidate(req)
        assert removed is False

    def test_cache_clear(self):
        cache = self._make_cache()
        for i in range(5):
            req = self._sample_request(content=f"Message {i}")
            cache.put(req, self._sample_response())
        assert cache.stats.entries == 5
        cache.clear()
        assert cache.stats.entries == 0

    def test_cache_stats_tracking(self):
        cache = self._make_cache()
        req = self._sample_request()
        resp = self._sample_response(tokens=100)
        # Miss
        cache.get(req)
        assert cache.stats.misses == 1
        assert cache.stats.hits == 0
        # Store
        cache.put(req, resp)
        # Hit
        cache.get(req)
        assert cache.stats.hits == 1
        assert cache.stats.total_tokens_saved == 100

    def test_cache_hit_rate(self):
        cache = self._make_cache()
        req = self._sample_request()
        resp = self._sample_response()
        cache.put(req, resp)
        # 1 miss, 3 hits
        cache.get(self._sample_request(content="miss"))
        cache.get(req)
        cache.get(req)
        cache.get(req)
        assert cache.stats.hit_rate == pytest.approx(0.75, abs=0.01)

    def test_cache_lru_eviction(self):
        cache = self._make_cache(max_size=3)
        # Fill cache beyond capacity
        for i in range(5):
            req = self._sample_request(content=f"Msg {i}")
            cache.put(req, self._sample_response())
        # Only last 3 should remain
        assert len(cache._lru) == 3

    def test_cache_tools_change_key(self):
        """Requests with tools produce different cache keys."""
        cache = self._make_cache()
        req1 = self._sample_request()
        req2 = self._sample_request()
        req2["tools"] = [{"type": "function", "function": {"name": "search"}}]
        resp = self._sample_response()
        cache.put(req1, resp)
        assert cache.get(req2) is None

    def test_cache_deterministic_key(self):
        """Same request always produces same key."""
        cache = self._make_cache()
        req = self._sample_request()
        k1 = cache._compute_key(req)
        k2 = cache._compute_key(req)
        assert k1 == k2
        assert len(k1) == 32  # SHA-256 truncated to 32 hex chars


# ═══════════════════════════════════════════════════════════════════════
# Virtual Keys Tests
# ═══════════════════════════════════════════════════════════════════════


class TestVirtualKeys:
    """Unit tests for VirtualKeyManager."""

    def _make_manager(self):
        """Create a fresh manager without Redis."""
        from src.services.virtual_keys import VirtualKeyManager
        mgr = VirtualKeyManager()
        mgr._redis = None
        return mgr

    def test_create_key(self):
        mgr = self._make_manager()
        vkey = mgr.create_key(
            tenant_id="acme-corp",
            provider="openai",
            backend_api_key="sk-real-openai-key-12345",
            description="Production OpenAI key",
        )
        assert vkey.key_id.startswith("vk_")
        assert vkey.tenant_id == "acme-corp"
        assert vkey.provider == "openai"
        assert vkey.is_active is True
        assert vkey.expired is False

    def test_get_backend_key(self):
        mgr = self._make_manager()
        mgr.create_key(
            tenant_id="acme-corp",
            provider="openai",
            backend_api_key="sk-test-key-abc",
        )
        result = mgr.get_backend_key("acme-corp", "openai")
        assert result == "sk-test-key-abc"

    def test_get_backend_key_nonexistent_tenant(self):
        mgr = self._make_manager()
        result = mgr.get_backend_key("ghost-tenant", "openai")
        assert result is None

    def test_get_backend_key_nonexistent_provider(self):
        mgr = self._make_manager()
        mgr.create_key("acme-corp", "openai", "sk-key")
        result = mgr.get_backend_key("acme-corp", "anthropic")
        assert result is None

    def test_key_encryption_roundtrip(self):
        mgr = self._make_manager()
        original = "sk-very-secret-api-key-xyz"
        encrypted = mgr._encrypt(original)
        assert encrypted != original  # Must not be plaintext
        decrypted = mgr._decrypt(encrypted)
        assert decrypted == original

    def test_key_rotation(self):
        mgr = self._make_manager()
        mgr.create_key("acme-corp", "openai", "sk-old-key")
        # Verify old key works
        assert mgr.get_backend_key("acme-corp", "openai") == "sk-old-key"
        # Rotate
        new_vkey = mgr.rotate_key("acme-corp", "openai", "sk-new-key")
        assert new_vkey is not None
        assert new_vkey.is_active is True
        # New key should be returned
        assert mgr.get_backend_key("acme-corp", "openai") == "sk-new-key"

    def test_key_revocation(self):
        mgr = self._make_manager()
        vkey = mgr.create_key("acme-corp", "openai", "sk-key-to-revoke")
        assert mgr.get_backend_key("acme-corp", "openai") == "sk-key-to-revoke"
        revoked = mgr.revoke_key("acme-corp", vkey.key_id)
        assert revoked is True
        # After revoke, key should not be returned
        assert mgr.get_backend_key("acme-corp", "openai") is None

    def test_revoke_nonexistent_key(self):
        mgr = self._make_manager()
        revoked = mgr.revoke_key("acme-corp", "vk_nonexistent")
        assert revoked is False

    def test_key_expiration(self):
        mgr = self._make_manager()
        vkey = mgr.create_key(
            "acme-corp", "openai", "sk-expiring",
            expires_in_days=1,
        )
        assert vkey.expired is False
        # Manually expire
        vkey.expires_at = time.time() - 1
        assert vkey.expired is True
        # Expired keys should not be returned
        assert mgr.get_backend_key("acme-corp", "openai") is None

    def test_list_keys(self):
        mgr = self._make_manager()
        mgr.create_key("acme-corp", "openai", "sk-key1", description="Key 1")
        mgr.create_key("acme-corp", "anthropic", "sk-key2", description="Key 2")
        keys = mgr.list_keys("acme-corp")
        assert len(keys) == 2
        providers = {k["provider"] for k in keys}
        assert providers == {"openai", "anthropic"}
        # Should NOT expose actual keys
        for k in keys:
            assert "sk-" not in str(k)

    def test_list_keys_empty_tenant(self):
        mgr = self._make_manager()
        keys = mgr.list_keys("ghost-tenant")
        assert keys == []

    def test_multiple_tenants_isolated(self):
        mgr = self._make_manager()
        mgr.create_key("tenant-a", "openai", "sk-tenant-a-key")
        mgr.create_key("tenant-b", "openai", "sk-tenant-b-key")
        assert mgr.get_backend_key("tenant-a", "openai") == "sk-tenant-a-key"
        assert mgr.get_backend_key("tenant-b", "openai") == "sk-tenant-b-key"

    def test_usage_tracking(self):
        mgr = self._make_manager()
        vkey = mgr.create_key("acme-corp", "openai", "sk-tracked")
        assert vkey.usage_count == 0
        mgr.get_backend_key("acme-corp", "openai")
        mgr.get_backend_key("acme-corp", "openai")
        mgr.get_backend_key("acme-corp", "openai")
        assert vkey.usage_count == 3
        assert vkey.last_used_at is not None

    def test_encryption_key_derivation(self):
        """Encryption key should be derived deterministically."""
        with patch.dict(os.environ, {"SENTINEL_JWT_SECRET": "test-secret-32chars-minimum!!!!"}):
            from src.services.virtual_keys import VirtualKeyManager
            mgr1 = VirtualKeyManager()
            mgr1._redis = None
            mgr2 = VirtualKeyManager()
            mgr2._redis = None
            assert mgr1._encryption_key == mgr2._encryption_key

    def test_create_key_with_no_expiry(self):
        mgr = self._make_manager()
        vkey = mgr.create_key("acme-corp", "openai", "sk-forever")
        assert vkey.expires_at is None
        assert vkey.expired is False


# ═══════════════════════════════════════════════════════════════════════
# Integration: Cache + Virtual Keys together
# ═══════════════════════════════════════════════════════════════════════


class TestServiceIntegration:
    """Verify services don't interfere with each other."""

    def test_cache_singleton_respects_env(self):
        """get_response_cache() should read env vars."""
        import src.services.response_cache as rc_module
        rc_module._cache = None  # Reset singleton
        with patch.dict(os.environ, {
            "SENTINEL_CACHE_ENABLED": "true",
            "SENTINEL_CACHE_TTL": "120",
            "SENTINEL_CACHE_MAX_SIZE": "500",
        }):
            cache = rc_module.get_response_cache()
            assert cache.enabled is True
            assert cache._ttl == 120
        rc_module._cache = None  # Cleanup

    def test_vkey_singleton(self):
        """get_virtual_key_manager() should return singleton."""
        import src.services.virtual_keys as vk_module
        vk_module._manager = None
        mgr1 = vk_module.get_virtual_key_manager()
        mgr2 = vk_module.get_virtual_key_manager()
        assert mgr1 is mgr2
        vk_module._manager = None  # Cleanup
