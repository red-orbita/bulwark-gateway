"""
Response Cache — Exact-match and semantic caching for LLM responses.

Reduces LLM costs by caching responses for identical or semantically
similar queries. Supports:
  - Exact match: SHA-256 hash of (model + messages + temperature)
  - TTL-based expiration (configurable per tenant)
  - Cache hit/miss counters for monitoring
  - Redis backend (persistent) with in-memory LRU fallback

Configuration:
  SENTINEL_CACHE_ENABLED=true         Enable response caching
  SENTINEL_CACHE_TTL=3600             Default TTL in seconds (1 hour)
  SENTINEL_CACHE_MAX_SIZE=10000       Max entries in LRU fallback
  SENTINEL_CACHE_SKIP_STREAMING=true  Don't cache streaming responses

Redis keys:
  sentinel:cache:{hash}               — JSON-serialized response
  sentinel:cache:stats                 — HASH {hits, misses, evictions, savings_tokens}
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass
from typing import Any

from cachetools import LRUCache

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """A cached response with metadata."""

    response_data: dict[str, Any]
    model: str
    created_at: float
    ttl: int
    hit_count: int = 0
    tokens_saved: int = 0  # Accumulated tokens saved by serving from cache

    @property
    def expired(self) -> bool:
        return (time.time() - self.created_at) > self.ttl


@dataclass
class CacheStats:
    """Cache performance statistics."""

    hits: int = 0
    misses: int = 0
    evictions: int = 0
    total_tokens_saved: int = 0
    entries: int = 0

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0


class ResponseCache:
    """LLM response cache with exact-match lookup.

    Cache key = SHA-256(model + sorted_messages + temperature + tools).
    Ignores fields that don't affect output (stream, max_tokens, etc.)

    Usage:
        cache = ResponseCache(ttl=3600)

        # Check cache before backend call
        cached = cache.get(request_body)
        if cached:
            return cached  # Cache hit — no LLM call needed

        # After backend call, store response
        cache.put(request_body, response_data)
    """

    def __init__(
        self,
        ttl: int = 3600,
        max_size: int = 10000,
        enabled: bool = True,
    ):
        self._ttl = ttl
        self._enabled = enabled
        self._redis = None
        self._lru: LRUCache = LRUCache(maxsize=max_size)
        self._stats = CacheStats()
        self._init_redis()

    def _init_redis(self):
        """Try to connect to Redis."""
        try:
            from src.guardrails.dynamic_registry import get_pattern_registry
            registry = get_pattern_registry()
            self._redis = registry._redis
        except Exception:
            self._redis = None

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def stats(self) -> CacheStats:
        self._stats.entries = len(self._lru)
        return self._stats

    def get(self, request_body: dict[str, Any], tenant_id: str = "", agent_id: str = "") -> dict[str, Any] | None:
        """Look up cached response for a request.

        Args:
            request_body: The original chat completion request body.
            tenant_id: Tenant identifier for cache isolation.
            agent_id: Agent identifier for cache isolation.

        Returns:
            Cached response dict if hit, None if miss.
        """
        if not self._enabled:
            return None

        cache_key = self._compute_key(request_body, tenant_id, agent_id)

        # Try Redis first
        if self._redis:
            try:
                raw = self._redis.get(f"sentinel:cache:{cache_key}")
                if raw:
                    entry_data = json.loads(raw)
                    # Check TTL (Redis TTL handles this but double-check)
                    self._stats.hits += 1
                    tokens = entry_data.get("_tokens_saved", 0)
                    self._stats.total_tokens_saved += tokens
                    self._redis.hincrby("sentinel:cache:stats", "hits", 1)
                    self._redis.hincrby("sentinel:cache:stats", "savings_tokens", tokens)
                    # Return without internal metadata
                    response = entry_data.copy()
                    response.pop("_tokens_saved", None)
                    response.pop("_cached_at", None)
                    return response
            except Exception as e:
                logger.debug("cache_redis_get_error", extra={"error": str(e)[:100]})

        # Try in-memory LRU
        entry = self._lru.get(cache_key)
        if entry and isinstance(entry, CacheEntry):
            if entry.expired:
                # Expired — evict
                self._lru.pop(cache_key, None)
                self._stats.evictions += 1
                self._stats.misses += 1
                return None
            # Cache hit
            entry.hit_count += 1
            self._stats.hits += 1
            tokens = entry.response_data.get("usage", {}).get("total_tokens", 0)
            self._stats.total_tokens_saved += tokens
            return entry.response_data

        self._stats.misses += 1
        if self._redis:
            try:
                self._redis.hincrby("sentinel:cache:stats", "misses", 1)
            except Exception:
                pass
        return None

    def put(self, request_body: dict[str, Any], response_data: dict[str, Any], tenant_id: str = "", agent_id: str = "") -> None:
        """Store a response in the cache.

        Args:
            request_body: The original request (used to compute cache key).
            response_data: The backend response to cache.
            tenant_id: Tenant identifier for cache isolation.
            agent_id: Agent identifier for cache isolation.
        """
        if not self._enabled:
            return

        # Don't cache error responses
        if "error" in response_data:
            return

        # Don't cache empty responses
        choices = response_data.get("choices", [])
        if not choices:
            return

        cache_key = self._compute_key(request_body, tenant_id, agent_id)
        total_tokens = response_data.get("usage", {}).get("total_tokens", 0)

        # Store in Redis with TTL
        if self._redis:
            try:
                cache_data = response_data.copy()
                cache_data["_cached_at"] = time.time()
                cache_data["_tokens_saved"] = total_tokens
                self._redis.setex(
                    f"sentinel:cache:{cache_key}",
                    self._ttl,
                    json.dumps(cache_data),
                )
            except Exception as e:
                logger.debug("cache_redis_put_error", extra={"error": str(e)[:100]})

        # Also store in LRU (fast path for same-pod repeated queries)
        entry = CacheEntry(
            response_data=response_data,
            model=request_body.get("model", "unknown"),
            created_at=time.time(),
            ttl=self._ttl,
            tokens_saved=total_tokens,
        )
        self._lru[cache_key] = entry

    def invalidate(self, request_body: dict[str, Any], tenant_id: str = "", agent_id: str = "") -> bool:
        """Remove a specific entry from cache.

        Returns True if entry existed.
        """
        cache_key = self._compute_key(request_body, tenant_id, agent_id)
        removed = cache_key in self._lru
        self._lru.pop(cache_key, None)
        if self._redis:
            try:
                self._redis.delete(f"sentinel:cache:{cache_key}")
            except Exception:
                pass
        return removed

    def clear(self) -> None:
        """Clear all cached responses. Called on policy/IOC updates.

        SECURITY FIX (M-01): Invalidate cache when security policies change
        to prevent stale cached responses from bypassing updated IOC/policy rules.
        """
        self._lru.clear()
        self._stats = CacheStats()
        logger.info("response_cache_cleared", extra={"reason": "policy_or_ioc_update"})
        if self._redis:
            try:
                # Clear cache keys (scan + delete pattern)
                cursor = 0
                while True:
                    cursor, keys = self._redis.scan(cursor, match="sentinel:cache:*", count=100)
                    if keys:
                        self._redis.delete(*keys)
                    if cursor == 0:
                        break
            except Exception:
                pass

    def _compute_key(self, request_body: dict[str, Any], tenant_id: str = "", agent_id: str = "") -> str:
        """Compute deterministic cache key from request.

        Key components (order-independent):
          - tenant_id (isolation boundary)
          - agent_id (isolation boundary)
          - model
          - messages (sorted by role+content for stability)
          - temperature (affects output randomness)
          - tools (if present, affects response structure)

        Excluded (don't affect output content):
          - stream (presentation, not content)
          - max_tokens (truncation, not different content)
          - n (number of choices)
        """
        # SECURITY FIX (C-01): Tenant-isolated cache keys prevent cross-tenant data leakage
        key_parts = {
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "model": request_body.get("model", ""),
            "messages": self._normalize_messages(request_body.get("messages", [])),
            "temperature": request_body.get("temperature", 1.0),
        }

        # Include tools if present (they change response format)
        tools = request_body.get("tools")
        if tools:
            key_parts["tools"] = json.dumps(tools, sort_keys=True)

        tool_choice = request_body.get("tool_choice")
        if tool_choice:
            key_parts["tool_choice"] = str(tool_choice)

        key_str = json.dumps(key_parts, sort_keys=True, ensure_ascii=True)
        return hashlib.sha256(key_str.encode()).hexdigest()[:32]

    def _normalize_messages(self, messages: list[dict]) -> str:
        """Normalize messages for stable hashing."""
        normalized = []
        for msg in messages:
            normalized.append({
                "role": msg.get("role", ""),
                "content": msg.get("content", ""),
            })
        return json.dumps(normalized, sort_keys=True, ensure_ascii=True)


# === Singleton ===
_cache: ResponseCache | None = None


def get_response_cache() -> ResponseCache:
    """Get or create the global response cache singleton."""
    global _cache
    if _cache is None:
        import os
        enabled = os.environ.get("SENTINEL_CACHE_ENABLED", "false").lower() in ("true", "1")
        # SECURITY FIX (M-01): Reduced default TTL from 3600s to 300s to limit
        # staleness window when IOC/policy updates don't trigger explicit invalidation
        ttl = int(os.environ.get("SENTINEL_CACHE_TTL", "300"))
        max_size = int(os.environ.get("SENTINEL_CACHE_MAX_SIZE", "10000"))
        _cache = ResponseCache(ttl=ttl, max_size=max_size, enabled=enabled)
    return _cache
