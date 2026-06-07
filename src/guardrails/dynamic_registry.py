"""Dynamic guardrail registry — reads pattern state from Redis.

The admin portal writes to Redis when patterns are toggled/created/deleted.
The proxy reads from Redis with a local TTL cache to avoid per-request latency.

Redis keys:
  sentinel:guardrails:disabled   — SET of pattern_ids that are disabled
  sentinel:guardrails:custom     — HASH { pattern_id: JSON(regex, severity, category, layer) }
  sentinel:guardrails:version    — INT incremented on every change (cache invalidation)
"""

from __future__ import annotations

import json
import re
import signal
import threading
import time
from typing import Optional

import redis


# --- ReDoS protection ---
# Reject patterns with dangerous quantifier nesting (e.g., (a+)+ or (a*)*b)
_REDOS_DANGEROUS = re.compile(
    r"(\(.+[\*\+]\)[\*\+])"  # nested quantifiers like (x+)+
    r"|(\.\*.*\.\*.*\.\*)"   # excessive .* chains (3+)
    r"|([\*\+\?]\{?\d*,?\d*\}?[\*\+\?])"  # adjacent quantifiers
)
_MAX_PATTERN_LENGTH = 500


def _safe_compile(pattern: str) -> re.Pattern:
    """Compile regex with ReDoS protection.
    
    Raises ValueError if pattern is potentially dangerous.
    Raises re.error if pattern is invalid.
    """
    if len(pattern) > _MAX_PATTERN_LENGTH:
        raise ValueError(f"Pattern too long ({len(pattern)} > {_MAX_PATTERN_LENGTH})")
    if _REDOS_DANGEROUS.search(pattern):
        raise ValueError("Pattern contains potentially dangerous quantifier nesting (ReDoS risk)")
    return re.compile(pattern, re.IGNORECASE)

from src.config import settings

# Cache TTL — proxy re-reads Redis every N seconds
_CACHE_TTL = 5.0

# Maximum time (seconds) for a single custom regex match
_REGEX_TIMEOUT_SEC = 0.005  # 5ms

# Redis keys
KEY_DISABLED = "sentinel:guardrails:disabled"
KEY_CUSTOM = "sentinel:guardrails:custom"
KEY_VERSION = "sentinel:guardrails:version"


class DynamicPatternRegistry:
    """Reads pattern overrides from Redis with local caching."""

    def __init__(self, redis_url: Optional[str] = None):
        self._redis: Optional[redis.Redis] = None
        self._disabled: set[str] = set()
        self._custom: list[dict] = []
        self._compiled_custom: list[tuple[re.Pattern, dict]] = []
        self._last_fetch: float = 0.0
        self._cached_version: int = -1
        self._lock = threading.Lock()

        url = redis_url or getattr(settings, "redis_url", None)
        if url:
            try:
                kwargs: dict = {"decode_responses": True, "socket_timeout": 1.0}
                if url.startswith("rediss://") and getattr(settings, "redis_tls_insecure", False):
                    import ssl
                    kwargs["ssl_cert_reqs"] = ssl.CERT_NONE
                self._redis = redis.from_url(url, **kwargs)
                self._redis.ping()
            except Exception:
                self._redis = None

    @property
    def available(self) -> bool:
        return self._redis is not None

    def is_disabled(self, pattern_id: str) -> bool:
        """Check if a pattern is disabled. Uses cached state."""
        self._refresh_if_needed()
        return pattern_id in self._disabled

    def get_custom_patterns(self) -> list[tuple[re.Pattern, dict]]:
        """Get compiled custom patterns. Uses cached state."""
        self._refresh_if_needed()
        return self._compiled_custom

    def _refresh_if_needed(self) -> None:
        """Re-read Redis if cache expired or version changed."""
        now = time.time()
        if now - self._last_fetch < _CACHE_TTL:
            return
        if not self._redis:
            return

        # Prevent concurrent refresh from multiple threads/tasks
        if not self._lock.acquire(blocking=False):
            return  # Another thread is refreshing; use cached state

        try:
            # Check version first (cheap)
            version = self._redis.get(KEY_VERSION)
            version = int(version) if version else 0
            if version == self._cached_version:
                self._last_fetch = now
                return

            # Version changed — refresh
            self._disabled = self._redis.smembers(KEY_DISABLED) or set()
            raw_custom = self._redis.hgetall(KEY_CUSTOM) or {}

            custom_patterns = []
            for pid, raw in raw_custom.items():
                try:
                    data = json.loads(raw)
                    compiled = _safe_compile(data["regex"])
                    custom_patterns.append((compiled, {
                        "id": pid,
                        "severity": data.get("severity", "high"),
                        "category": data.get("category", "custom"),
                        "description": data.get("description", "Custom pattern"),
                        "layer": data.get("layer", "input"),
                    }))
                except (json.JSONDecodeError, re.error, ValueError):
                    continue

            self._compiled_custom = custom_patterns
            self._custom = list(raw_custom.values())
            self._cached_version = version
            self._last_fetch = now
        except Exception:
            # Redis down — use last cached state
            self._last_fetch = now
        finally:
            self._lock.release()


# Singleton
_registry: Optional[DynamicPatternRegistry] = None


def get_pattern_registry() -> DynamicPatternRegistry:
    global _registry
    if _registry is None:
        _registry = DynamicPatternRegistry()
    return _registry


def safe_regex_search(compiled: re.Pattern, text: str, timeout: float = _REGEX_TIMEOUT_SEC) -> Optional[re.Match]:
    """Execute regex search with a timeout to prevent ReDoS in the hot path.

    Uses a thread with join(timeout) — if the regex doesn't complete in time,
    returns None (fail-closed: pattern is skipped, not the request).
    """
    import threading

    result: list = [None]

    def _search():
        result[0] = compiled.search(text)

    t = threading.Thread(target=_search, daemon=True)
    t.start()
    t.join(timeout=timeout)
    if t.is_alive():
        # Regex timed out — possible ReDoS; skip this pattern
        return None
    return result[0]
