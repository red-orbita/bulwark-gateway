"""Dynamic guardrail registry — reads pattern state from Redis.

The admin portal writes to Redis when patterns are toggled/created/deleted.
The proxy reads from Redis with a local TTL cache to avoid per-request latency.

Redis keys:
  bulwark:guardrails:disabled   — SET of pattern_ids that are disabled
  bulwark:guardrails:custom     — HASH { pattern_id: JSON(regex, severity, category, layer) }
  bulwark:guardrails:exceptions — HASH { pattern_id: JSON(list of "tenant:agent" scopes) }
  bulwark:guardrails:version    — INT incremented on every change (cache invalidation)

Allow-exceptions (F2): a per-tenant/agent scoped exception does NOT silence a
pattern. When a would-be BLOCK matches a pattern that has an exception for the
requesting tenant/agent, the proxy degrades the verdict to WARN and stamps the
security event with ``allowed_by_exception=true`` so the allow remains fully
auditable. Scopes support ``tenant:agent`` (exact), ``tenant:*`` (any agent in
the tenant) and ``*:*`` (global).
"""

from __future__ import annotations

import json
import re
import threading
import time
from typing import Optional

import redis

from src.config import settings

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


# SECURITY FIX (M-04): Reduced cache TTL from 5s to 1s.
# 5s staleness window allowed disabled patterns to still trigger for too long
# after admin disables them. 1s is a reasonable balance between consistency
# and Redis load (version check only, not full data read on every request).
_CACHE_TTL = 1.0

# Maximum time (seconds) for a single custom regex match
_REGEX_TIMEOUT_SEC = 0.005  # 5ms

# Redis keys
KEY_DISABLED = "bulwark:guardrails:disabled"
KEY_CUSTOM = "bulwark:guardrails:custom"
KEY_EXCEPTIONS = "bulwark:guardrails:exceptions"
KEY_VERSION = "bulwark:guardrails:version"


class DynamicPatternRegistry:
    """Reads pattern overrides from Redis with local caching."""

    def __init__(self, redis_url: Optional[str] = None):
        self._redis: Optional[redis.Redis] = None
        self._disabled: set[str] = set()
        self._custom: list[str] = []
        self._compiled_custom: list[tuple[re.Pattern, dict]] = []
        self._exceptions: dict[str, set[str]] = {}
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

    def matched_exception(
        self, pattern_id: str, tenant_id: str, agent_id: str
    ) -> Optional[str]:
        """Return the scope string that grants an allow-exception, or None.

        An exception does NOT disable the pattern — it signals the caller to
        degrade a would-be BLOCK to WARN while keeping the event auditable.
        Scope precedence (most specific first): ``tenant:agent`` → ``tenant:*``
        → ``*:*``. Returns the FIRST matching scope so the audit trail records
        exactly which rule granted the allow.
        """
        self._refresh_if_needed()
        if not pattern_id:
            return None
        scopes = self._exceptions.get(pattern_id)
        if not scopes:
            return None
        for candidate in (
            f"{tenant_id}:{agent_id}",
            f"{tenant_id}:*",
            "*:*",
        ):
            if candidate in scopes:
                return candidate
        return None

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
            raw_version = self._redis.get(KEY_VERSION)
            version = int(raw_version) if raw_version else 0
            if version == self._cached_version:
                self._last_fetch = now
                return

            # Version changed — refresh
            self._disabled = {
                s.decode() if isinstance(s, bytes) else s
                for s in (self._redis.smembers(KEY_DISABLED) or set())
            }
            raw_custom = self._redis.hgetall(KEY_CUSTOM) or {}

            custom_patterns = []
            for pid_raw, raw in raw_custom.items():
                try:
                    pid = pid_raw.decode() if isinstance(pid_raw, bytes) else pid_raw
                    raw_str = raw.decode() if isinstance(raw, bytes) else raw
                    data = json.loads(raw_str)
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
            self._custom = [v.decode() if isinstance(v, bytes) else v for v in raw_custom.values()]

            # Allow-exceptions: HASH { pattern_id: JSON([ "tenant:agent", ... ]) }
            raw_exc = self._redis.hgetall(KEY_EXCEPTIONS) or {}
            exceptions: dict[str, set[str]] = {}
            for pid_raw, raw in raw_exc.items():
                try:
                    pid = pid_raw.decode() if isinstance(pid_raw, bytes) else pid_raw
                    raw_str = raw.decode() if isinstance(raw, bytes) else raw
                    scopes = json.loads(raw_str)
                    if isinstance(scopes, list) and scopes:
                        exceptions[pid] = {str(s) for s in scopes}
                except (json.JSONDecodeError, TypeError, ValueError):
                    continue
            self._exceptions = exceptions

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
