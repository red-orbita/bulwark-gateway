"""Runtime-configurable settings for the durable security-events history.

Historically retention/storage knobs were env-only (``BULWARK_EVENTS_*``). This
module makes them **configurable from the admin portal** by persisting overrides
in the shared ``config`` key-value table, while keeping the env vars as the
bootstrap fallback.

Precedence for every effective value (highest wins):

1. **DB override** — set via the portal (``config`` table, ``events.*`` keys),
2. **environment variable** — ``BULWARK_EVENTS_*`` (deploy/Helm bootstrap),
3. **built-in default** — SIEM-aware for retention, fixed for the rest.

Retention semantics (``retention_days``):

* ``-1`` (or no override)  → *automatic*: env var if set, else SIEM-aware
  (90 days when a SIEM exporter is on, else 0 = keep forever),
* ``0``                    → keep forever (unlimited),
* ``> 0``                  → prune events older than N days.

The three ``config`` keys are read into a small process-level cache so the sync
loop's ``status()`` (sync context) and the pruning logic can resolve values
without awaiting the DB every call. ``refresh_cache()`` reloads it; the portal's
POST handler calls it right after a write so changes take effect immediately.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger("bulwark.events_settings")

# ``config`` table keys (namespaced to avoid collisions with other settings).
KEY_RETENTION_DAYS = "events.retention_days"
KEY_MAX_PER_TENANT = "events.max_per_tenant"
KEY_SYNC_INTERVAL = "events.sync_interval_seconds"

# Sentinel meaning "no explicit retention — fall back to env/SIEM-aware default".
RETENTION_AUTO = -1

# Built-in defaults (used when neither DB override nor env var is set).
DEFAULT_MAX_PER_TENANT = 1000
DEFAULT_SYNC_INTERVAL = 30
DEFAULT_SIEM_RETENTION_DAYS = 90

# Guardrails for operator-supplied values.
MIN_SYNC_INTERVAL = 5
MAX_SYNC_INTERVAL = 3600
MIN_MAX_PER_TENANT = 10
MAX_MAX_PER_TENANT = 1_000_000
MAX_RETENTION_DAYS = 3650  # 10 years

# Process-level cache of the raw DB overrides. ``None`` = key not overridden.
_cache: dict[str, Optional[int]] = {
    KEY_RETENTION_DAYS: None,
    KEY_MAX_PER_TENANT: None,
    KEY_SYNC_INTERVAL: None,
}
_cache_loaded = False


# ─── env / helpers ────────────────────────────────────────────────────────────

def _env_int(name: str) -> Optional[int]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _telemetry_enabled() -> bool:
    """Whether a SIEM exporter is configured (proxy's ``BULWARK_TELEMETRY_ENABLED``)."""
    return os.getenv("BULWARK_TELEMETRY_ENABLED", "").strip().lower() in (
        "1", "true", "yes", "on",
    )


# ─── cache load / persistence ─────────────────────────────────────────────────

async def refresh_cache() -> dict[str, Optional[int]]:
    """Reload the DB overrides into the process cache. Best-effort.

    A missing/uninitialised DB simply leaves the cache empty (all ``None``), so
    resolution falls back to env vars and defaults.
    """
    global _cache_loaded
    try:
        from .database import get_database
        db = get_database()
        rows = await db.fetch_all(
            "SELECT key, value FROM config WHERE key IN (?, ?, ?)",
            [KEY_RETENTION_DAYS, KEY_MAX_PER_TENANT, KEY_SYNC_INTERVAL],
        )
        loaded: dict[str, Optional[int]] = {
            KEY_RETENTION_DAYS: None,
            KEY_MAX_PER_TENANT: None,
            KEY_SYNC_INTERVAL: None,
        }
        for row in rows:
            d = row.to_dict() if hasattr(row, "to_dict") else dict(row)
            key = d.get("key")
            raw = d.get("value")
            if key in loaded and raw is not None:
                try:
                    loaded[key] = int(raw)
                except (TypeError, ValueError):
                    loaded[key] = None
        _cache.update(loaded)
        _cache_loaded = True
    except Exception as exc:  # noqa: BLE001 - best-effort; keep prior cache
        logger.debug("events_settings_cache_refresh_failed: %s", exc)
    return dict(_cache)


async def _persist(key: str, value: Optional[int], actor: str) -> None:
    """Upsert (or delete) a single override in the ``config`` table."""
    from datetime import datetime, timezone

    from .database import get_database
    db = get_database()
    if value is None:
        await db.execute("DELETE FROM config WHERE key = ?", [key])
    else:
        now = datetime.now(timezone.utc).isoformat()
        await db.execute(
            "INSERT OR REPLACE INTO config (key, value, updated_at, updated_by) "
            "VALUES (?, ?, ?, ?)",
            [key, str(int(value)), now, actor],
        )
    _cache[key] = value


# ─── effective-value resolution (sync — reads cache + env + default) ──────────

def effective_retention_days() -> int:
    """Resolve the effective retention window in days (0 = keep forever).

    DB override wins (unless it is the ``-1`` auto sentinel); then the
    ``BULWARK_EVENTS_RETENTION_DAYS`` env var; else SIEM-aware default.
    """
    override = _cache.get(KEY_RETENTION_DAYS)
    if override is not None and override != RETENTION_AUTO:
        return max(0, override)
    env = _env_int("BULWARK_EVENTS_RETENTION_DAYS")
    if env is not None:
        return max(0, env)
    return DEFAULT_SIEM_RETENTION_DAYS if _telemetry_enabled() else 0


def effective_max_items() -> int:
    """Resolve the per-tenant cap used when draining the Redis buffer."""
    override = _cache.get(KEY_MAX_PER_TENANT)
    if override is not None and override > 0:
        return override
    env = _env_int("BULWARK_EVENTS_MAX_PER_TENANT")
    if env is not None and env > 0:
        return env
    return DEFAULT_MAX_PER_TENANT


def effective_sync_interval() -> int:
    """Resolve the sync loop interval in seconds."""
    override = _cache.get(KEY_SYNC_INTERVAL)
    if override is not None and override > 0:
        return override
    env = _env_int("BULWARK_EVENTS_SYNC_INTERVAL")
    if env is not None and env > 0:
        return env
    return DEFAULT_SYNC_INTERVAL


def _source(key: str, env_name: str) -> str:
    """Report where the current effective value comes from (for the UI)."""
    override = _cache.get(key)
    if override is not None and not (key == KEY_RETENTION_DAYS and override == RETENTION_AUTO):
        return "portal"
    if _env_int(env_name) is not None:
        return "environment"
    return "default"


# ─── portal-facing API ────────────────────────────────────────────────────────

async def get_settings() -> dict:
    """Return the full settings view for the portal: overrides + effective + source."""
    await refresh_cache()
    retention_override = _cache.get(KEY_RETENTION_DAYS)
    retention_mode = (
        "auto"
        if retention_override is None or retention_override == RETENTION_AUTO
        else "custom"
    )
    return {
        "retention": {
            "mode": retention_mode,
            "custom_days": retention_override if retention_mode == "custom" else None,
            "effective_days": effective_retention_days(),
            "unlimited": effective_retention_days() == 0,
            "source": _source(KEY_RETENTION_DAYS, "BULWARK_EVENTS_RETENTION_DAYS"),
            "siem_aware": _telemetry_enabled(),
        },
        "max_per_tenant": {
            "override": _cache.get(KEY_MAX_PER_TENANT),
            "effective": effective_max_items(),
            "source": _source(KEY_MAX_PER_TENANT, "BULWARK_EVENTS_MAX_PER_TENANT"),
        },
        "sync_interval_seconds": {
            "override": _cache.get(KEY_SYNC_INTERVAL),
            "effective": effective_sync_interval(),
            "source": _source(KEY_SYNC_INTERVAL, "BULWARK_EVENTS_SYNC_INTERVAL"),
        },
    }


class SettingsValidationError(ValueError):
    """Raised when a portal-supplied settings payload is invalid."""


def _coerce_int(value, field: str) -> int:
    if isinstance(value, bool):  # bool is an int subclass — reject explicitly
        raise SettingsValidationError(f"{field} must be an integer")
    try:
        return int(value)
    except (TypeError, ValueError):
        raise SettingsValidationError(f"{field} must be an integer") from None


async def update_settings(data: dict, actor: str) -> dict:
    """Validate and persist portal-supplied overrides, then return the new view.

    Accepted keys (all optional; only provided keys are changed):

    * ``retention_mode``  — ``"auto"`` or ``"custom"``,
    * ``retention_days``  — required when mode is ``custom`` (0 = forever),
    * ``max_per_tenant``  — per-tenant Redis drain cap (or null to clear),
    * ``sync_interval_seconds`` — sync loop cadence (or null to clear).
    """
    if not isinstance(data, dict):
        raise SettingsValidationError("payload must be an object")

    # Retention
    if "retention_mode" in data or "retention_days" in data:
        mode = (data.get("retention_mode") or "").strip().lower()
        if not mode:
            # Infer from presence of retention_days.
            mode = "custom" if data.get("retention_days") is not None else "auto"
        if mode == "auto":
            await _persist(KEY_RETENTION_DAYS, RETENTION_AUTO, actor)
        elif mode == "custom":
            if data.get("retention_days") is None:
                raise SettingsValidationError("retention_days is required for custom mode")
            days = _coerce_int(data["retention_days"], "retention_days")
            if days < 0 or days > MAX_RETENTION_DAYS:
                raise SettingsValidationError(
                    f"retention_days must be between 0 and {MAX_RETENTION_DAYS}"
                )
            await _persist(KEY_RETENTION_DAYS, days, actor)
        else:
            raise SettingsValidationError("retention_mode must be 'auto' or 'custom'")

    # Max per tenant
    if "max_per_tenant" in data:
        val = data["max_per_tenant"]
        if val is None:
            await _persist(KEY_MAX_PER_TENANT, None, actor)
        else:
            n = _coerce_int(val, "max_per_tenant")
            if n < MIN_MAX_PER_TENANT or n > MAX_MAX_PER_TENANT:
                raise SettingsValidationError(
                    f"max_per_tenant must be between {MIN_MAX_PER_TENANT} and {MAX_MAX_PER_TENANT}"
                )
            await _persist(KEY_MAX_PER_TENANT, n, actor)

    # Sync interval
    if "sync_interval_seconds" in data:
        val = data["sync_interval_seconds"]
        if val is None:
            await _persist(KEY_SYNC_INTERVAL, None, actor)
        else:
            n = _coerce_int(val, "sync_interval_seconds")
            if n < MIN_SYNC_INTERVAL or n > MAX_SYNC_INTERVAL:
                raise SettingsValidationError(
                    f"sync_interval_seconds must be between {MIN_SYNC_INTERVAL} and {MAX_SYNC_INTERVAL}"
                )
            await _persist(KEY_SYNC_INTERVAL, n, actor)

    # Audit (best-effort — never block a successful settings write on audit).
    try:
        from .audit_logger import get_audit_logger
        await get_audit_logger().log(
            actor=actor,
            action="events_settings_update",
            resource_type="config",
            resource_id="events",
            details=f"retention={effective_retention_days()}d "
            f"max_per_tenant={effective_max_items()} "
            f"interval={effective_sync_interval()}s",
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("events_settings_audit_failed: %s", exc)

    return await get_settings()


def reset_cache_for_tests() -> None:
    """Clear the in-process cache (test helper)."""
    global _cache_loaded
    for k in _cache:
        _cache[k] = None
    _cache_loaded = False
