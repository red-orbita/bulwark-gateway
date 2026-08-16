"""Session decomposition tracker routes — observability + runtime tuning.

The proxy's ``SessionDecompositionTracker`` accumulates per-session "threat
signals" in Redis sorted sets to catch multi-turn decomposition attacks (a
dangerous request split into individually-benign chunks). This admin surface
exposes:

  * live thresholds (defaults merged with any runtime override)
  * the read-only signal catalog (decomposition indicators + dangerous combos)
  * active sessions with accumulated score / signal count / TTL
  * a **real** runtime override (thresholds + windows) written to
    ``bulwark:session:config`` — the proxy honors it within ~5s without restart
  * per-session and global reset controls

Redis keys read/managed here:
  bulwark:session:{key}:signals      — 5-minute sliding window (sorted set)
  bulwark:session_30m:{key}:signals  — 30-minute sliding window (sorted set)
  bulwark:session:config             — runtime override HASH

Session keys are irreversible SHA-256 digests (tenant+agent, or tenant-level);
they cannot be mapped back to a tenant/agent identity, so they are shown as-is.

Reads require ``sessions:read`` (all roles); mutations require ``sessions:write``
(admin + security). Tightening thresholds hardens detection immediately; the
reset controls exist for incident response and tuning validation.
"""

from __future__ import annotations

import contextlib
import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..models.auth import TokenPayload
from ..services.audit_logger import get_audit_logger
from ..services.auth_service import require_permission

router = APIRouter()

_CONFIG_KEY = "bulwark:session:config"
_SIGNALS_5M_PREFIX = "bulwark:session:"
_SIGNALS_30M_PREFIX = "bulwark:session_30m:"
_SIGNALS_SUFFIX = ":signals"

# Session keys are sha256()[:16] hex digests.
_KEY_RE = re.compile(r"^[0-9a-f]{16}$")

# Tunable override fields: name -> (is_int, human label). Floats unless is_int.
_CONFIG_FIELDS: dict[str, tuple[bool, str]] = {
    "block_threshold": (False, "5-min BLOCK threshold"),
    "warn_threshold": (False, "5-min WARN threshold"),
    "window_seconds": (True, "5-min window (seconds)"),
    "block_threshold_30m": (False, "30-min BLOCK threshold"),
    "warn_threshold_30m": (False, "30-min WARN threshold"),
    "window_30m_seconds": (True, "30-min window (seconds)"),
}


class SessionConfigUpdate(BaseModel):
    """Runtime override for the decomposition tracker thresholds/windows.

    All fields optional; only provided fields are written. Values must be
    positive. Windows are integer seconds; thresholds are floats.
    """

    block_threshold: float | None = Field(default=None, gt=0, le=1000)
    warn_threshold: float | None = Field(default=None, gt=0, le=1000)
    window_seconds: int | None = Field(default=None, ge=10, le=86400)
    block_threshold_30m: float | None = Field(default=None, gt=0, le=1000)
    warn_threshold_30m: float | None = Field(default=None, gt=0, le=1000)
    window_30m_seconds: int | None = Field(default=None, ge=10, le=604800)


def _redis():
    try:
        from ..services.redis_sync import get_redis_client

        return get_redis_client()
    except Exception:
        return None


def _can_write(user: TokenPayload) -> bool:
    """True if the caller's role includes sessions:write."""
    try:
        from ..models.auth import ROLE_PERMISSIONS

        return "sessions:write" in ROLE_PERMISSIONS.get(user.role, set())
    except Exception:
        return False


def _num(v, is_int: bool):
    """Parse a redis string into int/float, or None if invalid/non-positive."""
    try:
        parsed = int(float(v)) if is_int else float(v)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _defaults() -> dict:
    """Class-level default thresholds/windows from the proxy tracker.

    Lazily imported so this admin module stays importable even if the proxy
    package is unavailable; falls back to the documented defaults.
    """
    try:
        from src.guardrails.session_tracker import SessionDecompositionTracker as T

        return {
            "block_threshold": float(T.BLOCK_THRESHOLD),
            "warn_threshold": float(T.WARN_THRESHOLD),
            "window_seconds": int(T.WINDOW_SECONDS),
            "block_threshold_30m": float(T.BLOCK_THRESHOLD_30M),
            "warn_threshold_30m": float(T.WARN_THRESHOLD_30M),
            "window_30m_seconds": int(T.WINDOW_30M_SECONDS),
        }
    except Exception:
        return {
            "block_threshold": 8.0,
            "warn_threshold": 5.0,
            "window_seconds": 300,
            "block_threshold_30m": 4.8,
            "warn_threshold_30m": 3.0,
            "window_30m_seconds": 1800,
        }


def _catalog() -> dict:
    """Read-only decomposition signal catalog + dangerous combinations."""
    try:
        from src.guardrails.session_tracker import (
            _DANGEROUS_COMBINATIONS,
            _DECOMPOSITION_SIGNALS,
        )

        signals = [
            {"signal_id": sid, "weight": float(weight)}
            for _pat, sid, weight in _DECOMPOSITION_SIGNALS
        ]
        combos = [
            {
                "signals": sorted(required),
                "bonus": float(bonus),
                "description": desc,
            }
            for required, bonus, desc in _DANGEROUS_COMBINATIONS
        ]
        return {"signals": signals, "combinations": combos}
    except Exception:
        return {"signals": [], "combinations": []}


def _read_override(r) -> dict:
    """Read the runtime override HASH. Missing = no override (defaults apply)."""
    try:
        raw = r.hgetall(_CONFIG_KEY) or {}
    except Exception:
        raw = {}
    override: dict[str, float | int] = {}
    for field_name, (is_int, _label) in _CONFIG_FIELDS.items():
        if field_name in raw:
            val = _num(raw[field_name], is_int)
            if val is not None:
                override[field_name] = val
    return override


def _decode(k) -> str:
    return k.decode() if isinstance(k, bytes) else k


def _scan(r, match: str) -> list[str]:
    keys: list[str] = []
    with contextlib.suppress(Exception):
        for k in r.scan_iter(match=match, count=200):
            keys.append(_decode(k))
    return keys


def _summarize_session(r, redis_key: str, window: str) -> dict | None:
    """Compute score/signal summary for one session signals key.

    Members are stored as ``signal_id:weight`` with the timestamp as score.
    Returns None on error or empty set.
    """
    try:
        members = r.zrange(redis_key, 0, -1, withscores=True)
    except Exception:
        return None
    if not members:
        return None

    signal_ids: set[str] = set()
    total_score = 0.0
    oldest_ts: float | None = None
    newest_ts: float | None = None
    for member, ts in members:
        entry = _decode(member)
        parts = entry.rsplit(":", 1)
        if len(parts) == 2:
            signal_ids.add(parts[0])
            with contextlib.suppress(ValueError):
                total_score += float(parts[1])
        try:
            ts_f = float(ts)
        except (TypeError, ValueError):
            continue
        oldest_ts = ts_f if oldest_ts is None else min(oldest_ts, ts_f)
        newest_ts = ts_f if newest_ts is None else max(newest_ts, ts_f)

    ttl = None
    with contextlib.suppress(Exception):
        raw_ttl = r.ttl(redis_key)
        if isinstance(raw_ttl, int) and raw_ttl >= 0:
            ttl = raw_ttl

    # Extract the hashed session key from the redis key.
    prefix = _SIGNALS_30M_PREFIX if window == "30m" else _SIGNALS_5M_PREFIX
    key = redis_key[len(prefix):]
    if key.endswith(_SIGNALS_SUFFIX):
        key = key[: -len(_SIGNALS_SUFFIX)]

    return {
        "session_key": key,
        "window": window,
        "score": round(total_score, 2),
        "signal_count": len(members),
        "distinct_signals": sorted(signal_ids),
        "ttl_seconds": ttl,
        "oldest_ts": oldest_ts,
        "newest_ts": newest_ts,
    }


def _all_session_keys(r) -> list[tuple[str, str]]:
    """Return (redis_key, window) for every active session signals key."""
    out: list[tuple[str, str]] = []
    # 30m keys share the bulwark:session prefix space; match precisely.
    for k in _scan(r, f"{_SIGNALS_30M_PREFIX}*{_SIGNALS_SUFFIX}"):
        out.append((k, "30m"))
    for k in _scan(r, f"{_SIGNALS_5M_PREFIX}*{_SIGNALS_SUFFIX}"):
        if k.startswith(_SIGNALS_30M_PREFIX):
            continue  # already captured as 30m
        out.append((k, "5m"))
    return out


@router.get("/status")
async def sessions_status(
    user: TokenPayload = Depends(require_permission("sessions:read")),
):
    """Effective thresholds, override state, catalog counts, active count."""
    defaults = _defaults()
    catalog = _catalog()

    r = _redis()
    connected = False
    override: dict = {}
    active = 0
    if r:
        try:
            r.ping()
            connected = True
            override = _read_override(r)
            active = len(_all_session_keys(r))
        except Exception:
            connected = False

    effective = {**defaults, **override}

    return {
        "redis_connected": connected,
        "can_write": _can_write(user),
        "effective": effective,
        "defaults": defaults,
        "override": override,
        "overridden": bool(override),
        "active_sessions": active,
        "catalog_counts": {
            "signals": len(catalog["signals"]),
            "combinations": len(catalog["combinations"]),
        },
        "note": None
        if connected
        else "Redis not reachable — active sessions and runtime override require Redis.",
    }


@router.get("/signals")
async def sessions_signals(
    user: TokenPayload = Depends(require_permission("sessions:read")),
):
    """Read-only decomposition signal catalog + dangerous combinations."""
    catalog = _catalog()
    return {
        "signals": catalog["signals"],
        "combinations": catalog["combinations"],
        "count": len(catalog["signals"]),
    }


@router.get("/active")
async def sessions_active(
    user: TokenPayload = Depends(require_permission("sessions:read")),
    limit: int = 200,
):
    """List active sessions across both time windows with accumulated scores."""
    limit = max(1, min(limit, 1000))
    r = _redis()
    if not r:
        return {"redis_connected": False, "sessions": [], "count": 0}

    try:
        r.ping()
    except Exception:
        return {"redis_connected": False, "sessions": [], "count": 0}

    sessions: list[dict] = []
    for redis_key, window in _all_session_keys(r):
        summary = _summarize_session(r, redis_key, window)
        if summary:
            sessions.append(summary)
        if len(sessions) >= limit:
            break

    # Highest accumulated score first — most suspicious sessions on top.
    sessions.sort(key=lambda s: s["score"], reverse=True)
    return {"redis_connected": True, "sessions": sessions, "count": len(sessions)}


@router.put("/config")
async def update_session_config(
    body: SessionConfigUpdate,
    user: TokenPayload = Depends(require_permission("sessions:write")),
):
    """Set a runtime override for tracker thresholds/windows.

    Written to ``bulwark:session:config``; the proxy re-reads within ~5s.
    Passing no fields is rejected to avoid silent no-ops.
    """
    provided = body.model_dump(exclude_none=True)
    if not provided:
        raise HTTPException(
            status_code=400,
            detail="Provide at least one field: " + ", ".join(_CONFIG_FIELDS),
        )
    r = _redis()
    if not r:
        raise HTTPException(status_code=503, detail="Redis not reachable — cannot set runtime override")

    mapping = {k: str(v) for k, v in provided.items()}
    try:
        r.hset(_CONFIG_KEY, mapping=mapping)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Redis write error: {e}") from None

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="sessions.config_update",
        resource_type="sessions",
        resource_id="config",
        details=str(mapping),
    )
    return {"message": "Session tracker override updated", "override": _read_override(r)}


@router.delete("/config")
async def clear_session_config(
    user: TokenPayload = Depends(require_permission("sessions:write")),
):
    """Remove the runtime override so the proxy reverts to built-in defaults."""
    r = _redis()
    if not r:
        raise HTTPException(status_code=503, detail="Redis not reachable")
    try:
        r.delete(_CONFIG_KEY)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Redis delete error: {e}") from None

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="sessions.config_clear",
        resource_type="sessions",
        resource_id="config",
        details="reverted to built-in defaults",
    )
    return {"message": "Runtime override cleared — proxy reverts to built-in defaults"}


@router.delete("/session/{session_key}")
async def delete_session(
    session_key: str,
    user: TokenPayload = Depends(require_permission("sessions:write")),
):
    """Clear accumulated signals for one session (both time windows).

    ``session_key`` is the irreversible 16-hex digest shown in the active list.
    """
    if not _KEY_RE.match(session_key):
        raise HTTPException(status_code=400, detail="Invalid session key (expected 16 hex chars)")
    r = _redis()
    if not r:
        raise HTTPException(status_code=503, detail="Redis not reachable")

    keys = [
        f"{_SIGNALS_5M_PREFIX}{session_key}{_SIGNALS_SUFFIX}",
        f"{_SIGNALS_30M_PREFIX}{session_key}{_SIGNALS_SUFFIX}",
    ]
    deleted = 0
    try:
        deleted = r.delete(*keys)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Redis delete error: {e}") from None

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="sessions.delete",
        resource_type="sessions",
        resource_id=session_key,
        details=f"cleared {deleted} window key(s)",
    )
    return {"message": "Session cleared", "keys_deleted": deleted}


@router.post("/reset")
async def reset_all_sessions(
    user: TokenPayload = Depends(require_permission("sessions:write")),
):
    """Clear ALL accumulated session signals (both windows). Keeps config."""
    r = _redis()
    if not r:
        raise HTTPException(status_code=503, detail="Redis not reachable")

    keys = [k for k, _w in _all_session_keys(r)]
    deleted = 0
    if keys:
        try:
            deleted = r.delete(*keys)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Redis delete error: {e}") from None

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="sessions.reset",
        resource_type="sessions",
        resource_id="*",
        details=f"cleared {deleted} session key(s)",
    )
    return {"message": "All sessions cleared", "keys_deleted": deleted}
