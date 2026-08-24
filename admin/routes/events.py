"""Security Events routes — per-tenant event viewer + analytics.

The viewer reads from the **durable** ``security_events`` table (the admin's
queryable history), NOT the Redis live buffer. The proxy writes a capped buffer
to Redis on the hot path; a background sync (``events_sync``) drains that buffer
into the table. Reading from the table means the viewer:

* is not bounded by the Redis per-tenant cap (full retained history),
* survives Redis flushes / restarts,
* supports real SQL filtering, pagination and aggregate summaries.

``tenant-analytics`` still reads the Redis usage counters directly — those are
live rolling counters, not events, and have no durable-history equivalent.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query

from ..models.auth import TokenPayload
from ..services.auth_service import require_permission

logger = logging.getLogger("bulwark.routes.events")

router = APIRouter()


@router.get("")
async def list_security_events(
    tenant: Optional[str] = Query(None, description="Filter by tenant ID"),
    category: Optional[str] = Query(None, description="Filter by threat category"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    verdict: Optional[str] = Query(
        None,
        description="Feed selector: 'allowed' reads the opt-in allowed-event feed; "
        "'blocked'/'warned' filter the security feed; default = blocked + warned.",
    ),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user: TokenPayload = Depends(require_permission("guardrails:read")),
):
    """Get security events from the durable store, filtered by tenant/category/severity.

    The default feed is the security feed (BLOCK + WARN). ``verdict=allowed`` reads
    the separate, opt-in allowed-event records (``BULWARK_LOG_ALLOWED``) so
    legitimate traffic is browsable without drowning the security-relevant events.
    """
    try:
        from ..services.security_events_store import get_security_events_store
        store = get_security_events_store()
        return await store.query(
            tenant=tenant,
            category=category,
            severity=severity,
            verdict=verdict,
            limit=limit,
            offset=offset,
        )
    except Exception:
        return []


@router.get("/summary")
async def event_summary(
    user: TokenPayload = Depends(require_permission("guardrails:read")),
):
    """Get aggregated summary: events by category, severity, and tenant.

    Aggregates the *full retained* security feed (BLOCK + WARN) from the durable
    store — not just the last N Redis entries — plus a count of browsable
    allowed-event records (opt-in feed; zero unless BULWARK_LOG_ALLOWED is on).
    """
    try:
        from ..services.security_events_store import get_security_events_store
        store = get_security_events_store()
        return await store.summary()
    except Exception:
        return {"by_tenant": {}, "by_category": {}, "by_severity": {}, "total": 0, "allowed_recorded": 0}


@router.get("/tenant-analytics")
async def tenant_analytics(
    user: TokenPayload = Depends(require_permission("guardrails:read")),
):
    """Get combined per-tenant analytics: usage counters + recent event breakdown."""
    def _fetch() -> dict:
        try:
            from ..services.redis_sync import fetch_recent_blocks, get_redis_client
            r = get_redis_client(timeout=2.0)
            if r is None:
                return {"tenants": {}}

            pipe = r.pipeline(transaction=False)
            pipe.hgetall("bulwark:usage:total")
            pipe.hgetall("bulwark:usage:block")
            pipe.hgetall("bulwark:usage:allow")
            total, blocked, allowed = pipe.execute()
            # Recent blocks live in per-tenant lists — aggregate separately.
            recent = fetch_recent_blocks(r, max_items=500)

            total = total or {}
            blocked = blocked or {}
            allowed = allowed or {}

            # Build per-tenant result
            tenants: dict = {}
            all_tenant_ids = set(total.keys()) | set(blocked.keys()) | set(allowed.keys())
            for tid in all_tenant_ids:
                tenants[tid] = {
                    "total": int(total.get(tid, 0)),
                    "blocked": int(blocked.get(tid, 0)),
                    "allowed": int(allowed.get(tid, 0)),
                    "block_rate": 0.0,
                    "categories": {},
                }
                t = tenants[tid]["total"]
                if t > 0:
                    tenants[tid]["block_rate"] = round(
                        tenants[tid]["blocked"] / t * 100, 1
                    )

            # Enrich with category breakdown from recent blocks
            for evt in recent:
                tid = evt.get("tenant", "unknown")
                cat = evt.get("category", "unknown")
                if tid not in tenants:
                    tenants[tid] = {
                        "total": 0, "blocked": 0, "allowed": 0,
                        "block_rate": 0.0, "categories": {},
                    }
                tenants[tid]["categories"][cat] = tenants[tid]["categories"].get(cat, 0) + 1

            return {"tenants": tenants}
        except Exception:
            return {"tenants": {}}

    return await asyncio.get_event_loop().run_in_executor(None, _fetch)


@router.get("/settings")
async def get_events_settings(
    user: TokenPayload = Depends(require_permission("guardrails:read")),
):
    """Return the durable-history retention/storage settings for the portal.

    Shows the current overrides (set from this portal), the effective values
    (portal → env → default) and where each value comes from, so an operator can
    see at a glance whether retention is portal-managed, env-driven or default.
    """
    from ..services import events_settings
    return await events_settings.get_settings()


@router.post("/settings")
async def update_events_settings(
    data: dict = Body(...),
    user: TokenPayload = Depends(require_permission("guardrails:write")),
):
    """Persist retention/storage overrides and apply them to the live sync task.

    Body keys (all optional): ``retention_mode`` ('auto'|'custom'),
    ``retention_days`` (required for custom; 0 = keep forever),
    ``max_per_tenant`` (or null to clear), ``sync_interval_seconds`` (or null).
    """
    from ..services import events_settings
    from ..services.events_sync import get_events_sync

    try:
        result = await events_settings.update_settings(data, actor=user.sub)
    except events_settings.SettingsValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Apply to the running sync task immediately (don't wait for the next cycle).
    try:
        await get_events_sync().reload()
    except Exception as exc:  # noqa: BLE001 - settings are persisted regardless
        logger.debug("events_settings_reload_failed: %s", exc)

    return result
