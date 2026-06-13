"""Security Events routes — per-tenant event viewer + analytics."""

from __future__ import annotations

import asyncio
import json
from typing import Optional

from fastapi import APIRouter, Depends, Query

from ..models.auth import TokenPayload
from ..services.auth_service import require_permission

router = APIRouter()


@router.get("")
async def list_security_events(
    tenant: Optional[str] = Query(None, description="Filter by tenant ID"),
    category: Optional[str] = Query(None, description="Filter by threat category"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(50, ge=1, le=200),
    user: TokenPayload = Depends(require_permission("guardrails:read")),
):
    """Get security events from Redis, optionally filtered by tenant/category/severity."""
    def _fetch() -> list:
        try:
            from ..services.redis_sync import get_redis_client
            r = get_redis_client(timeout=2.0)
            if r is None:
                return []
            # Fetch from recent_blocks (up to 200 items to allow client-side post-filter)
            raw = r.lrange("sentinel:recent_blocks", 0, 199)
            events = []
            for item in raw:
                try:
                    evt = json.loads(item)
                    # Apply filters
                    if tenant and evt.get("tenant") != tenant:
                        continue
                    if category and evt.get("category") != category:
                        continue
                    if severity and evt.get("severity") != severity:
                        continue
                    events.append(evt)
                except (json.JSONDecodeError, TypeError):
                    continue
            return events[:limit]
        except Exception:
            return []

    return await asyncio.get_event_loop().run_in_executor(None, _fetch)


@router.get("/summary")
async def event_summary(
    user: TokenPayload = Depends(require_permission("guardrails:read")),
):
    """Get aggregated summary: events by category, severity, and tenant."""
    def _fetch() -> dict:
        try:
            from ..services.redis_sync import get_redis_client
            r = get_redis_client(timeout=2.0)
            if r is None:
                return {"by_tenant": {}, "by_category": {}, "by_severity": {}, "total": 0}
            raw = r.lrange("sentinel:recent_blocks", 0, 499)
            by_tenant: dict = {}
            by_category: dict = {}
            by_severity: dict = {}
            for item in raw:
                try:
                    evt = json.loads(item)
                    t = evt.get("tenant", "unknown")
                    c = evt.get("category", "unknown")
                    s = evt.get("severity", "unknown")
                    by_tenant[t] = by_tenant.get(t, 0) + 1
                    by_category[c] = by_category.get(c, 0) + 1
                    by_severity[s] = by_severity.get(s, 0) + 1
                except (json.JSONDecodeError, TypeError):
                    continue
            return {
                "by_tenant": by_tenant,
                "by_category": by_category,
                "by_severity": by_severity,
                "total": len(raw),
            }
        except Exception:
            return {"by_tenant": {}, "by_category": {}, "by_severity": {}, "total": 0}

    return await asyncio.get_event_loop().run_in_executor(None, _fetch)


@router.get("/tenant-analytics")
async def tenant_analytics(
    user: TokenPayload = Depends(require_permission("guardrails:read")),
):
    """Get combined per-tenant analytics: usage counters + recent event breakdown."""
    def _fetch() -> dict:
        try:
            from ..services.redis_sync import get_redis_client
            r = get_redis_client(timeout=2.0)
            if r is None:
                return {"tenants": {}}

            pipe = r.pipeline(transaction=False)
            pipe.hgetall("sentinel:usage:total")
            pipe.hgetall("sentinel:usage:block")
            pipe.hgetall("sentinel:usage:allow")
            pipe.lrange("sentinel:recent_blocks", 0, 499)
            total, blocked, allowed, recent_raw = pipe.execute()

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
            for item in (recent_raw or []):
                try:
                    evt = json.loads(item)
                    tid = evt.get("tenant", "unknown")
                    cat = evt.get("category", "unknown")
                    if tid not in tenants:
                        tenants[tid] = {
                            "total": 0, "blocked": 0, "allowed": 0,
                            "block_rate": 0.0, "categories": {},
                        }
                    tenants[tid]["categories"][cat] = tenants[tid]["categories"].get(cat, 0) + 1
                except (json.JSONDecodeError, TypeError):
                    continue

            return {"tenants": tenants}
        except Exception:
            return {"tenants": {}}

    return await asyncio.get_event_loop().run_in_executor(None, _fetch)
