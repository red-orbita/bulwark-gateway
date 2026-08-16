"""Cost tracking management routes — token usage & spend per tenant/agent.

The proxy's ``CostTracker`` accumulates token counts and estimated USD cost in
Redis (``bulwark:cost:*`` hashes). This admin surface reads those counters
directly from the shared Redis instance and exposes reset controls.

Cost accounting is always-on (there is no enable toggle to fake here). Pricing
is shown read-only for reference — it mirrors the proxy's built-in table.

Reads require ``cost:read`` (all roles); resets require ``cost:write``
(admin + security).
"""

from __future__ import annotations

import contextlib
import re

from fastapi import APIRouter, Depends, HTTPException

from ..models.auth import TokenPayload
from ..services.audit_logger import get_audit_logger
from ..services.auth_service import require_permission

router = APIRouter()

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,62}[a-z0-9]$")

_FIELDS = ("prompt", "completion", "total", "requests", "cost_usd")


def _can_write(user: TokenPayload) -> bool:
    """True if the caller's role includes cost:write."""
    try:
        from ..models.auth import ROLE_PERMISSIONS

        return "cost:write" in ROLE_PERMISSIONS.get(user.role, set())
    except Exception:
        return False


def _redis():
    try:
        from ..services.redis_sync import get_redis_client

        return get_redis_client()
    except Exception:
        return None


def _to_summary(raw: dict) -> dict:
    """Normalize a bulwark:cost hash into a typed summary dict."""
    raw = raw or {}

    def _i(k: str) -> int:
        try:
            return int(float(raw.get(k, 0) or 0))
        except (TypeError, ValueError):
            return 0

    def _f(k: str) -> float:
        try:
            return round(float(raw.get(k, 0) or 0), 6)
        except (TypeError, ValueError):
            return 0.0

    return {
        "prompt_tokens": _i("prompt"),
        "completion_tokens": _i("completion"),
        "total_tokens": _i("total"),
        "total_requests": _i("requests"),
        "estimated_cost_usd": _f("cost_usd"),
    }


def _scan(r, match: str) -> list[str]:
    """SCAN helper returning all keys matching a pattern (decode-safe)."""
    keys: list[str] = []
    with contextlib.suppress(Exception):
        for k in r.scan_iter(match=match, count=200):
            keys.append(k.decode() if isinstance(k, bytes) else k)
    return keys


@router.get("/status")
async def cost_status(
    user: TokenPayload = Depends(require_permission("cost:read")),
):
    """Global spend totals and coverage."""
    r = _redis()
    connected = False
    global_summary = _to_summary({})
    tenant_count = 0
    if r:
        try:
            r.ping()
            connected = True
            global_summary = _to_summary(r.hgetall("bulwark:cost:global"))
            tenant_count = len(_scan(r, "bulwark:cost:*:tokens"))
        except Exception:
            connected = False
    return {
        "redis_connected": connected,
        "can_write": _can_write(user),
        "global": global_summary,
        "tenants_tracked": tenant_count,
        "note": None
        if connected
        else "Redis not reachable — cost counters live in the proxy process only.",
    }


@router.get("/tenants")
async def cost_tenants(
    _user: TokenPayload = Depends(require_permission("cost:read")),
):
    """Per-tenant spend breakdown."""
    r = _redis()
    if not r:
        return {"tenants": [], "count": 0}
    out = []
    try:
        for key in _scan(r, "bulwark:cost:*:tokens"):
            # key = bulwark:cost:{tenant}:tokens
            parts = key.split(":")
            if len(parts) != 4:
                continue
            tenant_id = parts[2]
            summary = _to_summary(r.hgetall(key))
            summary["tenant_id"] = tenant_id
            out.append(summary)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Redis read error: {e}") from None
    out.sort(key=lambda s: s["estimated_cost_usd"], reverse=True)
    return {"tenants": out, "count": len(out)}


@router.get("/tenant/{tenant_id}")
async def cost_tenant_detail(
    tenant_id: str,
    _user: TokenPayload = Depends(require_permission("cost:read")),
):
    """Detailed per-agent spend for a single tenant."""
    if not _ID_RE.match(tenant_id):
        raise HTTPException(status_code=400, detail="Invalid tenant_id")
    r = _redis()
    if not r:
        raise HTTPException(status_code=503, detail="Redis not reachable")
    tenant_summary = _to_summary(r.hgetall(f"bulwark:cost:{tenant_id}:tokens"))
    tenant_summary["tenant_id"] = tenant_id
    agents = []
    for key in _scan(r, f"bulwark:cost:{tenant_id}:*"):
        if key.endswith(":tokens"):
            continue
        parts = key.split(":")
        if len(parts) != 4:
            continue
        agent_id = parts[3]
        raw = r.hgetall(key)
        summary = _to_summary(raw)
        summary["agent_id"] = agent_id
        model = raw.get("model") or raw.get(b"model") if raw else None
        if isinstance(model, bytes):
            model = model.decode()
        summary["model"] = model or "—"
        agents.append(summary)
    agents.sort(key=lambda s: s["estimated_cost_usd"], reverse=True)
    return {"tenant": tenant_summary, "agents": agents, "agent_count": len(agents)}


@router.get("/pricing")
async def cost_pricing(
    _user: TokenPayload = Depends(require_permission("cost:read")),
):
    """Reference model pricing table used for cost estimation (read-only)."""
    try:
        from src.services.cost_tracker import DEFAULT_PRICING

        pricing = DEFAULT_PRICING
    except Exception:
        pricing = {}
    rows = [
        {"model": m, "input_per_1m": p.get("input", 0.0), "output_per_1m": p.get("output", 0.0)}
        for m, p in pricing.items()
    ]
    return {"pricing": rows, "currency": "USD", "unit": "per 1M tokens", "editable": False}


@router.delete("/tenant/{tenant_id}")
async def reset_tenant_cost(
    tenant_id: str,
    user: TokenPayload = Depends(require_permission("cost:write")),
):
    """Reset accumulated cost counters for a single tenant (and its agents)."""
    if not _ID_RE.match(tenant_id):
        raise HTTPException(status_code=400, detail="Invalid tenant_id")
    r = _redis()
    if not r:
        raise HTTPException(status_code=503, detail="Redis not reachable")
    keys = _scan(r, f"bulwark:cost:{tenant_id}:*")
    deleted = 0
    if keys:
        try:
            deleted = r.delete(*keys)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Redis delete error: {e}") from None

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="cost.reset_tenant",
        resource_type="cost",
        resource_id=tenant_id,
        details=f"deleted {deleted} keys",
    )
    return {"message": f"Cost counters reset for '{tenant_id}'", "keys_deleted": deleted}


@router.post("/reset")
async def reset_all_cost(
    user: TokenPayload = Depends(require_permission("cost:write")),
):
    """Reset ALL accumulated cost counters (global + every tenant/agent)."""
    r = _redis()
    if not r:
        raise HTTPException(status_code=503, detail="Redis not reachable")
    keys = _scan(r, "bulwark:cost:*")
    deleted = 0
    if keys:
        try:
            deleted = r.delete(*keys)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Redis delete error: {e}") from None

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="cost.reset_all",
        resource_type="cost",
        resource_id="*",
        details=f"deleted {deleted} keys",
    )
    return {"message": "All cost counters reset", "keys_deleted": deleted}
