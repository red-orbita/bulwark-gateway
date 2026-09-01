"""Event-webhook subscription routes — SOAR trigger seed (Investigation Phase 1.3).

Manages the outbound event-webhook subscriptions that receive case lifecycle
events (``case.opened`` / ``case.severity_raised`` / ``case.resolved``). This is a
**separate router** mounted at ``/admin/integrations/webhooks`` and — critically —
registered *before* the ``/admin/integrations/{integration_id}`` catch-all in
``main.py`` so a bare ``GET /webhooks`` is not swallowed by the single-segment
integration lookup.

Reuses the ``integrations:read`` / ``integrations:write`` permission namespace.
Emission itself is best-effort and fail-open (see
:mod:`admin.services.integrations.event_webhook`).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Body, Depends, HTTPException

from ..models.auth import TokenPayload
from ..services.audit_logger import get_audit_logger
from ..services.auth_service import require_permission
from ..services.integrations.event_webhook import (
    EVENT_TYPES,
    WebhookSubscription,
    get_event_webhook_emitter,
)

router = APIRouter()


@router.get("")
async def list_webhooks(
    user: TokenPayload = Depends(require_permission("integrations:read")),
):
    """List all configured event-webhook subscriptions."""
    emitter = get_event_webhook_emitter()
    return {
        "webhooks": [s.to_dict() for s in emitter.subscriptions],
        "event_types": list(EVENT_TYPES),
    }


@router.get("/events")
async def list_event_types(
    user: TokenPayload = Depends(require_permission("integrations:read")),
):
    """List the lifecycle event types a subscription can filter on."""
    return {"event_types": list(EVENT_TYPES)}


@router.post("")
async def create_webhook(
    data: dict = Body(...),
    user: TokenPayload = Depends(require_permission("integrations:write")),
):
    """Create a new event-webhook subscription."""
    if not data.get("name"):
        raise HTTPException(status_code=400, detail="'name' is required")
    if not data.get("url"):
        raise HTTPException(status_code=400, detail="'url' is required")

    data["id"] = str(uuid.uuid4())[:8]
    sub = WebhookSubscription.from_dict(data)
    emitter = get_event_webhook_emitter()
    try:
        emitter.add(sub)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None

    await get_audit_logger().log(
        actor=user.sub,
        action="integration_webhook_created",
        resource_type="integration_webhook",
        resource_id=sub.id,
        details=str({"name": sub.name, "events": sub.events or "all"}),
    )
    return {"webhook": sub.to_dict(), "message": "Webhook created"}


@router.put("/{subscription_id}")
async def update_webhook(
    subscription_id: str,
    data: dict = Body(...),
    user: TokenPayload = Depends(require_permission("integrations:write")),
):
    """Update an existing event-webhook subscription."""
    data.pop("id", None)
    updated = get_event_webhook_emitter().update(subscription_id, data)
    if updated is None:
        raise HTTPException(status_code=404, detail="Webhook not found")

    await get_audit_logger().log(
        actor=user.sub,
        action="integration_webhook_updated",
        resource_type="integration_webhook",
        resource_id=subscription_id,
        details=str({"fields": list(data.keys())}),
    )
    return {"webhook": updated.to_dict(), "message": "Webhook updated"}


@router.delete("/{subscription_id}")
async def delete_webhook(
    subscription_id: str,
    user: TokenPayload = Depends(require_permission("integrations:write")),
):
    """Delete an event-webhook subscription."""
    if not get_event_webhook_emitter().remove(subscription_id):
        raise HTTPException(status_code=404, detail="Webhook not found")

    await get_audit_logger().log(
        actor=user.sub,
        action="integration_webhook_deleted",
        resource_type="integration_webhook",
        resource_id=subscription_id,
        details="",
    )
    return {"message": "Webhook deleted"}


@router.post("/{subscription_id}/toggle")
async def toggle_webhook(
    subscription_id: str,
    user: TokenPayload = Depends(require_permission("integrations:write")),
):
    """Enable/disable an event-webhook subscription."""
    enabled = get_event_webhook_emitter().toggle(subscription_id)
    if enabled is None:
        raise HTTPException(status_code=404, detail="Webhook not found")

    await get_audit_logger().log(
        actor=user.sub,
        action="integration_webhook_toggled",
        resource_type="integration_webhook",
        resource_id=subscription_id,
        details=str({"enabled": enabled}),
    )
    return {"id": subscription_id, "enabled": enabled}


@router.post("/{subscription_id}/test")
async def test_webhook(
    subscription_id: str,
    user: TokenPayload = Depends(require_permission("integrations:write")),
):
    """Send a synthetic ``test.ping`` event to one subscription."""
    if get_event_webhook_emitter().get(subscription_id) is None:
        raise HTTPException(status_code=404, detail="Webhook not found")
    result = await get_event_webhook_emitter().test(subscription_id)
    return {"ok": result.ok, "detail": result.detail}


@router.post("/reload")
async def reload_webhooks(
    user: TokenPayload = Depends(require_permission("integrations:write")),
):
    """Reload the subscription registry from disk."""
    get_event_webhook_emitter().reload()
    return {"message": "Webhooks reloaded"}
