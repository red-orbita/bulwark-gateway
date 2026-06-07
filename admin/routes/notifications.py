"""Notification channel management routes."""

from __future__ import annotations

import uuid
from fastapi import APIRouter, Body, Depends, HTTPException

from ..models.auth import TokenPayload
from ..services.auth_service import require_permission
from ..services.audit_logger import get_audit_logger

import sys
sys.path.insert(0, ".")
from src.telemetry.notifications import (
    NotificationChannel,
    get_notification_engine,
)

router = APIRouter()


def _mask_secrets(ch: dict) -> dict:
    """Mask sensitive fields in API responses."""
    masked = dict(ch)
    for field in ("smtp_password", "routing_key", "api_key", "bot_token", "auth_value"):
        if masked.get(field):
            masked[field] = "***"
    # Mask URL tokens (common pattern: hooks.slack.com/services/T.../B.../xxx)
    if masked.get("url") and len(masked["url"]) > 30:
        masked["url"] = masked["url"][:30] + "***"
    return masked


@router.get("/channels")
async def list_channels(user: TokenPayload = Depends(require_permission("notifications:read"))):
    """List all configured notification channels."""
    engine = get_notification_engine()
    return {"channels": [_mask_secrets(c.to_dict()) for c in engine.channels]}


@router.get("/channels/{channel_id}")
async def get_channel(channel_id: str, user: TokenPayload = Depends(require_permission("notifications:read"))):
    """Get a single notification channel."""
    engine = get_notification_engine()
    for c in engine.channels:
        if c.id == channel_id:
            return {"channel": _mask_secrets(c.to_dict())}
    raise HTTPException(status_code=404, detail="Channel not found")


@router.post("/channels")
async def create_channel(
    data: dict = Body(...),
    user: TokenPayload = Depends(require_permission("notifications:write")),
):
    """Create a new notification channel."""
    engine = get_notification_engine()
    audit = get_audit_logger()

    # Validate required fields
    if not data.get("name"):
        raise HTTPException(status_code=400, detail="'name' is required")
    if not data.get("type"):
        raise HTTPException(status_code=400, detail="'type' is required")

    valid_types = ("slack", "teams", "discord", "pagerduty", "opsgenie",
                   "telegram", "google_chat", "email", "generic")
    if data["type"] not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid type. Must be one of: {', '.join(valid_types)}")

    # Validate type-specific required fields
    _validate_channel_fields(data)

    data["id"] = str(uuid.uuid4())[:8]
    channel = NotificationChannel.from_dict(data)
    engine.add_channel(channel)

    await audit.log(
        actor=user.sub,
        action="notification_channel_created",
        resource_type="notification_channel",
        resource_id=channel.id,
        details=str({"name": channel.name, "type": channel.type}),
    )
    return {"channel": _mask_secrets(channel.to_dict()), "message": "Channel created"}


@router.put("/channels/{channel_id}")
async def update_channel(
    channel_id: str,
    data: dict = Body(...),
    user: TokenPayload = Depends(require_permission("notifications:write")),
):
    """Update an existing notification channel."""
    engine = get_notification_engine()
    audit = get_audit_logger()

    # Verify channel exists
    if not any(c.id == channel_id for c in engine.channels):
        raise HTTPException(status_code=404, detail="Channel not found")

    # Don't allow changing ID
    data.pop("id", None)
    engine.update_channel(channel_id, data)

    await audit.log(
        actor=user.sub,
        action="notification_channel_updated",
        resource_type="notification_channel",
        resource_id=channel_id,
        details=str({"fields": list(data.keys())}),
    )
    return {"message": "Channel updated"}


@router.delete("/channels/{channel_id}")
async def delete_channel(
    channel_id: str,
    user: TokenPayload = Depends(require_permission("notifications:write")),
):
    """Delete a notification channel."""
    engine = get_notification_engine()
    audit = get_audit_logger()

    if not any(c.id == channel_id for c in engine.channels):
        raise HTTPException(status_code=404, detail="Channel not found")

    engine.remove_channel(channel_id)

    await audit.log(
        actor=user.sub,
        action="notification_channel_deleted",
        resource_type="notification_channel",
        resource_id=channel_id,
    )
    return {"message": "Channel deleted"}


@router.post("/channels/{channel_id}/test")
async def test_channel(
    channel_id: str,
    user: TokenPayload = Depends(require_permission("notifications:write")),
):
    """Send a test notification to verify channel connectivity."""
    engine = get_notification_engine()

    channel = None
    for c in engine.channels:
        if c.id == channel_id:
            channel = c
            break
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")

    result = await engine.test_channel(channel)
    return result


@router.post("/channels/{channel_id}/toggle")
async def toggle_channel(
    channel_id: str,
    user: TokenPayload = Depends(require_permission("notifications:write")),
):
    """Enable/disable a notification channel."""
    engine = get_notification_engine()

    for c in engine.channels:
        if c.id == channel_id:
            c.enabled = not c.enabled
            engine.save_channels(engine.channels)
            return {"enabled": c.enabled, "message": f"Channel {'enabled' if c.enabled else 'disabled'}"}
    raise HTTPException(status_code=404, detail="Channel not found")


@router.post("/reload")
async def reload_channels(user: TokenPayload = Depends(require_permission("notifications:write"))):
    """Reload notification channels from disk/YAML."""
    engine = get_notification_engine()
    engine.reload()
    return {"message": "Channels reloaded", "count": len(engine.channels)}


def _validate_channel_fields(data: dict):
    """Validate required fields per channel type."""
    ch_type = data["type"]

    if ch_type in ("slack", "teams", "discord", "google_chat", "generic"):
        if not data.get("url"):
            raise HTTPException(status_code=400, detail=f"'url' is required for {ch_type} channels")

    elif ch_type == "pagerduty":
        if not data.get("routing_key"):
            raise HTTPException(status_code=400, detail="'routing_key' is required for PagerDuty")

    elif ch_type == "opsgenie":
        if not data.get("api_key"):
            raise HTTPException(status_code=400, detail="'api_key' is required for Opsgenie")

    elif ch_type == "telegram":
        if not data.get("bot_token") or not data.get("chat_id"):
            raise HTTPException(status_code=400, detail="'bot_token' and 'chat_id' are required for Telegram")

    elif ch_type == "email":
        if not data.get("smtp_host") or not data.get("smtp_to"):
            raise HTTPException(status_code=400, detail="'smtp_host' and 'smtp_to' are required for email")
