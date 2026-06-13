"""Audit log routes — Query + Export."""

from __future__ import annotations

import json
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse

from ..models.auth import TokenPayload
from ..models.metrics import AuditQuery
from ..services.auth_service import require_permission
from ..services.audit_logger import get_audit_logger

router = APIRouter()


@router.get("")
async def query_audit_log(
    actor: str = None,
    action: str = None,
    resource_type: str = None,
    tenant_id: str = None,
    limit: int = 50,
    offset: int = 0,
    user: TokenPayload = Depends(require_permission("audit:read")),
):
    """Query audit log with filters (including optional tenant_id)."""
    audit = get_audit_logger()
    query = AuditQuery(
        actor=actor, action=action, resource_type=resource_type,
        tenant_id=tenant_id, limit=limit, offset=offset,
    )
    entries = await audit.query(query)
    # If tenant_id filter is set, post-filter entries whose details mention the tenant
    if tenant_id:
        filtered = []
        for e in entries:
            if e.details and tenant_id in e.details:
                filtered.append(e)
            elif e.resource_id and tenant_id in e.resource_id:
                filtered.append(e)
        entries = filtered
    return [e.model_dump() for e in entries]


@router.get("/export")
async def export_audit_log(
    format: str = "json",
    user: TokenPayload = Depends(require_permission("audit:export")),
):
    """Export full audit log as JSON or CSV."""
    audit = get_audit_logger()
    entries = await audit.query(AuditQuery(limit=10000))

    if format == "csv":
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["id", "timestamp", "actor", "action", "resource_type", "resource_id", "result", "payload_hash"])
        for e in entries:
            writer.writerow([e.id, e.timestamp.isoformat(), e.actor, e.action, e.resource_type, e.resource_id, e.result, e.payload_hash])
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit_log.csv"},
        )
    else:
        data = json.dumps([e.model_dump(mode="json") for e in entries], indent=2, default=str)
        return StreamingResponse(
            iter([data]),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=audit_log.json"},
        )
