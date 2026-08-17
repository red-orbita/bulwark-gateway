"""Audit log routes — Query + Export + Hash-Chain Verification."""

from __future__ import annotations

import json
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse, StreamingResponse

from ..models.auth import TokenPayload
from ..models.metrics import AuditQuery
from ..services.audit_chain import (
    ChainProof,
    ChainStatus,
    ChainVerification,
    TamperEvent,
    detect_tampering,
    export_chain_proof,
    get_chain_status,
    verify_chain,
)
from ..services.audit_logger import get_audit_logger
from ..services.auth_service import require_permission

router = APIRouter()


@router.get("")
async def query_audit_log(
    actor: str = None,
    action: str = None,
    resource_type: str = None,
    tenant_id: str = None,
    search: str = None,
    date_from: str = None,
    date_to: str = None,
    limit: int = 50,
    offset: int = 0,
    user: TokenPayload = Depends(require_permission("audit:read")),
):
    """Query audit log with filters.

    Supports free-text ``search`` (matches actor/action/resource/details),
    ``tenant_id``, and an inclusive ``date_from``/``date_to`` window. The total
    number of entries matching the filters (ignoring pagination) is returned in
    the ``X-Total-Count`` header so the UI can render an honest page count.
    """
    def _parse_date(value: str | None, *, end_of_day: bool) -> datetime | None:
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
        # A bare date (YYYY-MM-DD) parses to midnight; for the upper bound we
        # extend to the end of that day so the day itself is included.
        if end_of_day and parsed.hour == 0 and parsed.minute == 0 and parsed.second == 0:
            parsed = parsed.replace(hour=23, minute=59, second=59, microsecond=999999)
        return parsed

    audit = get_audit_logger()
    query = AuditQuery(
        actor=actor, action=action, resource_type=resource_type,
        tenant_id=tenant_id, search=search,
        start_date=_parse_date(date_from, end_of_day=False),
        end_date=_parse_date(date_to, end_of_day=True),
        limit=limit, offset=offset,
    )
    entries = await audit.query(query)
    total = await audit.count(query)
    return JSONResponse(
        content=[e.model_dump(mode="json") for e in entries],
        headers={
            "X-Total-Count": str(total),
            "Access-Control-Expose-Headers": "X-Total-Count",
        },
    )


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
        writer.writerow([
            "id", "timestamp", "actor", "action", "resource_type",
            "resource_id", "result", "payload_hash", "sequence_id",
            "previous_hash", "entry_hash",
        ])
        for e in entries:
            writer.writerow([
                e.id, e.timestamp.isoformat(), e.actor, e.action,
                e.resource_type, e.resource_id, e.result, e.payload_hash,
                e.sequence_id, e.previous_hash, e.entry_hash,
            ])
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


# ─── Hash-Chain Verification Endpoints ───────────────────────────────────────


@router.get("/chain/status", response_model=ChainStatus)
async def chain_status(
    user: TokenPayload = Depends(require_permission("audit:read")),
):
    """Get current audit chain status: head hash, length, health."""
    return await get_chain_status()


@router.post("/chain/verify", response_model=ChainVerification)
async def chain_verify(
    start_seq: int = Query(default=1, ge=1, description="Start sequence ID"),
    end_seq: int | None = Query(default=None, ge=1, description="End sequence ID (None = latest)"),
    user: TokenPayload = Depends(require_permission("audit:read")),
):
    """Verify hash-chain integrity over a range of entries.

    Returns an integrity report with any detected chain breaks.
    Processes in batches of 1000 for memory efficiency.
    """
    return await verify_chain(start_seq=start_seq, end_seq=end_seq)


@router.get("/chain/proof/{start_seq}/{end_seq}", response_model=ChainProof)
async def chain_proof(
    start_seq: int,
    end_seq: int,
    user: TokenPayload = Depends(require_permission("audit:export")),
):
    """Export a verifiable cryptographic proof for a range of entries.

    The proof contains all fields needed for an independent auditor to
    recompute every hash and verify chain integrity without DB access.
    Suitable for SOC 2 evidence packages.
    """
    return await export_chain_proof(start_seq=start_seq, end_seq=end_seq)


@router.get("/chain/tampering", response_model=list[TamperEvent])
async def chain_detect_tampering(
    user: TokenPayload = Depends(require_permission("audit:read")),
):
    """Scan the full chain for any broken links or tampered entries.

    Returns a list of TamperEvent objects describing each detected issue.
    Empty list means the chain is intact.
    """
    return await detect_tampering()
