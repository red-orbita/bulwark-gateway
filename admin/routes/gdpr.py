"""GDPR Compliance API — Pseudonymization, Data Export, Retention, Inventory.

Endpoints for GDPR Art.15 (access), Art.17 (erasure), Art.30 (processing records).
All actions are audit-logged. Pseudonymization is irreversible.
"""

from __future__ import annotations

import json
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse

from ..models.auth import UserRole, TokenPayload
from ..services.auth_service import require_role
from ..services.gdpr import (
    PseudonymizeRequest,
    ExportRequest,
    get_gdpr_service,
)

router = APIRouter()

# ─── Rate Limiting (per-endpoint, in-memory) ─────────────────────────────────
# GDPR endpoints are sensitive — limit to prevent abuse.

_rate_limit_store: dict[str, list[float]] = {}  # key -> [timestamps]
_GDPR_RATE_LIMIT_RPM = 10  # max 10 GDPR requests per minute per user


def _check_rate_limit(user_id: str, endpoint: str) -> None:
    """Simple sliding-window rate limiter for GDPR endpoints."""
    key = f"{user_id}:{endpoint}"
    now = time.time()
    window_start = now - 60.0

    timestamps = _rate_limit_store.get(key, [])
    # Prune old entries
    timestamps = [t for t in timestamps if t > window_start]

    if len(timestamps) >= _GDPR_RATE_LIMIT_RPM:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"GDPR rate limit exceeded ({_GDPR_RATE_LIMIT_RPM} requests/minute). "
                   "These operations are audit-logged and rate-limited for security."
        )

    timestamps.append(now)
    _rate_limit_store[key] = timestamps


def _validate_confirmation(confirmation: str, expected_count: int) -> None:
    """Validate the GDPR confirmation string matches expected format."""
    expected = f"I confirm this action affects {expected_count} records"
    if confirmation != expected:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "Confirmation mismatch",
                "expected_format": "I confirm this action affects N records",
                "hint": f"Use the count endpoint first to determine affected records, "
                        f"then confirm with the exact count.",
            }
        )


# ─── POST /admin/gdpr/pseudonymize ───────────────────────────────────────────

@router.post("/pseudonymize")
async def pseudonymize_subject(
    request: Request,
    body: PseudonymizeRequest,
    user: TokenPayload = Depends(require_role(UserRole.ADMIN)),
):
    """Pseudonymize all PII for a data subject (GDPR Art.17).

    Replaces identifiable fields with irreversible HMAC-SHA256 hashes.
    This action CANNOT be undone.

    Requires:
    - Admin role
    - Confirmation string matching affected record count
    """
    _check_rate_limit(user.sub, "pseudonymize")

    gdpr = get_gdpr_service()

    # Count affected records first to validate confirmation
    affected = await gdpr._count_subject_records(body.subject_id)
    _validate_confirmation(body.confirmation, affected)

    # Execute pseudonymization
    ip_address = request.client.host if request.client else None
    result = await gdpr.pseudonymize_subject(
        subject_id=body.subject_id,
        requested_by=user.sub,
        ip_address=ip_address,
    )

    return result


# ─── POST /admin/gdpr/export ─────────────────────────────────────────────────

@router.post("/export")
async def export_subject_data(
    request: Request,
    body: ExportRequest,
    user: TokenPayload = Depends(require_role(UserRole.ADMIN)),
):
    """Export all data related to a subject (GDPR Art.15 — right of access).

    Returns a downloadable JSON file with all personal data.
    """
    _check_rate_limit(user.sub, "export")

    gdpr = get_gdpr_service()
    ip_address = request.client.host if request.client else None

    export_data = await gdpr.export_subject_data(
        subject_id=body.subject_id,
        requested_by=user.sub,
        include_security_events=body.include_security_events,
        include_audit_entries=body.include_audit_entries,
        include_rate_limit_history=body.include_rate_limit_history,
        ip_address=ip_address,
    )

    # Return as downloadable JSON
    content = json.dumps(export_data, indent=2, default=str)
    filename = f"gdpr_export_{body.subject_id}_{export_data['export_id'][:8]}.json"

    return StreamingResponse(
        iter([content]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ─── GET /admin/gdpr/data-inventory ──────────────────────────────────────────

@router.get("/data-inventory")
async def get_data_inventory(
    user: TokenPayload = Depends(require_role(UserRole.ADMIN, UserRole.AUDITOR)),
):
    """Records of processing activities (GDPR Art.30).

    Returns structured list of all data categories processed,
    with purpose, legal basis, retention period, and recipients.
    """
    gdpr = get_gdpr_service()
    inventory = await gdpr.data_inventory()
    return {
        "processing_activities": inventory,
        "controller": "Sentinel Gateway operator (see deployment config)",
        "dpo_contact": "Configured by deploying organization",
        "last_updated": "auto-generated",
        "total_categories": len(inventory),
    }


# ─── POST /admin/gdpr/retention/enforce ──────────────────────────────────────

@router.post("/retention/enforce")
async def enforce_retention_policy(
    request: Request,
    user: TokenPayload = Depends(require_role(UserRole.ADMIN)),
):
    """Trigger retention policy enforcement.

    Archives records beyond retention period to cold storage,
    then deletes from active database. Audit-logged.
    """
    _check_rate_limit(user.sub, "retention_enforce")

    gdpr = get_gdpr_service()
    ip_address = request.client.host if request.client else None

    result = await gdpr.retention_policy_enforce(
        requested_by=user.sub,
        ip_address=ip_address,
    )

    return result


# ─── GET /admin/gdpr/retention/status ─────────────────────────────────────────

@router.get("/retention/status")
async def get_retention_status(
    user: TokenPayload = Depends(require_role(UserRole.ADMIN, UserRole.AUDITOR)),
):
    """Get retention policy configuration and last enforcement status."""
    gdpr = get_gdpr_service()
    status = await gdpr.get_retention_status()
    return status.model_dump()


# ─── GET /admin/gdpr/requests ─────────────────────────────────────────────────

@router.get("/requests")
async def list_gdpr_requests(
    limit: int = 50,
    offset: int = 0,
    request_type: Optional[str] = None,
    user: TokenPayload = Depends(require_role(UserRole.ADMIN)),
):
    """List all GDPR requests (audit trail of GDPR operations).

    Provides accountability record showing who requested what GDPR action,
    when, and how many records were affected.
    """
    gdpr = get_gdpr_service()
    requests = await gdpr.get_requests(
        limit=limit, offset=offset, request_type=request_type
    )
    return [r.model_dump() for r in requests]


# ─── GET /admin/gdpr/subject/count ───────────────────────────────────────────

@router.get("/subject/count")
async def count_subject_records(
    subject_id: str,
    user: TokenPayload = Depends(require_role(UserRole.ADMIN)),
):
    """Count records associated with a data subject.

    Use this before pseudonymization to determine the confirmation string.
    Returns the count needed for the confirmation field.
    """
    _check_rate_limit(user.sub, "subject_count")

    gdpr = get_gdpr_service()
    count = await gdpr._count_subject_records(subject_id)

    return {
        "subject_id": subject_id,
        "records_found": count,
        "confirmation_required": f"I confirm this action affects {count} records",
    }
