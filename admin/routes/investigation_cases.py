"""Investigation *cases* — grouping related subjects into one investigation.

A companion to :mod:`admin.routes.investigation`. Where that route drives the
per-subject triage workflow (a single incident / origin / session), a **case**
collects several such subjects under one analyst-owned investigation with its own
status, severity, assignee and shared note trail. Evidence for each linked
subject still lives in the durable event store and risk state — a case adds only
the human grouping on top.

Reads require ``investigation:read``; mutations require ``investigation:write``.
Tenant scoping mirrors the rest of the Investigation Center: a tenant-scoped
operator only sees and mutates cases stamped with their own tenant, and may only
link subjects that belong to them (validated via the shared
``_authorize_subject`` helper — a cross-tenant subject is rejected 404 with no
existence leak).
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ..models.auth import TokenPayload
from ..services.audit_logger import get_audit_logger
from ..services.auth_service import require_permission
from ..services.investigation_case_store import (
    CASE_SEVERITIES,
    CASE_STATUSES,
    get_case_store,
)

# Reuse the Investigation Center's tenant/authorisation helpers so cases enforce
# exactly the same scoping rules as triage (admin→admin, no import cycle).
from .investigation import _authorize_subject, _can_write, _scoped_tenant

router = APIRouter()

_MAX_CASES = 500


class CaseCreateRequest(BaseModel):
    """Open a new investigation case."""

    title: str = Field(..., min_length=1, max_length=200)
    severity: str = Field(default="medium", description=f"one of {CASE_SEVERITIES}")
    summary: Optional[str] = Field(default=None, max_length=4000)
    tenant: Optional[str] = Field(default=None, max_length=128)


class CaseStateRequest(BaseModel):
    """Set a case's status, severity and/or assignee."""

    status: Optional[str] = Field(default=None, description=f"one of {CASE_STATUSES}")
    severity: Optional[str] = Field(default=None, description=f"one of {CASE_SEVERITIES}")
    assignee: Optional[str] = Field(default=None, max_length=128)


class CaseNoteRequest(BaseModel):
    """Append a free-text note to a case."""

    text: str = Field(..., min_length=1, max_length=4000)


class CaseSubjectRequest(BaseModel):
    """Link a triage subject to a case."""

    subject_type: str = Field(..., description="incident | origin | session")
    subject_key: str = Field(..., min_length=1, max_length=256)


async def _get_case_scoped(user: TokenPayload, case_id: str) -> dict:
    """Fetch a case, enforcing tenant scoping (404 on cross-tenant, no leak)."""
    case = await get_case_store().get(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    if user.tenant and (case.get("tenant") or "") != user.tenant:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.get("")
async def list_cases(
    user: TokenPayload = Depends(require_permission("investigation:read")),
    status: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=_MAX_CASES),
    offset: int = Query(0, ge=0),
):
    """List investigation cases (most-recently-updated first)."""
    tenant = user.tenant or None
    cases = await get_case_store().list_cases(
        status=status, tenant=tenant, limit=limit, offset=offset
    )
    return {
        "cases": cases,
        "count": len(cases),
        "can_write": _can_write(user),
        "statuses": list(CASE_STATUSES),
        "severities": list(CASE_SEVERITIES),
    }


@router.post("")
async def create_case(
    body: CaseCreateRequest,
    user: TokenPayload = Depends(require_permission("investigation:write")),
):
    """Open a new case, owned by the operator's tenant scope."""
    tenant = _scoped_tenant(user, body.tenant)
    try:
        case = await get_case_store().create_case(
            title=body.title,
            actor=user.sub,
            severity=body.severity,
            tenant=tenant,
            summary=body.summary,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None

    await get_audit_logger().log(
        actor=user.sub,
        action="investigation.case_create",
        resource_type="investigation_case",
        resource_id=case["case_id"],
        details=f"title={case['title']} severity={case['severity']}",
    )
    return {"message": "Case created", "case": case}


@router.get("/for-subject/{subject_type}/{subject_key}")
async def cases_for_subject(
    subject_type: str,
    subject_key: str,
    user: TokenPayload = Depends(require_permission("investigation:read")),
):
    """Return the cases a given subject is linked to (tenant-filtered)."""
    cases = await get_case_store().find_cases_for_subject(subject_type, subject_key)
    if user.tenant:
        cases = [c for c in cases if (c.get("tenant") or "") == user.tenant]
    return {"cases": cases, "count": len(cases)}


@router.get("/{case_id}")
async def get_case(
    case_id: str,
    user: TokenPayload = Depends(require_permission("investigation:read")),
):
    """Full case detail: metadata, linked subjects, and note trail."""
    return {"case": await _get_case_scoped(user, case_id)}


@router.post("/{case_id}/state")
async def set_case_state(
    case_id: str,
    body: CaseStateRequest,
    user: TokenPayload = Depends(require_permission("investigation:write")),
):
    """Set a case's status, severity and/or assignee."""
    if body.status is None and body.severity is None and body.assignee is None:
        raise HTTPException(status_code=400, detail="Provide status, severity and/or assignee.")
    await _get_case_scoped(user, case_id)  # tenant gate

    try:
        case = await get_case_store().set_state(
            case_id=case_id,
            actor=user.sub,
            status=body.status,
            severity=body.severity,
            assignee=body.assignee,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")

    await get_audit_logger().log(
        actor=user.sub,
        action="investigation.case_state",
        resource_type="investigation_case",
        resource_id=case_id,
        details=f"status={body.status} severity={body.severity} assignee={body.assignee}",
    )
    return {"message": "Case updated", "case": case}


@router.post("/{case_id}/note")
async def add_case_note(
    case_id: str,
    body: CaseNoteRequest,
    user: TokenPayload = Depends(require_permission("investigation:write")),
):
    """Append an investigation note to a case."""
    await _get_case_scoped(user, case_id)  # tenant gate

    try:
        case = await get_case_store().add_note(
            case_id=case_id, actor=user.sub, text=body.text
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")

    await get_audit_logger().log(
        actor=user.sub,
        action="investigation.case_note",
        resource_type="investigation_case",
        resource_id=case_id,
        details=f"note_len={len(body.text)}",
    )
    return {"message": "Note added", "case": case}


@router.post("/{case_id}/subject")
async def add_case_subject(
    case_id: str,
    body: CaseSubjectRequest,
    user: TokenPayload = Depends(require_permission("investigation:write")),
):
    """Link a triage subject to a case (validates subject + tenant scope)."""
    await _get_case_scoped(user, case_id)  # case tenant gate
    # Validate the subject exists / is in-scope (raises 400/404 as appropriate).
    await _authorize_subject(user, body.subject_type, body.subject_key)

    try:
        case = await get_case_store().add_subject(
            case_id=case_id,
            subject_type=body.subject_type,
            subject_key=body.subject_key,
            actor=user.sub,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")

    await get_audit_logger().log(
        actor=user.sub,
        action="investigation.case_link",
        resource_type="investigation_case",
        resource_id=case_id,
        details=f"linked {body.subject_type}:{body.subject_key}",
    )
    return {"message": "Subject linked", "case": case}


@router.delete("/{case_id}/subject")
async def remove_case_subject(
    case_id: str,
    user: TokenPayload = Depends(require_permission("investigation:write")),
    subject_type: str = Query(...),
    subject_key: str = Query(..., min_length=1, max_length=256),
):
    """Unlink a subject from a case."""
    await _get_case_scoped(user, case_id)  # tenant gate

    case = await get_case_store().remove_subject(
        case_id=case_id,
        subject_type=subject_type,
        subject_key=subject_key,
        actor=user.sub,
    )
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")

    await get_audit_logger().log(
        actor=user.sub,
        action="investigation.case_unlink",
        resource_type="investigation_case",
        resource_id=case_id,
        details=f"unlinked {subject_type}:{subject_key}",
    )
    return {"message": "Subject unlinked", "case": case}
