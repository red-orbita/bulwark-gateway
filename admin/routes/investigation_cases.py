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
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from ..models.auth import TokenPayload
from ..services.audit_logger import get_audit_logger
from ..services.auth_service import require_permission
from ..services.investigation_case_store import (
    CASE_SEVERITIES,
    CASE_STATUSES,
    get_case_store,
    render_case_markdown,
)

# Reuse the Investigation Center's tenant/authorisation helpers so cases enforce
# exactly the same scoping rules as triage (admin→admin, no import cycle). Imported
# as a module (not a bare symbol) for ``get_security_events_store`` so a monkeypatch
# on the investigation module is honoured here too — the events store is a shared
# singleton, so both surfaces must resolve it through the same reference.
from . import investigation as _investigation
from .investigation import _MAX_TIMELINE, _authorize_subject, _can_write, _scoped_tenant

router = APIRouter()

_MAX_CASES = 500

# Timeline (Fase 5A) bounds. ``_MAX_TIMELINE_ENTRIES`` caps the merged, deduped
# stream returned to the client; ``_TIMELINE_COLLECT_CAP`` guards the raw
# gather step so a case linking many high-volume origins can never build an
# unbounded intermediate list before the cap is applied.
_MAX_TIMELINE_ENTRIES = 1000
_TIMELINE_COLLECT_CAP = 5000

# Compliance axes rolled up in a case export, in the canonical order used by
# ``src/telemetry/compliance.py``. Populated only from ``incident`` subjects (the
# only subject type carrying explicit threat categories).
_COMPLIANCE_AXES = (
    "owasp_llm",
    "mitre_atlas",
    "mitre_attack",
    "nist_ai_rmf",
    "eu_ai_act",
)

# Sort keys the list endpoint accepts, mirroring the store's whitelist. Kept as an
# explicit surface so an unknown key is rejected at the API boundary rather than
# silently falling back inside the store.
_SORT_KEYS = ("updated_at", "created_at", "title", "status", "severity")
_EXPORT_FORMATS = ("json", "md")


# ─── Timeline reconstruction (Fase 5A) ───────────────────────────────────────
# Pure helpers that normalise the two evidence sources of a case — durable
# security events (unix-epoch ``ts``) and the case's own append-only note trail
# (ISO-8601 ``ts``) — into one comparably-timestamped stream. Kept side-effect
# free so they are unit-testable without a request or a database.


def _iso_from_epoch(ts: object) -> str:
    """Render a unix-epoch timestamp (as stored on events) as a UTC ISO string.

    Returns ``""`` for anything unparseable rather than raising, so one bad row
    never aborts the timeline.
    """
    from datetime import datetime, timezone

    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()  # type: ignore[arg-type]
    except (TypeError, ValueError, OSError):
        return ""


def _parse_iso_ts(value: object) -> float:
    """Parse an ISO-8601 timestamp (as stored on case notes) into a unix epoch.

    Tolerant: returns ``0.0`` for anything unparseable so a malformed note ts
    sorts to the start of the timeline rather than raising.
    """
    if not value:
        return 0.0
    from datetime import datetime

    try:
        return datetime.fromisoformat(str(value)).timestamp()
    except (TypeError, ValueError):
        return 0.0


def _event_epoch(event: dict) -> float:
    """Read an event's unix-epoch ``ts`` defensively (0.0 when absent/bad)."""
    ts = event.get("ts")
    try:
        return float(ts) if ts is not None else 0.0
    except (TypeError, ValueError):
        return 0.0


def _event_timeline_entry(event: dict) -> dict:
    """Normalise a durable security event into a timeline entry (pure).

    Provenance (``via``) records which linked subject surfaced the event, read
    from the ``_via`` key the endpoint stamps while gathering (an internal marker,
    not part of the stored event shape).
    """
    epoch = _event_epoch(event)
    return {
        "type": "event",
        "epoch": epoch,
        "ts": _iso_from_epoch(epoch) if epoch else "",
        "event_id": event.get("event_id") or "",
        "verdict": event.get("verdict") or "",
        "category": event.get("category") or "",
        "severity": event.get("severity") or "",
        "source": event.get("source") or "",
        "description": event.get("description") or "",
        "request_id": event.get("request_id") or "",
        "incident_id": event.get("incident_id") or "",
        "via": event.get("_via") or "",
    }


def _note_timeline_entry(note: dict) -> dict:
    """Normalise a case note into a timeline entry (pure)."""
    ts = note.get("ts") or ""
    return {
        "type": "note",
        "epoch": _parse_iso_ts(ts),
        "ts": ts,
        "note_kind": note.get("kind") or "note",
        "author": note.get("author") or "system",
        "text": note.get("text") or "",
    }


def _assemble_timeline(
    events: list[dict], notes: list[dict], *, limit: int
) -> tuple[list[dict], bool]:
    """Merge event + note entries into one chronological stream (pure).

    Events are deduped by ``event_id`` — the same detection can surface via more
    than one linked subject (e.g. an incident and the origin that drove it), and
    the first occurrence wins. The merged stream is sorted oldest→newest; when it
    exceeds ``limit`` the most recent ``limit`` entries are kept (a reconstruction
    reads forward from the most relevant recent window) and ``truncated`` is
    returned ``True``.
    """
    entries: list[dict] = []
    seen: set[str] = set()
    for event in events:
        eid = event.get("event_id") or ""
        if eid:
            if eid in seen:
                continue
            seen.add(eid)
        entries.append(_event_timeline_entry(event))
    for note in notes:
        entries.append(_note_timeline_entry(note))
    entries.sort(key=lambda e: e["epoch"])
    truncated = len(entries) > limit
    if truncated:
        entries = entries[-limit:]
    return entries, truncated


async def _reconstruct_case_timeline(
    case: dict, user: TokenPayload, *, limit: int
) -> tuple[list[dict], bool, dict]:
    """Gather + scope + assemble a case's unified chronological timeline.

    Shared by the ``/{case_id}/timeline`` endpoint and the enriched case export so
    both surfaces reconstruct identically. Gathers the durable evidence behind every
    linked subject (an incident's correlation event(s) plus their
    ``metadata.contributing_event_ids`` detections, and an origin's stamped event
    ledger), applies the operator's tenant scope, and merges it with the case's own
    note trail — including the append-only ``kind=action`` response/remediation
    notes (Fase 5B). The raw gather is bounded by ``_TIMELINE_COLLECT_CAP`` and the
    returned stream by ``limit``. Returns ``(entries, truncated, subject_counts)``.
    """
    store = _investigation.get_security_events_store()

    collected: list[dict] = []
    incident_count = 0
    origin_count = 0

    for subject in (case.get("subjects") or []):
        if len(collected) >= _TIMELINE_COLLECT_CAP:
            break
        stype = subject.get("subject_type")
        skey = (subject.get("subject_key") or "").strip()
        if not skey:
            continue

        if stype == "incident":
            incident_count += 1
            contributing_ids: list[str] = []
            for ev in await store.find_by_incident(skey):
                ev["_via"] = f"incident:{skey}"
                collected.append(ev)
                meta = ev.get("metadata") or {}
                for cid in (meta.get("contributing_event_ids") or []):
                    if cid:
                        contributing_ids.append(cid)
            if contributing_ids and len(collected) < _TIMELINE_COLLECT_CAP:
                for ev in await store.find_by_event_ids(contributing_ids):
                    ev["_via"] = f"incident:{skey}"
                    collected.append(ev)
        elif stype == "origin":
            # Origin subjects are "scope_type:digest" tokens; a request-keyed
            # origin (no digest) carries no stamped evidence, so only whole-token
            # subjects resolve to events (find_by_scope_digest is LIKE-safe). The
            # token already carries its "origin:"-style prefix, so it is used as
            # the provenance marker verbatim.
            if len(skey.split(":", 1)) == 2:
                origin_count += 1
                for ev in await store.find_by_scope_digest(skey, limit=_MAX_TIMELINE):
                    ev["_via"] = skey
                    collected.append(ev)
        # session: pseudonymous decomposition digest with no durable events.

    # Tenant scoping: a scoped operator only sees their own tenant's events.
    if user.tenant:
        collected = [e for e in collected if (e.get("tenant") or "") == user.tenant]

    entries, truncated = _assemble_timeline(
        collected, case.get("notes") or [], limit=limit
    )
    return entries, truncated, {"incident": incident_count, "origin": origin_count}


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
    severity: Optional[str] = Query(None),
    assignee: Optional[str] = Query(None, max_length=128),
    search: Optional[str] = Query(None, max_length=128),
    sort: str = Query("updated_at"),
    order: str = Query("desc", description="asc | desc"),
    limit: int = Query(100, ge=1, le=_MAX_CASES),
    offset: int = Query(0, ge=0),
):
    """List investigation cases with filtering, search, sorting and paging."""
    tenant = user.tenant or None
    sort_key = sort if sort in _SORT_KEYS else "updated_at"
    descending = order.lower() != "asc"
    store = get_case_store()
    cases = await store.list_cases(
        status=status,
        severity=severity,
        assignee=assignee,
        tenant=tenant,
        search=search,
        sort=sort_key,
        descending=descending,
        limit=limit,
        offset=offset,
    )
    total = await store.count_cases(
        status=status, severity=severity, assignee=assignee,
        tenant=tenant, search=search,
    )
    return {
        "cases": cases,
        "count": len(cases),
        "total": total,
        "limit": limit,
        "offset": offset,
        "sort": sort_key,
        "order": "desc" if descending else "asc",
        "can_write": _can_write(user),
        "statuses": list(CASE_STATUSES),
        "severities": list(CASE_SEVERITIES),
        "sort_keys": list(_SORT_KEYS),
    }


@router.get("/stats")
async def case_stats(
    user: TokenPayload = Depends(require_permission("investigation:read")),
    assignee: Optional[str] = Query(None, max_length=128),
):
    """Aggregate case counts (by status/severity + optional "my work" workload)."""
    tenant = user.tenant or None
    stats = await get_case_store().stats(tenant=tenant, assignee=assignee or None)
    return {"stats": stats}


@router.get("/analytics")
async def case_analytics(
    user: TokenPayload = Depends(require_permission("investigation:read")),
    trend_days: int = Query(14, ge=1, le=365),
    top_origins: int = Query(10, ge=1, le=100),
):
    """Investigation programme analytics (Fase 5E): MTTR, trends, top origins.

    Extends the status/severity roll-up with mean/median time-to-resolve over
    terminal cases, per-day opened-vs-resolved inflow/throughput over ``trend_days``,
    and the origins recurring across the most cases. Tenant-scoped: a scoped operator
    only ever aggregates their own tenant's cases.
    """
    tenant = user.tenant or None
    analytics = await get_case_store().analytics(
        tenant=tenant, trend_days=trend_days, top_origins=top_origins
    )
    return {"analytics": analytics}


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


@router.get("/{case_id}/timeline")
async def case_timeline(
    case_id: str,
    user: TokenPayload = Depends(require_permission("investigation:read")),
    limit: int = Query(500, ge=1, le=_MAX_TIMELINE_ENTRIES),
):
    """Reconstruct a case's unified chronological timeline.

    Gathers the durable evidence behind every linked subject — an incident's
    correlation event(s) plus the input/output detections that contributed to it
    (``metadata.contributing_event_ids``), and an origin's stamped event ledger —
    merges it with the case's own note trail (opens, state changes, subject links,
    analyst notes), and returns one time-ordered stream. Session subjects carry no
    durable events (pseudonymous scores only) so they contribute nothing here.

    Tenant-scoped like every other case read: the case itself is gated by
    ``_get_case_scoped`` (404 on cross-tenant, no leak), and a tenant-scoped
    operator only sees events stamped with their own tenant. The raw gather is
    bounded by ``_TIMELINE_COLLECT_CAP`` and the returned stream by ``limit`` so a
    case linking many high-volume subjects can never build or emit an unbounded
    list.
    """
    case = await _get_case_scoped(user, case_id)

    entries, truncated, subject_counts = await _reconstruct_case_timeline(
        case, user, limit=limit
    )
    return {
        "case_id": case.get("case_id") or case_id,
        "timeline": entries,
        "count": len(entries),
        "truncated": truncated,
        "limit": limit,
        "subject_counts": subject_counts,
    }


async def _resolve_case_compliance(case: dict) -> Optional[dict]:
    """Derive an OWASP/MITRE/NIST/EU compliance roll-up from a case's incidents.

    Only ``incident`` subjects carry explicit threat categories — the correlation
    event's own ``category`` plus its ``metadata.input_categories`` /
    ``output_categories``. Origins and sessions do not, so they contribute nothing
    here rather than having a category fabricated for them. Each distinct category
    is mapped through ``src/telemetry/compliance.py`` — the SAME single source of
    truth that tags every exported SIEM event — so a case export and its underlying
    events can never disagree on the framework references. Unknown / ad-hoc category
    strings map to nothing (no fabricated tag). Returns ``None`` when the case links
    no incident that resolves to any framework, so the export omits the block
    entirely rather than emitting an empty section.
    """
    from src.telemetry.compliance import (
        OWASP_LLM_VERSION,
        compliance_for,
        reference_catalog,
    )

    incident_ids = [
        s.get("subject_key")
        for s in (case.get("subjects") or [])
        if s.get("subject_type") == "incident" and s.get("subject_key")
    ]
    if not incident_ids:
        return None

    store = _investigation.get_security_events_store()
    categories: set[str] = set()
    for incident_id in incident_ids:
        for event in await store.find_by_incident(incident_id):
            cat = event.get("category")
            if cat:
                categories.add(cat)
            meta = event.get("metadata") or {}
            for c in (meta.get("input_categories") or []):
                if c:
                    categories.add(c)
            for c in (meta.get("output_categories") or []):
                if c:
                    categories.add(c)
    if not categories:
        return None

    axes: dict[str, set[str]] = {axis: set() for axis in _COMPLIANCE_AXES}
    contributing: set[str] = set()
    for cat in categories:
        mapping = compliance_for(cat)
        if mapping is None or mapping.is_empty():
            continue
        contributing.add(cat)
        for axis, codes in mapping.to_dict().items():
            axes[axis].update(codes)
    if not contributing:
        return None

    codes = {axis: sorted(vals) for axis in _COMPLIANCE_AXES if (vals := axes[axis])}
    # Only OWASP/ATLAS/ATT&CK codes have a per-code catalog entry (label + URL); the
    # NIST/EU axes are policy references rendered as plain codes.
    catalog_all = reference_catalog()
    badged = (
        codes.get("owasp_llm", [])
        + codes.get("mitre_atlas", [])
        + codes.get("mitre_attack", [])
    )
    catalog = {
        code: catalog_all[code].to_dict() for code in badged if code in catalog_all
    }
    return {
        "owasp_version": OWASP_LLM_VERSION,
        "categories": sorted(contributing),
        "codes": codes,
        "catalog": catalog,
    }


@router.get("/{case_id}/export")
async def export_case(
    case_id: str,
    user: TokenPayload = Depends(require_permission("investigation:read")),
    format: str = Query("json", description="json | md"),
):
    """Export a full case as a downloadable JSON or Markdown investigation record.

    Tenant-scoped like every other case read; the export is audit-logged so a
    record leaving the system leaves a trail. Content-Disposition marks it as an
    attachment named after the case id.
    """
    fmt = format.lower()
    if fmt not in _EXPORT_FORMATS:
        raise HTTPException(status_code=400, detail=f"format must be one of {_EXPORT_FORMATS}")
    case = await _get_case_scoped(user, case_id)
    cid = case.get("case_id") or case_id

    # Enrich the export with the OWASP/MITRE/NIST/EU mapping derived from the case's
    # linked incidents (resolved here, off the request-free render path, so
    # ``render_case_markdown`` stays pure). Omitted entirely when nothing maps.
    compliance = await _resolve_case_compliance(case)
    if compliance:
        case["compliance"] = compliance

    # Enrich the export with the reconstructed chronological timeline (Fase 5C):
    # the durable evidence behind every linked subject merged with the case's own
    # note trail — including the Fase 5B response/remediation action notes — so the
    # portable record carries the full story, not just static metadata. Tenant
    # scoping and bounds are those of the timeline endpoint (same helper).
    timeline, timeline_truncated, timeline_counts = await _reconstruct_case_timeline(
        case, user, limit=_MAX_TIMELINE_ENTRIES
    )
    case["timeline"] = timeline
    case["timeline_truncated"] = timeline_truncated
    case["timeline_subject_counts"] = timeline_counts

    await get_audit_logger().log(
        actor=user.sub,
        action="investigation.case_export",
        resource_type="investigation_case",
        resource_id=case_id,
        details=f"format={fmt}",
    )

    if fmt == "md":
        body = render_case_markdown(case)
        return PlainTextResponse(
            content=body,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{cid}.md"'},
        )
    return JSONResponse(
        content=jsonable_encoder({"case": case}),
        headers={"Content-Disposition": f'attachment; filename="{cid}.json"'},
    )


@router.get("/{case_id}/related")
async def related_cases(
    case_id: str,
    user: TokenPayload = Depends(require_permission("investigation:read")),
):
    """Cross-case correlation (Fase 5D): other cases sharing a subject with this one.

    A subject (incident / origin / session) linked to more than one case is a
    campaign signal — the same indicator or actor surfacing across separate
    investigations. Returns each related case with the concrete shared subjects and
    a count, ranked by overlap strength then recency.

    Tenant-scoped: the target case is gated by ``_get_case_scoped`` (404 on
    cross-tenant, no leak), and a tenant-scoped operator only sees related cases in
    their own tenant — a shared subject must never reveal another tenant's case.
    """
    case = await _get_case_scoped(user, case_id)
    related = await get_case_store().find_related_cases(case.get("case_id") or case_id)
    if user.tenant:
        related = [c for c in related if (c.get("tenant") or "") == user.tenant]
    return {
        "case_id": case.get("case_id") or case_id,
        "related": related,
        "count": len(related),
    }



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
