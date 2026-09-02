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

import logging
from typing import TYPE_CHECKING, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from ..models.auth import TokenPayload
from ..services.audit_logger import get_audit_logger
from ..services.auth_service import require_permission
from ..services.integrations.base import ConnectorError
from ..services.integrations.event_webhook import get_event_webhook_emitter
from ..services.integrations.registry import get_integration_registry
from ..services.investigation_case_store import (
    CASE_SEVERITIES,
    CASE_STATUSES,
    get_case_store,
    render_case_markdown,
)
from ..services.investigation_export import (
    build_iris_case,
    build_stix_bundle,
    build_thehive_case,
)
from ..services.investigation_observable_store import (
    OBSERVABLE_SOURCES,
    OBSERVABLE_TYPES,
    PAP_LEVELS,
    TLP_LEVELS,
    get_observable_store,
)
from ..services.investigation_task_store import (
    TASK_STATUSES,
    get_task_store,
)

# Reuse the Investigation Center's tenant/authorisation helpers so cases enforce
# exactly the same scoping rules as triage (admin→admin, no import cycle). Imported
# as a module (not a bare symbol) for ``get_security_events_store`` so a monkeypatch
# on the investigation module is honoured here too — the events store is a shared
# singleton, so both surfaces must resolve it through the same reference.
from . import investigation as _investigation
from .correlation import _DIGEST_RE, _VALID_SCOPES, _redis
from .investigation import (
    _MAX_TIMELINE,
    _authorize_subject,
    _can_write,
    _correlation_enabled,
    _raise_origin_risk,
    _scoped_tenant,
)

if TYPE_CHECKING:
    from ..services.integrations.cortex import CortexConnector
    from ..services.integrations.opencti import OpenCTIConnector

router = APIRouter()

logger = logging.getLogger(__name__)


# Severity ordering for detecting an *escalation* (only a raise fires the webhook).
_SEVERITY_RANK = {sev: rank for rank, sev in enumerate(CASE_SEVERITIES)}

async def _emit_case_event(event_type: str, case: dict, extra: Optional[dict] = None) -> None:
    """Fire a lifecycle event to configured webhooks (best-effort, fail-open).

    Emission never blocks or breaks case management: the emitter returns instantly
    when nothing subscribes to the event and swallows every delivery error. A
    programming error here must not take down the route, so the whole call is
    defensively guarded.
    """
    try:
        data = {
            "case_id": case.get("case_id"),
            "title": case.get("title"),
            "severity": case.get("severity"),
            "status": case.get("status"),
        }
        if extra:
            data.update(extra)
        await get_event_webhook_emitter().emit(
            event_type, tenant=case.get("tenant") or None, data=data
        )
    except Exception:  # noqa: BLE001 — fail-open: a webhook must never break a case op
        logger.warning("case_event_emit_failed", exc_info=True)

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
_EXPORT_FORMATS = ("json", "md", "stix", "thehive", "iris")


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
    """Normalise a case note into a timeline entry (pure).

    A manual timeline note (``kind='timeline'``) may carry an ``event_ts`` — when
    the event actually occurred, distinct from when the note was recorded — which
    is used for chronological ordering in preference to the record timestamp.
    """
    event_ts = note.get("event_ts")
    ts = event_ts or note.get("ts") or ""
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
    severity: Optional[str] = Field(
        default=None,
        description=f"one of {CASE_SEVERITIES}; defaults to the template's or 'medium'",
    )
    summary: Optional[str] = Field(default=None, max_length=4000)
    tenant: Optional[str] = Field(default=None, max_length=128)
    template_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="apply a case template (seeds severity/summary/tags/tasks)",
    )


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


class CaseTagsRequest(BaseModel):
    """Replace a case's tag (TTP / label badge) list."""

    tags: list[str] = Field(default_factory=list, max_length=50)


class CaseTimelineEntryRequest(BaseModel):
    """Add a manual entry to a case's reconstructed timeline."""

    text: str = Field(..., min_length=1, max_length=4000)
    event_ts: Optional[str] = Field(
        default=None,
        description="ISO-8601 timestamp of when the event occurred (defaults to now)",
    )


class ObservableAddRequest(BaseModel):
    """Add an observable (atomic indicator) to a case."""

    type: str = Field(..., description=f"one of {OBSERVABLE_TYPES}")
    value: str = Field(..., min_length=1, max_length=2048)
    is_ioc: bool = Field(default=False)
    tlp: str = Field(default="amber", description=f"one of {TLP_LEVELS}")
    pap: str = Field(default="amber", description=f"one of {PAP_LEVELS}")
    tags: list[str] = Field(default_factory=list, max_length=50)
    source: str = Field(default="manual", description=f"one of {OBSERVABLE_SOURCES}")


class ObservableEnrichRequest(BaseModel):
    """Enrich an observable via a Cortex integration's analyzers."""

    integration_id: str = Field(..., min_length=1, max_length=64)
    analyzer_ids: list[str] = Field(..., min_length=1, max_length=20)
    tlp: Optional[str] = Field(default=None, description=f"one of {TLP_LEVELS}")


class ObservableResponderRequest(BaseModel):
    """Run a Cortex responder (response action) against an observable."""

    integration_id: str = Field(..., min_length=1, max_length=64)
    responder_id: str = Field(..., min_length=1, max_length=128)
    tlp: Optional[str] = Field(default=None, description=f"one of {TLP_LEVELS}")


class ObservableLookupRequest(BaseModel):
    """Look an observable up against an OpenCTI integration's indicator graph."""

    integration_id: str = Field(..., min_length=1, max_length=64)


class TaskAddRequest(BaseModel):
    """Add a checklist task to a case."""

    title: str = Field(..., min_length=1, max_length=200)
    assignee: Optional[str] = Field(default=None, max_length=128)
    due_at: Optional[str] = Field(default=None, max_length=64)


class TaskStateRequest(BaseModel):
    """Set a task's status, assignee and/or due date."""

    status: Optional[str] = Field(default=None, description=f"one of {TASK_STATUSES}")
    assignee: Optional[str] = Field(default=None, max_length=128)
    due_at: Optional[str] = Field(default=None, max_length=64)


class TaskNoteRequest(BaseModel):
    """Append a note to a task."""

    text: str = Field(..., min_length=1, max_length=2000)


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


@router.get("/templates")
async def list_case_templates(
    user: TokenPayload = Depends(require_permission("investigation:read")),
):
    """List the available case templates (investigation blueprints)."""
    from ..services.investigation_templates import list_templates

    return {"templates": list_templates()}


@router.post("")
async def create_case(
    body: CaseCreateRequest,
    user: TokenPayload = Depends(require_permission("investigation:write")),
):
    """Open a new case, owned by the operator's tenant scope.

    When ``template_id`` is supplied, the named template supplies defaults the
    request did not: the severity (unless explicitly set), the summary (unless
    provided), the case tags, and an ordered checklist of tasks. An unknown
    template id is rejected 400.
    """
    from ..services.investigation_templates import get_template

    tenant = _scoped_tenant(user, body.tenant)

    template = None
    if body.template_id:
        template = get_template(body.template_id)
        if template is None:
            raise HTTPException(
                status_code=400, detail=f"unknown template: {body.template_id}"
            )

    severity = body.severity or (template["severity"] if template else None) or "medium"
    summary = body.summary or (template["summary"] if template else None)

    try:
        case = await get_case_store().create_case(
            title=body.title,
            actor=user.sub,
            severity=severity,
            tenant=tenant,
            summary=summary,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None

    case_id = case["case_id"]

    # Seed the template's tags + task checklist (best-effort; a bad template value
    # is skipped by the store's own validation rather than failing the create).
    if template:
        if template.get("tags"):
            updated = await get_case_store().set_tags(
                case_id=case_id, actor=user.sub, tags=template["tags"]
            )
            if updated is not None:
                case = updated
        for task in template.get("tasks") or []:
            try:
                await get_task_store().add(
                    case_id=case_id,
                    title=task.get("title") or "",
                    actor=user.sub,
                    assignee=task.get("assignee") or None,
                )
            except ValueError:
                continue
        case["subjects"] = case.get("subjects") or []

    await get_audit_logger().log(
        actor=user.sub,
        action="investigation.case_create",
        resource_type="investigation_case",
        resource_id=case["case_id"],
        details=(
            f"title={case['title']} severity={case['severity']}"
            + (f" template={body.template_id}" if template else "")
        ),
    )
    await _emit_case_event("case.opened", case)
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
    format: str = Query("json", description="json | md | stix | thehive | iris"),
):
    """Export a full case as a downloadable investigation record.

    Five shapes are offered: the native ``json`` / ``md`` record, plus three
    interop exports (Fase 0) for handing an investigation to an external
    platform — ``stix`` (STIX 2.1 bundle), ``thehive`` (TheHive case), and
    ``iris`` (DFIR-IRIS case). The interop shapes carry the case's first-class
    observables and tasks; the native shapes additionally carry the compliance
    roll-up and reconstructed timeline.

    Tenant-scoped like every other case read; the export is audit-logged so a
    record leaving the system leaves a trail. Content-Disposition marks it as an
    attachment named after the case id.
    """
    fmt = format.lower()
    if fmt not in _EXPORT_FORMATS:
        raise HTTPException(status_code=400, detail=f"format must be one of {_EXPORT_FORMATS}")
    case = await _get_case_scoped(user, case_id)
    cid = case.get("case_id") or case_id

    await get_audit_logger().log(
        actor=user.sub,
        action="investigation.case_export",
        resource_type="investigation_case",
        resource_id=case_id,
        details=f"format={fmt}",
    )

    if fmt in ("stix", "thehive", "iris"):
        # Interop exports (Fase 0) hand the investigation to an external platform.
        # They carry the case's first-class observables and tasks (which live in
        # dedicated stores, not on the case row) but not the native compliance
        # roll-up / reconstructed timeline — so skip that enrichment work here.
        observables = await get_observable_store().list_for_case(cid)
        tasks = await get_task_store().list_for_case(cid)
        if fmt == "stix":
            payload = build_stix_bundle(case, observables, tasks)
        elif fmt == "thehive":
            payload = build_thehive_case(case, observables, tasks)
        else:
            payload = build_iris_case(case, observables, tasks)
        return JSONResponse(
            content=jsonable_encoder(payload),
            headers={
                "Content-Disposition": f'attachment; filename="{cid}.{fmt}.json"'
            },
        )

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
    prior = await _get_case_scoped(user, case_id)  # tenant gate
    prior_severity = prior.get("severity") or ""
    prior_status = prior.get("status") or ""

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

    # Lifecycle webhooks: only a genuine severity *escalation* or a transition
    # *into* resolved fires (no event on a no-op or a de-escalation).
    new_severity = case.get("severity") or ""
    if _SEVERITY_RANK.get(new_severity, -1) > _SEVERITY_RANK.get(prior_severity, -1):
        await _emit_case_event(
            "case.severity_raised",
            case,
            {"from_severity": prior_severity, "to_severity": new_severity},
        )
    new_status = case.get("status") or ""
    if new_status == "resolved" and prior_status != "resolved":
        await _emit_case_event("case.resolved", case, {"from_status": prior_status})

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


# ─── Case tags (Phase 0) ──────────────────────────────────────────────────────


@router.post("/{case_id}/tags")
async def set_case_tags(
    case_id: str,
    body: CaseTagsRequest,
    user: TokenPayload = Depends(require_permission("investigation:write")),
):
    """Replace a case's tag (TTP / label badge) list.

    Tags are normalised (trimmed, lower-cased, deduped, capped) by the store and
    the change is recorded on the case's append-only note trail.
    """
    await _get_case_scoped(user, case_id)  # tenant gate

    case = await get_case_store().set_tags(
        case_id=case_id, actor=user.sub, tags=body.tags
    )
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")

    await get_audit_logger().log(
        actor=user.sub,
        action="investigation.case_tags",
        resource_type="investigation_case",
        resource_id=case_id,
        details=f"tags={case.get('tags')}",
    )
    return {"message": "Tags updated", "case": case}


# ─── Manual timeline entry (Phase 0) ──────────────────────────────────────────


def _validate_event_ts(event_ts: Optional[str]) -> Optional[str]:
    """Validate an optional ISO-8601 event timestamp (400 on a bad value)."""
    if event_ts is None:
        return None
    candidate = event_ts.strip()
    if not candidate:
        return None
    from datetime import datetime

    try:
        datetime.fromisoformat(candidate)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=400, detail="event_ts must be an ISO-8601 timestamp"
        ) from None
    return candidate


@router.post("/{case_id}/timeline")
async def add_case_timeline_entry(
    case_id: str,
    body: CaseTimelineEntryRequest,
    user: TokenPayload = Depends(require_permission("investigation:write")),
):
    """Add a manual entry to a case's reconstructed timeline.

    A manual entry records an event with no durable detection behind it (an
    out-of-band action, an observed attacker move) so the reconstructed timeline
    can carry the full story. Stored on the case's append-only note trail as a
    ``kind='timeline'`` note, ordered by its optional ``event_ts``.
    """
    await _get_case_scoped(user, case_id)  # tenant gate
    event_ts = _validate_event_ts(body.event_ts)

    try:
        case = await get_case_store().add_timeline_entry(
            case_id=case_id, actor=user.sub, text=body.text, event_ts=event_ts
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")

    await get_audit_logger().log(
        actor=user.sub,
        action="investigation.case_timeline_entry",
        resource_type="investigation_case",
        resource_id=case_id,
        details=f"event_ts={event_ts or 'now'}",
    )
    return {"message": "Timeline entry added", "case": case}


# ─── Observables (Phase 0) ────────────────────────────────────────────────────

# Map an observable type onto the IOC database's own type enum for promotion.
# Only network/host/hash indicators promote; email/filename/user/other have no
# IOC-database representation and are rejected at the boundary.
_OBSERVABLE_TO_IOC_TYPE = {
    "ip": "ip",
    "domain": "domain",
    "url": "url",
}


@router.get("/{case_id}/observables")
async def list_case_observables(
    case_id: str,
    user: TokenPayload = Depends(require_permission("investigation:read")),
):
    """List a case's observables (atomic indicators), most-recently-seen first."""
    await _get_case_scoped(user, case_id)  # tenant gate
    observables = await get_observable_store().list_for_case(case_id)
    return {
        "case_id": case_id,
        "observables": observables,
        "count": len(observables),
        "can_write": _can_write(user),
        "types": list(OBSERVABLE_TYPES),
        "tlp_levels": list(TLP_LEVELS),
        "pap_levels": list(PAP_LEVELS),
        "sources": list(OBSERVABLE_SOURCES),
    }


@router.post("/{case_id}/observables")
async def add_case_observable(
    case_id: str,
    body: ObservableAddRequest,
    user: TokenPayload = Depends(require_permission("investigation:write")),
):
    """Add an observable to a case (idempotent per type+value)."""
    await _get_case_scoped(user, case_id)  # tenant gate

    try:
        observable = await get_observable_store().add(
            case_id=case_id,
            observable_type=body.type,
            value=body.value,
            actor=user.sub,
            is_ioc=body.is_ioc,
            tlp=body.tlp,
            pap=body.pap,
            tags=body.tags,
            source=body.source,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None

    await get_audit_logger().log(
        actor=user.sub,
        action="investigation.observable_add",
        resource_type="investigation_case",
        resource_id=case_id,
        details=f"{body.type}={observable.get('value')} is_ioc={body.is_ioc}",
    )
    return {"message": "Observable added", "observable": observable}


@router.delete("/{case_id}/observables/{observable_id}")
async def remove_case_observable(
    case_id: str,
    observable_id: str,
    user: TokenPayload = Depends(require_permission("investigation:write")),
):
    """Remove an observable from a case."""
    await _get_case_scoped(user, case_id)  # tenant gate

    removed = await get_observable_store().remove(
        case_id=case_id, observable_id=observable_id
    )
    if not removed:
        raise HTTPException(status_code=404, detail="Observable not found")

    await get_audit_logger().log(
        actor=user.sub,
        action="investigation.observable_remove",
        resource_type="investigation_case",
        resource_id=case_id,
        details=f"observable_id={observable_id}",
    )
    return {"message": "Observable removed"}


@router.post("/{case_id}/observables/{observable_id}/promote-ioc")
async def promote_observable_to_ioc(
    case_id: str,
    observable_id: str,
    user: TokenPayload = Depends(require_permission("investigation:write")),
):
    """Promote a case observable into the shared IOC database.

    Only network/host/hash indicators promote (ip/domain/url/hash); email,
    filename, user and other observables have no IOC-database representation and
    are rejected 400. Hashes are classed as MD5 (32 hex) or SHA-256 (64 hex) by
    length; any other length is rejected. The observable is marked ``is_ioc`` on
    success so the UI can reflect that it is now a tracked indicator.
    """
    from ..models.iocs import IOCCreate, IOCType
    from ..services.ioc_store import get_ioc_store

    await _get_case_scoped(user, case_id)  # tenant gate

    observable = await get_observable_store().get(case_id, observable_id)
    if observable is None:
        raise HTTPException(status_code=404, detail="Observable not found")

    otype = observable.get("type")
    value = observable.get("value") or ""
    if otype == "hash":
        length = len(value)
        if length == 64:
            ioc_type = IOCType.HASH_SHA256
        elif length == 32:
            ioc_type = IOCType.HASH_MD5
        else:
            raise HTTPException(
                status_code=400,
                detail="hash must be 32 (MD5) or 64 (SHA-256) hex characters to promote",
            )
    elif otype in _OBSERVABLE_TO_IOC_TYPE:
        ioc_type = IOCType(_OBSERVABLE_TO_IOC_TYPE[otype])
    else:
        raise HTTPException(
            status_code=400,
            detail=f"observable type '{otype}' cannot be promoted to an IOC",
        )

    tags = list(observable.get("tags") or [])
    if "investigation" not in tags:
        tags.append("investigation")
    # IOCStore is a synchronous in-memory/JSON store (no await).
    entry = get_ioc_store().create(
        IOCCreate(
            type=ioc_type,
            value=value,
            notes=f"Promoted from investigation case {case_id}",
            tags=tags,
        ),
        source="investigation",
    )

    # Reflect the promotion back onto the observable (idempotent add refreshes it).
    await get_observable_store().add(
        case_id=case_id,
        observable_type=otype,
        value=value,
        actor=user.sub,
        is_ioc=True,
        tlp=observable.get("tlp") or "amber",
        pap=observable.get("pap") or "amber",
        tags=observable.get("tags") or [],
        source=observable.get("source") or "manual",
    )

    await get_audit_logger().log(
        actor=user.sub,
        action="investigation.observable_promote",
        resource_type="investigation_case",
        resource_id=case_id,
        details=f"{otype}={value} → ioc={entry.id}",
    )
    return {
        "message": "Observable promoted to IOC",
        "ioc_id": entry.id,
        "ioc_type": ioc_type.value,
    }


# Amount added on top of the effective block threshold when an enrichment
# auto-hardens a case's origins. ``0.0`` sets each origin's score to *exactly* the
# block threshold — guaranteeing the origin's next request is escalated by the
# proxy without over-penalising it (mirrors the manual raise_risk default).
_ENRICH_AUTORAISE_AMOUNT = 0.0


def _resolve_cortex_connector(integration_id: str) -> "CortexConnector":
    """Resolve a configured, enabled Cortex enrichment connector, or raise.

    Shared by the observable enrich + responder endpoints so both apply identical
    validation: unknown id ⇒ 404; non-cortex ⇒ 400; disabled ⇒ 400; missing
    credentials ⇒ 400. The returned connector is ready to call.
    """
    registry = get_integration_registry()
    config = registry.get(integration_id)
    if config is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    if config.type != "cortex":
        raise HTTPException(
            status_code=400, detail="This action requires a cortex integration"
        )
    if not config.enabled:
        raise HTTPException(status_code=400, detail="Integration is disabled")
    connector = registry.build_enrichment_connector(config)
    if connector is None:
        raise HTTPException(status_code=400, detail="Integration is not fully configured")
    return connector


def _resolve_opencti_connector(integration_id: str) -> "OpenCTIConnector":
    """Resolve a configured, enabled OpenCTI lookup connector, or raise.

    Mirrors :func:`_resolve_cortex_connector`: unknown id ⇒ 404; non-opencti ⇒
    400; disabled ⇒ 400; missing credentials ⇒ 400. The returned connector is
    ready to call.
    """
    registry = get_integration_registry()
    config = registry.get(integration_id)
    if config is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    if config.type != "opencti":
        raise HTTPException(
            status_code=400, detail="This action requires an opencti integration"
        )
    if not config.enabled:
        raise HTTPException(status_code=400, detail="Integration is disabled")
    connector = registry.build_lookup_connector(config)
    if connector is None:
        raise HTTPException(status_code=400, detail="Integration is not fully configured")
    return connector


def _case_origin_tokens(case: dict) -> list[str]:
    """Return the valid ``scope_type:digest`` origin tokens linked to a case.

    Only ``origin`` subjects whose key parses as a known correlation scope + a
    16-hex digest are returned; anything malformed is dropped (never raised).
    """
    tokens: list[str] = []
    for subject in case.get("subjects") or []:
        if subject.get("subject_type") != "origin":
            continue
        key = str(subject.get("subject_key") or "")
        scope, _, digest = key.partition(":")
        if scope in _VALID_SCOPES and _DIGEST_RE.match(digest):
            tokens.append(key)
    return tokens


async def _auto_raise_case_origins(case: dict, *, case_id: str, actor: str) -> dict:
    """Harden every at-risk origin linked to a case (best-effort, fail-open).

    Invoked when an enrichment confirms an observable is ``malicious``: each
    ``origin`` subject on the case is pushed to (or above) the effective block
    threshold so its next request is escalated by the proxy. Never raises — a
    missing/unreachable Redis simply yields ``raised=[]`` with a reason, and the
    enrichment response is unaffected. Successful raises are journalled onto the
    case's append-only action trail.
    """
    result: dict = {"raised": [], "correlation_enabled": _correlation_enabled()}
    tokens = _case_origin_tokens(case)
    if not tokens:
        result["skipped_reason"] = "no_origin_subjects"
        return result
    r = _redis()
    if r is None:
        result["skipped_reason"] = "redis_unavailable"
        return result
    try:
        r.ping()
    except Exception:
        result["skipped_reason"] = "redis_unavailable"
        return result

    raised: list[dict] = []
    for token in tokens:
        try:
            effect = _raise_origin_risk(r, token, _ENRICH_AUTORAISE_AMOUNT)
        except Exception:  # noqa: BLE001, S112 - one origin failing must not abort the rest
            continue
        raised.append({"token": token, **effect})
    result["raised"] = raised

    if raised:
        try:
            await get_case_store().add_action_note(
                case_id=case_id,
                actor=actor,
                text=(
                    f"enrichment auto-raised {len(raised)} origin(s) to block threshold: "
                    f"{', '.join(e['token'] for e in raised)}"
                ),
            )
        except Exception:  # noqa: BLE001, S110 - journaling is best-effort, never fatal
            pass
    return result


@router.post("/{case_id}/observables/{observable_id}/enrich")
async def enrich_case_observable(
    case_id: str,
    observable_id: str,
    body: ObservableEnrichRequest,
    user: TokenPayload = Depends(require_permission("investigation:write")),
):
    """Enrich an observable via a Cortex integration's analyzers (Phase 2).

    Runs the requested ``analyzer_ids`` against the observable, folds the reports
    into a compact verdict blob, and stores it under ``enrichment['cortex']``. A
    ``malicious`` verdict flags the observable ``is_ioc`` *and* auto-hardens every
    ``origin`` subject linked to the case (best-effort — see
    :func:`_auto_raise_case_origins`) so the confirmed-bad indicator escalates the
    origins that produced it. Fail-open: an unreachable/failing Cortex surfaces a
    ``502`` (audited) and never mutates the observable.
    """
    case = await _get_case_scoped(user, case_id)  # tenant gate

    observable = await get_observable_store().get(case_id, observable_id)
    if observable is None:
        raise HTTPException(status_code=404, detail="Observable not found")

    if body.tlp is not None and body.tlp not in TLP_LEVELS:
        raise HTTPException(
            status_code=400, detail=f"tlp must be one of: {', '.join(TLP_LEVELS)}"
        )

    connector = _resolve_cortex_connector(body.integration_id)

    tlp = body.tlp or observable.get("tlp") or "amber"
    audit = get_audit_logger()
    try:
        enrichment = await connector.enrich_observable(
            observable_type=observable.get("type") or "other",
            value=observable.get("value") or "",
            analyzer_ids=body.analyzer_ids,
            tlp=tlp,
        )
    except ConnectorError as exc:
        await audit.log(
            actor=user.sub,
            action="investigation.observable_enrich_failed",
            resource_type="investigation_case",
            resource_id=case_id,
            details=str({"observable_id": observable_id, "error": str(exc)}),
        )
        # Fail-open: surface the failure without ever touching the observable.
        raise HTTPException(status_code=502, detail=f"Enrichment failed: {exc}") from None

    is_malicious = bool(enrichment.get("is_malicious"))
    updated = await get_observable_store().set_enrichment(
        case_id=case_id,
        observable_id=observable_id,
        key="cortex",
        data=enrichment,
        mark_ioc=is_malicious,
    )
    if updated is None:  # pragma: no cover — observable existence checked above
        raise HTTPException(status_code=404, detail="Observable not found")

    # A confirmed-malicious verdict auto-hardens the case's linked origins so the
    # proxy escalates their next request. Best-effort / fail-open — never blocks the
    # enrichment response, even if Redis is down or no origins are linked.
    origin_risk: Optional[dict] = None
    if is_malicious:
        origin_risk = await _auto_raise_case_origins(case, case_id=case_id, actor=user.sub)

    await audit.log(
        actor=user.sub,
        action="investigation.observable_enrich",
        resource_type="investigation_case",
        resource_id=case_id,
        details=str(
            {
                "observable_id": observable_id,
                "integration_id": body.integration_id,
                "verdict": enrichment.get("verdict"),
                "analyzers": len(body.analyzer_ids),
                "origins_raised": len(origin_risk["raised"]) if origin_risk else 0,
            }
        ),
    )
    response: dict = {
        "message": "Observable enriched",
        "observable": updated,
        "enrichment": enrichment,
    }
    if origin_risk is not None:
        response["origin_risk"] = origin_risk
    return response


@router.post("/{case_id}/observables/{observable_id}/respond")
async def run_observable_responder(
    case_id: str,
    observable_id: str,
    body: ObservableResponderRequest,
    user: TokenPayload = Depends(require_permission("investigation:write")),
):
    """Run a Cortex responder (response action) against an observable (Phase 2).

    Triggers a bounded Cortex responder (block an IP, notify, …) against the
    observable's value and records the outcome under ``enrichment['cortex_responder']``
    (never flags ``is_ioc`` — a responder is an action, not a verdict). Fail-open:
    an unreachable/failing Cortex surfaces a ``502`` (audited) and never mutates the
    observable.
    """
    await _get_case_scoped(user, case_id)  # tenant gate

    observable = await get_observable_store().get(case_id, observable_id)
    if observable is None:
        raise HTTPException(status_code=404, detail="Observable not found")

    if body.tlp is not None and body.tlp not in TLP_LEVELS:
        raise HTTPException(
            status_code=400, detail=f"tlp must be one of: {', '.join(TLP_LEVELS)}"
        )

    connector = _resolve_cortex_connector(body.integration_id)

    tlp = body.tlp or observable.get("tlp") or "amber"
    audit = get_audit_logger()
    try:
        outcome = await connector.run_responder(
            responder_id=body.responder_id,
            observable_type=observable.get("type") or "other",
            value=observable.get("value") or "",
            tlp=tlp,
        )
    except ConnectorError as exc:
        await audit.log(
            actor=user.sub,
            action="investigation.observable_respond_failed",
            resource_type="investigation_case",
            resource_id=case_id,
            details=str({"observable_id": observable_id, "error": str(exc)}),
        )
        # Fail-open: surface the failure without ever touching the observable.
        raise HTTPException(status_code=502, detail=f"Responder failed: {exc}") from None

    updated = await get_observable_store().set_enrichment(
        case_id=case_id,
        observable_id=observable_id,
        key="cortex_responder",
        data=outcome,
    )
    if updated is None:  # pragma: no cover — observable existence checked above
        raise HTTPException(status_code=404, detail="Observable not found")

    await audit.log(
        actor=user.sub,
        action="investigation.observable_respond",
        resource_type="investigation_case",
        resource_id=case_id,
        details=str(
            {
                "observable_id": observable_id,
                "integration_id": body.integration_id,
                "responder_id": body.responder_id,
                "status": outcome.get("status"),
            }
        ),
    )
    return {
        "message": "Responder executed",
        "observable": updated,
        "responder": outcome,
    }


@router.post("/{case_id}/observables/{observable_id}/lookup")
async def lookup_case_observable(
    case_id: str,
    observable_id: str,
    body: ObservableLookupRequest,
    user: TokenPayload = Depends(require_permission("investigation:write")),
):
    """Look an observable up against an OpenCTI integration's indicators (Phase 2).

    Searches OpenCTI for the observable's literal value, folds the matching STIX
    indicators into a compact verdict blob, and stores it under
    ``enrichment['opencti']``. A ``malicious`` verdict flags the observable
    ``is_ioc`` *and* auto-hardens every ``origin`` subject linked to the case
    (best-effort — see :func:`_auto_raise_case_origins`) so the confirmed-bad
    indicator escalates the origins that produced it. Fail-open: an
    unreachable/failing OpenCTI surfaces a ``502`` (audited) and never mutates the
    observable.
    """
    case = await _get_case_scoped(user, case_id)  # tenant gate

    observable = await get_observable_store().get(case_id, observable_id)
    if observable is None:
        raise HTTPException(status_code=404, detail="Observable not found")

    connector = _resolve_opencti_connector(body.integration_id)

    audit = get_audit_logger()
    try:
        enrichment = await connector.lookup_observable(
            observable_type=observable.get("type") or "other",
            value=observable.get("value") or "",
        )
    except ConnectorError as exc:
        await audit.log(
            actor=user.sub,
            action="investigation.observable_lookup_failed",
            resource_type="investigation_case",
            resource_id=case_id,
            details=str({"observable_id": observable_id, "error": str(exc)}),
        )
        # Fail-open: surface the failure without ever touching the observable.
        raise HTTPException(status_code=502, detail=f"Lookup failed: {exc}") from None

    is_malicious = bool(enrichment.get("is_malicious"))
    updated = await get_observable_store().set_enrichment(
        case_id=case_id,
        observable_id=observable_id,
        key="opencti",
        data=enrichment,
        mark_ioc=is_malicious,
    )
    if updated is None:  # pragma: no cover — observable existence checked above
        raise HTTPException(status_code=404, detail="Observable not found")

    # A confirmed-malicious verdict auto-hardens the case's linked origins so the
    # proxy escalates their next request. Best-effort / fail-open — never blocks the
    # lookup response, even if Redis is down or no origins are linked.
    origin_risk: Optional[dict] = None
    if is_malicious:
        origin_risk = await _auto_raise_case_origins(case, case_id=case_id, actor=user.sub)

    await audit.log(
        actor=user.sub,
        action="investigation.observable_lookup",
        resource_type="investigation_case",
        resource_id=case_id,
        details=str(
            {
                "observable_id": observable_id,
                "integration_id": body.integration_id,
                "verdict": enrichment.get("verdict"),
                "indicators": enrichment.get("indicator_count"),
                "origins_raised": len(origin_risk["raised"]) if origin_risk else 0,
            }
        ),
    )
    response: dict = {
        "message": "Observable looked up",
        "observable": updated,
        "enrichment": enrichment,
    }
    if origin_risk is not None:
        response["origin_risk"] = origin_risk
    return response


# ─── Tasks (Phase 0) ──────────────────────────────────────────────────────────


@router.get("/{case_id}/tasks")
async def list_case_tasks(
    case_id: str,
    user: TokenPayload = Depends(require_permission("investigation:read")),
):
    """List a case's checklist tasks in manual order, with a progress roll-up."""
    await _get_case_scoped(user, case_id)  # tenant gate
    store = get_task_store()
    tasks = await store.list_for_case(case_id)
    progress = await store.progress(case_id)
    return {
        "case_id": case_id,
        "tasks": tasks,
        "count": len(tasks),
        "progress": progress,
        "can_write": _can_write(user),
        "statuses": list(TASK_STATUSES),
    }


@router.post("/{case_id}/tasks")
async def add_case_task(
    case_id: str,
    body: TaskAddRequest,
    user: TokenPayload = Depends(require_permission("investigation:write")),
):
    """Add a checklist task to a case."""
    await _get_case_scoped(user, case_id)  # tenant gate

    try:
        task = await get_task_store().add(
            case_id=case_id,
            title=body.title,
            actor=user.sub,
            assignee=body.assignee,
            due_at=body.due_at,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None

    await get_audit_logger().log(
        actor=user.sub,
        action="investigation.task_add",
        resource_type="investigation_case",
        resource_id=case_id,
        details=f"task={task.get('task_id')} title={task.get('title')}",
    )
    return {"message": "Task added", "task": task}


@router.post("/{case_id}/tasks/{task_id}/state")
async def set_case_task_state(
    case_id: str,
    task_id: str,
    body: TaskStateRequest,
    user: TokenPayload = Depends(require_permission("investigation:write")),
):
    """Set a task's status, assignee and/or due date."""
    if body.status is None and body.assignee is None and body.due_at is None:
        raise HTTPException(
            status_code=400, detail="Provide status, assignee and/or due_at."
        )
    await _get_case_scoped(user, case_id)  # tenant gate

    try:
        task = await get_task_store().set_state(
            case_id=case_id,
            task_id=task_id,
            actor=user.sub,
            status=body.status,
            assignee=body.assignee,
            due_at=body.due_at,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")

    await get_audit_logger().log(
        actor=user.sub,
        action="investigation.task_state",
        resource_type="investigation_case",
        resource_id=case_id,
        details=f"task={task_id} status={body.status} assignee={body.assignee}",
    )
    return {"message": "Task updated", "task": task}


@router.post("/{case_id}/tasks/{task_id}/note")
async def add_case_task_note(
    case_id: str,
    task_id: str,
    body: TaskNoteRequest,
    user: TokenPayload = Depends(require_permission("investigation:write")),
):
    """Append a note to a task."""
    await _get_case_scoped(user, case_id)  # tenant gate

    try:
        task = await get_task_store().add_note(
            case_id=case_id, task_id=task_id, actor=user.sub, text=body.text
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")

    await get_audit_logger().log(
        actor=user.sub,
        action="investigation.task_note",
        resource_type="investigation_case",
        resource_id=case_id,
        details=f"task={task_id} note_len={len(body.text)}",
    )
    return {"message": "Note added", "task": task}


@router.delete("/{case_id}/tasks/{task_id}")
async def remove_case_task(
    case_id: str,
    task_id: str,
    user: TokenPayload = Depends(require_permission("investigation:write")),
):
    """Delete a task from a case."""
    await _get_case_scoped(user, case_id)  # tenant gate

    removed = await get_task_store().remove(case_id=case_id, task_id=task_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Task not found")

    await get_audit_logger().log(
        actor=user.sub,
        action="investigation.task_remove",
        resource_type="investigation_case",
        resource_id=case_id,
        details=f"task={task_id}",
    )
    return {"message": "Task removed"}
