"""Investigation Center — the SOC analyst workspace over correlation alerts.

Where the correlation console (``/admin/correlation``) *tunes* the adaptive
risk engine, this route lets an analyst *investigate* what it produced. It stitches
together evidence that already exists but was previously scattered:

* the **alert queue** — correlation-engine events (confirmed input↔output
  exfiltration incidents + adaptive origin-risk enforcement) from the durable
  event store, annotated with their triage state;
* **incident drill-down** — a confirmed incident joined to the exact input/output
  detections that produced it (via ``contributing_event_ids``) plus the persisted
  per-signal confidence breakdown, so *why* it escalated is auditable;
* **origin timeline** — an at-risk origin's current decayed risk score (read from
  the correlation risk state in Redis) alongside the durable ledger of events that
  drove that score up (pivoted via the ``scope_digests`` the proxy stamped);
* **triage workflow** — acknowledge / assign / resolve an alert and attach
  investigation notes (persisted in ``investigation_triage``).

Reads require ``investigation:read`` (all roles); triage mutations require
``investigation:write`` (admin + security). The evidence is reconstructed entirely
from the durable store + existing Redis risk state — this route adds no hot-path
cost and no new proxy-side structures.
"""

from __future__ import annotations

import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ..models.auth import TokenPayload
from ..services.audit_logger import get_audit_logger
from ..services.auth_service import require_permission
from ..services.investigation_store import STATUSES, SUBJECT_TYPES, get_triage_store
from ..services.security_events_store import get_security_events_store

# Reuse the correlation console's origin-risk readers (admin→admin) so the risk
# score shown here is byte-identical to /admin/correlation/origins.
from .correlation import (
    _DIGEST_RE,
    _RISK_PREFIX,
    _VALID_SCOPES,
    _defaults,
    _read_override,
    _redis,
    _summarize_origin,
)

# Session-decomposition drill-down reuses the Session Tracker's own Redis
# readers so the score/signal picture shown here is byte-identical to
# /admin/sessions/active. Imported (not reimplemented) to keep one source of
# truth; sessions.py has no dependency on this module, so no import cycle.
from .sessions import (
    _KEY_RE as _SESSION_DIGEST_RE,
)
from .sessions import (
    _SIGNALS_5M_PREFIX,
    _SIGNALS_30M_PREFIX,
    _SIGNALS_SUFFIX,
    _all_session_keys,
    _summarize_session,
)
from .sessions import (
    _defaults as _session_defaults,
)
from .sessions import (
    _read_override as _session_read_override,
)

router = APIRouter()

# Upper bound on how far back an alert-queue / timeline lookback may reach, and the
# per-request row caps — keeps every query bounded regardless of client input.
_MAX_LOOKBACK_HOURS = 24 * 90  # 90 days
_MAX_ALERTS = 500
_MAX_TIMELINE = 500


def _scoped_tenant(user: TokenPayload, requested: Optional[str]) -> Optional[str]:
    """Resolve the effective tenant filter, enforcing tenant scoping.

    A tenant-scoped operator (``user.tenant`` set) is pinned to their own tenant
    regardless of any requested value; a global operator may filter freely.
    """
    if user.tenant:
        return user.tenant
    return requested


def _tenant_allowed(user: TokenPayload, tenant: Optional[str]) -> bool:
    """True if ``user`` may view an artefact belonging to ``tenant``."""
    if not user.tenant:
        return True
    return (tenant or "") == user.tenant


def _can_write(user: TokenPayload) -> bool:
    """True if the caller's role includes ``investigation:write``."""
    try:
        from ..models.auth import ROLE_PERMISSIONS

        return "investigation:write" in ROLE_PERMISSIONS.get(user.role, set())
    except Exception:
        return False


def _since_from_hours(hours: Optional[float]) -> Optional[float]:
    """Convert an optional lookback window (hours) into a unix ``since`` bound."""
    if hours is None:
        return None
    hours = max(0.0, min(float(hours), _MAX_LOOKBACK_HOURS))
    if hours == 0.0:
        return None
    return time.time() - hours * 3600.0


def _session_verdict(score: float, warn: float, block: float) -> str:
    """Classify a decomposition-session score against its window thresholds.

    Mirrors the proxy tracker's own escalation ladder (BLOCK dominates WARN);
    a non-positive threshold is treated as "not configured" and skipped.
    """
    if block > 0 and score >= block:
        return "block"
    if warn > 0 and score >= warn:
        return "warn"
    return "ok"


class TriageStateRequest(BaseModel):
    """Set the workflow status and/or assignee for a triage subject."""

    subject_type: str = Field(..., description="incident | origin")
    subject_key: str = Field(..., min_length=1, max_length=256)
    status: Optional[str] = Field(default=None, description=f"one of {STATUSES}")
    assignee: Optional[str] = Field(default=None, max_length=128)


class TriageNoteRequest(BaseModel):
    """Append a free-text investigation note to a triage subject."""

    subject_type: str = Field(..., description="incident | origin")
    subject_key: str = Field(..., min_length=1, max_length=256)
    text: str = Field(..., min_length=1, max_length=4000)


class BulkTriageSubject(BaseModel):
    """One subject targeted by a bulk triage action."""

    subject_type: str = Field(..., description="incident | origin | session")
    subject_key: str = Field(..., min_length=1, max_length=256)


class BulkTriageRequest(BaseModel):
    """Apply one status/assignee change across several subjects in a single call.

    A single request keeps the whole batch in one audit action and avoids the
    partial-failure ambiguity of many client-side round-trips: each subject is
    authorised and mutated independently and its individual outcome is reported.
    """

    subjects: list[BulkTriageSubject] = Field(..., min_length=1, max_length=100)
    status: Optional[str] = Field(default=None, description=f"one of {STATUSES}")
    assignee: Optional[str] = Field(default=None, max_length=128)


def _alert_subject(evt: dict) -> tuple[str, str] | None:
    """Derive the triage subject (type, key) an alert row hangs off.

    A confirmed incident is keyed by its ``incident_id``; anything else from the
    correlation engine (e.g. an adaptive origin-risk enforcement) is keyed by its
    request id under the ``origin`` bucket so it can still be triaged.
    """
    incident_id = (evt.get("incident_id") or "").strip()
    if incident_id:
        return ("incident", incident_id)
    meta = evt.get("metadata") or {}
    inc = str(meta.get("incident_id") or "").strip()
    if inc:
        return ("incident", inc)
    rid = (evt.get("request_id") or "").strip()
    if rid:
        return ("origin", f"request:{rid}")
    return None


@router.get("/status")
async def investigation_status(
    user: TokenPayload = Depends(require_permission("investigation:read")),
):
    """Feature availability + queue counts for the Investigation Center header."""
    store = get_security_events_store()
    triage = get_triage_store()

    correlation_enabled = False
    try:
        from src.config import settings

        correlation_enabled = bool(getattr(settings, "correlation_enabled", False))
    except Exception:
        correlation_enabled = False

    tenant = user.tenant or None
    since = _since_from_hours(24)
    try:
        recent_alerts = await store.list_correlation_alerts(
            tenant=tenant, since=since, limit=_MAX_ALERTS
        )
    except Exception:
        recent_alerts = []
    try:
        open_triage = await triage.list_records(
            status="open", tenant=tenant, limit=_MAX_ALERTS
        )
        in_progress = await triage.list_records(
            status="in_progress", tenant=tenant, limit=_MAX_ALERTS
        )
    except Exception:
        open_triage, in_progress = [], []

    return {
        "correlation_enabled": correlation_enabled,
        "can_write": _can_write(user),
        "alerts_last_24h": len(recent_alerts),
        "open_triage": len(open_triage),
        "in_progress_triage": len(in_progress),
        "statuses": list(STATUSES),
        "subject_types": list(SUBJECT_TYPES),
    }


@router.get("/alerts")
async def investigation_alerts(
    user: TokenPayload = Depends(require_permission("investigation:read")),
    tenant: Optional[str] = Query(None, description="Filter by tenant (ignored for tenant-scoped users)"),
    verdict: Optional[str] = Query(None, description="block | warn"),
    lookback_hours: Optional[float] = Query(24, ge=0, le=_MAX_LOOKBACK_HOURS),
    limit: int = Query(50, ge=1, le=_MAX_ALERTS),
    offset: int = Query(0, ge=0),
):
    """Return the correlation-alert queue, annotated with triage state."""
    eff_tenant = _scoped_tenant(user, tenant)
    since = _since_from_hours(lookback_hours)
    store = get_security_events_store()
    triage = get_triage_store()

    alerts = await store.list_correlation_alerts(
        tenant=eff_tenant, verdict=verdict, since=since, limit=limit, offset=offset
    )

    # Batch-annotate with triage state in a single round-trip.
    subjects: list[tuple[str, str]] = []
    for a in alerts:
        subj = _alert_subject(a)
        if subj:
            subjects.append(subj)
    triage_map = await triage.get_map(subjects)

    out: list[dict] = []
    for a in alerts:
        subj = _alert_subject(a)
        rec = triage_map.get(subj) if subj else None
        out.append({
            **a,
            "subject_type": subj[0] if subj else None,
            "subject_key": subj[1] if subj else None,
            "triage_status": (rec or {}).get("status", "open"),
            "assignee": (rec or {}).get("assignee", ""),
        })
    return {"alerts": out, "count": len(out)}


@router.get("/incident/{incident_id}")
async def investigation_incident(
    incident_id: str,
    user: TokenPayload = Depends(require_permission("investigation:read")),
):
    """Full drill-down for a confirmed incident: chain + confidence + triage."""
    incident_id = (incident_id or "").strip()
    if not incident_id:
        raise HTTPException(status_code=400, detail="incident_id is required")

    store = get_security_events_store()
    incident_events = await store.find_by_incident(incident_id)
    if not incident_events:
        raise HTTPException(status_code=404, detail="Incident not found")

    primary = incident_events[0]
    if not _tenant_allowed(user, primary.get("tenant")):
        # Do not leak cross-tenant existence.
        raise HTTPException(status_code=404, detail="Incident not found")

    meta = primary.get("metadata") or {}
    contributing_ids = meta.get("contributing_event_ids") or []
    contributing = await store.find_by_event_ids(list(contributing_ids))

    triage = await get_triage_store().get("incident", incident_id)

    return {
        "incident_id": incident_id,
        "incident_events": incident_events,
        "contributing_events": contributing,
        "confidence": meta.get("confidence"),
        "confidence_breakdown": meta.get("confidence_breakdown") or {},
        "input_categories": meta.get("input_categories") or [],
        "output_categories": meta.get("output_categories") or [],
        "risk_score": meta.get("risk_score"),
        "input_hash": meta.get("input_hash") or primary.get("input_hash") or "",
        "triage": triage,
    }


@router.get("/origin/{scope_type}/{digest}")
async def investigation_origin(
    scope_type: str,
    digest: str,
    user: TokenPayload = Depends(require_permission("investigation:read")),
    lookback_hours: Optional[float] = Query(None, ge=0, le=_MAX_LOOKBACK_HOURS),
    limit: int = Query(200, ge=1, le=_MAX_TIMELINE),
):
    """Origin drill-down: current decayed risk + the durable event ledger."""
    if scope_type not in _VALID_SCOPES:
        raise HTTPException(status_code=400, detail=f"Invalid scope_type (expected one of {_VALID_SCOPES})")
    if not _DIGEST_RE.match(digest):
        raise HTTPException(status_code=400, detail="Invalid digest (expected 16 hex chars)")

    token = f"{scope_type}:{digest}"
    since = _since_from_hours(lookback_hours)

    # Current decayed risk score (best-effort; Redis may be unavailable).
    risk: dict | None = None
    r = _redis()
    if r is not None:
        try:
            r.ping()
            effective = {**_defaults(), **_read_override(r)}
            half_life = float(effective.get("risk_decay_seconds", 900.0))
            risk = _summarize_origin(r, f"{_RISK_PREFIX}{token}", half_life, time.time())
        except Exception:
            risk = None

    store = get_security_events_store()
    timeline = await store.find_by_scope_digest(token, since=since, limit=limit)

    # Tenant scoping: a tenant-scoped operator only sees their own contributions.
    if user.tenant:
        timeline = [e for e in timeline if (e.get("tenant") or "") == user.tenant]

    triage = await get_triage_store().get("origin", token)

    return {
        "scope_type": scope_type,
        "digest": digest,
        "token": token,
        "risk": risk,
        "timeline": timeline,
        "event_count": len(timeline),
        "triage": triage,
    }


@router.get("/sessions")
async def investigation_sessions(
    user: TokenPayload = Depends(require_permission("investigation:read")),
    limit: int = Query(50, ge=1, le=_MAX_ALERTS),
):
    """At-risk decomposition sessions (highest accumulated score first).

    A browsable pivot into the Session Decomposition Tracker's live accumulator,
    annotated with any existing triage state. Session digests are irreversible
    SHA-256 identifiers with no recoverable tenant, so this is not tenant-scoped;
    it exposes only pseudonymous scores/signal ids, never message content.
    Returns an empty list when Redis is unavailable.
    """
    r = _redis()
    if r is None:
        return {"redis_connected": False, "sessions": [], "count": 0}
    try:
        r.ping()
    except Exception:
        return {"redis_connected": False, "sessions": [], "count": 0}

    effective = {**_session_defaults(), **_session_read_override(r)}
    rows: list[dict] = []
    for redis_key, window in _all_session_keys(r):
        summary = _summarize_session(r, redis_key, window)
        if not summary:
            continue
        warn_f = "warn_threshold_30m" if window == "30m" else "warn_threshold"
        block_f = "block_threshold_30m" if window == "30m" else "block_threshold"
        summary["verdict"] = _session_verdict(
            summary["score"],
            float(effective.get(warn_f, 0) or 0),
            float(effective.get(block_f, 0) or 0),
        )
        rows.append(summary)
        if len(rows) >= limit:
            break

    # Most suspicious sessions on top.
    rows.sort(key=lambda s: s["score"], reverse=True)

    # Batch-annotate with triage state (subject_key is the bare session digest).
    subjects = [("session", s["session_key"]) for s in rows]
    triage_map = await get_triage_store().get_map(subjects)
    for s in rows:
        rec = triage_map.get(("session", s["session_key"]))
        s["triage_status"] = (rec or {}).get("status", "open")
        s["assignee"] = (rec or {}).get("assignee", "")

    return {"redis_connected": True, "sessions": rows, "count": len(rows)}


@router.get("/session/{digest}")
async def investigation_session(
    digest: str,
    user: TokenPayload = Depends(require_permission("investigation:read")),
):
    """Decomposition-session drill-down: accumulated signals per window + triage.

    Shows the 5-minute and 30-minute signal accumulators (score, distinct signal
    ids, TTL) the proxy tracker maintains, each classified against the live
    thresholds. Digests are irreversible and carry no message content, so this is
    available to any ``investigation:read`` operator.
    """
    digest = (digest or "").strip()
    if not _SESSION_DIGEST_RE.match(digest):
        raise HTTPException(status_code=400, detail="Invalid digest (expected 16 hex chars)")

    effective = _session_defaults()
    windows: list[dict] = []
    r = _redis()
    if r is not None:
        try:
            r.ping()
            effective = {**_session_defaults(), **_session_read_override(r)}
            for prefix, window, warn_f, block_f in (
                (_SIGNALS_5M_PREFIX, "5m", "warn_threshold", "block_threshold"),
                (_SIGNALS_30M_PREFIX, "30m", "warn_threshold_30m", "block_threshold_30m"),
            ):
                key = f"{prefix}{digest}{_SIGNALS_SUFFIX}"
                summary = _summarize_session(r, key, window)
                if not summary:
                    continue
                summary["verdict"] = _session_verdict(
                    summary["score"],
                    float(effective.get(warn_f, 0) or 0),
                    float(effective.get(block_f, 0) or 0),
                )
                summary["warn_threshold"] = effective.get(warn_f)
                summary["block_threshold"] = effective.get(block_f)
                windows.append(summary)
        except Exception:
            windows = []

    triage = await get_triage_store().get("session", digest)
    return {
        "digest": digest,
        "windows": windows,
        "effective": effective,
        "triage": triage,
    }


@router.get("/triage")
async def investigation_triage_list(
    user: TokenPayload = Depends(require_permission("investigation:read")),
    status: Optional[str] = Query(None),
    subject_type: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=_MAX_ALERTS),
    offset: int = Query(0, ge=0),
):
    """List triage records (most-recently-updated first) for the workqueue."""
    tenant = user.tenant or None
    records = await get_triage_store().list_records(
        status=status, subject_type=subject_type, tenant=tenant,
        limit=limit, offset=offset,
    )
    return {"records": records, "count": len(records)}


@router.post("/triage/state")
async def investigation_triage_state(
    body: TriageStateRequest,
    user: TokenPayload = Depends(require_permission("investigation:write")),
):
    """Set an alert's workflow status and/or assignee."""
    if body.status is None and body.assignee is None:
        raise HTTPException(status_code=400, detail="Provide status and/or assignee.")

    tenant = await _authorize_subject(user, body.subject_type, body.subject_key)

    try:
        record = await get_triage_store().set_state(
            subject_type=body.subject_type,
            subject_key=body.subject_key,
            tenant=tenant,
            actor=user.sub,
            status=body.status,
            assignee=body.assignee,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None

    await get_audit_logger().log(
        actor=user.sub,
        action="investigation.triage_state",
        resource_type="investigation",
        resource_id=f"{body.subject_type}:{body.subject_key}",
        details=f"status={body.status} assignee={body.assignee}",
    )
    return {"message": "Triage updated", "triage": record}


@router.post("/triage/note")
async def investigation_triage_note(
    body: TriageNoteRequest,
    user: TokenPayload = Depends(require_permission("investigation:write")),
):
    """Append an investigation note to an alert."""
    tenant = await _authorize_subject(user, body.subject_type, body.subject_key)

    try:
        record = await get_triage_store().add_note(
            subject_type=body.subject_type,
            subject_key=body.subject_key,
            tenant=tenant,
            actor=user.sub,
            text=body.text,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None

    await get_audit_logger().log(
        actor=user.sub,
        action="investigation.triage_note",
        resource_type="investigation",
        resource_id=f"{body.subject_type}:{body.subject_key}",
        details=f"note_len={len(body.text)}",
    )
    return {"message": "Note added", "triage": record}


@router.post("/triage/bulk")
async def investigation_triage_bulk(
    body: BulkTriageRequest,
    user: TokenPayload = Depends(require_permission("investigation:write")),
):
    """Apply one status/assignee change to several subjects at once.

    Each subject is authorised (tenant-scoped, 404 on cross-tenant with no leak)
    and mutated independently: a subject that fails validation or scoping is
    reported as ``ok=false`` with a reason and does not abort the rest of the
    batch. The whole action is recorded as a single audit entry.
    """
    if body.status is None and body.assignee is None:
        raise HTTPException(status_code=400, detail="Provide status and/or assignee.")
    if body.status is not None and body.status not in STATUSES:
        raise HTTPException(status_code=400, detail=f"invalid status: {body.status}")

    store = get_triage_store()
    results: list[dict] = []
    updated = 0
    for subj in body.subjects:
        entry: dict = {"subject_type": subj.subject_type, "subject_key": subj.subject_key}
        try:
            tenant = await _authorize_subject(user, subj.subject_type, subj.subject_key)
            await store.set_state(
                subject_type=subj.subject_type,
                subject_key=subj.subject_key,
                tenant=tenant,
                actor=user.sub,
                status=body.status,
                assignee=body.assignee,
            )
            entry["ok"] = True
            updated += 1
        except HTTPException as e:
            entry["ok"] = False
            entry["error"] = e.detail
        except ValueError as e:
            entry["ok"] = False
            entry["error"] = str(e)
        results.append(entry)

    await get_audit_logger().log(
        actor=user.sub,
        action="investigation.triage_bulk",
        resource_type="investigation",
        resource_id=f"bulk:{len(body.subjects)}",
        details=(
            f"status={body.status} assignee={body.assignee} "
            f"updated={updated} failed={len(body.subjects) - updated}"
        ),
    )
    return {
        "message": f"Updated {updated} of {len(body.subjects)}",
        "updated": updated,
        "failed": len(body.subjects) - updated,
        "results": results,
    }


async def _authorize_subject(
    user: TokenPayload, subject_type: str, subject_key: str
) -> Optional[str]:
    """Validate the subject and enforce tenant scoping; return its tenant.

    Resolves the owning tenant from the durable evidence (incident id → its
    events; origin token → the events it is stamped on). A tenant-scoped operator
    is rejected (404 — no cross-tenant existence leak) when the subject belongs to
    another tenant. Returns the resolved tenant (or the operator's own tenant as a
    fallback for a not-yet-evidenced subject) to stamp on the triage row.
    """
    if subject_type not in SUBJECT_TYPES:
        raise HTTPException(status_code=400, detail=f"invalid subject_type: {subject_type}")

    store = get_security_events_store()
    owner_tenant: Optional[str] = None

    if subject_type == "incident":
        events = await store.find_by_incident(subject_key)
        if events:
            owner_tenant = events[0].get("tenant")
    elif subject_type == "origin":
        # Origin subjects are "scope_type:digest"; request-keyed origins carry no
        # digest evidence, so only digest-shaped tokens are tenant-resolved.
        parts = subject_key.split(":", 1)
        if len(parts) == 2 and parts[0] in _VALID_SCOPES and _DIGEST_RE.match(parts[1]):
            evidence = await store.find_by_scope_digest(subject_key, limit=1)
            if evidence:
                owner_tenant = evidence[0].get("tenant")
    # else: session — a pseudonymous decomposition digest with no reversible
    # tenant identity. It leaks no cross-tenant content (scores/signal ids only),
    # so it is left unattributed and stamped with the operator's own scope below.

    if user.tenant and owner_tenant is not None and owner_tenant != user.tenant:
        raise HTTPException(status_code=404, detail="Subject not found")

    # Stamp the resolved tenant, falling back to the operator's own scope.
    return owner_tenant or user.tenant
