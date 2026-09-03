"""Inbound reconcile engine (Investigation Phase 4 — bidirectional federation).

Phases 1–3 made Bulwark a *producer*: it pushes a case out to TheHive / DFIR-IRIS
and fires lifecycle events. Phase 4 closes the loop by folding the remote's
*workflow* state back into the local case so a case worked in the remote platform
(or by a SOAR playbook) stays consistent here — **without conflict loops**.

Design stance (resolves roadmap §10.1): reconcile is **field-partitioned**, not
last-writer-wins.

* Bulwark stays authoritative for **detection-derived facts** — subjects,
  observables, enrichment, origin-risk, compliance. A remote can *never* overwrite
  those; this engine does not touch them.
* The remote is authoritative for **workflow state** only — status, severity
  (escalate-only by default), assignee, and analyst comments (folded in as
  ``[remote]``-tagged case notes).

Two hard safety properties make the partition loop-safe:

1. **Anti-reopen guard** — a locally ``resolved``/``closed`` case is *never*
   silently reopened by a remote. A remote reopen is recorded as an audited
   ``conflict`` for an operator to adjudicate, never auto-applied.
2. **Idempotent comment sync** — remote comments are de-duplicated against the
   ``[remote]``-tagged notes already on the case, so re-reading the same remote
   state (poll + webhook both fire, or a connector returns the full comment list)
   never double-appends.

The core planner (:func:`plan_reconcile`) is a **pure function** — no I/O — so the
field-partition logic is unit-testable without a database or a live remote. The
async orchestrator (:func:`reconcile_case`) wires it to the connector, the case
store, the link store, the audit log and the lifecycle-webhook emitter, and is
**fail-open** end to end: a dead remote, an unsupported connector, or a downstream
error degrades to "no change" and never raises into the caller.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional, Protocol

from ..audit_logger import get_audit_logger
from ..investigation_case_store import (
    CASE_SEVERITIES,
    get_case_store,
)
from .base import (
    REMOTE_STATUS_CLOSED,
    REMOTE_STATUS_IN_PROGRESS,
    REMOTE_STATUS_OPEN,
    RemoteState,
)
from .event_webhook import get_event_webhook_emitter

logger = logging.getLogger(__name__)

# ── Field-partition maps ─────────────────────────────────────────────────────

# Normalized remote workflow status → local case status. Deliberately partial:
# only the three statuses a remote can meaningfully drive are mapped. ``open`` and
# ``in_progress`` are the "active" remote states; ``closed`` is terminal.
_REMOTE_TO_LOCAL_STATUS: dict[str, str] = {
    REMOTE_STATUS_OPEN: "open",
    REMOTE_STATUS_IN_PROGRESS: "investigating",
    REMOTE_STATUS_CLOSED: "closed",
}

# Remote statuses that represent an *active* (non-terminal) case — the ones that
# would "reopen" a locally-terminal case and therefore trip the anti-reopen guard.
_REMOTE_ACTIVE_STATUSES = (REMOTE_STATUS_OPEN, REMOTE_STATUS_IN_PROGRESS)

# Local terminal statuses the anti-reopen guard protects. Mirrors
# ``investigation_case_store._TERMINAL_STATUSES`` (kept as a local copy so this
# service does not depend on a private symbol).
_LOCAL_TERMINAL_STATUSES = ("resolved", "closed")

# Severity ordering (low→critical) for the escalate-only comparison. Derived from
# the case store's own ordered tuple so the two never drift.
_SEVERITY_RANK = {sev: rank for rank, sev in enumerate(CASE_SEVERITIES)}

# Every note this engine writes onto a case (a synced remote comment or a conflict
# marker) is tagged with this prefix. It doubles as the idempotency key: the set of
# already-synced remote texts is recovered by stripping this prefix from the case's
# existing notes, so re-reading the same remote state never double-appends.
_REMOTE_NOTE_PREFIX = "[remote] "

# Actor stamped on reconcile-originated audit entries + case notes. The integration
# id is appended so the trail shows *which* remote drove the change.
_ACTOR_PREFIX = "integration:"


@dataclass
class ReconcilePlan:
    """The set of workflow changes a reconcile would apply (pure planner output).

    Detection-derived facts are absent by construction — this only ever carries
    the whitelisted workflow fields.
    """

    status: Optional[str] = None
    severity: Optional[str] = None
    assignee: Optional[str] = None
    new_comments: list[str] = field(default_factory=list)
    conflict: bool = False
    conflict_reason: str = ""

    @property
    def has_field_changes(self) -> bool:
        """True if a status/severity/assignee change would be written."""
        return bool(self.status or self.severity or self.assignee)

    @property
    def has_changes(self) -> bool:
        """True if the plan would mutate the case at all (fields or notes)."""
        return self.has_field_changes or bool(self.new_comments)

    @property
    def reconcile_state(self) -> str:
        """The link-store reconcile marker this plan resolves to.

        A conflict always dominates (it needs operator attention even if some
        non-conflicting fields were applied alongside it).
        """
        return "conflict" if self.conflict else "synced"


@dataclass
class ReconcileResult:
    """Outcome of an attempted reconcile (fail-open: ``ok=False`` is normal)."""

    ok: bool
    detail: str = ""
    reconcile_state: str = ""
    status: Optional[str] = None
    severity: Optional[str] = None
    assignee: Optional[str] = None
    comments_added: int = 0
    conflict: bool = False
    conflict_reason: str = ""
    remote_id: str = ""


class _SyncCapable(Protocol):
    """Structural type for a connector that supports inbound reconcile.

    ``sync_status`` is added *ad-hoc* on the concrete connectors (like
    ``enrich_observable`` / ``lookup_observable`` / ``run_responder``) rather than
    widened onto the base ``Connector`` protocol, so the orchestrator resolves it
    by capability check.
    """

    async def sync_status(self, remote_id: str) -> Optional[RemoteState]: ...


def _note_texts_from_remote(case: dict) -> set[str]:
    """Recover the set of remote texts already recorded on a case.

    Reads the case's append-only note trail and returns every ``[remote]``-tagged
    note with the prefix stripped, so both synced comments and conflict markers are
    de-duplicated on the next reconcile.
    """
    out: set[str] = set()
    for note in case.get("notes") or []:
        if not isinstance(note, dict):
            continue
        text = note.get("text") or ""
        if isinstance(text, str) and text.startswith(_REMOTE_NOTE_PREFIX):
            out.add(text[len(_REMOTE_NOTE_PREFIX):])
    return out


def plan_reconcile(
    case: dict,
    remote: RemoteState,
    *,
    escalate_only_severity: bool = True,
    known_remote_texts: Optional[set[str]] = None,
) -> ReconcilePlan:
    """Compute the workflow changes to fold a remote state into a local case.

    Pure — no I/O. Applies the field partition + the anti-reopen guard and returns
    a :class:`ReconcilePlan`. ``known_remote_texts`` is the set of remote comment /
    conflict texts already recorded on the case (see :func:`_note_texts_from_remote`);
    comments already present are not re-added.
    """
    plan = ReconcilePlan()
    known = set(known_remote_texts or ())

    local_status = (case.get("status") or "").lower()

    # ── status (with the hard anti-reopen guard) ─────────────────────────────
    target = _REMOTE_TO_LOCAL_STATUS.get(remote.status or "")
    if target and target != local_status:
        local_is_terminal = local_status in _LOCAL_TERMINAL_STATUSES
        remote_is_active = remote.status in _REMOTE_ACTIVE_STATUSES
        if local_is_terminal and remote_is_active:
            # Never silently reopen a locally-closed/resolved case — surface a
            # conflict for an operator instead. This is the anti-ping-pong guard.
            plan.conflict = True
            plan.conflict_reason = (
                f"remote status '{remote.raw_status or remote.status}' would reopen "
                f"locally-{local_status} case"
            )
        else:
            plan.status = target

    # ── severity (escalate-only by default) ──────────────────────────────────
    if remote.severity and remote.severity in _SEVERITY_RANK:
        local_sev = (case.get("severity") or "").lower()
        if remote.severity != local_sev:
            remote_rank = _SEVERITY_RANK[remote.severity]
            local_rank = _SEVERITY_RANK.get(local_sev, -1)
            if not escalate_only_severity or remote_rank > local_rank:
                plan.severity = remote.severity

    # ── assignee ─────────────────────────────────────────────────────────────
    if remote.assignee:
        local_assignee = case.get("assignee") or ""
        if remote.assignee != local_assignee:
            plan.assignee = remote.assignee

    # ── comments → notes (de-duped against what's already recorded) ──────────
    for comment in remote.comments:
        text = (comment or "").strip()
        if text and text not in known:
            plan.new_comments.append(text)
            known.add(text)  # guard against duplicates within one batch too

    return plan


def _lifecycle_events(plan: ReconcilePlan) -> list[str]:
    """Lifecycle event types to re-emit for the changes this reconcile applied.

    Mirrors the case-route emission rules: entering a terminal status re-emits
    ``case.resolved``; a severity change (already escalate-only by the time it is
    in the plan) re-emits ``case.severity_raised``. ``case.opened`` never fires from
    a reconcile (a remote does not *create* local cases).
    """
    events: list[str] = []
    if plan.status and plan.status in _LOCAL_TERMINAL_STATUSES:
        events.append("case.resolved")
    if plan.severity:
        events.append("case.severity_raised")
    return events


class ReconcileEngine:
    """Wires the pure planner to the connector + stores (fail-open orchestrator)."""

    def __init__(self) -> None:
        from ..integration_link_store import get_integration_link_store

        self._links = get_integration_link_store()
        self._cases = get_case_store()

    async def reconcile_case(
        self,
        *,
        connector: object,
        connector_type: str,
        integration_id: str,
        case: dict,
        escalate_only_severity: bool = True,
    ) -> ReconcileResult:
        """Fold a linked remote's workflow state into one local case.

        ``case`` is the already tenant-scoped local case dict (the route resolves +
        authorizes it). ``connector_type`` is the link-store key (``config.type``);
        ``integration_id`` identifies the instance for the audit/actor/event trail.

        Fail-open: an unlinked case, a connector without ``sync_status``, an
        unreachable remote, or any downstream error returns ``ok=False`` with a
        reason and never raises.
        """
        case_id = case.get("case_id") or ""
        link = await self._links.get(connector_type, "case", case_id)
        remote_id = (link or {}).get("remote_id") or ""
        if not remote_id:
            return ReconcileResult(ok=False, detail="case is not linked to this integration")

        sync = getattr(connector, "sync_status", None)
        if not callable(sync):
            return ReconcileResult(
                ok=False, detail="connector does not support inbound sync", remote_id=remote_id
            )

        try:
            remote = await sync(remote_id)
        except Exception:  # noqa: BLE001 — fail-open: a broken read is "no update"
            logger.warning("reconcile_sync_status_failed", exc_info=True)
            remote = None
        if remote is None:
            return ReconcileResult(ok=False, detail="remote unreachable", remote_id=remote_id)

        known = _note_texts_from_remote(case)
        plan = plan_reconcile(
            case, remote,
            escalate_only_severity=escalate_only_severity,
            known_remote_texts=known,
        )

        applied_case = case
        actor = f"{_ACTOR_PREFIX}{integration_id}"
        try:
            applied_case = await self._apply(
                case_id=case_id, actor=actor, plan=plan, known=known
            )
        except Exception:  # noqa: BLE001 — fail-open: never break on a store error
            logger.warning("reconcile_apply_failed", exc_info=True)
            # Still record provenance below; the plan simply did not fully apply.

        # Persist the reconcile marker on the link (best-effort).
        try:
            await self._links.set_reconcile(
                connector=connector_type,
                local_type="case",
                local_id=case_id,
                reconcile_state=plan.reconcile_state,
                last_remote_update=remote.last_remote_update or None,
            )
        except Exception:  # noqa: BLE001 — fail-open
            logger.warning("reconcile_link_update_failed", exc_info=True)

        await self._audit(actor, integration_id, case_id, plan, remote_id)
        await self._reemit(plan, applied_case)

        return ReconcileResult(
            ok=True,
            detail="reconciled",
            reconcile_state=plan.reconcile_state,
            status=plan.status,
            severity=plan.severity,
            assignee=plan.assignee,
            comments_added=len(plan.new_comments),
            conflict=plan.conflict,
            conflict_reason=plan.conflict_reason,
            remote_id=remote_id,
        )

    async def reconcile_by_remote_id(
        self,
        *,
        connector: object,
        connector_type: str,
        integration_id: str,
        remote_id: str,
        escalate_only_severity: bool = True,
    ) -> list[ReconcileResult]:
        """Reconcile every local case linked to one remote id (inbound-webhook path).

        An inbound callback carries only the *remote* platform id, so this resolves
        the local link(s) via the ``(connector, remote_id)`` index and reconciles
        each case. Returns one :class:`ReconcileResult` per linked case (empty when
        the remote id maps to nothing here). Fail-open: a per-case error is logged
        and skipped, never raised.
        """
        if not remote_id:
            return []
        try:
            links = await self._links.find_by_remote(connector_type, remote_id)
        except Exception:  # noqa: BLE001 — fail-open: a lookup error is "no match"
            logger.warning("reconcile_find_by_remote_failed", exc_info=True)
            return []
        results: list[ReconcileResult] = []
        for link in links:
            if link.get("local_type") != "case":
                continue
            results.append(
                await self._reconcile_link_case(
                    connector=connector,
                    connector_type=connector_type,
                    integration_id=integration_id,
                    case_id=link.get("local_id") or "",
                    escalate_only_severity=escalate_only_severity,
                )
            )
        return results

    async def sweep(
        self,
        *,
        connector: object,
        connector_type: str,
        integration_id: str,
        limit: int = 200,
        escalate_only_severity: bool = True,
    ) -> list[ReconcileResult]:
        """Reconcile every *active* linked case on a connector (poll-fallback path).

        Backs the periodic :class:`ReconcilePoller`: it walks the connector's
        non-terminal linked cases (least-recently-reconciled first, bounded by
        ``limit``) and reconciles each. Skips locally-terminal cases at the query
        level (they need no further sync). Fail-open per case.
        """
        try:
            links = await self._links.list_active_case_links(
                connector_type,
                exclude_statuses=_LOCAL_TERMINAL_STATUSES,
                limit=limit,
            )
        except Exception:  # noqa: BLE001 — fail-open: a listing error is an empty sweep
            logger.warning("reconcile_sweep_list_failed", exc_info=True)
            return []
        results: list[ReconcileResult] = []
        for link in links:
            results.append(
                await self._reconcile_link_case(
                    connector=connector,
                    connector_type=connector_type,
                    integration_id=integration_id,
                    case_id=link.get("local_id") or "",
                    escalate_only_severity=escalate_only_severity,
                )
            )
        return results

    async def _reconcile_link_case(
        self,
        *,
        connector: object,
        connector_type: str,
        integration_id: str,
        case_id: str,
        escalate_only_severity: bool,
    ) -> ReconcileResult:
        """Load one linked case and reconcile it (shared by the two trigger paths)."""
        if not case_id:
            return ReconcileResult(ok=False, detail="missing case id")
        try:
            case = await self._cases.get(case_id)
        except Exception:  # noqa: BLE001 — fail-open: a store error is "skip this case"
            logger.warning("reconcile_case_load_failed", exc_info=True)
            return ReconcileResult(ok=False, detail="case load failed")
        if case is None:
            return ReconcileResult(ok=False, detail="case not found")
        return await self.reconcile_case(
            connector=connector,
            connector_type=connector_type,
            integration_id=integration_id,
            case=case,
            escalate_only_severity=escalate_only_severity,
        )

    async def _apply(
        self, *, case_id: str, actor: str, plan: ReconcilePlan, known: set[str]
    ) -> dict:
        """Apply a plan to the case store, returning the resulting case dict."""
        result = None
        if plan.has_field_changes:
            result = await self._cases.set_state(
                case_id=case_id,
                actor=actor,
                status=plan.status,
                severity=plan.severity,
                assignee=plan.assignee,
            )

        # Fold in new remote comments as [remote]-tagged action notes.
        for comment in plan.new_comments:
            result = await self._cases.add_action_note(
                case_id=case_id, actor=actor, text=f"{_REMOTE_NOTE_PREFIX}{comment}"
            )

        # Record the conflict once (de-duped against prior conflict markers), so an
        # operator sees why the case was not reopened.
        if plan.conflict:
            conflict_text = f"reconcile conflict: {plan.conflict_reason}"
            if conflict_text not in known:
                result = await self._cases.add_action_note(
                    case_id=case_id, actor=actor,
                    text=f"{_REMOTE_NOTE_PREFIX}{conflict_text}",
                )

        # Fall back to a fresh read if nothing was applied (so callers always get
        # the current case for event emission).
        if result is None:
            result = await self._cases.get(case_id)
        return result or {}

    async def _audit(
        self, actor: str, integration_id: str, case_id: str,
        plan: ReconcilePlan, remote_id: str,
    ) -> None:
        """Append a ``case_reconciled`` audit entry (fail-open)."""
        try:
            await get_audit_logger().log(
                actor=actor,
                action="case_reconciled",
                resource_type="investigation_case",
                resource_id=case_id,
                details=str(
                    {
                        "integration_id": integration_id,
                        "remote_id": remote_id,
                        "status": plan.status,
                        "severity": plan.severity,
                        "assignee": plan.assignee,
                        "comments_added": len(plan.new_comments),
                        "conflict": plan.conflict,
                    }
                ),
            )
        except Exception:  # noqa: BLE001 — audit is advisory here; never break
            logger.warning("reconcile_audit_failed", exc_info=True)

    async def _reemit(self, plan: ReconcilePlan, applied_case: dict) -> None:
        """Re-emit lifecycle webhooks for applied changes (loop-safe, fail-open).

        Every event carries ``source: reconcile`` so a downstream SOAR trigger can
        recognise a reconcile-originated event and avoid pushing the same change
        straight back to the remote it came from.
        """
        events = _lifecycle_events(plan)
        if not events:
            return
        emitter = get_event_webhook_emitter()
        for event_type in events:
            try:
                data = {
                    "case_id": applied_case.get("case_id"),
                    "title": applied_case.get("title"),
                    "severity": applied_case.get("severity"),
                    "status": applied_case.get("status"),
                    "source": "reconcile",
                }
                await emitter.emit(
                    event_type, tenant=applied_case.get("tenant") or None, data=data
                )
            except Exception:  # noqa: BLE001 — fail-open: a webhook never breaks reconcile
                logger.warning("reconcile_reemit_failed", exc_info=True)


_engine: Optional[ReconcileEngine] = None


def get_reconcile_engine() -> ReconcileEngine:
    """Return the process-wide :class:`ReconcileEngine` singleton."""
    global _engine
    if _engine is None:
        _engine = ReconcileEngine()
    return _engine
