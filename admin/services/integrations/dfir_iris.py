"""DFIR-IRIS connector — push an investigation case to IRIS via its REST API.

Maps a Bulwark case (plus observables and tasks) onto IRIS's case shape using the
shared pure builder in :mod:`admin.services.investigation_export` and layers the
add/update REST calls on top of :class:`HttpConnectorBase` (retries + circuit
breaker).

IRIS quirks handled here:

* All mutating calls are scoped to a case context id (``cid``) query parameter;
  case-add uses the configured ``customer_id`` and returns the new ``case_id`` in
  ``data.case_id``.
* Responses are enveloped as ``{"status": "success"|"error", "data": ...}`` — a
  200 with ``status == "error"`` is treated as a failure.

Idempotency mirrors the TheHive connector: first push adds a case; a re-push
(``remote_id`` known) updates that case's envelope. IOCs/tasks are attached
best-effort on **create only** to avoid server-side duplication on re-push.
"""

from __future__ import annotations

import logging
from typing import Optional

from ..investigation_export import build_iris_case
from .base import (
    REMOTE_STATUS_CLOSED,
    REMOTE_STATUS_IN_PROGRESS,
    REMOTE_STATUS_OPEN,
    ConnectorError,
    ConnectorHealth,
    HttpConnectorBase,
    PushResult,
    RemoteState,
)
from .util import iso_now

logger = logging.getLogger(__name__)

# DFIR-IRIS ``severity_id`` → Bulwark severity. IRIS severities are operator-
# configurable, but the default seed is 1=Informational … 5=Critical; we map that
# default conservatively and fall back to ``""`` (unknown) for anything else, which
# the reconcile engine treats as "no severity signal" rather than guessing.
_IRIS_SEVERITY = {1: "low", 2: "low", 3: "medium", 4: "high", 5: "critical"}

# IRIS ``state_name`` vocabulary → normalized workflow status. Only an explicit
# ``closed`` (or a populated close date, checked separately) marks closure.
_IRIS_STATE = {
    "open": REMOTE_STATUS_OPEN,
    "inprogress": REMOTE_STATUS_IN_PROGRESS,
    "in progress": REMOTE_STATUS_IN_PROGRESS,
    "closed": REMOTE_STATUS_CLOSED,
}


# Bulwark task-status vocabulary → IRIS ``task-status`` ``status_name``. IRIS
# rejects the legacy string ``task_status``/``task_assignee`` fields since v1.5.0
# and requires an integer ``task_status_id`` (resolved from this name via a runtime
# lookup) plus a ``task_assignees_id`` list. Anything unmapped falls back to
# "To do" (the IRIS default), so a task always attaches rather than 400-ing.
_IRIS_TASK_STATUS_NAME = {
    "todo": "To do",
    "open": "To do",
    "pending": "To do",
    "in_progress": "In progress",
    "inprogress": "In progress",
    "on_hold": "On hold",
    "onhold": "On hold",
    "done": "Done",
    "completed": "Done",
    "closed": "Done",
    "cancelled": "Canceled",
    "canceled": "Canceled",
}
_IRIS_DEFAULT_TASK_STATUS = "To do"


def _map_iris_status(state_name: str) -> str:
    """Map an IRIS ``state_name`` to a normalized status (defensive)."""
    return _IRIS_STATE.get((state_name or "").strip().lower(), "")


def _map_iris_severity(value) -> str:
    """Map an IRIS ``severity_id`` to a normalized severity, or ``""``."""
    try:
        return _IRIS_SEVERITY.get(int(value), "")
    except (TypeError, ValueError):
        return ""


class DfirIrisConnector(HttpConnectorBase):
    """Outbound connector for DFIR-IRIS."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        customer_id: int = 1,
        verify_tls: bool = True,
        timeout: float = 15.0,
    ) -> None:
        super().__init__(base_url=base_url, verify_tls=verify_tls, timeout=timeout)
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        self.customer_id = customer_id
        # Lazily-populated, per-instance name→id lookup caches. IRIS reference ids
        # (ioc types, TLPs, task statuses) are auto-increment and NOT stable across
        # instances, so we resolve them at attach time from the live server rather
        # than hardcoding. ``None`` means "not yet fetched".
        self._ioc_type_ids: Optional[dict[str, int]] = None
        self._tlp_ids: Optional[dict[str, int]] = None
        self._task_status_ids: Optional[dict[str, int]] = None

    @property
    def kind(self) -> str:
        return "dfir_iris"

    def _case_url(self, remote_id: str) -> str:
        return f"{self.base_url.rstrip('/')}/case?cid={remote_id}"

    async def test_connection(self) -> ConnectorHealth:
        """Probe ``GET /api/ping`` (unauthenticated liveness + auth header echo)."""
        try:
            resp = await self._request("GET", "/api/ping", expected=(200,))
            _require_success(resp)
        except ConnectorError as exc:
            return ConnectorHealth(
                ok=False,
                detail=str(exc),
                checked_at=iso_now(),
                circuit_state=self.circuit_state,
            )
        return ConnectorHealth(
            ok=True,
            detail="reachable",
            checked_at=iso_now(),
            circuit_state=self.circuit_state,
        )

    async def push_case(
        self,
        case: dict,
        observables: list[dict],
        tasks: list[dict],
        *,
        remote_id: Optional[str] = None,
    ) -> PushResult:
        body = build_iris_case(case, observables, tasks)
        envelope = {
            "case_name": body["case_name"],
            "case_description": body["case_description"],
            "case_soc_id": body["case_soc_id"],
            "case_customer": self.customer_id,
            "case_tags": body.get("case_tags", ""),
        }

        if remote_id:
            resp = await self._request(
                "POST",
                f"/manage/cases/update/{remote_id}?cid={remote_id}",
                json_body=envelope,
                expected=(200,),
            )
            _require_success(resp)
            return PushResult(
                remote_id=remote_id,
                remote_url=self._case_url(remote_id),
                created=False,
                detail="case updated",
            )

        resp = await self._request(
            "POST", "/manage/cases/add", json_body=envelope, expected=(200,)
        )
        data = _require_success(resp)
        new_id = str(data.get("case_id") or "")
        if not new_id:
            raise ConnectorError("IRIS add returned no case_id")

        attached = await self._attach_children(new_id, body)
        return PushResult(
            remote_id=new_id,
            remote_url=self._case_url(new_id),
            created=True,
            detail=f"case created ({attached})",
        )

    async def _attach_children(self, remote_id: str, body: dict) -> str:
        """Best-effort attach IOCs + tasks to a freshly created case.

        IRIS's ``/case/ioc/add`` and ``/case/tasks/add`` want integer reference ids
        (``ioc_type_id``/``ioc_tlp_id``/``task_status_id``), not the human names the
        pure builder emits, and reject the legacy ``task_assignee`` string since
        v1.5.0. We translate names→ids here via cached runtime lookups so the pure
        builder stays dialect-neutral. Each attach is independent and best-effort:
        one failure is logged and never aborts the rest or the push.
        """
        iocs_ok = 0
        tasks_ok = 0
        for ioc in body.get("iocs", []):
            try:
                payload = await self._iris_ioc_payload(ioc)
                if payload is None:
                    continue
                resp = await self._request(
                    "POST",
                    f"/case/ioc/add?cid={remote_id}",
                    json_body=payload,
                    expected=(200,),
                )
                _require_success(resp)
                iocs_ok += 1
            except ConnectorError as exc:
                logger.warning("iris_ioc_attach_failed", extra={"error": str(exc)})
        for task in body.get("tasks", []):
            try:
                payload = await self._iris_task_payload(task)
                resp = await self._request(
                    "POST",
                    f"/case/tasks/add?cid={remote_id}",
                    json_body=payload,
                    expected=(200,),
                )
                _require_success(resp)
                tasks_ok += 1
            except ConnectorError as exc:
                logger.warning("iris_task_attach_failed", extra={"error": str(exc)})
        return f"{iocs_ok} iocs, {tasks_ok} tasks"

    async def _load_lookup(
        self, path: str, id_key: str, name_key: str
    ) -> dict[str, int]:
        """Fetch an IRIS reference list into a lower-cased ``name → id`` map.

        Fail-open: a missing/malformed list yields ``{}`` so callers degrade to
        their own fallback rather than raising.
        """
        try:
            resp = await self._request("GET", path, expected=(200,))
            data = _unwrap(resp)
        except ConnectorError as exc:
            logger.warning(
                "iris_lookup_failed", extra={"path": path, "error": str(exc)}
            )
            return {}
        out: dict[str, int] = {}
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                name = str(item.get(name_key) or "").strip().lower()
                value = item.get(id_key)
                if name and isinstance(value, int):
                    out[name] = value
        return out

    async def _ioc_type_id(self, name: str) -> Optional[int]:
        """Resolve an IRIS ioc-type name to its id (falls back to ``other``)."""
        if self._ioc_type_ids is None:
            self._ioc_type_ids = await self._load_lookup(
                "/manage/ioc-types/list", "type_id", "type_name"
            )
        table = self._ioc_type_ids
        return table.get((name or "").strip().lower()) or table.get("other")

    async def _tlp_id(self, name: str) -> Optional[int]:
        """Resolve an IRIS TLP name to its id (falls back to ``amber``)."""
        if self._tlp_ids is None:
            self._tlp_ids = await self._load_lookup(
                "/manage/tlp/list", "tlp_id", "tlp_name"
            )
        table = self._tlp_ids
        return table.get((name or "").strip().lower()) or table.get("amber")

    async def _task_status_id(self, bulwark_status: str) -> Optional[int]:
        """Resolve a Bulwark task status to an IRIS ``task_status_id``."""
        if self._task_status_ids is None:
            self._task_status_ids = await self._load_lookup(
                "/manage/task-status/list", "id", "status_name"
            )
        table = self._task_status_ids
        iris_name = _IRIS_TASK_STATUS_NAME.get(
            (bulwark_status or "").strip().lower(), _IRIS_DEFAULT_TASK_STATUS
        )
        return table.get(iris_name.lower()) or table.get(
            _IRIS_DEFAULT_TASK_STATUS.lower()
        )

    async def _iris_ioc_payload(self, ioc: dict) -> Optional[dict]:
        """Translate a builder ioc (name-based) to an IRIS add payload (id-based)."""
        type_id = await self._ioc_type_id(str(ioc.get("ioc_type") or ""))
        if type_id is None:
            logger.warning(
                "iris_ioc_type_unresolved", extra={"type": ioc.get("ioc_type")}
            )
            return None
        payload: dict = {
            "ioc_value": ioc.get("ioc_value") or "",
            "ioc_type_id": type_id,
            "ioc_tags": ioc.get("ioc_tags") or "",
            "ioc_description": ioc.get("ioc_description") or "",
        }
        tlp_id = await self._tlp_id(str(ioc.get("ioc_tlp") or "amber"))
        if tlp_id is not None:
            payload["ioc_tlp_id"] = tlp_id
        return payload

    async def _iris_task_payload(self, task: dict) -> dict:
        """Translate a builder task (name-based) to an IRIS add payload (id-based)."""
        payload: dict = {
            "task_title": task.get("task_title") or "",
            "task_description": task.get("task_description") or "",
            "task_assignees_id": [],
            "task_tags": "",
        }
        status_id = await self._task_status_id(str(task.get("task_status") or "todo"))
        if status_id is not None:
            payload["task_status_id"] = status_id
        return payload

    async def sync_status(self, remote_id: str) -> Optional[RemoteState]:
        """Read a case's current workflow state from IRIS (Phase 4 reconcile).

        Fetches ``GET /manage/cases/{cid}`` (standard ``{status,data}`` envelope) and
        maps IRIS's state / severity / owner onto a normalized :class:`RemoteState`.
        Closure is inferred from an explicit ``closed`` state *or* a populated close
        date. Fail-open: any connector/envelope error returns ``None`` (treated as
        "no update available"), never an exception.
        """
        if not remote_id:
            return None
        try:
            resp = await self._request(
                "GET",
                f"/manage/cases/{remote_id}?cid={remote_id}",
                expected=(200,),
            )
            data = _require_success(resp)
        except ConnectorError as exc:
            logger.info(
                "iris_sync_status_unavailable",
                extra={"remote_id": remote_id, "error": str(exc)},
            )
            return None

        if not data:
            return None

        state_name = str(data.get("state_name") or "")
        status = _map_iris_status(state_name)
        close_date = str(
            data.get("close_date") or data.get("case_close_date") or ""
        ).strip()
        closed = status == REMOTE_STATUS_CLOSED or bool(close_date)
        if closed:
            status = REMOTE_STATUS_CLOSED
        elif not status:
            # IRIS's ``state_name`` is often null on the default case shape; an
            # existing, non-closed case is open. Default to OPEN so reconcile has a
            # real workflow signal instead of an empty one.
            status = REMOTE_STATUS_OPEN
        assignee = str(data.get("owner") or data.get("user_name") or "")
        # IRIS exposes no single "last modified" field on the case payload; use the
        # best available real timestamp (closure > creation timestamp > open date).
        updated = str(
            close_date
            or data.get("initial_date")
            or data.get("open_date")
            or ""
        ).strip()
        comments = _extract_iris_comments(data)

        return RemoteState(
            remote_id=remote_id,
            status=status,
            raw_status=state_name,
            severity=_map_iris_severity(data.get("severity_id")),
            assignee=assignee,
            closed=closed,
            last_remote_update=updated,
            comments=comments,
            detail="ok",
        )


def _extract_iris_comments(data: dict) -> list[str]:
    """Pull comment text from an IRIS case payload, best-effort (never raises)."""
    raw = data.get("comments")
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for item in raw:
        if isinstance(item, dict):
            text = str(item.get("comment_text") or item.get("comment") or "").strip()
            if text:
                out.append(text)
    return out


def _unwrap(resp) -> object:
    """Unwrap IRIS's ``{"status","data"}`` envelope, returning the raw ``data``.

    Returns the payload as-is (a dict for single objects, a list for reference
    lists). Raises :class:`ConnectorError` on a non-JSON body, an unexpected shape,
    or an ``status != success`` envelope.
    """
    try:
        parsed = resp.json()
    except ValueError:
        raise ConnectorError("IRIS returned a non-JSON response") from None
    if not isinstance(parsed, dict):
        raise ConnectorError("IRIS returned an unexpected response shape")
    if parsed.get("status") not in (None, "success"):
        message = parsed.get("message") or "IRIS reported an error"
        raise ConnectorError(str(message))
    return parsed.get("data")


def _require_success(resp) -> dict:
    """Unwrap IRIS's envelope, coercing the payload to a dict (``{}`` otherwise)."""
    data = _unwrap(resp)
    return data if isinstance(data, dict) else {}
