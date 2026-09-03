"""TheHive 5 connector — push an investigation case to TheHive via its REST API.

Maps a Bulwark case (plus observables and tasks) onto TheHive's ``/api/v1`` case
shape using the shared pure builders in :mod:`admin.services.investigation_export`
and layers the create/update REST calls on top of :class:`HttpConnectorBase`
(retries + circuit breaker).

Idempotency: a first push ``POST``s a new case; a re-push (``remote_id`` known)
``PATCH``es that case's mutable fields. Observables/tasks are attached best-effort
on **create only** — re-attaching them on every update would duplicate them
server-side, so an update deliberately syncs the case envelope, not its children
(a conservative, documented choice — TheHive is the system of record once open).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from ..investigation_export import build_thehive_case
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

# TheHive 5 severity is an integer 1–4; map it onto Bulwark's vocabulary.
_THEHIVE_SEVERITY = {1: "low", 2: "medium", 3: "high", 4: "critical"}

# TheHive 5 case ``stage`` vocabulary → normalized workflow status. Unknown stages
# fall back to ``open`` (conservative: never implies closure without evidence).
_THEHIVE_STAGE = {
    "new": REMOTE_STATUS_OPEN,
    "inprogress": REMOTE_STATUS_IN_PROGRESS,
    "closed": REMOTE_STATUS_CLOSED,
}


def _map_thehive_status(stage: str) -> str:
    """Map a TheHive ``stage`` string to a normalized status (defensive)."""
    return _THEHIVE_STAGE.get((stage or "").strip().lower().replace(" ", ""), "")


def _map_thehive_severity(value) -> str:
    """Map a TheHive integer severity (1–4) to a normalized severity, or ``""``."""
    try:
        return _THEHIVE_SEVERITY.get(int(value), "")
    except (TypeError, ValueError):
        return ""


def _epoch_ms_to_iso(value) -> str:
    """Convert a TheHive epoch-millis timestamp to an ISO-8601 string (or ``""``)."""
    try:
        return datetime.fromtimestamp(
            int(value) / 1000.0, tz=timezone.utc
        ).isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


class TheHiveConnector(HttpConnectorBase):
    """Outbound connector for TheHive 5 (``/api/v1``)."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        organisation: str = "",
        verify_tls: bool = True,
        timeout: float = 15.0,
    ) -> None:
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        if organisation:
            headers["X-Organisation"] = organisation
        super().__init__(
            base_url=base_url, verify_tls=verify_tls, timeout=timeout
        )
        self._headers = headers

    @property
    def kind(self) -> str:
        return "thehive"

    def _case_url(self, remote_id: str) -> str:
        return f"{self.base_url.rstrip('/')}/cases/{remote_id}/details"

    async def test_connection(self) -> ConnectorHealth:
        """Probe ``GET /api/v1/user/current`` (cheap authenticated call)."""
        try:
            await self._request("GET", "/api/v1/user/current", expected=(200,))
        except ConnectorError as exc:
            return ConnectorHealth(
                ok=False,
                detail=str(exc),
                checked_at=iso_now(),
                circuit_state=self.circuit_state,
            )
        return ConnectorHealth(
            ok=True,
            detail="authenticated",
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
        body = build_thehive_case(case, observables, tasks)
        # TheHive v1 case-create rejects nested tasks/artifacts — send the envelope
        # and attach children separately on create.
        envelope = {
            k: body[k]
            for k in ("title", "description", "severity", "tlp", "pap", "tags", "flag")
            if k in body
        }

        if remote_id:
            await self._request(
                "PATCH",
                f"/api/v1/case/{remote_id}",
                json_body=envelope,
                expected=(200, 204),
            )
            return PushResult(
                remote_id=remote_id,
                remote_url=self._case_url(remote_id),
                created=False,
                detail="case updated",
            )

        resp = await self._request(
            "POST", "/api/v1/case", json_body=envelope, expected=(200, 201)
        )
        data = _safe_json(resp)
        new_id = str(data.get("_id") or data.get("id") or "")
        if not new_id:
            raise ConnectorError("TheHive create returned no case id")

        attached = await self._attach_children(new_id, body)
        return PushResult(
            remote_id=new_id,
            remote_url=self._case_url(new_id),
            created=True,
            detail=f"case created ({attached})",
        )

    async def _attach_children(self, remote_id: str, body: dict) -> str:
        """Best-effort attach tasks + observables to a freshly created case.

        A failure here does NOT fail the push — the case already exists, which is
        the durable outcome. We only surface a count in the result detail.
        """
        tasks_ok = 0
        obs_ok = 0
        for task in body.get("tasks", []):
            try:
                await self._request(
                    "POST",
                    f"/api/v1/case/{remote_id}/task",
                    json_body=task,
                    expected=(200, 201),
                )
                tasks_ok += 1
            except ConnectorError as exc:
                logger.warning("thehive_task_attach_failed", extra={"error": str(exc)})
        for artifact in body.get("artifacts", []):
            try:
                await self._request(
                    "POST",
                    f"/api/v1/case/{remote_id}/observable",
                    json_body=artifact,
                    expected=(200, 201),
                )
                obs_ok += 1
            except ConnectorError as exc:
                logger.warning("thehive_obs_attach_failed", extra={"error": str(exc)})
        return f"{tasks_ok} tasks, {obs_ok} observables"

    async def sync_status(self, remote_id: str) -> Optional[RemoteState]:
        """Read a case's current workflow state from TheHive (Phase 4 reconcile).

        Fetches ``GET /api/v1/case/{id}`` and maps the platform's stage / severity /
        assignee onto a normalized :class:`RemoteState`. Comments are best-effort:
        a separate fetch that, if it fails or the endpoint is unavailable, yields an
        empty comment list rather than failing the whole sync. Fail-open — any
        connector error (open circuit, unreachable, 4xx) returns ``None``; the
        caller treats that as "no update available", never an error.
        """
        if not remote_id:
            return None
        try:
            resp = await self._request(
                "GET", f"/api/v1/case/{remote_id}", expected=(200,)
            )
        except ConnectorError as exc:
            logger.info(
                "thehive_sync_status_unavailable",
                extra={"remote_id": remote_id, "error": str(exc)},
            )
            return None

        case = _safe_json(resp)
        if not case:
            return None

        raw_stage = str(case.get("stage") or case.get("status") or "")
        status = _map_thehive_status(raw_stage)
        assignee = str(case.get("assignee") or case.get("owner") or "")
        updated = _epoch_ms_to_iso(case.get("_updatedAt") or case.get("_createdAt"))
        comments = await self._fetch_comments(remote_id)

        return RemoteState(
            remote_id=remote_id,
            status=status,
            raw_status=raw_stage,
            severity=_map_thehive_severity(case.get("severity")),
            assignee=assignee,
            closed=status == REMOTE_STATUS_CLOSED,
            last_remote_update=updated,
            comments=comments,
            detail="ok",
        )

    async def _fetch_comments(self, remote_id: str) -> list[str]:
        """Best-effort fetch of a case's comments. Never raises — returns ``[]``."""
        try:
            resp = await self._request(
                "GET", f"/api/v1/case/{remote_id}/comment", expected=(200,)
            )
        except ConnectorError:
            return []
        try:
            parsed = resp.json()
        except ValueError:
            return []
        if not isinstance(parsed, list):
            return []
        out: list[str] = []
        for item in parsed:
            if isinstance(item, dict):
                text = str(item.get("message") or "").strip()
                if text:
                    out.append(text)
        return out


def _safe_json(resp) -> dict:
    """Parse a response body as a dict (TheHive may return a list on some calls)."""
    try:
        parsed = resp.json()
    except ValueError:
        return {}
    if isinstance(parsed, list):
        return parsed[0] if parsed and isinstance(parsed[0], dict) else {}
    return parsed if isinstance(parsed, dict) else {}
