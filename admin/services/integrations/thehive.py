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
from typing import Optional

from ..investigation_export import build_thehive_case
from .base import ConnectorError, ConnectorHealth, HttpConnectorBase, PushResult
from .util import iso_now

logger = logging.getLogger(__name__)


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


def _safe_json(resp) -> dict:
    """Parse a response body as a dict (TheHive may return a list on some calls)."""
    try:
        parsed = resp.json()
    except ValueError:
        return {}
    if isinstance(parsed, list):
        return parsed[0] if parsed and isinstance(parsed[0], dict) else {}
    return parsed if isinstance(parsed, dict) else {}
