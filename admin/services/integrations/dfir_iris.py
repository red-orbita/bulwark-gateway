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
from .base import ConnectorError, ConnectorHealth, HttpConnectorBase, PushResult
from .util import iso_now

logger = logging.getLogger(__name__)


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
        """Best-effort attach IOCs + tasks to a freshly created case."""
        iocs_ok = 0
        tasks_ok = 0
        for ioc in body.get("iocs", []):
            try:
                resp = await self._request(
                    "POST",
                    f"/case/ioc/add?cid={remote_id}",
                    json_body=ioc,
                    expected=(200,),
                )
                _require_success(resp)
                iocs_ok += 1
            except ConnectorError as exc:
                logger.warning("iris_ioc_attach_failed", extra={"error": str(exc)})
        for task in body.get("tasks", []):
            try:
                resp = await self._request(
                    "POST",
                    f"/case/tasks/add?cid={remote_id}",
                    json_body=task,
                    expected=(200,),
                )
                _require_success(resp)
                tasks_ok += 1
            except ConnectorError as exc:
                logger.warning("iris_task_attach_failed", extra={"error": str(exc)})
        return f"{iocs_ok} iocs, {tasks_ok} tasks"


def _require_success(resp) -> dict:
    """Unwrap IRIS's ``{"status","data"}`` envelope. Raises on ``status != success``."""
    try:
        parsed = resp.json()
    except ValueError:
        raise ConnectorError("IRIS returned a non-JSON response") from None
    if not isinstance(parsed, dict):
        raise ConnectorError("IRIS returned an unexpected response shape")
    if parsed.get("status") not in (None, "success"):
        message = parsed.get("message") or "IRIS reported an error"
        raise ConnectorError(str(message))
    data = parsed.get("data")
    return data if isinstance(data, dict) else {}
