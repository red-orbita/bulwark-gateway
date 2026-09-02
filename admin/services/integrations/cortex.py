"""Cortex connector — observable enrichment via analyzers + bounded responders.

Cortex (the TheHive project's analysis engine) runs *analyzers* against an
atomic observable (an IP, domain, hash, …) and returns a structured report whose
``summary.taxonomies`` carry a normalized verdict (``info`` / ``safe`` /
``suspicious`` / ``malicious``). This connector submits an analyzer job, polls it
to completion under a hard bound, and folds the taxonomies into a compact
enrichment blob suitable for storing on an investigation observable.

Unlike TheHive / DFIR-IRIS (case *push* targets), Cortex is an *enrichment*
connector, so it does not implement the ``Connector`` push protocol. It reuses
:class:`HttpConnectorBase` purely for the retry + circuit-breaker HTTP machinery.

Everything is fail-open and bounded: a slow, failing, or never-completing job can
never tie up an admin worker — polling is capped, each request is short-timeout,
and an exhausted/again-failing call raises :class:`ConnectorError` for the route
layer to audit without ever touching the observable/case store.
"""

from __future__ import annotations

import asyncio
import logging

from .base import ConnectorError, ConnectorHealth, HttpConnectorBase
from .util import iso_now

logger = logging.getLogger(__name__)

# Verdict severity ordering — used to fold many analyzer taxonomies into one
# worst-case verdict for the observable.
_LEVEL_ORDER = {"info": 0, "safe": 1, "suspicious": 2, "malicious": 3}
_UNKNOWN_LEVEL = "info"

# Map Bulwark observable types → Cortex dataTypes. Types Cortex has no native slot
# for (user identifiers, free-form) degrade to ``other`` rather than being guessed.
_DATATYPE_MAP = {
    "ip": "ip",
    "domain": "domain",
    "url": "url",
    "hash": "hash",
    "email": "mail",
    "filename": "filename",
    "user": "other",
    "other": "other",
}

# TLP name → Cortex numeric marking (white=0 … red=3).
_TLP_MAP = {"white": 0, "green": 1, "amber": 2, "red": 3}

# Bounded job polling — a Cortex analyzer job runs asynchronously; we poll it to a
# terminal state but never indefinitely. Defaults cap a single enrichment at
# ~30s; tests override these to run instantly.
_DEFAULT_POLL_INTERVAL_SECONDS = 1.0
_DEFAULT_MAX_POLLS = 30

# Terminal Cortex job statuses.
_TERMINAL_SUCCESS = "Success"
_TERMINAL_FAILURE = "Failure"


def cortex_datatype(observable_type: str) -> str:
    """Map a Bulwark observable type to a Cortex dataType (pure)."""
    return _DATATYPE_MAP.get(observable_type, "other")


def _extract_taxonomies(job_report: dict) -> list[dict]:
    """Pull the normalized taxonomy list out of a Cortex job/report payload.

    Tolerant of both the ``GET /api/job/{id}/report`` envelope (``{"report":
    {"summary": {"taxonomies": [...]}}}``) and a job object that already carries
    ``report`` inline. Returns a list of ``{namespace, predicate, value, level}``
    dicts; malformed entries are dropped, never raised.
    """
    report = job_report.get("report", job_report) if isinstance(job_report, dict) else {}
    if not isinstance(report, dict):
        return []
    summary = report.get("summary", {})
    raw = summary.get("taxonomies", []) if isinstance(summary, dict) else []
    taxonomies: list[dict] = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        level = str(item.get("level") or _UNKNOWN_LEVEL).lower()
        if level not in _LEVEL_ORDER:
            level = _UNKNOWN_LEVEL
        taxonomies.append({
            "namespace": str(item.get("namespace") or "")[:64],
            "predicate": str(item.get("predicate") or "")[:64],
            "value": str(item.get("value") or "")[:256],
            "level": level,
        })
    return taxonomies


def _worst_level(taxonomies: list[dict]) -> str:
    """Return the most severe taxonomy level, defaulting to ``info``."""
    worst = _UNKNOWN_LEVEL
    for tax in taxonomies:
        if _LEVEL_ORDER.get(tax.get("level", _UNKNOWN_LEVEL), 0) > _LEVEL_ORDER[worst]:
            worst = tax["level"]
    return worst


class CortexConnector(HttpConnectorBase):
    """Enrichment connector for a Cortex analysis engine (API v0/v1 compatible)."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        verify_tls: bool = True,
        timeout: float = 15.0,
        poll_interval: float = _DEFAULT_POLL_INTERVAL_SECONDS,
        max_polls: int = _DEFAULT_MAX_POLLS,
    ) -> None:
        super().__init__(base_url=base_url, verify_tls=verify_tls, timeout=timeout)
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        self._poll_interval = max(0.0, poll_interval)
        self._max_polls = max(1, max_polls)

    @property
    def kind(self) -> str:
        return "cortex"

    async def test_connection(self) -> ConnectorHealth:
        """Probe ``GET /api/analyzer`` (cheap authenticated list). Never raises."""
        try:
            await self._request("GET", "/api/analyzer", expected=(200,))
        except ConnectorError as exc:
            return ConnectorHealth(
                ok=False, detail=str(exc), checked_at=iso_now(),
                circuit_state=self.circuit_state,
            )
        return ConnectorHealth(
            ok=True, detail="authenticated", checked_at=iso_now(),
            circuit_state=self.circuit_state,
        )

    async def list_analyzers(self) -> list[dict]:
        """Return the enabled analyzer catalog as ``{id, name, data_types}`` dicts."""
        resp = await self._request("GET", "/api/analyzer", expected=(200,))
        try:
            raw = resp.json()
        except ValueError:
            return []
        analyzers: list[dict] = []
        for item in raw if isinstance(raw, list) else []:
            if not isinstance(item, dict):
                continue
            aid = str(item.get("id") or item.get("_id") or "")
            if not aid:
                continue
            analyzers.append({
                "id": aid,
                "name": str(item.get("name") or aid),
                "data_types": [str(t) for t in item.get("dataTypeList", []) if isinstance(t, str)],
            })
        return analyzers

    async def enrich_observable(
        self,
        *,
        observable_type: str,
        value: str,
        analyzer_ids: list[str],
        tlp: str = "amber",
    ) -> dict:
        """Run one or more analyzers against an observable and fold the reports.

        Returns a compact enrichment blob:
        ``{connector, checked_at, data_type, verdict, is_malicious, analyzers:[…]}``.
        Individual analyzer failures are captured per-entry (they never abort the
        whole enrichment); the overall ``verdict`` is the worst level seen.
        """
        data_type = cortex_datatype(observable_type)
        tlp_num = _TLP_MAP.get(tlp, 2)
        results: list[dict] = []
        for analyzer_id in analyzer_ids:
            results.append(await self._run_one_analyzer(analyzer_id, data_type, value, tlp_num))

        all_tax = [tax for r in results for tax in r.get("taxonomies", [])]
        verdict = _worst_level(all_tax)
        return {
            "connector": "cortex",
            "checked_at": iso_now(),
            "data_type": data_type,
            "verdict": verdict,
            "is_malicious": verdict == "malicious",
            "analyzers": results,
        }

    async def _run_one_analyzer(
        self, analyzer_id: str, data_type: str, value: str, tlp_num: int
    ) -> dict:
        """Submit + poll a single analyzer job; normalize into a result entry."""
        entry: dict = {
            "analyzer": analyzer_id, "job_id": "", "status": "",
            "level": _UNKNOWN_LEVEL, "taxonomies": [], "error": "",
        }
        try:
            resp = await self._request(
                "POST", f"/api/analyzer/{analyzer_id}/run",
                json_body={"data": value, "dataType": data_type, "tlp": tlp_num},
                expected=(200, 201),
            )
            job = _safe_json(resp)
            job_id = str(job.get("id") or job.get("_id") or "")
            if not job_id:
                entry["error"] = "analyzer run returned no job id"
                return entry
            entry["job_id"] = job_id
            status = await self._poll_job(job_id)
            entry["status"] = status
            if status != _TERMINAL_SUCCESS:
                entry["error"] = f"job did not succeed (status={status})"
                return entry
            report_resp = await self._request(
                "GET", f"/api/job/{job_id}/report", expected=(200,)
            )
            taxonomies = _extract_taxonomies(_safe_json(report_resp))
            entry["taxonomies"] = taxonomies
            entry["level"] = _worst_level(taxonomies)
        except ConnectorError as exc:
            entry["error"] = str(exc)
        return entry

    async def _poll_job(self, job_id: str) -> str:
        """Poll ``GET /api/job/{id}`` until terminal or the poll budget is spent.

        Returns the last observed status (``Success`` / ``Failure`` / the last
        in-progress status if the budget is exhausted). Never raises for a slow
        job — only genuine transport/HTTP errors surface via :class:`ConnectorError`.
        """
        last_status = "InProgress"
        for poll in range(self._max_polls):
            resp = await self._request("GET", f"/api/job/{job_id}", expected=(200,))
            job = _safe_json(resp)
            last_status = str(job.get("status") or last_status)
            if last_status in (_TERMINAL_SUCCESS, _TERMINAL_FAILURE):
                return last_status
            if poll < self._max_polls - 1 and self._poll_interval:
                await asyncio.sleep(self._poll_interval)
        return last_status

    async def run_responder(
        self, *, responder_id: str, observable_type: str, value: str, tlp: str = "amber"
    ) -> dict:
        """Trigger a Cortex responder against an observable (bounded, best-effort).

        Returns ``{responder, job_id, status}``. Response actions are fire-and-poll
        like analyzers; a failure raises :class:`ConnectorError`.
        """
        data_type = cortex_datatype(observable_type)
        resp = await self._request(
            "POST", f"/api/responder/{responder_id}/run",
            json_body={
                "data": value, "dataType": data_type,
                "tlp": _TLP_MAP.get(tlp, 2),
            },
            expected=(200, 201),
        )
        job = _safe_json(resp)
        job_id = str(job.get("id") or job.get("_id") or "")
        status = await self._poll_job(job_id) if job_id else "unknown"
        return {"responder": responder_id, "job_id": job_id, "status": status}


def _safe_json(resp) -> dict:
    """Parse a response body as a dict (never raises)."""
    try:
        parsed = resp.json()
    except ValueError:
        return {}
    if isinstance(parsed, list):
        return parsed[0] if parsed and isinstance(parsed[0], dict) else {}
    return parsed if isinstance(parsed, dict) else {}


__all__ = ["CortexConnector", "cortex_datatype"]
