"""OpenCTI connector — observable lookup **and** case push via the platform GraphQL API.

OpenCTI is a threat-intelligence knowledge graph. This connector serves two roles:

* **Lookup** (read): for an investigation observable it answers *does OpenCTI
  already know this atomic indicator, and how bad does it think it is?* — it
  searches the ``indicators`` collection for the observable's literal value, folds
  the matching STIX indicators into one worst-case verdict (driven by
  ``x_opencti_score``, 0–100), and returns a compact enrichment blob.

* **Push** (write): it materialises a Bulwark investigation case into the graph —
  one Cyber-observable (SCO) per mappable observable, an ``indicator`` + a
  ``sighting`` per flagged IOC, and a ``report`` tying them together — via raw
  GraphQL create mutations (no ``pycti``). It implements the ``Connector`` push
  protocol so it reuses the shared ``/push/case`` route + link-store idempotency
  (the report's internal id is the ``remote_id``; a re-push patches that report).

**TLP data-sharing gate**: OpenCTI is an *external, shared* platform, so
``TLP:RED`` observables are never sent — they are silently excluded from the
push. If a case has *no* shareable (non-red, mappable) observable left, the whole
push is refused with :class:`TlpGateError` (a local policy decision, surfaced as a
``400`` — the remote is never contacted for restricted data). Included objects are
marked with the case's most-restrictive remaining TLP marking-definition.

Everything is fail-open and bounded: a slow or failing platform can never tie up
an admin worker — each request is short-timeout and an exhausted/again-failing
call raises :class:`ConnectorError` for the route layer to audit without ever
touching the observable/case store.
"""

from __future__ import annotations

import logging
from typing import Optional

from .base import (
    ConnectorError,
    ConnectorHealth,
    HttpConnectorBase,
    PushResult,
    TlpGateError,
)
from .util import iso_now

logger = logging.getLogger(__name__)

# OpenCTI ``x_opencti_score`` bands (0–100). At/above malicious ⇒ the observable is
# flagged an IOC and the case's origins are auto-raised; suspicious is advisory.
_SCORE_MALICIOUS = 70
_SCORE_SUSPICIOUS = 40

# How many candidate indicators to pull per lookup. OpenCTI ``search`` is fuzzy, so
# we over-fetch a little and then keep only nodes whose STIX pattern literally
# contains the observable value.
_DEFAULT_LOOKUP_FIRST = 25

# ─── Push (case → graph) ──────────────────────────────────────────────────────

# Standard STIX 2.x TLP marking-definition ids. OpenCTI ships these built-in and
# resolves ``objectMarking`` refs by standard STIX id, so we can reference them
# directly without a version-fragile ``markingDefinitions`` filter round-trip.
_TLP_MARKING_IDS = {
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}

# The marking that must never leave Bulwark for an external shared platform.
_TLP_RESTRICTED = "red"

# Restrictiveness order (low → high) for picking a report-level marking.
_TLP_ORDER = ("white", "green", "amber", "red")

# Observable type → (OpenCTI observable type, GraphQL per-type input variable key).
# The variable value is built by :func:`_observable_payload`.
_OBS_TYPE_MAP = {
    "domain": ("Domain-Name", "DomainName"),
    "url": ("Url", "Url"),
    "email": ("Email-Addr", "EmailAddr"),
    "user": ("User-Account", "UserAccount"),
}

# Observable type → OpenCTI ``x_opencti_main_observable_type`` for indicators.
_MAIN_OBS_TYPE = {
    "ip": None,  # resolved dynamically (IPv4-Addr / IPv6-Addr)
    "domain": "Domain-Name",
    "url": "Url",
    "email": "Email-Addr",
    "hash": "StixFile",
}

# Cheap authenticated probe — returns the running platform version.
_ABOUT_QUERY = "query BulwarkAbout { about { version } }"

# Lookup query — order by score desc so the worst indicator surfaces first. Only
# STIX patterns are interpretable (yara/sigma/snort rules are skipped downstream).
_LOOKUP_QUERY = """
query BulwarkLookup($search: String!, $first: Int!) {
    indicators(search: $search, first: $first, orderBy: x_opencti_score, orderMode: desc) {
        edges {
            node {
                pattern
                pattern_type
                revoked
                confidence
                x_opencti_score
                objectLabel { value }
            }
        }
    }
}
"""

# ─── Push mutations ───────────────────────────────────────────────────────────

# Create a Cyber-observable. All per-type inputs are nullable variables; only the
# one matching the observable's type is supplied. ``update: true`` makes the create
# idempotent — re-pushing the same value returns the existing node instead of
# erroring, which is what our re-push path relies on.
_OBS_MUTATION = """
mutation BulwarkObsAdd(
    $type: String!, $markings: [String],
    $IPv4Addr: IPv4AddrAddInput, $IPv6Addr: IPv6AddrAddInput,
    $DomainName: DomainNameAddInput, $Url: UrlAddInput,
    $EmailAddr: EmailAddrAddInput, $StixFile: StixFileAddInput,
    $UserAccount: UserAccountAddInput
) {
    stixCyberObservableAdd(
        type: $type, objectMarking: $markings, update: true,
        IPv4Addr: $IPv4Addr, IPv6Addr: $IPv6Addr,
        DomainName: $DomainName, Url: $Url,
        EmailAddr: $EmailAddr, StixFile: $StixFile, UserAccount: $UserAccount
    ) { id standard_id }
}
"""

_INDICATOR_MUTATION = """
mutation BulwarkIndicatorAdd($input: IndicatorAddInput!) {
    indicatorAdd(input: $input) { id standard_id }
}
"""

_SIGHTING_MUTATION = """
mutation BulwarkSightingAdd($input: StixSightingRelationshipAddInput!) {
    stixSightingRelationshipAdd(input: $input) { id standard_id }
}
"""

_REPORT_ADD_MUTATION = """
mutation BulwarkReportAdd($input: ReportAddInput!) {
    reportAdd(input: $input) { id standard_id }
}
"""

_REPORT_PATCH_MUTATION = """
mutation BulwarkReportPatch($id: ID!, $input: [EditInput!]!) {
    reportEdit(id: $id) { fieldPatch(input: $input) { id standard_id } }
}
"""

_REPORT_RELATION_MUTATION = """
mutation BulwarkReportRelAdd($id: ID!, $input: StixRefRelationshipAddInput!) {
    reportEdit(id: $id) { relationAdd(input: $input) { id } }
}
"""


def score_verdict(score: int, *, found: bool) -> str:
    """Fold an OpenCTI score into a verdict label (pure).

    ``found`` reflects whether *any* indicator matched the observable value. A
    value known only via revoked indicators folds to ``clean`` — it matched
    (``found``) but contributes no *active* score — while a value OpenCTI has
    never seen is ``not_found``.
    """
    if not found:
        return "not_found"
    if score >= _SCORE_MALICIOUS:
        return "malicious"
    if score >= _SCORE_SUSPICIOUS:
        return "suspicious"
    return "clean"


def _coerce_score(raw: object) -> int:
    """Coerce a raw ``x_opencti_score`` / ``confidence`` value to a 0–100 int."""
    try:
        val = int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0
    return max(0, min(100, val))


def _node_labels(node: dict) -> list[str]:
    """Extract up to 3 OpenCTI label strings from an indicator node as tags."""
    raw = node.get("objectLabel") or []
    labels: list[str] = []
    for item in raw if isinstance(raw, list) else []:
        val = item.get("value") if isinstance(item, dict) else item
        if isinstance(val, str) and val.strip():
            labels.append(val.strip()[:30])
        if len(labels) >= 3:
            break
    return labels


def _hash_algo(value: str) -> Optional[str]:
    """Classify a hex hash by length into a STIX hash-algorithm name (or ``None``)."""
    length = len(value)
    if length == 32:
        return "MD5"
    if length == 40:
        return "SHA-1"
    if length == 64:
        return "SHA-256"
    return None


def _observable_payload(obs: dict) -> Optional[tuple[str, str, dict]]:
    """Map an observable to ``(opencti_type, input_var_key, input_payload)``.

    Returns ``None`` for a value that cannot be represented as an OpenCTI Cyber
    observable (empty value, or a hash whose length matches no known algorithm).
    Pure — no I/O.
    """
    otype = obs.get("type")
    value = (obs.get("value") or "").strip()
    if not value:
        return None
    if otype == "ip":
        is_v6 = ":" in value
        return (
            "IPv6-Addr" if is_v6 else "IPv4-Addr",
            "IPv6Addr" if is_v6 else "IPv4Addr",
            {"value": value},
        )
    if otype == "hash":
        algo = _hash_algo(value)
        if algo is None:
            return None
        return ("StixFile", "StixFile", {"hashes": [{"algorithm": algo, "hash": value}]})
    if otype == "filename":
        return ("StixFile", "StixFile", {"name": value})
    mapped = _OBS_TYPE_MAP.get(otype or "")
    if mapped is None:
        return None
    octype, var_key = mapped
    return (octype, var_key, {"value": value})


def _indicator_pattern(obs: dict) -> Optional[str]:
    """Build a STIX pattern for an IOC observable (``None`` if unmappable). Pure."""
    otype = obs.get("type")
    raw = (obs.get("value") or "").strip()
    if not raw:
        return None
    value = raw.replace("\\", "\\\\").replace("'", "\\'")
    if otype == "ip":
        addr = "ipv6-addr" if ":" in raw else "ipv4-addr"
        return f"[{addr}:value = '{value}']"
    if otype == "domain":
        return f"[domain-name:value = '{value}']"
    if otype == "url":
        return f"[url:value = '{value}']"
    if otype == "email":
        return f"[email-addr:value = '{value}']"
    if otype == "hash":
        algo = _hash_algo(raw)
        if algo is None:
            return None
        return f"[file:hashes.'{algo}' = '{value}']"
    return None


def _main_observable_type(obs: dict) -> str:
    """OpenCTI ``x_opencti_main_observable_type`` for an indicator (never empty)."""
    otype = obs.get("type")
    if otype == "ip":
        return "IPv6-Addr" if ":" in (obs.get("value") or "") else "IPv4-Addr"
    return _MAIN_OBS_TYPE.get(otype or "") or "Unknown"


def _is_restricted(obs: dict) -> bool:
    """True when an observable's TLP marking is too restrictive to share externally."""
    return (obs.get("tlp") or "amber").lower() == _TLP_RESTRICTED


def select_report_marking(observables: list[dict]) -> str:
    """Pick the most-restrictive TLP among shareable observables (pure).

    ``red`` observables are excluded before this is called, so the result is
    ``white``/``green``/``amber``; defaults to ``amber`` when nothing carries a
    marking (OpenCTI's own conservative default).
    """
    best = 0  # index into _TLP_ORDER; 0 == white
    seen = False
    for obs in observables:
        level = (obs.get("tlp") or "amber").lower()
        if level == _TLP_RESTRICTED:
            continue
        try:
            idx = _TLP_ORDER.index(level)
        except ValueError:
            idx = _TLP_ORDER.index("amber")
        best = max(best, idx)
        seen = True
    return _TLP_ORDER[best] if seen else "amber"


def _report_description(case: dict) -> str:
    """Human-readable report body derived from the case summary (pure, bounded)."""
    summary = (case.get("summary") or "").strip()
    prefix = f"Bulwark investigation case {case.get('case_id') or ''}".strip()
    body = f"{prefix}\n\n{summary}".strip() if summary else prefix
    return body[:5000]


def _report_input(case: dict, object_ids: list[str], marking: str) -> dict:
    """Build the ``ReportAddInput`` for a case (pure).

    ``published`` is required by OpenCTI; we use the case's update time, falling
    back to *now* via :func:`iso_now`. ``objects`` may be empty (a report with no
    refs is still valid) but callers only reach here with shareable objects.
    """
    published = str(case.get("updated_at") or case.get("created_at") or iso_now())
    return {
        "name": case.get("title") or "(untitled case)",
        "description": _report_description(case),
        "published": published,
        "report_types": ["threat-report"],
        "objectMarking": [marking],
        "objects": object_ids,
    }




class OpenCTIConnector(HttpConnectorBase):
    """Lookup (read) + case-push (write) connector for an OpenCTI platform."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        verify_tls: bool = True,
        timeout: float = 15.0,
    ) -> None:
        super().__init__(base_url=base_url, verify_tls=verify_tls, timeout=timeout)
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

    @property
    def kind(self) -> str:
        return "opencti"

    def _report_url(self, internal_id: str) -> str:
        return f"{self.base_url.rstrip('/')}/dashboard/analyses/reports/{internal_id}"

    async def test_connection(self) -> ConnectorHealth:
        """Probe ``about { version }`` (cheap authenticated query). Never raises."""
        try:
            data = await self._graphql(_ABOUT_QUERY, {})
        except ConnectorError as exc:
            return ConnectorHealth(
                ok=False, detail=str(exc), checked_at=iso_now(),
                circuit_state=self.circuit_state,
            )
        version = str((data.get("about") or {}).get("version") or "").strip()
        return ConnectorHealth(
            ok=True, detail=f"OpenCTI {version}".strip(), checked_at=iso_now(),
            circuit_state=self.circuit_state,
        )

    async def lookup_observable(
        self, *, observable_type: str, value: str, first: int = _DEFAULT_LOOKUP_FIRST
    ) -> dict:
        """Look an observable value up against OpenCTI's indicator collection.

        Returns a compact enrichment blob::

            {connector, checked_at, verdict, is_malicious, found,
             score, indicator_count, labels:[…], indicators:[…]}

        The verdict is driven by the worst *active* (non-revoked) matching STIX
        indicator's ``x_opencti_score``. ``observable_type`` is accepted for parity
        with the enrichment call surface; matching is by literal value so a
        non-network value simply yields ``not_found``.
        """
        needle = value.strip().lower()
        if not needle:
            return self._empty_result()

        data = await self._graphql(
            _LOOKUP_QUERY, {"search": value, "first": max(1, first)}
        )
        edges = ((data.get("indicators") or {}).get("edges")) or []

        matches: list[dict] = []
        labels_acc: list[str] = []
        top_score = 0
        for edge in edges if isinstance(edges, list) else []:
            node = (edge or {}).get("node") or {} if isinstance(edge, dict) else {}
            pattern = str(node.get("pattern") or "")
            # Only STIX patterns are interpretable; ``search`` is fuzzy, so require
            # the literal observable value to appear in the pattern.
            if (node.get("pattern_type") or "stix").lower() != "stix":
                continue
            if needle not in pattern.lower():
                continue
            revoked = bool(node.get("revoked"))
            raw_score = node.get("x_opencti_score")
            if raw_score is None:
                raw_score = node.get("confidence")
            score = _coerce_score(raw_score)
            node_labels = _node_labels(node)
            matches.append({
                "pattern": pattern[:256],
                "score": score,
                "revoked": revoked,
                "labels": node_labels,
            })
            if not revoked and score > top_score:
                top_score = score
            for label in node_labels:
                if label not in labels_acc:
                    labels_acc.append(label)

        found = len(matches) > 0
        # ``top_score`` only accumulates active (non-revoked) indicators, so a
        # revoked-only match keeps ``top_score`` at 0 and folds to ``clean``.
        verdict = score_verdict(top_score, found=found)
        return {
            "connector": "opencti",
            "checked_at": iso_now(),
            "verdict": verdict,
            "is_malicious": verdict == "malicious",
            "found": len(matches) > 0,
            "score": top_score,
            "indicator_count": len(matches),
            "labels": labels_acc[:5],
            "indicators": matches[:10],
        }

    def _empty_result(self) -> dict:
        """A well-formed 'nothing to look up' blob (empty observable value)."""
        return {
            "connector": "opencti",
            "checked_at": iso_now(),
            "verdict": "not_found",
            "is_malicious": False,
            "found": False,
            "score": 0,
            "indicator_count": 0,
            "labels": [],
            "indicators": [],
        }

    # ─── Push (case → graph) ───────────────────────────────────────────────────

    async def push_case(
        self,
        case: dict,
        observables: list[dict],
        tasks: list[dict],
        *,
        remote_id: Optional[str] = None,
    ) -> PushResult:
        """Materialise a case into OpenCTI as SCOs + indicators + sightings + report.

        ``TLP:RED`` observables are excluded (never shared externally). If nothing
        shareable remains, :class:`TlpGateError` is raised and no remote call for
        the restricted data is made. On re-push (``remote_id`` = report internal
        id) the SCOs/indicators upsert idempotently and the report envelope is
        patched; new object refs are best-effort re-attached.
        """
        shareable = [o for o in observables if not _is_restricted(o)]
        excluded = len(observables) - len(shareable)
        mappable = [o for o in shareable if _observable_payload(o) is not None]
        if not mappable:
            raise TlpGateError(
                "OpenCTI push refused: no shareable observable "
                f"(excluded {excluded} TLP:RED, {len(shareable) - len(mappable)} unmappable)"
            )

        marking = _TLP_MARKING_IDS[select_report_marking(shareable)]

        object_ids: list[str] = []
        indicator_count = 0
        sighting_count = 0
        for obs in mappable:
            obs_id = await self._create_observable(obs, marking)
            if obs_id:
                object_ids.append(obs_id)
            if not obs.get("is_ioc"):
                continue
            ind_id = await self._create_indicator(obs, marking)
            if not ind_id:
                continue
            indicator_count += 1
            object_ids.append(ind_id)
            if await self._create_sighting(obs, ind_id, marking):
                sighting_count += 1

        detail = (
            f"{len(object_ids)} objects, {indicator_count} indicators, "
            f"{sighting_count} sightings, {excluded} TLP:RED excluded"
        )
        if remote_id:
            await self._update_report(remote_id, case, object_ids)
            return PushResult(
                remote_id=remote_id,
                remote_url=self._report_url(remote_id),
                created=False,
                detail=f"report updated ({detail})",
            )

        report_id = await self._create_report(case, object_ids, marking)
        return PushResult(
            remote_id=report_id,
            remote_url=self._report_url(report_id),
            created=True,
            detail=f"report created ({detail})",
        )

    async def _create_observable(self, obs: dict, marking: str) -> str:
        """Create/upsert one SCO; return its internal id (``""`` on soft failure)."""
        payload = _observable_payload(obs)
        if payload is None:
            return ""
        octype, var_key, var_val = payload
        variables = {"type": octype, "markings": [marking], var_key: var_val}
        data = await self._graphql(_OBS_MUTATION, variables)
        node = data.get("stixCyberObservableAdd") or {}
        return str(node.get("id") or "")

    async def _create_indicator(self, obs: dict, marking: str) -> str:
        """Create an indicator SDO for an IOC observable; return internal id."""
        pattern = _indicator_pattern(obs)
        if pattern is None:
            return ""
        name = f"{obs.get('type')}:{obs.get('value')}"[:512]
        input_obj: dict = {
            "name": name,
            "pattern": pattern,
            "pattern_type": "stix",
            "x_opencti_main_observable_type": _main_observable_type(obs),
            "objectMarking": [marking],
        }
        valid_from = obs.get("first_seen")
        if valid_from:
            input_obj["valid_from"] = str(valid_from)
        data = await self._graphql(_INDICATOR_MUTATION, {"input": input_obj})
        node = data.get("indicatorAdd") or {}
        return str(node.get("id") or "")

    async def _create_sighting(self, obs: dict, indicator_id: str, marking: str) -> bool:
        """Create a sighting of ``indicator_id`` (temporal context). Best-effort."""
        input_obj: dict = {
            "fromId": indicator_id,
            "objectMarking": [marking],
            "count": 1,
        }
        first_seen = obs.get("first_seen")
        last_seen = obs.get("last_seen")
        if first_seen:
            input_obj["first_seen"] = str(first_seen)
        if last_seen:
            input_obj["last_seen"] = str(last_seen)
        try:
            data = await self._graphql(_SIGHTING_MUTATION, {"input": input_obj})
        except ConnectorError as exc:
            logger.warning("opencti_sighting_failed", extra={"error": str(exc)})
            return False
        node = data.get("stixSightingRelationshipAdd") or {}
        return bool(node.get("id"))

    async def _create_report(
        self, case: dict, object_ids: list[str], marking: str
    ) -> str:
        """Create the container report tying the case's objects together."""
        input_obj = _report_input(case, object_ids, marking)
        data = await self._graphql(_REPORT_ADD_MUTATION, {"input": input_obj})
        node = data.get("reportAdd") or {}
        report_id = str(node.get("id") or "")
        if not report_id:
            raise ConnectorError("OpenCTI report create returned no id")
        return report_id

    async def _update_report(
        self, report_id: str, case: dict, object_ids: list[str]
    ) -> None:
        """Patch the report envelope + best-effort re-attach object refs."""
        patch = [
            {"key": "name", "value": [case.get("title") or "(untitled case)"]},
            {"key": "description", "value": [_report_description(case)]},
        ]
        await self._graphql(_REPORT_PATCH_MUTATION, {"id": report_id, "input": patch})
        for obj_id in object_ids:
            try:
                await self._graphql(
                    _REPORT_RELATION_MUTATION,
                    {"id": report_id, "input": {"toId": obj_id, "relationship_type": "object"}},
                )
            except ConnectorError as exc:
                logger.warning("opencti_report_reladd_failed", extra={"error": str(exc)})

    async def _graphql(self, query: str, variables: dict) -> dict:
        """POST a GraphQL query and return the ``data`` object.

        A body-level ``errors`` array (HTTP 200 with GraphQL errors — OpenCTI's
        normal failure mode) is surfaced as :class:`ConnectorError`, matching the
        transport/HTTP failures already raised by :meth:`_request`.
        """
        resp = await self._request(
            "POST", "/graphql",
            json_body={"query": query, "variables": variables},
            expected=(200,),
        )
        try:
            body = resp.json()
        except ValueError as exc:
            raise ConnectorError("OpenCTI returned a non-JSON response") from exc
        if not isinstance(body, dict):
            raise ConnectorError("OpenCTI returned an unexpected payload")
        errors = body.get("errors")
        if errors:
            msg = "unknown error"
            if isinstance(errors, list) and errors and isinstance(errors[0], dict):
                msg = str(errors[0].get("message") or msg)
            raise ConnectorError(f"OpenCTI GraphQL error: {msg}")
        data = body.get("data")
        return data if isinstance(data, dict) else {}


__all__ = ["OpenCTIConnector", "score_verdict", "select_report_marking"]
