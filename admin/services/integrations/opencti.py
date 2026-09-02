"""OpenCTI connector — read-only observable lookup via the platform GraphQL API.

OpenCTI is a threat-intelligence knowledge graph. This connector answers a single
question for an investigation observable: *does OpenCTI already know this atomic
indicator, and how bad does it think it is?* It searches the ``indicators``
collection for the observable's literal value, folds the matching STIX indicators
into one worst-case verdict (driven by ``x_opencti_score``, 0–100), and returns a
compact enrichment blob suitable for storing on the observable.

Like :class:`~admin.services.integrations.cortex.CortexConnector`, OpenCTI is an
*enrichment* target, not a case *push* target, so it does not implement the
``Connector`` push protocol — it reuses :class:`HttpConnectorBase` purely for the
retry + circuit-breaker HTTP machinery. This slice is **lookup-only** (read); the
push side (SCOs / indicators / sightings / case→report) lands separately.

Everything is fail-open and bounded: a slow or failing platform can never tie up
an admin worker — each request is short-timeout and an exhausted/again-failing
call raises :class:`ConnectorError` for the route layer to audit without ever
touching the observable/case store.
"""

from __future__ import annotations

import logging

from .base import ConnectorError, ConnectorHealth, HttpConnectorBase
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


class OpenCTIConnector(HttpConnectorBase):
    """Read-only enrichment connector for an OpenCTI platform (GraphQL API)."""

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


__all__ = ["OpenCTIConnector", "score_verdict"]
