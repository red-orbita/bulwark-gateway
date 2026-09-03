"""TAXII 2.1 collection feed client — consume STIX 2.1 indicators into the IOC store.

TAXII 2.1 is the OASIS standard transport for exchanging STIX threat intelligence.
A *collection* is a logical bucket of STIX objects a server exposes at
``{api_root}/collections/{id}/objects/``; polling it returns a STIX *envelope*
(``{"objects": [...], "more": bool, "next": cursor}``). This module is the
consume side of Phase 5's TAXII support: a vendor-neutral feed source that sits
alongside the OpenCTI/MISP fetchers and flows into the same live IOC store via the
feed scheduler.

**Design stance** (matches the roadmap): standards over SDKs — raw ``httpx`` + STIX
2.1 as plain dicts (no ``taxii2-client`` / ``stix2``). Only ``indicator`` SDOs with
a parseable ``stix`` pattern are consumed; revoked and sub-confidence indicators are
dropped. Every collection URL is SSRF-validated (parity with the OpenCTI/MISP/custom
fetchers) and redirects are never followed, so a poll can never be bounced to an
internal host after the initial check.

The fetchers run synchronously in the scheduler's executor thread, so this module is
deliberately sync (unlike the async investigation *connectors*). It reuses the
shared STIX-pattern parser and SSRF guard from :mod:`admin.services.ioc_store`;
that import is safe (``ioc_store`` never imports this module at top level — it does
so lazily inside ``_fetch_taxii``), so there is no import cycle regardless of load
order.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator

import httpx

from ...models.iocs import IOCType
from ..ioc_store import _parse_stix_indicator_pattern, _validate_url_no_ssrf

logger = logging.getLogger(__name__)

# TAXII 2.1 media type — sent as ``Accept`` so a 2.0/2.1-dual server serves 2.1.
_TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"

# Per-request object cap and how many pages of the ``more``/``next`` cursor chain to
# follow — bounds a single poll against a huge or adversarial collection.
_DEFAULT_PAGE_LIMIT = 100
_DEFAULT_MAX_PAGES = 5
_MAX_OBJECTS = 500

# Neutral score assigned to an indicator that carries no STIX ``confidence`` (the
# field is optional). ``50`` maps to a HIGH severity band without claiming CRITICAL.
_DEFAULT_CONFIDENCE_SCORE = 50


class TaxiiError(RuntimeError):
    """A TAXII poll failed (SSRF-blocked URL, transport error, or bad envelope)."""


# ─── Pure STIX-2.1 helpers ───────────────────────────────────────────────────────


def stix_indicator_iocs(sdo: object) -> list[tuple[IOCType, str]]:
    """Extract enforceable ``(IOCType, value)`` atoms from one STIX object (pure).

    Returns ``[]`` for anything that is not a live, STIX-patterned ``indicator``
    SDO: non-dicts, non-indicators, ``revoked`` indicators, non-``stix`` pattern
    types (yara/sigma/snort), and empty/unparseable patterns are all skipped
    rather than guessed.
    """
    if not isinstance(sdo, dict):
        return []
    if sdo.get("type") != "indicator":
        return []
    if sdo.get("revoked") is True:
        return []
    if str(sdo.get("pattern_type") or "stix").lower() != "stix":
        return []
    pattern = sdo.get("pattern") or ""
    if not isinstance(pattern, str) or not pattern:
        return []
    return _parse_stix_indicator_pattern(pattern)


def stix_confidence_score(sdo: dict) -> int:
    """Return a STIX indicator's 0–100 ``confidence`` (or a neutral default) (pure)."""
    conf = sdo.get("confidence")
    if conf is None:
        return _DEFAULT_CONFIDENCE_SCORE
    try:
        return max(0, min(100, int(conf)))
    except (TypeError, ValueError):
        return _DEFAULT_CONFIDENCE_SCORE


def indicator_meets_confidence(sdo: dict, min_confidence: float) -> bool:
    """True when an indicator clears the feed's confidence floor (pure).

    STIX ``confidence`` is optional; an indicator that omits it is *kept* (it cannot
    be judged and over-filtering a curated feed is worse than passing it), whereas a
    present-but-below-floor confidence is dropped.
    """
    conf = sdo.get("confidence")
    if conf is None:
        return True
    try:
        conf = int(conf)
    except (TypeError, ValueError):
        return True
    return conf >= int(round(min_confidence * 100))


def stix_labels(sdo: dict) -> list[str]:
    """Extract up to 3 STIX ``labels`` from an indicator SDO as IOC tags (pure)."""
    raw = sdo.get("labels")
    out: list[str] = []
    for item in raw if isinstance(raw, list) else []:
        if isinstance(item, str) and item.strip():
            label = item.strip()[:30]
            if label not in out:
                out.append(label)
        if len(out) >= 3:
            break
    return out


# ─── Transport ───────────────────────────────────────────────────────────────────


def poll_collection(
    *,
    url: str,
    api_key: str = "",
    auth_header: str = "Authorization",
    page_limit: int = _DEFAULT_PAGE_LIMIT,
    max_pages: int = _DEFAULT_MAX_PAGES,
    verify_tls: bool = True,
) -> Iterator[dict]:
    """Yield raw STIX objects from a TAXII 2.1 collection's ``objects`` endpoint.

    ``url`` is the full collection-objects URL (operator-supplied). It is
    SSRF-validated before the first request and redirects are never followed, so a
    server cannot bounce the poll to an internal host. The ``more``/``next`` cursor
    chain is followed up to ``max_pages`` and a hard ``_MAX_OBJECTS`` ceiling, so a
    single poll is always bounded. Raises :class:`TaxiiError` on a blocked URL,
    transport failure, non-200, or non-JSON/malformed envelope.
    """
    ssrf_error = _validate_url_no_ssrf(url)
    if ssrf_error:
        raise TaxiiError(f"TAXII collection URL blocked (SSRF protection): {ssrf_error}")

    headers = {"Accept": _TAXII_MEDIA_TYPE}
    if api_key:
        headers[auth_header or "Authorization"] = api_key

    next_cursor: str | None = None
    pages = 0
    emitted = 0
    with httpx.Client(timeout=60, verify=verify_tls, follow_redirects=False) as client:
        while pages < max_pages and emitted < _MAX_OBJECTS:
            params: dict[str, str | int] = {"limit": max(1, page_limit)}
            if next_cursor:
                params["next"] = next_cursor
            try:
                resp = client.get(url, headers=headers, params=params)
            except httpx.HTTPError as exc:
                raise TaxiiError(f"TAXII request failed: {exc}") from exc
            if resp.status_code != 200:
                raise TaxiiError(f"TAXII server returned {resp.status_code}")
            try:
                envelope = resp.json()
            except ValueError as exc:
                raise TaxiiError("TAXII returned a non-JSON response") from exc
            if not isinstance(envelope, dict):
                raise TaxiiError("TAXII returned an unexpected envelope")

            for obj in envelope.get("objects") or []:
                if isinstance(obj, dict):
                    yield obj
                    emitted += 1
                    if emitted >= _MAX_OBJECTS:
                        return

            pages += 1
            if not envelope.get("more"):
                return
            next_cursor = envelope.get("next")
            if not next_cursor:
                return


__all__ = [
    "TaxiiError",
    "indicator_meets_confidence",
    "poll_collection",
    "stix_confidence_score",
    "stix_indicator_iocs",
    "stix_labels",
]
