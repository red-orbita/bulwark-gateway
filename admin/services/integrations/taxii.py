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
from typing import Optional

import httpx

from ...models.iocs import IOCType
from ..investigation_export import build_stix_bundle
from ..ioc_store import _parse_stix_indicator_pattern, _validate_url_no_ssrf
from .base import (
    ConnectorError,
    ConnectorHealth,
    HttpConnectorBase,
    PushResult,
    TlpGateError,
)
from .util import iso_now

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


# ─── Publish (case → TAXII collection) ─────────────────────────────────────────
#
# The consume side (above) pulls STIX indicators *out* of a TAXII collection into
# the IOC store. This side pushes a case *into* a writable collection as a STIX 2.1
# bundle (the "Add Objects" operation, ``POST {collection}/objects/``), so an
# investigation can be shared with any STIX-aware SOC platform over the OASIS
# standard transport. It reuses the pure :func:`build_stix_bundle` builder (one
# report SDO + SCOs + indicator SDOs, deterministic ids ⇒ server-side upsert on
# re-push) and is TLP-gated: ``TLP:RED`` observables are never shared, and the
# selected sharing level is stamped as a standard STIX TLP marking-definition.

# Well-known STIX 2.1 TLP marking-definition ids (fixed by the spec). ``red`` is
# intentionally absent — a red observable is excluded before a marking is chosen,
# so a published bundle can only ever carry white/green/amber.
_TLP_MARKING_IDS = {
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
}
# Ascending restrictiveness — index into this drives "most restrictive wins".
_TLP_ORDER = ("white", "green", "amber")
# The spec-mandated fixed creation timestamp for the TLP marking-definitions.
_TLP_MARKING_CREATED = "2017-01-20T00:00:00.000Z"

# STIX object types that are envelope scaffolding rather than shared intelligence;
# a bundle carrying only these (no SCO/indicator) has nothing to publish.
_SCAFFOLD_TYPES = frozenset({"identity", "report", "marking-definition"})


def _is_restricted(obs: dict) -> bool:
    """True when an observable's TLP marking is too restrictive to share (pure).

    Unmarked observables default to ``amber`` (shareable) — the same conservative
    default the MISP/OpenCTI connectors use.
    """
    return (obs.get("tlp") or "amber").lower() == "red"


def select_publish_tlp(observables: list[dict]) -> str:
    """Pick the most-restrictive shareable TLP among observables (pure).

    ``red`` observables are excluded before this is called, so the result is
    ``white``/``green``/``amber``; defaults to ``amber`` when nothing carries a
    marking.
    """
    best = 0  # index into _TLP_ORDER; 0 == white
    seen = False
    for obs in observables:
        level = (obs.get("tlp") or "amber").lower()
        if level == "red":
            continue
        try:
            idx = _TLP_ORDER.index(level)
        except ValueError:
            idx = _TLP_ORDER.index("amber")
        best = max(best, idx)
        seen = True
    return _TLP_ORDER[best] if seen else "amber"


def _tlp_marking_object(tlp: str) -> dict:
    """Build the standard STIX 2.1 TLP ``marking-definition`` SDO (pure)."""
    return {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": _TLP_MARKING_IDS.get(tlp, _TLP_MARKING_IDS["amber"]),
        "created": _TLP_MARKING_CREATED,
        "definition_type": "tlp",
        "name": f"TLP:{tlp.upper()}",
        "definition": {"tlp": tlp},
    }


def apply_tlp_markings(bundle: dict, tlp: str) -> dict:
    """Stamp a bundle's objects with a TLP marking-definition (pure, mutates ``bundle``).

    Prepends the TLP ``marking-definition`` SDO and sets ``object_marking_refs`` on
    every other object, so a downstream store honours the sharing level. Returns the
    same bundle for chaining.
    """
    marking_id = _TLP_MARKING_IDS.get(tlp, _TLP_MARKING_IDS["amber"])
    objects = bundle.get("objects") or []
    for obj in objects:
        if obj.get("type") == "marking-definition":
            continue
        obj["object_marking_refs"] = [marking_id]
    bundle["objects"] = [_tlp_marking_object(tlp), *objects]
    return bundle


class TaxiiConnector(HttpConnectorBase):
    """Case *publish* connector for a writable TAXII 2.1 collection.

    ``base_url`` is the collection's objects endpoint (operator-supplied, the same
    URL shape the feed poller consumes). :meth:`push_case` materialises the case as
    a STIX 2.1 bundle and POSTs it to the collection; on re-push the deterministic
    object ids make the server upsert idempotently.
    """

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str = "",
        verify_tls: bool = True,
        timeout: float = 15.0,
    ) -> None:
        super().__init__(base_url=base_url, verify_tls=verify_tls, timeout=timeout)
        # A TAXII server authenticates with a raw ``Authorization`` header value
        # (Basic/Bearer are both operator-supplied verbatim, matching the poller).
        self._auth_value = api_key
        self._headers = {
            "Accept": _TAXII_MEDIA_TYPE,
            "Content-Type": _TAXII_MEDIA_TYPE,
        }
        if api_key:
            self._headers["Authorization"] = api_key

    @property
    def kind(self) -> str:
        return "taxii"

    def _collection_info_url(self) -> str:
        """Derive the collection metadata URL (objects endpoint minus ``objects/``)."""
        url = self.base_url.rstrip("/")
        if url.endswith("/objects"):
            url = url[: -len("/objects")]
        return url

    async def test_connection(self) -> ConnectorHealth:
        """Probe the collection's metadata endpoint (cheap). Never raises.

        SSRF-validates the URL, then GETs the collection resource and checks the
        server advertises ``can_write`` — a read-only collection can never receive a
        push, so it is reported unhealthy up front. Redirects are never followed.
        """
        ssrf_error = _validate_url_no_ssrf(self.base_url)
        if ssrf_error:
            return ConnectorHealth(
                ok=False, detail=f"SSRF-blocked URL: {ssrf_error}",
                checked_at=iso_now(), circuit_state=self.circuit_state,
            )
        headers = {"Accept": _TAXII_MEDIA_TYPE}
        if self._auth_value:
            headers["Authorization"] = self._auth_value
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, verify=self.verify_tls, follow_redirects=False
            ) as client:
                resp = await client.get(self._collection_info_url(), headers=headers)
        except (httpx.HTTPError, OSError) as exc:
            return ConnectorHealth(
                ok=False, detail=f"{type(exc).__name__}: {exc}",
                checked_at=iso_now(), circuit_state=self.circuit_state,
            )
        if resp.status_code != 200:
            return ConnectorHealth(
                ok=False, detail=f"HTTP {resp.status_code}",
                checked_at=iso_now(), circuit_state=self.circuit_state,
            )
        info = self._safe_json(resp)
        title = str(info.get("title") or "").strip()
        if info.get("can_write") is False:
            return ConnectorHealth(
                ok=False, detail=f"collection '{title}' is not writable".strip(),
                checked_at=iso_now(), circuit_state=self.circuit_state,
            )
        return ConnectorHealth(
            ok=True, detail=f"TAXII collection '{title}' writable".strip(),
            checked_at=iso_now(), circuit_state=self.circuit_state,
        )

    async def push_case(
        self,
        case: dict,
        observables: list[dict],
        tasks: list[dict],
        *,
        remote_id: Optional[str] = None,
    ) -> PushResult:
        """Publish a case to the collection as a TLP-marked STIX 2.1 bundle.

        ``TLP:RED`` observables are excluded (never shared externally). If nothing
        shareable remains, :class:`TlpGateError` is raised and no remote call is
        made. The bundle's deterministic object ids mean a re-push upserts
        server-side, so ``remote_id`` only distinguishes a first push from an update
        for audit/UX.
        """
        ssrf_error = _validate_url_no_ssrf(self.base_url)
        if ssrf_error:
            raise ConnectorError(
                f"TAXII collection URL blocked (SSRF protection): {ssrf_error}"
            )

        shareable = [o for o in observables if not _is_restricted(o)]
        excluded = len(observables) - len(shareable)
        bundle = build_stix_bundle(case, shareable, tasks)
        shared = [
            o for o in bundle.get("objects", [])
            if o.get("type") not in _SCAFFOLD_TYPES
        ]
        if not shared:
            raise TlpGateError(
                "TAXII push refused: no shareable STIX object "
                f"(excluded {excluded} TLP:RED)"
            )

        tlp = select_publish_tlp(shareable)
        apply_tlp_markings(bundle, tlp)
        envelope = {"objects": bundle["objects"]}

        # The objects endpoint requires a trailing slash; ``path='/'`` restores it
        # after _request rstrips the base URL (works whether or not the operator's
        # URL already carried one). 202 (Accepted, async ingest) is the norm.
        resp = await self._request("POST", "/", json_body=envelope, expected=(200, 202))
        status = str(self._safe_json(resp).get("status") or "")

        bundle_id = str(bundle.get("id") or "")
        detail = (
            f"{len(shared)} STIX objects, TLP:{tlp.upper()}, "
            f"{excluded} TLP:RED excluded"
        )
        if status:
            detail = f"{detail} — status {status}"
        created = remote_id is None
        return PushResult(
            remote_id=remote_id or bundle_id,
            remote_url=self._collection_info_url(),
            created=created,
            detail=(
                f"objects published ({detail})" if created
                else f"objects re-published ({detail})"
            ),
        )

    @staticmethod
    def _safe_json(resp: httpx.Response) -> dict:
        """Parse a JSON body to a dict, tolerating a non-JSON/non-object reply."""
        try:
            data = resp.json()
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {}


__all__ = [
    "TaxiiConnector",
    "TaxiiError",
    "apply_tlp_markings",
    "indicator_meets_confidence",
    "poll_collection",
    "select_publish_tlp",
    "stix_confidence_score",
    "stix_indicator_iocs",
    "stix_labels",
]
