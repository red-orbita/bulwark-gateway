"""MISP connector — observable lookup **and** case push via the MISP REST API.

MISP (Malware Information Sharing Platform) is a community threat-intelligence
platform built around *events* (a container) holding *attributes* (atomic
indicators). This connector promotes the pull-only ``IOCStore._fetch_misp`` feed
into a first-class :class:`~admin.services.integrations.base.Connector` serving
two roles:

* **Lookup** (read): for an investigation observable it answers *does MISP already
  track this atomic indicator, and is it flagged actionable?* — it queries
  ``/attributes/restSearch`` for the observable's literal value and folds the
  matching attributes into one verdict (driven by whether any attribute carries
  ``to_ids=true``), returning a compact enrichment blob.

* **Push** (write): it materialises a Bulwark investigation case into MISP as a
  single **Event** whose **Attributes** are the case's observables (type-mapped;
  ``is_ioc`` ⇒ ``to_ids=true``), tagged with the case's TLP + ``bulwark:*`` labels
  + any MITRE ATT&CK technique galaxy tags. It implements the ``Connector`` push
  protocol so it reuses the shared ``/push/case`` route + link-store idempotency
  (the event UUID is the ``remote_id``; a re-push edits that event — MISP dedups
  attributes by type+value within an event, so the edit is idempotent).

**TLP data-sharing gate**: MISP is an *external, shared* platform, so ``TLP:RED``
observables are never sent — they are silently excluded from the push. If a case
has *no* shareable (non-red, mappable) observable left, the whole push is refused
with :class:`TlpGateError` (a local policy decision, surfaced as a ``400`` — the
remote is never contacted for restricted data). The event is tagged with the
case's most-restrictive remaining TLP.

Everything is fail-open and bounded via :class:`HttpConnectorBase`: a slow or
failing platform can never tie up an admin worker — each request is short-timeout
and an exhausted/again-failing call raises :class:`ConnectorError` for the route
layer to audit without ever touching the observable/case store.
"""

from __future__ import annotations

import logging
import re
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

# How many candidate attributes to pull per lookup. MISP ``restSearch`` matches on
# the literal value, so a small cap is plenty (an indicator rarely appears in many
# events, and we only need enough to decide the verdict + surface context).
_DEFAULT_LOOKUP_LIMIT = 25

# The TLP marking that must never leave Bulwark for an external shared platform.
_TLP_RESTRICTED = "red"

# Restrictiveness order (low → high) for picking an event-level TLP tag.
_TLP_ORDER = ("white", "green", "amber", "red")

# Observable type → (MISP attribute type, MISP attribute category). Hashes are
# resolved dynamically by digest length (:func:`_hash_attribute`).
_ATTR_TYPE_MAP = {
    "ip": ("ip-dst", "Network activity"),
    "domain": ("domain", "Network activity"),
    "url": ("url", "Network activity"),
    "email": ("email-src", "Payload delivery"),
    "filename": ("filename", "Payload delivery"),
}

# Hash digest length → MISP attribute type (category is always Payload delivery).
_HASH_TYPE_BY_LEN = {32: "md5", 40: "sha1", 64: "sha256"}

# Bulwark case severity → MISP ``threat_level_id`` (1=high, 2=medium, 3=low,
# 4=undefined). Conservative: an unknown/absent severity is "undefined".
_THREAT_LEVEL = {"critical": "1", "high": "1", "medium": "2", "low": "3"}

# A MITRE ATT&CK technique id (e.g. ``T1041`` / ``T1059.001``) — case tags matching
# this become MISP ATT&CK galaxy tags on push.
_ATTACK_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


# ─── Pure helpers ──────────────────────────────────────────────────────────────


def _hash_attribute(value: str) -> Optional[tuple[str, str]]:
    """Classify a hex hash by length into ``(misp_type, category)`` (or ``None``)."""
    misp_type = _HASH_TYPE_BY_LEN.get(len(value))
    if misp_type is None:
        return None
    return (misp_type, "Payload delivery")


def attribute_mapping(obs: dict) -> Optional[tuple[str, str]]:
    """Map an observable to ``(misp_attribute_type, misp_category)`` (pure).

    Returns ``None`` for a value that cannot be represented as a MISP attribute
    (empty value, or a hash whose length matches no known algorithm).
    """
    otype = obs.get("type")
    value = (obs.get("value") or "").strip()
    if not value:
        return None
    if otype == "hash":
        return _hash_attribute(value)
    return _ATTR_TYPE_MAP.get(otype or "")


def _is_restricted(obs: dict) -> bool:
    """True when an observable's TLP marking is too restrictive to share externally."""
    return (obs.get("tlp") or "amber").lower() == _TLP_RESTRICTED


def select_event_tlp(observables: list[dict]) -> str:
    """Pick the most-restrictive TLP among shareable observables (pure).

    ``red`` observables are excluded before this is called, so the result is
    ``white``/``green``/``amber``; defaults to ``amber`` when nothing carries a
    marking (MISP's own conservative default).
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


def misp_verdict(*, found: bool, actionable: bool) -> str:
    """Fold a MISP match into a verdict label (pure).

    MISP has no single numeric reputation score (unlike OpenCTI's
    ``x_opencti_score``), so the verdict is driven by whether the value is *known*
    and whether any matching attribute is flagged **actionable** (``to_ids=true`` —
    i.e. the community considers it a detectable IOC, not mere context):

    * ``not_found`` — MISP has never seen the value.
    * ``malicious`` — found *and* at least one attribute is ``to_ids=true``.
    * ``suspicious`` — found only as non-actionable context (all ``to_ids=false``).
    """
    if not found:
        return "not_found"
    return "malicious" if actionable else "suspicious"


def _threat_level_id(case: dict) -> str:
    """Map a case's severity to a MISP ``threat_level_id`` (defaults to undefined)."""
    return _THREAT_LEVEL.get(str(case.get("severity") or "").lower(), "4")


def _case_tag_names(case: dict, tlp: str) -> list[str]:
    """Build the event-level MISP tag names for a case (pure, deduped, bounded).

    Always includes the TLP tag + a ``bulwark:investigation`` provenance tag. Each
    case tag becomes either an ATT&CK galaxy tag (technique ids like ``T1041``) or
    a namespaced ``bulwark:<tag>`` label.
    """
    names: list[str] = [f"tlp:{tlp}", "bulwark:investigation"]
    for raw in case.get("tags") or []:
        tag = str(raw or "").strip()
        if not tag:
            continue
        if _ATTACK_TECHNIQUE_RE.match(tag):
            names.append(f'misp-galaxy:mitre-attack-pattern="{tag.upper()}"')
        else:
            names.append(f"bulwark:{tag}")
    # Dedup while preserving order; cap to keep the payload bounded.
    seen: set[str] = set()
    out: list[str] = []
    for name in names:
        if name not in seen:
            seen.add(name)
            out.append(name)
        if len(out) >= 30:
            break
    return out


def _attribute_input(obs: dict, tlp: str) -> Optional[dict]:
    """Build one MISP ``Attribute`` dict for an observable (pure, ``None`` if unmappable)."""
    mapping = attribute_mapping(obs)
    if mapping is None:
        return None
    misp_type, category = mapping
    value = (obs.get("value") or "").strip()
    is_ioc = bool(obs.get("is_ioc"))
    tags = [{"name": f"tlp:{tlp}"}]
    if is_ioc:
        tags.append({"name": "bulwark:ioc"})
    attr: dict = {
        "type": misp_type,
        "category": category,
        "value": value,
        "to_ids": is_ioc,
        "distribution": "5",  # inherit from event
        "Tag": tags,
    }
    comment = str(obs.get("note") or "").strip()
    if comment:
        attr["comment"] = comment[:255]
    return attr


def _event_input(case: dict, attributes: list[dict], tlp: str) -> dict:
    """Build the ``Event`` payload for a case (pure).

    ``distribution`` defaults to ``0`` (this-organisation-only) — the conservative
    default; the TLP tag governs any wider sharing policy. ``analysis`` is
    ``1`` (ongoing) and ``date`` is derived from the case timestamps.
    """
    date = str(case.get("created_at") or case.get("updated_at") or iso_now())[:10]
    return {
        "info": (case.get("title") or "(untitled case)")[:255],
        "distribution": "0",
        "threat_level_id": _threat_level_id(case),
        "analysis": "1",
        "date": date,
        "Attribute": attributes,
        "Tag": [{"name": name} for name in _case_tag_names(case, tlp)],
    }


def _extract_event_uuid(event: dict) -> str:
    """Pull a stable event UUID (preferred) or numeric id from a MISP event dict."""
    return str(event.get("uuid") or event.get("id") or "")


class MispConnector(HttpConnectorBase):
    """Lookup (read) + case-push (write) connector for a MISP platform."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        verify_tls: bool = True,
        timeout: float = 15.0,
    ) -> None:
        super().__init__(base_url=base_url, verify_tls=verify_tls, timeout=timeout)
        # MISP authenticates with a bare API key in the ``Authorization`` header
        # (no ``Bearer`` prefix).
        self._headers = {
            "Authorization": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    @property
    def kind(self) -> str:
        return "misp"

    def _event_url(self, uuid: str) -> str:
        return f"{self.base_url.rstrip('/')}/events/view/{uuid}"

    async def test_connection(self) -> ConnectorHealth:
        """Probe ``GET /servers/getVersion`` (cheap authenticated query). Never raises."""
        try:
            data = await self._get("/servers/getVersion")
        except ConnectorError as exc:
            return ConnectorHealth(
                ok=False, detail=str(exc), checked_at=iso_now(),
                circuit_state=self.circuit_state,
            )
        version = str(data.get("version") or "").strip()
        return ConnectorHealth(
            ok=True, detail=f"MISP {version}".strip(), checked_at=iso_now(),
            circuit_state=self.circuit_state,
        )

    async def lookup_observable(
        self, *, observable_type: str, value: str, limit: int = _DEFAULT_LOOKUP_LIMIT
    ) -> dict:
        """Look an observable value up against MISP's attribute corpus.

        Returns a compact enrichment blob::

            {connector, checked_at, verdict, is_malicious, found,
             attribute_count, event_count, to_ids_count, tags:[…], attributes:[…]}

        The verdict is driven by whether any matching attribute is ``to_ids=true``
        (see :func:`misp_verdict`). ``observable_type`` is accepted for parity with
        the enrichment call surface; matching is by literal value.
        """
        needle = value.strip()
        if not needle:
            return self._empty_result()

        body = {
            "returnFormat": "json",
            "value": needle,
            "limit": max(1, limit),
            "enforceWarninglist": True,
            "includeEventTags": True,
            "deleted": False,
        }
        data = await self._post("/attributes/restSearch", body)
        raw = ((data.get("response") or {}).get("Attribute")) or []

        attributes: list[dict] = []
        event_ids: set[str] = set()
        tags_acc: list[str] = []
        to_ids_count = 0
        for attr in raw if isinstance(raw, list) else []:
            if not isinstance(attr, dict):
                continue
            actionable = bool(attr.get("to_ids"))
            if actionable:
                to_ids_count += 1
            event_id = str(attr.get("event_id") or "")
            if event_id:
                event_ids.add(event_id)
            for tag in _attribute_tag_names(attr):
                if tag not in tags_acc:
                    tags_acc.append(tag)
            attributes.append({
                "type": str(attr.get("type") or "")[:64],
                "category": str(attr.get("category") or "")[:64],
                "to_ids": actionable,
                "event_id": event_id,
            })

        found = len(attributes) > 0
        verdict = misp_verdict(found=found, actionable=to_ids_count > 0)
        return {
            "connector": "misp",
            "checked_at": iso_now(),
            "verdict": verdict,
            "is_malicious": verdict == "malicious",
            "found": found,
            "attribute_count": len(attributes),
            "event_count": len(event_ids),
            "to_ids_count": to_ids_count,
            "tags": tags_acc[:10],
            "attributes": attributes[:10],
        }

    def _empty_result(self) -> dict:
        """A well-formed 'nothing to look up' blob (empty observable value)."""
        return {
            "connector": "misp",
            "checked_at": iso_now(),
            "verdict": "not_found",
            "is_malicious": False,
            "found": False,
            "attribute_count": 0,
            "event_count": 0,
            "to_ids_count": 0,
            "tags": [],
            "attributes": [],
        }

    # ─── Push (case → event) ───────────────────────────────────────────────────

    async def push_case(
        self,
        case: dict,
        observables: list[dict],
        tasks: list[dict],
        *,
        remote_id: Optional[str] = None,
    ) -> PushResult:
        """Materialise a case into MISP as a tagged Event of Attributes.

        ``TLP:RED`` observables are excluded (never shared externally). If nothing
        shareable remains, :class:`TlpGateError` is raised and no remote call for
        the restricted data is made. On re-push (``remote_id`` = event UUID) the
        event is edited — MISP dedups attributes by type+value within an event, so
        the edit upserts idempotently.
        """
        shareable = [o for o in observables if not _is_restricted(o)]
        excluded = len(observables) - len(shareable)
        attributes = [a for o in shareable if (a := _attribute_input(o, "amber")) is not None]
        if not attributes:
            raise TlpGateError(
                "MISP push refused: no shareable observable "
                f"(excluded {excluded} TLP:RED, {len(shareable) - len(attributes)} unmappable)"
            )

        tlp = select_event_tlp(shareable)
        # Rebuild attribute tags with the resolved event-level TLP (cheap; keeps the
        # per-attribute tlp tag consistent with the event tag).
        attributes = [
            a for o in shareable if (a := _attribute_input(o, tlp)) is not None
        ]
        ioc_count = sum(1 for a in attributes if a.get("to_ids"))
        event_input = _event_input(case, attributes, tlp)
        detail = (
            f"{len(attributes)} attributes, {ioc_count} IOCs, "
            f"{excluded} TLP:RED excluded"
        )

        if remote_id:
            event = await self._write_event(f"/events/edit/{remote_id}", event_input)
            uuid = _extract_event_uuid(event) or remote_id
            return PushResult(
                remote_id=uuid,
                remote_url=self._event_url(uuid),
                created=False,
                detail=f"event updated ({detail})",
            )

        event = await self._write_event("/events/add", event_input)
        uuid = _extract_event_uuid(event)
        if not uuid:
            raise ConnectorError("MISP event create returned no uuid")
        return PushResult(
            remote_id=uuid,
            remote_url=self._event_url(uuid),
            created=True,
            detail=f"event created ({detail})",
        )

    # ─── REST plumbing ─────────────────────────────────────────────────────────

    async def _write_event(self, path: str, event_input: dict) -> dict:
        """POST an event add/edit and return the ``Event`` object from the reply."""
        data = await self._post(path, {"Event": event_input})
        event = data.get("Event")
        return event if isinstance(event, dict) else data

    async def _get(self, path: str) -> dict:
        resp = await self._request("GET", path, expected=(200,))
        return self._parse(resp)

    async def _post(self, path: str, body: dict) -> dict:
        resp = await self._request("POST", path, json_body=body, expected=(200,))
        return self._parse(resp)

    def _parse(self, resp) -> dict:
        """Parse a MISP JSON reply, surfacing its error envelope as ConnectorError.

        MISP reports most failures with a 4xx (handled by :meth:`_request`), but a
        200 body can still carry an ``errors`` field or a ``{name, message}`` error
        envelope, which we normalise to :class:`ConnectorError`.
        """
        try:
            body = resp.json()
        except ValueError as exc:
            raise ConnectorError("MISP returned a non-JSON response") from exc
        if not isinstance(body, dict):
            raise ConnectorError("MISP returned an unexpected payload")
        errors = body.get("errors")
        if errors:
            raise ConnectorError(f"MISP error: {_error_text(errors)}")
        # A bare error envelope: ``{"name": "...", "message": "..."}`` with no data.
        name = str(body.get("name") or "")
        if name and "Attribute" not in body and "Event" not in body and "version" not in body:
            message = str(body.get("message") or name)
            raise ConnectorError(f"MISP error: {message}")
        return body


def _attribute_tag_names(attr: dict) -> list[str]:
    """Extract up to 5 tag names from a MISP attribute (its own + event tags)."""
    out: list[str] = []
    raw = attr.get("Tag")
    for item in raw if isinstance(raw, list) else []:
        if isinstance(item, dict):
            name = str(item.get("name") or "").strip()
            if name and name not in out:
                out.append(name[:64])
        if len(out) >= 5:
            break
    return out


def _error_text(errors: object) -> str:
    """Coerce a MISP ``errors`` value (str / list / dict) into a short message."""
    if isinstance(errors, str):
        return errors[:200]
    if isinstance(errors, list) and errors:
        return str(errors[0])[:200]
    if isinstance(errors, dict):
        return str(errors)[:200]
    return "unknown error"


__all__ = [
    "MispConnector",
    "attribute_mapping",
    "misp_verdict",
    "select_event_tlp",
]
