"""Interoperability exports for the Investigation Center (Phase 0).

Renders a case (its metadata, tags, observables and tasks) into three
widely-consumed interchange shapes so an investigation can leave Bulwark and land
in an external case-management / threat-intel platform:

* **STIX 2.1** — an OASIS ``bundle`` of a ``report`` SDO plus one Cyber-observable
  Object (SCO) per observable and an ``indicator`` SDO for each flagged IOC. For
  OpenCTI / MISP / any STIX-aware store.
* **TheHive** — a case object in TheHive's import shape (severity/TLP/PAP as their
  integer enums, tasks, and observables as ``artifacts``).
* **DFIR-IRIS** — a case object in IRIS's import shape (iocs + tasks).

Everything here is **pure** (no DB, no I/O) and emits plain ``dict``s built from
the durable store — there is NO dependency on ``stix2`` / ``thehive4py`` /
``dfir-iris-client``; the shapes are constructed directly. The mappings are
deliberately conservative and best-effort: each is a portable starting point an
analyst can import and refine, not a certified bidirectional connector.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

# OASIS STIX 2.1 namespace UUID — deterministic SCO/SDO ids are derived from it so
# re-exporting the same case/observable yields stable identifiers (idempotent
# import into a downstream store).
_STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

# ─── shared severity / handling-marker mappings ───────────────────────────────

# Case severity → TheHive/IRIS 1–4 integer severity.
_SEVERITY_TO_INT = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# TLP / PAP marker → TheHive/IRIS 0–3 integer.
_TLP_TO_INT = {"white": 0, "green": 1, "amber": 2, "red": 3}

# Observable type → TheHive dataType.
_TYPE_TO_THEHIVE = {
    "ip": "ip",
    "domain": "domain",
    "url": "url",
    "hash": "hash",
    "email": "mail",
    "filename": "filename",
    "user": "other",
    "other": "other",
}

# Task status → TheHive task status enum.
_TASK_TO_THEHIVE = {
    "todo": "Waiting",
    "in_progress": "InProgress",
    "done": "Completed",
    "cancelled": "Cancel",
}


def _stix_ts(value: object) -> str:
    """Render a stored ISO timestamp as a STIX ``YYYY-MM-DDTHH:MM:SS.sssZ`` string.

    Falls back to *now* for anything unparseable so an export is always valid.
    """
    dt: Optional[datetime] = None
    if value:
        try:
            dt = datetime.fromisoformat(str(value))
        except (TypeError, ValueError):
            dt = None
    if dt is None:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _stix_id(stix_type: str, key: str) -> str:
    """Deterministic ``<type>--<uuid5>`` id (stable across re-exports)."""
    return f"{stix_type}--{uuid.uuid5(_STIX_NAMESPACE, f'{stix_type}:{key}')}"


def _hash_algo(value: str) -> Optional[str]:
    """Classify a hex hash by length into a STIX hash-algorithm name."""
    length = len(value)
    if length == 32:
        return "MD5"
    if length == 64:
        return "SHA-256"
    if length == 40:
        return "SHA-1"
    return None


def _observable_sco(obs: dict) -> Optional[dict]:
    """Map an observable to a STIX Cyber-observable Object (``None`` if no mapping)."""
    otype = obs.get("type")
    value = obs.get("value") or ""
    if not value:
        return None
    if otype == "ip":
        sco_type = "ipv6-addr" if ":" in value else "ipv4-addr"
        return {"type": sco_type, "id": _stix_id(sco_type, value), "value": value}
    if otype == "domain":
        return {"type": "domain-name", "id": _stix_id("domain-name", value), "value": value}
    if otype == "url":
        return {"type": "url", "id": _stix_id("url", value), "value": value}
    if otype == "email":
        return {"type": "email-addr", "id": _stix_id("email-addr", value), "value": value}
    if otype == "hash":
        algo = _hash_algo(value)
        if algo is None:
            return None
        return {
            "type": "file",
            "id": _stix_id("file", value),
            "hashes": {algo: value},
        }
    if otype == "filename":
        return {"type": "file", "id": _stix_id("file", value), "name": value}
    if otype == "user":
        return {
            "type": "user-account",
            "id": _stix_id("user-account", value),
            "account_login": value,
        }
    return None


def _indicator_pattern(obs: dict) -> Optional[str]:
    """Build a STIX pattern for an IOC observable (``None`` if unmappable)."""
    otype = obs.get("type")
    value = (obs.get("value") or "").replace("'", "\\'")
    if not value:
        return None
    if otype == "ip":
        addr = "ipv6-addr" if ":" in (obs.get("value") or "") else "ipv4-addr"
        return f"[{addr}:value = '{value}']"
    if otype == "domain":
        return f"[domain-name:value = '{value}']"
    if otype == "url":
        return f"[url:value = '{value}']"
    if otype == "email":
        return f"[email-addr:value = '{value}']"
    if otype == "hash":
        algo = _hash_algo(obs.get("value") or "")
        if algo is None:
            return None
        return f"[file:hashes.'{algo}' = '{value}']"
    return None


def build_stix_bundle(case: dict, observables: list[dict], tasks: list[dict]) -> dict:
    """Build a STIX 2.1 bundle for a case (pure).

    Emits an identity for Bulwark, one SCO per mappable observable, an indicator
    SDO per flagged IOC, and a report SDO tying them together. ``tasks`` are
    summarised in the report description (STIX has no native task object).
    """
    created = _stix_ts(case.get("created_at"))
    modified = _stix_ts(case.get("updated_at"))

    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": _stix_id("identity", "bulwark-gateway"),
        "created": created,
        "modified": modified,
        "name": "Bulwark Gateway",
        "identity_class": "system",
    }

    objects: list[dict] = [identity]
    object_refs: list[str] = []

    for obs in observables:
        sco = _observable_sco(obs)
        if sco is not None:
            sco["spec_version"] = "2.1"
            objects.append(sco)
            object_refs.append(sco["id"])
        if obs.get("is_ioc"):
            pattern = _indicator_pattern(obs)
            if pattern is not None:
                ind_id = _stix_id("indicator", f"{obs.get('type')}:{obs.get('value')}")
                seen = _stix_ts(obs.get("first_seen"))
                indicator: dict[str, Any] = {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": ind_id,
                    "created": seen,
                    "modified": _stix_ts(obs.get("last_seen")),
                    "name": f"{obs.get('type')}:{obs.get('value')}",
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": seen,
                    "created_by_ref": identity["id"],
                }
                if obs.get("tags"):
                    indicator["labels"] = list(obs["tags"])
                objects.append(indicator)
                object_refs.append(ind_id)

    task_lines = [
        f"- [{t.get('status')}] {t.get('title')}" for t in tasks if t.get("title")
    ]
    description = (case.get("summary") or "").strip()
    if task_lines:
        description = (description + "\n\nTasks:\n" + "\n".join(task_lines)).strip()

    report = {
        "type": "report",
        "spec_version": "2.1",
        "id": _stix_id("report", case.get("case_id") or ""),
        "created": created,
        "modified": modified,
        "created_by_ref": identity["id"],
        "name": case.get("title") or "(untitled case)",
        "report_types": ["threat-report"],
        "published": modified,
        "object_refs": object_refs or [identity["id"]],
    }
    if description:
        report["description"] = description
    if case.get("tags"):
        report["labels"] = list(case["tags"])
    objects.append(report)

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(_STIX_NAMESPACE, 'bundle:' + (case.get('case_id') or ''))}",
        "objects": objects,
    }


def build_thehive_case(case: dict, observables: list[dict], tasks: list[dict]) -> dict:
    """Build a TheHive case object for a case (pure)."""
    artifacts = []
    for obs in observables:
        artifacts.append({
            "dataType": _TYPE_TO_THEHIVE.get(str(obs.get("type") or ""), "other"),
            "data": obs.get("value") or "",
            "ioc": bool(obs.get("is_ioc")),
            "tlp": _TLP_TO_INT.get(obs.get("tlp") or "amber", 2),
            "pap": _TLP_TO_INT.get(obs.get("pap") or "amber", 2),
            "tags": list(obs.get("tags") or []),
            "message": f"source={obs.get('source') or 'manual'}",
        })
    hive_tasks = [
        {
            "title": t.get("title") or "",
            "status": _TASK_TO_THEHIVE.get(str(t.get("status") or ""), "Waiting"),
            "owner": t.get("assignee") or "",
        }
        for t in tasks if t.get("title")
    ]
    return {
        "title": case.get("title") or "(untitled case)",
        "description": (case.get("summary") or "").strip(),
        "severity": _SEVERITY_TO_INT.get(case.get("severity") or "medium", 2),
        "tlp": 2,
        "pap": 2,
        "tags": list(case.get("tags") or []),
        "flag": False,
        "tasks": hive_tasks,
        "artifacts": artifacts,
        "customFields": {
            "bulwark-case-id": {"string": case.get("case_id") or ""},
            "bulwark-status": {"string": case.get("status") or "open"},
        },
    }


def _iris_ioc_type(obs: dict) -> str:
    """Map an observable to an IRIS ioc type string."""
    otype = str(obs.get("type") or "")
    if otype == "hash":
        algo = _hash_algo(obs.get("value") or "")
        if algo == "MD5":
            return "md5"
        if algo == "SHA-256":
            return "sha256"
        if algo == "SHA-1":
            return "sha1"
        return "hash"
    return {
        "ip": "ip-any",
        "domain": "domain",
        "url": "url",
        "email": "email",
        "filename": "filename",
        "user": "account",
        "other": "other",
    }.get(otype, "other")


def build_iris_case(case: dict, observables: list[dict], tasks: list[dict]) -> dict:
    """Build a DFIR-IRIS case object for a case (pure)."""
    iocs = [
        {
            "ioc_value": obs.get("value") or "",
            "ioc_type": _iris_ioc_type(obs),
            "ioc_tlp": obs.get("tlp") or "amber",
            "ioc_tags": ",".join(obs.get("tags") or []),
            "ioc_description": f"source={obs.get('source') or 'manual'}",
        }
        for obs in observables
    ]
    iris_tasks = [
        {
            "task_title": t.get("title") or "",
            "task_status": t.get("status") or "todo",
            "task_description": "",
            "task_assignee": t.get("assignee") or "",
        }
        for t in tasks if t.get("title")
    ]
    return {
        "case_name": case.get("title") or "(untitled case)",
        "case_description": (case.get("summary") or "").strip(),
        "case_soc_id": case.get("case_id") or "",
        "case_severity": _SEVERITY_TO_INT.get(case.get("severity") or "medium", 2),
        "case_tags": ",".join(case.get("tags") or []),
        "case_customer": case.get("tenant") or "",
        "iocs": iocs,
        "tasks": iris_tasks,
    }
