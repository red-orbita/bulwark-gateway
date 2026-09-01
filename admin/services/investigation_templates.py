"""Case templates for the Investigation Center (Phase 0).

A **case template** is a reusable investigation blueprint — a starting severity,
a set of TTP/label tags, a default summary, and an ordered checklist of tasks —
that an analyst can apply when opening a new case so a standard playbook
(a phishing triage, a data-exfiltration response, a prompt-injection campaign)
starts pre-populated rather than blank.

Templates are declarative YAML files under a read-only config directory
(``config/investigation/templates`` by default, overridable via
``BULWARK_INVESTIGATION_TEMPLATES_DIR``). They are loaded and validated on demand;
the set is small and read-rarely, so a light mtime-keyed cache avoids re-parsing
on every request without risking staleness after an operator edits a file.

This module never writes: templates are curated content shipped with the
deployment, not user data. Parsing is fully defensive — a malformed file is
skipped with a log line rather than breaking the template list.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(
    os.getenv("BULWARK_INVESTIGATION_TEMPLATES_DIR", "config/investigation/templates")
)

# Bounds so a hand-authored (or tampered) template can never seed an unbounded
# case. Mirrors the store-side caps the seeded values will be validated against.
_MAX_TAGS = 50
_MAX_TAG_LEN = 64
_MAX_TASKS = 100
_MAX_TITLE_LEN = 200
_MAX_SUMMARY_LEN = 4000
_MAX_NAME_LEN = 120
_MAX_DESC_LEN = 500

_VALID_SEVERITIES = ("low", "medium", "high", "critical")

# mtime-keyed cache: {path: (mtime, parsed_template)}. Cleared/refreshed lazily.
_cache: dict[str, tuple[float, dict]] = {}


def _coerce_tags(raw) -> list[str]:
    """Normalise a template's tag list (trim, lower-case, dedupe, cap)."""
    out: list[str] = []
    seen: set[str] = set()
    if not isinstance(raw, list):
        return out
    for tag in raw:
        if not isinstance(tag, (str, int, float)):
            continue
        norm = str(tag).strip().lower()[:_MAX_TAG_LEN]
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)
        if len(out) >= _MAX_TAGS:
            break
    return out


def _coerce_tasks(raw) -> list[dict]:
    """Normalise a template's task list into ``[{title, assignee}]`` (bounded)."""
    out: list[dict] = []
    if not isinstance(raw, list):
        return out
    for item in raw:
        title = ""
        assignee = ""
        if isinstance(item, str):
            title = item.strip()
        elif isinstance(item, dict):
            title = str(item.get("title") or "").strip()
            assignee = str(item.get("assignee") or "").strip()
        if not title:
            continue
        out.append({"title": title[:_MAX_TITLE_LEN], "assignee": assignee[:128]})
        if len(out) >= _MAX_TASKS:
            break
    return out


def _parse_template(path: Path) -> Optional[dict]:
    """Parse + validate a single template file (``None`` on any problem)."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        logger.warning("investigation template unreadable: %s (%s)", path, e)
        return None
    if not isinstance(raw, dict):
        logger.warning("investigation template is not a mapping: %s", path)
        return None

    template_id = str(raw.get("id") or path.stem).strip()
    if not template_id:
        return None
    severity = str(raw.get("severity") or "medium").strip().lower()
    if severity not in _VALID_SEVERITIES:
        severity = "medium"
    return {
        "id": template_id,
        "name": str(raw.get("name") or template_id).strip()[:_MAX_NAME_LEN],
        "description": str(raw.get("description") or "").strip()[:_MAX_DESC_LEN],
        "severity": severity,
        "summary": str(raw.get("summary") or "").strip()[:_MAX_SUMMARY_LEN],
        "tags": _coerce_tags(raw.get("tags")),
        "tasks": _coerce_tasks(raw.get("tasks")),
    }


def _load_all() -> dict[str, dict]:
    """Load every template under the templates dir, keyed by id (defensive)."""
    result: dict[str, dict] = {}
    if not TEMPLATES_DIR.is_dir():
        return result
    for path in sorted(TEMPLATES_DIR.glob("*.y*ml")):
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        key = str(path)
        cached = _cache.get(key)
        if cached is not None and cached[0] == mtime:
            template = cached[1]
        else:
            parsed = _parse_template(path)
            if parsed is None:
                _cache.pop(key, None)
                continue
            _cache[key] = (mtime, parsed)
            template = parsed
        # Last id wins on a collision; sorted() makes that deterministic.
        result[template["id"]] = template
    return result


def list_templates() -> list[dict]:
    """Return all available case templates (sorted by name)."""
    templates = list(_load_all().values())
    templates.sort(key=lambda t: (t.get("name") or "").lower())
    return templates


def get_template(template_id: str) -> Optional[dict]:
    """Return a single template by id, or ``None`` if unknown."""
    if not template_id:
        return None
    return _load_all().get(template_id.strip())
