"""Guardrails Persistence Store — Saves guardrail state to disk atomically."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Optional

from .audit_logger import get_audit_logger
from ..models.metrics import AuditQuery

CONFIG_PATH = Path("data/custom_patterns.json")


class GuardrailsStore:
    """Persistence layer for guardrail configuration state."""

    def __init__(self, path: Path = CONFIG_PATH):
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def save_state(self) -> None:
        """Persist current guardrail state atomically."""
        from ..routes.guardrails import _patterns_cache, _module_state, _params

        patterns = _patterns_cache or []
        custom_patterns = [p for p in patterns if "custom" in p.get("id", "")]
        disabled_patterns = [p["id"] for p in patterns if not p.get("enabled", True)]

        state = {
            "custom_patterns": custom_patterns,
            "disabled_patterns": disabled_patterns,
            "module_state": dict(_module_state),
            "params": dict(_params),
        }

        # Atomic write
        dir_path = self._path.parent
        with tempfile.NamedTemporaryFile(mode="w", dir=str(dir_path), suffix=".tmp", delete=False) as tmp:
            json.dump(state, tmp, indent=2)
            tmp_path = Path(tmp.name)
        tmp_path.replace(self._path)

    def load_state(self) -> Optional[dict[str, Any]]:
        """Load persisted state and apply to guardrail engines. Returns state or None."""
        if not self._path.exists():
            return None

        with open(self._path) as f:
            state = json.load(f)

        self._apply_state(state)
        return state

    def _apply_state(self, state: dict[str, Any]) -> None:
        """Apply loaded state to in-memory guardrail structures."""
        from ..routes.guardrails import _load_patterns, _module_state, _params

        # Apply module state
        if "module_state" in state:
            for k, v in state["module_state"].items():
                if k in _module_state:
                    _module_state[k] = v

        # Apply params
        if "params" in state:
            for k, v in state["params"].items():
                if k in _params:
                    _params[k] = v

        # Apply custom patterns and disabled state
        patterns = _load_patterns()

        if "custom_patterns" in state:
            existing_ids = {p["id"] for p in patterns}
            for cp in state["custom_patterns"]:
                if cp["id"] not in existing_ids:
                    patterns.append(cp)

        if "disabled_patterns" in state:
            disabled = set(state["disabled_patterns"])
            for p in patterns:
                if p["id"] in disabled:
                    p["enabled"] = False

    async def get_history(self, limit: int = 50) -> list[dict]:
        """Return guardrail change log from audit logger."""
        audit = get_audit_logger()
        entries = await audit.query(AuditQuery(
            resource_type="pattern",
            limit=limit,
        ))
        # Also get module and param changes
        module_entries = await audit.query(AuditQuery(
            resource_type="guardrail_module",
            limit=limit,
        ))
        param_entries = await audit.query(AuditQuery(
            resource_type="guardrail_params",
            limit=limit,
        ))
        all_entries = entries + module_entries + param_entries
        all_entries.sort(key=lambda e: e.timestamp, reverse=True)
        return [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "actor": e.actor,
                "action": e.action,
                "resource_type": e.resource_type,
                "resource_id": e.resource_id,
                "result": e.result,
                "details": e.details,
            }
            for e in all_entries[:limit]
        ]

    def export_config(self) -> dict[str, Any]:
        """Export full guardrails config as JSON."""
        from ..routes.guardrails import _load_patterns, _module_state, _params

        patterns = _load_patterns()
        return {
            "custom_patterns": [p for p in patterns if "custom" in p.get("id", "")],
            "disabled_patterns": [p["id"] for p in patterns if not p.get("enabled", True)],
            "all_patterns": patterns,
            "module_state": dict(_module_state),
            "params": dict(_params),
        }

    def import_config(self, data: dict[str, Any]) -> None:
        """Import and apply config from JSON."""
        self._apply_state(data)
        self.save_state()


_store: Optional[GuardrailsStore] = None


def get_guardrails_store() -> GuardrailsStore:
    global _store
    if _store is None:
        _store = GuardrailsStore()
    return _store
