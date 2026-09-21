"""
CrewAI Integration — Wraps CrewAI tools and task outputs with Bulwark scanning.

Provides a non-intrusive way to add security guardrails to CrewAI crews.
Does NOT import crewai at module level. Tool endpoints are duck-typed; payloads
follow docs/ADAPTER-CONTRACTS.md. Tests use doubles, not vendor-version checks.

Two integration styles are supported:

1. Tool wrapping (scan tool input + output)::

       from src.sdk import Guard
       from src.sdk.integrations import CrewAIGuard

       guard = Guard(scanners=["regex_injection", "output_redaction"])
       await guard.startup()

       crew_guard = CrewAIGuard(guard=guard)
       safe_tool = crew_guard.wrap_tool(my_tool)

2. Task output guardrail (CrewAI ``Task(guardrail=...)`` callback)::

       task = Task(..., guardrail=crew_guard.task_guardrail)
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from src.sdk.guard import Guard, SecurityError
from src.sdk.integrations._structured import StructuredValue, scan_structure

logger = logging.getLogger(__name__)


class CrewAIGuard:
    """Wraps CrewAI tools and task outputs with Bulwark scanning.

    Args:
        guard: An initialized :class:`Guard` instance. If None, a new Guard
            is created with default scanners.
        config: Configuration overrides used only when creating a new Guard.
        tenant_id: Tenant identifier for policy isolation.
        agent_id: Agent identifier for RBAC enforcement.
    """

    def __init__(
        self,
        guard: Guard | None = None,
        config: dict[str, Any] | None = None,
        tenant_id: str = "default",
        agent_id: str = "default",
    ) -> None:
        if guard is not None:
            self._guard = guard
            self._owns_guard = False
        else:
            self._guard = Guard(config=config)
            self._owns_guard = True
        self._tenant_id = tenant_id
        self._agent_id = agent_id

    @property
    def guard(self) -> Guard:
        """Access the underlying Guard instance."""
        return self._guard

    # === Tool wrapping ===

    def wrap_tool(self, tool: Any) -> Any:
        """Wrap a CrewAI tool so its inputs and outputs are scanned.

        Intercepts the tool's ``run`` (and ``_run`` if present) method:
        all supported nested inputs are scanned as input guardrails, and the tool's
        result is scanned as output before being returned to the agent.

        Fully duck-typed: only requires the tool to expose a callable
        ``run`` or ``_run``. Does not import ``crewai``.

        Args:
            tool: A CrewAI ``BaseTool`` (or compatible object).

        Returns:
            The same tool, with scanning installed on its run method(s).

        Raises:
            TypeError: If the object has no ``run``/``_run`` method.
        """
        run_attrs = [name for name in ("run", "_run") if callable(getattr(tool, name, None))]
        if not run_attrs:
            raise TypeError(
                "CrewAIGuard.wrap_tool requires an object with a callable "
                "'run' or '_run' method (e.g. crewai.tools.BaseTool)."
            )

        if getattr(tool, "_bulwark_wrapped", False):
            logger.debug("crewai_tool_already_wrapped")
            return tool

        for run_attr in run_attrs:
            setattr(tool, run_attr, self.guard_tool(getattr(tool, run_attr)))
        tool._bulwark_wrapped = True  # type: ignore[attr-defined]
        return tool

    def guard_tool(self, func: Callable[..., Any]) -> Callable[..., Any]:
        """Decorator that scans inputs/outputs of a plain tool function.

        Example::

            @crew_guard.guard_tool
            def search(query: str) -> str:
                return do_search(query)
        """
        import functools

        guard_self = self

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            args, kwargs = scan_structure(
                (args, kwargs), guard_self._guard.scan_input_sync, tenant_id=self._tenant_id, agent_id=self._agent_id
            )
            result = func(*args, **kwargs)
            return guard_self._scan_output(result)

        return wrapper

    # === Task output guardrail ===

    def task_guardrail(self, output: Any) -> tuple[bool, Any]:
        """CrewAI-compatible task guardrail callback.

        CrewAI calls ``guardrail(output)`` and expects a
        ``(success, data)`` tuple: on success ``(True, output)``, on
        failure ``(False, error_message)``. This scans the task output
        with the output filter and fails the task if it is blocked,
        returning redacted content when required.

        Args:
            output: Eager data or a supported passive record; opaque objects fail closed.

        Returns:
            ``(True, output)`` if allowed/redacted, ``(False, reason)`` if blocked.
        """
        try:
            return True, self._scan_output(output)
        except Exception:
            logger.warning("crewai_task_guardrail_error")
            return False, "Bulwark could not inspect task output"

    # === Internal scan helpers ===

    def _scan_input(self, text: str) -> None:
        scan_structure(text, self._guard.scan_input_sync, tenant_id=self._tenant_id, agent_id=self._agent_id)

    def _scan_output(self, result_value: Any) -> Any:
        return scan_structure(
            result_value, self._guard.scan_output_sync, output=True, tenant_id=self._tenant_id, agent_id=self._agent_id
        )


# === Internal helpers ===


def _iter_str_values(args: tuple[Any, ...], kwargs: dict[str, Any]):
    """Yield scannable string values from tool call arguments."""
    yield from StructuredValue((args, kwargs)).texts


def _extract_task_text(output: Any) -> str | None:
    """Extract text from a CrewAI tool result / TaskOutput."""
    return StructuredValue(output, output=True).text or None


def _replace_task_text(output: Any, new_content: str) -> Any:
    """Replace text content in a CrewAI tool result / TaskOutput."""
    if type(output) is str:
        return new_content
    raise SecurityError("Structured redaction requires per-field inspection")
