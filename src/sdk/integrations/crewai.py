"""
CrewAI Integration — Wraps CrewAI tools and task outputs with Bulwark scanning.

Provides a non-intrusive way to add security guardrails to CrewAI crews.
Does NOT import crewai at module level — the wrappers are fully duck-typed,
so they work with any object exposing ``run`` / ``_run`` and are testable
without the framework installed.

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
        string inputs are scanned as input guardrails, and the tool's
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
        run_attr = None
        for candidate in ("run", "_run"):
            if hasattr(tool, candidate) and callable(getattr(tool, candidate)):
                run_attr = candidate
                break
        if run_attr is None:
            raise TypeError(
                "CrewAIGuard.wrap_tool requires an object with a callable "
                "'run' or '_run' method (e.g. crewai.tools.BaseTool)."
            )

        if getattr(tool, "_bulwark_wrapped", False):
            logger.debug("crewai_tool_already_wrapped")
            return tool

        original_run = getattr(tool, run_attr)
        guard_self = self

        def guarded_run(*args: Any, **kwargs: Any) -> Any:
            # Scan string inputs (positional + kwargs) before execution
            for value in _iter_str_values(args, kwargs):
                guard_self._scan_input(value)  # raises SecurityError on block
            result = original_run(*args, **kwargs)
            return guard_self._scan_output(result)

        setattr(tool, run_attr, guarded_run)
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
            for value in _iter_str_values(args, kwargs):
                guard_self._scan_input(value)
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
            output: The task output (string or object with ``.raw``/``.content``).

        Returns:
            ``(True, output)`` if allowed/redacted, ``(False, reason)`` if blocked.
        """
        text = _extract_task_text(output)
        if not text:
            return True, output
        try:
            result = self._guard.scan_output_sync(
                text, tenant_id=self._tenant_id, agent_id=self._agent_id
            )
        except Exception as e:  # pragma: no cover - defensive
            logger.warning("crewai_task_guardrail_error", extra={"error": str(e)[:200]})
            return True, output
        if result.verdict.value == "block":
            reason = (
                result.events[0].description
                if result.events
                else "output blocked by policy"
            )
            return False, f"Bulwark blocked task output: {reason}"
        if result.verdict.value == "redact" and result.modified_content:
            return True, _replace_task_text(output, result.modified_content)
        return True, output

    # === Internal scan helpers ===

    def _scan_input(self, text: str) -> None:
        result = self._guard.scan_input_sync(
            text, tenant_id=self._tenant_id, agent_id=self._agent_id
        )
        if result.verdict.value == "block":
            raise SecurityError(
                f"Tool input blocked: {result.events[0].description if result.events else 'policy violation'}",
                result=result,
            )

    def _scan_output(self, result_value: Any) -> Any:
        text = _extract_task_text(result_value)
        if not text:
            return result_value
        out = self._guard.scan_output_sync(
            text, tenant_id=self._tenant_id, agent_id=self._agent_id
        )
        if out.verdict.value == "block":
            raise SecurityError(
                f"Tool output blocked: {out.events[0].description if out.events else 'policy violation'}",
                result=out,
            )
        if out.verdict.value == "redact" and out.modified_content:
            return _replace_task_text(result_value, out.modified_content)
        return result_value


# === Internal helpers ===


def _iter_str_values(args: tuple[Any, ...], kwargs: dict[str, Any]):
    """Yield scannable string values from tool call arguments."""
    for arg in args:
        if isinstance(arg, str) and len(arg) > 2:
            yield arg
    for value in kwargs.values():
        if isinstance(value, str) and len(value) > 2:
            yield value


def _extract_task_text(output: Any) -> str | None:
    """Extract text from a CrewAI tool result / TaskOutput."""
    if output is None:
        return None
    if isinstance(output, str):
        return output
    # CrewAI TaskOutput exposes .raw; messages expose .content
    for attr in ("raw", "content", "result", "output"):
        if hasattr(output, attr):
            value = getattr(output, attr)
            if isinstance(value, str):
                return value
    if isinstance(output, dict):
        for key in ("raw", "content", "result", "output", "text"):
            if isinstance(output.get(key), str):
                return output[key]
    return None


def _replace_task_text(output: Any, new_content: str) -> Any:
    """Replace text content in a CrewAI tool result / TaskOutput."""
    if isinstance(output, str):
        return new_content
    for attr in ("raw", "content", "result", "output"):
        if hasattr(output, attr) and isinstance(getattr(output, attr), str):
            try:
                setattr(output, attr, new_content)
                return output
            except AttributeError:
                pass
    if isinstance(output, dict):
        for key in ("raw", "content", "result", "output", "text"):
            if isinstance(output.get(key), str):
                output[key] = new_content
                return output
    return output
