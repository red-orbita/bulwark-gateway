"""
LangChain Integration — Wraps LangChain chains/runnables with Bulwark scanning.

Provides a non-intrusive way to add security guardrails to LangChain
applications. Does NOT import langchain at module level — all imports
are lazy and handle ImportError gracefully.

Usage:
    from src.sdk import Guard
    from src.sdk.integrations import LangChainGuard

    guard = Guard(scanners=["regex_injection", "output_redaction"])
    await guard.startup()

    lc_guard = LangChainGuard(guard=guard)
    safe_chain = lc_guard.wrap(my_chain)
    result = await safe_chain.ainvoke({"input": "user query"})
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from src.sdk.guard import Guard, SecurityError
from src.sdk.integrations._structured import StructuredValue, scan_structure, scan_structure_async

if TYPE_CHECKING:
    pass  # LangChain types would go here if available

logger = logging.getLogger(__name__)


class LangChainGuard:
    """Wraps LangChain chains/runnables with Bulwark security scanning.

    Intercepts input and output of a LangChain chain to apply
    input guardrails (prompt injection, jailbreak detection) and
    output filters (secret redaction, PII masking).

    Args:
        guard: An initialized Guard instance. If None, creates one with defaults.
        config: Configuration overrides for the guard (if creating a new one).

    Example:
        lc_guard = LangChainGuard(guard=my_guard)
        safe_chain = lc_guard.wrap(my_chain)
        response = await safe_chain.ainvoke({"input": "hello"})
    """

    def __init__(
        self,
        guard: Guard | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        if guard is not None:
            self._guard = guard
            self._owns_guard = False
        else:
            self._guard = Guard(config=config)
            self._owns_guard = True

    @property
    def guard(self) -> Guard:
        """Access the underlying Guard instance."""
        return self._guard

    def wrap(self, chain: Any) -> Any:
        """Wrap a LangChain chain/runnable with security scanning.

        Returns a new Runnable that scans input before and output after
        the chain executes. The wrapped chain supports both .invoke()
        and .ainvoke().

        Args:
            chain: A LangChain Runnable, Chain, or any object with
                invoke/ainvoke methods.

        Returns:
            A BulwarkRunnable that wraps the original chain.

        Raises:
            ImportError: If langchain-core is not installed.
        """
        try:
            from langchain_core.runnables import Runnable, RunnableConfig
        except ImportError:
            try:
                from langchain.schema.runnable import Runnable, RunnableConfig
            except ImportError:
                raise ImportError(
                    "LangChain integration requires 'langchain-core' or 'langchain'. "
                    "Install with: pip install langchain-core"
                ) from None

        guard = self._guard

        class BulwarkRunnable(Runnable):
            """A LangChain Runnable that applies Bulwark scanning."""

            def __init__(self, wrapped: Any) -> None:
                self._wrapped = wrapped

            @property
            def InputType(self) -> type:
                if hasattr(self._wrapped, "InputType"):
                    return self._wrapped.InputType
                return Any  # type: ignore[return-value]

            @property
            def OutputType(self) -> type:
                if hasattr(self._wrapped, "OutputType"):
                    return self._wrapped.OutputType
                return Any  # type: ignore[return-value]

            def invoke(self, input: Any, config: RunnableConfig | None = None, **kwargs: Any) -> Any:
                """Synchronous invoke with scanning."""
                if input is None:
                    raise SecurityError("Explicit input is required")
                input, kwargs = scan_structure((input, kwargs), guard.scan_input_sync)
                output = self._wrapped.invoke(input, config=config, **kwargs)
                return scan_structure(output, guard.scan_output_sync, output=True)

            async def ainvoke(self, input: Any, config: RunnableConfig | None = None, **kwargs: Any) -> Any:
                """Async invoke with scanning."""
                if input is None:
                    raise SecurityError("Explicit input is required")
                input, kwargs = await scan_structure_async((input, kwargs), guard.scan_input)
                if hasattr(self._wrapped, "ainvoke"):
                    output = await self._wrapped.ainvoke(input, config=config, **kwargs)
                else:
                    output = await asyncio.to_thread(self._wrapped.invoke, input, config=config, **kwargs)

                return await scan_structure_async(output, guard.scan_output, output=True)

        return BulwarkRunnable(chain)

    def as_callback(self) -> Any:
        """Return a LangChain callback handler for monitoring.

        The callback handler logs security events but does NOT block
        execution (fire-and-forget scanning for observability).

        Returns:
            A LangChain BaseCallbackHandler instance.

        Raises:
            ImportError: If langchain-core is not installed.
        """
        try:
            from langchain_core.callbacks import BaseCallbackHandler
        except ImportError:
            try:
                from langchain.callbacks.base import BaseCallbackHandler
            except ImportError:
                raise ImportError(
                    "LangChain integration requires 'langchain-core' or 'langchain'. "
                    "Install with: pip install langchain-core"
                ) from None

        guard = self._guard

        class BulwarkCallbackHandler(BaseCallbackHandler):
            """LangChain callback that logs Bulwark scan results."""

            name = "bulwark_guard"

            def on_llm_start(self, serialized: dict[str, Any], prompts: list[str], **kwargs: Any) -> None:
                """Scan prompts when LLM starts."""
                try:
                    tree = StructuredValue(prompts)
                    if tree.texts:
                        result = guard.scan_input_sync(tree.text)
                        if result.events or result.verdict.value in ("block", "redact"):
                            logger.warning("langchain_callback_input_event")
                except Exception:
                    logger.warning("langchain_callback_input_rejected")

            def on_llm_end(self, response: Any, **kwargs: Any) -> None:
                """Scan LLM output."""
                try:
                    tree = StructuredValue(response, output=True)
                    if tree.texts:
                        result = guard.scan_output_sync(tree.text)
                        if result.events or result.verdict.value in ("block", "redact"):
                            logger.warning("langchain_callback_output_event")
                except Exception:
                    logger.warning("langchain_callback_output_rejected")

        return BulwarkCallbackHandler()


# === Internal helpers ===


def _extract_lc_input(input_data: Any) -> str | None:
    """Extract text content from LangChain input formats."""
    return StructuredValue(input_data).text or None


def _extract_lc_output(output: Any) -> str | None:
    """Extract text content from LangChain output formats."""
    return StructuredValue(output, output=True).text or None


def _replace_lc_output(output: Any, new_content: str) -> Any:
    """Replace text content in a LangChain output object."""
    if type(output) is str:
        return new_content
    raise SecurityError("Structured redaction requires per-field inspection")
