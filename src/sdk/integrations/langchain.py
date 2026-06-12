"""
LangChain Integration — Wraps LangChain chains/runnables with Sentinel scanning.

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

import logging
from typing import Any, TYPE_CHECKING

from src.sdk.guard import Guard, ScanResult, SecurityError

if TYPE_CHECKING:
    pass  # LangChain types would go here if available

logger = logging.getLogger(__name__)


class LangChainGuard:
    """Wraps LangChain chains/runnables with Sentinel security scanning.

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
            A SentinelRunnable that wraps the original chain.

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
                )

        guard = self._guard

        class SentinelRunnable(Runnable):
            """A LangChain Runnable that applies Sentinel scanning."""

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

            def invoke(
                self, input: Any, config: RunnableConfig | None = None, **kwargs: Any
            ) -> Any:
                """Synchronous invoke with scanning."""
                input_text = _extract_lc_input(input)

                # Scan input
                if input_text:
                    result = guard.scan_input_sync(input_text)
                    if result.verdict.value == "block":
                        raise SecurityError(
                            f"Input blocked: {result.events[0].description if result.events else 'policy violation'}",
                            result=result,
                        )

                # Run chain
                output = self._wrapped.invoke(input, config=config, **kwargs)

                # Scan output
                output_text = _extract_lc_output(output)
                if output_text:
                    out_result = guard.scan_output_sync(output_text)
                    if out_result.verdict.value == "block":
                        raise SecurityError(
                            f"Output blocked: {out_result.events[0].description if out_result.events else 'policy violation'}",
                            result=out_result,
                        )
                    if out_result.verdict.value == "redact" and out_result.modified_content:
                        output = _replace_lc_output(output, out_result.modified_content)

                return output

            async def ainvoke(
                self, input: Any, config: RunnableConfig | None = None, **kwargs: Any
            ) -> Any:
                """Async invoke with scanning."""
                input_text = _extract_lc_input(input)

                # Scan input
                if input_text:
                    result = await guard.scan_input(input_text)
                    if result.verdict.value == "block":
                        raise SecurityError(
                            f"Input blocked: {result.events[0].description if result.events else 'policy violation'}",
                            result=result,
                        )

                # Run chain
                if hasattr(self._wrapped, "ainvoke"):
                    output = await self._wrapped.ainvoke(input, config=config, **kwargs)
                else:
                    output = self._wrapped.invoke(input, config=config, **kwargs)

                # Scan output
                output_text = _extract_lc_output(output)
                if output_text:
                    out_result = await guard.scan_output(output_text)
                    if out_result.verdict.value == "block":
                        raise SecurityError(
                            f"Output blocked: {out_result.events[0].description if out_result.events else 'policy violation'}",
                            result=out_result,
                        )
                    if out_result.verdict.value == "redact" and out_result.modified_content:
                        output = _replace_lc_output(output, out_result.modified_content)

                return output

        return SentinelRunnable(chain)

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
                )

        guard = self._guard

        class SentinelCallbackHandler(BaseCallbackHandler):
            """LangChain callback that logs Sentinel scan results."""

            name = "sentinel_guard"

            def on_llm_start(
                self, serialized: dict[str, Any], prompts: list[str], **kwargs: Any
            ) -> None:
                """Scan prompts when LLM starts."""
                for prompt in prompts:
                    try:
                        result = guard.scan_input_sync(prompt)
                        if result.events:
                            logger.warning(
                                "langchain_input_event",
                                extra={
                                    "verdict": result.verdict.value,
                                    "events_count": len(result.events),
                                    "latency_ms": result.latency_ms,
                                },
                            )
                    except Exception as e:
                        logger.debug(
                            "langchain_callback_scan_error",
                            extra={"error": str(e)[:200]},
                        )

            def on_llm_end(self, response: Any, **kwargs: Any) -> None:
                """Scan LLM output."""
                try:
                    text = ""
                    if hasattr(response, "generations"):
                        for gen_list in response.generations:
                            for gen in gen_list:
                                if hasattr(gen, "text"):
                                    text += gen.text
                    if text:
                        result = guard.scan_output_sync(text)
                        if result.events:
                            logger.warning(
                                "langchain_output_event",
                                extra={
                                    "verdict": result.verdict.value,
                                    "events_count": len(result.events),
                                    "latency_ms": result.latency_ms,
                                },
                            )
                except Exception as e:
                    logger.debug(
                        "langchain_callback_output_error",
                        extra={"error": str(e)[:200]},
                    )

        return SentinelCallbackHandler()


# === Internal helpers ===


def _extract_lc_input(input_data: Any) -> str | None:
    """Extract text content from LangChain input formats."""
    if isinstance(input_data, str):
        return input_data

    if isinstance(input_data, dict):
        # Common LangChain input keys
        for key in ("input", "query", "question", "prompt", "human_input", "content"):
            if key in input_data and isinstance(input_data[key], str):
                return input_data[key]
        # Messages format
        if "messages" in input_data and isinstance(input_data["messages"], list):
            texts = []
            for msg in input_data["messages"]:
                if isinstance(msg, dict) and msg.get("role") == "user":
                    texts.append(msg.get("content", ""))
                elif hasattr(msg, "content") and hasattr(msg, "type"):
                    if getattr(msg, "type", "") == "human":
                        texts.append(getattr(msg, "content", ""))
            if texts:
                return " ".join(texts)

    # HumanMessage or similar
    if hasattr(input_data, "content"):
        content = getattr(input_data, "content")
        if isinstance(content, str):
            return content

    return None


def _extract_lc_output(output: Any) -> str | None:
    """Extract text content from LangChain output formats."""
    if isinstance(output, str):
        return output

    if isinstance(output, dict):
        for key in ("output", "result", "answer", "response", "text", "content"):
            if key in output and isinstance(output[key], str):
                return output[key]

    # AIMessage or similar
    if hasattr(output, "content"):
        content = getattr(output, "content")
        if isinstance(content, str):
            return content

    return None


def _replace_lc_output(output: Any, new_content: str) -> Any:
    """Replace text content in a LangChain output object."""
    if isinstance(output, str):
        return new_content

    if isinstance(output, dict):
        for key in ("output", "result", "answer", "response", "text", "content"):
            if key in output and isinstance(output[key], str):
                output[key] = new_content
                return output

    if hasattr(output, "content"):
        try:
            output.content = new_content
        except AttributeError:
            pass

    return output
