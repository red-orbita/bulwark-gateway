"""
LangChain integration for Sentinel Gateway SDK.

Provides a callback handler that scans LLM inputs and outputs for
security threats as part of a LangChain execution pipeline.

Usage:
    from sentinel_sdk import SentinelClient
    from sentinel_sdk.integrations.langchain import SentinelCallbackHandler

    client = SentinelClient(base_url="...", api_key="...")
    handler = SentinelCallbackHandler(client=client)

    chain.invoke(
        {"input": "user question"},
        config={"callbacks": [handler]},
    )
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional, Sequence
from uuid import UUID

from sentinel_sdk.exceptions import SecurityError
from sentinel_sdk.guard import SentinelGuard
from sentinel_sdk.models import ScanResult, Verdict

logger = logging.getLogger(__name__)


def _get_base_callback_class() -> type:
    """Lazily import BaseCallbackHandler from langchain."""
    try:
        from langchain_core.callbacks import BaseCallbackHandler
        return BaseCallbackHandler
    except ImportError:
        try:
            from langchain.callbacks.base import BaseCallbackHandler
            return BaseCallbackHandler
        except ImportError:
            raise ImportError(
                "LangChain integration requires 'langchain-core>=0.2'. "
                "Install with: pip install sentinel-gateway-sdk[langchain]"
            )


class SentinelCallbackHandler:
    """LangChain callback handler that enforces Sentinel security policies.

    Scans LLM prompts on `on_llm_start` and LLM responses on `on_llm_end`.
    Can operate in two modes:

    1. **Remote mode** — Uses a SentinelClient to scan via the gateway API.
    2. **Local mode** — Uses a SentinelGuard for offline regex-based scanning.

    Args:
        client: A SentinelClient instance for remote scanning.
            Mutually exclusive with `guard`.
        guard: A SentinelGuard instance for local scanning.
            Mutually exclusive with `client`. If neither is provided,
            a default SentinelGuard is created.
        block_on_detect: If True (default), raises SecurityError when a
            threat is detected. If False, logs a warning but allows execution.
        scan_output: Whether to scan LLM outputs (default: True).

    Example:
        from sentinel_sdk import SentinelClient
        from sentinel_sdk.integrations.langchain import SentinelCallbackHandler

        client = SentinelClient(base_url="...", api_key="...")
        handler = SentinelCallbackHandler(client=client)

        # Use with any LangChain chain
        chain.invoke({"input": "..."}, config={"callbacks": [handler]})
    """

    def __new__(cls, **kwargs: Any) -> Any:
        """Dynamically inherit from BaseCallbackHandler at instantiation."""
        base = _get_base_callback_class()

        # Create a new class that inherits from both
        combined = type(
            "SentinelCallbackHandler",
            (base,),
            {
                "name": "sentinel_guard",
                "__init__": cls._init_impl,
                "on_llm_start": cls._on_llm_start_impl,
                "on_llm_end": cls._on_llm_end_impl,
                "on_chain_start": cls._on_chain_start_impl,
            },
        )
        instance = object.__new__(combined)
        combined.__init__(instance, **kwargs)
        return instance

    @staticmethod
    def _init_impl(
        self: Any,
        client: Any = None,
        guard: Optional[SentinelGuard] = None,
        block_on_detect: bool = True,
        scan_output: bool = True,
        **kwargs: Any,
    ) -> None:
        """Initialize the callback handler."""
        # Call parent init if it exists
        parent_init = getattr(super(type(self), self), "__init__", None)
        if parent_init:
            parent_init()

        self._client = client
        self._guard = guard or (SentinelGuard() if client is None else None)
        self._block_on_detect = block_on_detect
        self._scan_output = scan_output

    @staticmethod
    def _on_llm_start_impl(
        self: Any,
        serialized: dict[str, Any],
        prompts: list[str],
        **kwargs: Any,
    ) -> None:
        """Scan prompts when the LLM starts processing."""
        for prompt in prompts:
            result = self._scan_content(prompt, direction="input")
            if result and result.is_blocked and self._block_on_detect:
                raise SecurityError(
                    f"Input blocked by Sentinel: {result.reason}",
                    result=result,
                )
            elif result and result.verdict == Verdict.WARN:
                logger.warning(
                    "sentinel_langchain_input_warning",
                    extra={
                        "verdict": result.verdict.value,
                        "events_count": len(result.events),
                        "reason": result.reason,
                    },
                )

    @staticmethod
    def _on_llm_end_impl(self: Any, response: Any, **kwargs: Any) -> None:
        """Scan LLM output when generation completes."""
        if not self._scan_output:
            return

        text = ""
        if hasattr(response, "generations"):
            for gen_list in response.generations:
                for gen in gen_list:
                    if hasattr(gen, "text"):
                        text += gen.text

        if text:
            result = self._scan_content(text, direction="output")
            if result and result.is_blocked and self._block_on_detect:
                raise SecurityError(
                    f"Output blocked by Sentinel: {result.reason}",
                    result=result,
                )
            elif result and result.verdict == Verdict.WARN:
                logger.warning(
                    "sentinel_langchain_output_warning",
                    extra={
                        "verdict": result.verdict.value,
                        "events_count": len(result.events),
                        "reason": result.reason,
                    },
                )

    @staticmethod
    def _on_chain_start_impl(
        self: Any,
        serialized: dict[str, Any],
        inputs: dict[str, Any],
        **kwargs: Any,
    ) -> None:
        """Scan chain inputs for security threats."""
        # Extract text from common input keys
        for key in ("input", "query", "question", "prompt", "human_input"):
            if key in inputs and isinstance(inputs[key], str):
                result = self._scan_content(inputs[key], direction="input")
                if result and result.is_blocked and self._block_on_detect:
                    raise SecurityError(
                        f"Chain input blocked by Sentinel: {result.reason}",
                        result=result,
                    )
                break

    def _scan_content(self: Any, content: str, direction: str = "input") -> Optional[ScanResult]:
        """Scan content using either the client or local guard."""
        try:
            if self._guard:
                return self._guard.scan(content, direction=direction)
            elif self._client:
                # For sync callbacks, we need to run async client in a thread
                import concurrent.futures

                async def _do_scan() -> ScanResult:
                    if direction == "input":
                        return await self._client.scan_input(content)
                    else:
                        return await self._client.scan_output(content)

                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    loop = None

                if loop and loop.is_running():
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        future = pool.submit(asyncio.run, _do_scan())
                        return future.result(timeout=10)
                else:
                    return asyncio.run(_do_scan())
        except SecurityError:
            raise
        except Exception as e:
            # SECURITY (H-17 fix): Non-SecurityError exceptions in scan path
            # are treated as fail-closed. If we can't verify content is safe,
            # we must not silently allow it through.
            logger.warning(
                "sentinel_langchain_scan_error: fail-closed",
                extra={"error": str(e)[:200], "direction": direction},
            )
            raise SecurityError(
                f"Scan failed (fail-closed): {e}",
            ) from e
        return None
