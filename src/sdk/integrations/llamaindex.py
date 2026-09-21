"""
LlamaIndex Integration — Wraps LlamaIndex query engines with Bulwark scanning.

Provides security guardrails for LlamaIndex applications without tight
coupling. All llama_index imports are lazy and handle ImportError gracefully.

Usage:
    from src.sdk import Guard
    from src.sdk.integrations import LlamaIndexGuard

    guard = Guard(scanners=["regex_injection", "output_redaction"])
    await guard.startup()

    li_guard = LlamaIndexGuard(guard=guard)
    safe_engine = li_guard.wrap(my_query_engine)
    response = safe_engine.query("user question")
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from src.sdk.guard import Guard, SecurityError
from src.sdk.integrations._structured import StructuredValue, scan_structure, scan_structure_async

if TYPE_CHECKING:
    pass  # LlamaIndex types would go here if available

logger = logging.getLogger(__name__)


class LlamaIndexGuard:
    """Wraps LlamaIndex query engines with Bulwark security scanning.

    Intercepts queries and responses to apply input guardrails and
    output filters transparently.

    Args:
        guard: An initialized Guard instance. If None, creates one with defaults.
        config: Configuration overrides for the guard (if creating a new one).

    Example:
        li_guard = LlamaIndexGuard(guard=my_guard)
        safe_engine = li_guard.wrap(index.as_query_engine())
        response = safe_engine.query("What is the revenue?")
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

    def wrap(self, query_engine: Any) -> Any:
        """Wrap a LlamaIndex query engine with security scanning.

        Returns a proxy object that scans queries before execution and
        responses before returning to the user.

        Args:
            query_engine: A LlamaIndex BaseQueryEngine or any object with
                query/aquery methods.

        Returns:
            A BulwarkQueryEngine that wraps the original engine.
        """
        guard = self._guard
        return _BulwarkQueryEngine(query_engine, guard)


class _BulwarkQueryEngine:
    """Proxy query engine that applies Bulwark scanning.

    Wraps a LlamaIndex query engine and scans both input queries
    and output responses for security threats.
    """

    def __init__(self, wrapped: Any, guard: Guard) -> None:
        self._wrapped = wrapped
        self._guard = guard

    def query(self, query: Any, **kwargs: Any) -> Any:
        """Synchronous query with security scanning.

        Args:
            query: The query string or QueryBundle.
            **kwargs: Additional arguments passed to the underlying engine.

        Returns:
            The query response (potentially with redacted content).

        Raises:
            SecurityError: If input or output is blocked.
        """
        if query is None:
            raise SecurityError("Explicit query is required")
        query, kwargs = scan_structure((query, kwargs), self._guard.scan_input_sync)
        response = self._wrapped.query(query, **kwargs)
        return scan_structure(response, self._guard.scan_output_sync, output=True)

    async def aquery(self, query: Any, **kwargs: Any) -> Any:
        """Async query with security scanning.

        Args:
            query: The query string or QueryBundle.
            **kwargs: Additional arguments passed to the underlying engine.

        Returns:
            The query response (potentially with redacted content).

        Raises:
            SecurityError: If input or output is blocked.
        """
        if query is None:
            raise SecurityError("Explicit query is required")
        query, kwargs = await scan_structure_async((query, kwargs), self._guard.scan_input)
        if hasattr(self._wrapped, "aquery"):
            response = await self._wrapped.aquery(query, **kwargs)
        else:
            response = await asyncio.to_thread(self._wrapped.query, query, **kwargs)

        return await scan_structure_async(response, self._guard.scan_output, output=True)


# === Internal helpers ===


def _extract_query_text(query: Any) -> str | None:
    """Extract text from a LlamaIndex query (str or QueryBundle)."""
    return StructuredValue(query).text or None


def _extract_response_text(response: Any) -> str | None:
    """Extract text from a LlamaIndex Response object."""
    return StructuredValue(response, output=True).text or None


def _replace_response_text(response: Any, new_content: str) -> Any:
    """Replace text content in a LlamaIndex Response object."""
    if type(response) is str:
        return new_content
    raise SecurityError("Structured redaction requires per-field inspection")
