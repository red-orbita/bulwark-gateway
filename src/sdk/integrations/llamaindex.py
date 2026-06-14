"""
LlamaIndex Integration — Wraps LlamaIndex query engines with Sentinel scanning.

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

import logging
from typing import Any, TYPE_CHECKING

from src.sdk.guard import Guard, SecurityError

if TYPE_CHECKING:
    pass  # LlamaIndex types would go here if available

logger = logging.getLogger(__name__)


class LlamaIndexGuard:
    """Wraps LlamaIndex query engines with Sentinel security scanning.

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
            A SentinelQueryEngine that wraps the original engine.
        """
        guard = self._guard
        return _SentinelQueryEngine(query_engine, guard)


class _SentinelQueryEngine:
    """Proxy query engine that applies Sentinel scanning.

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
        query_text = _extract_query_text(query)

        # Scan input
        if query_text:
            result = self._guard.scan_input_sync(query_text)
            if result.verdict.value == "block":
                raise SecurityError(
                    f"Query blocked: {result.events[0].description if result.events else 'policy violation'}",
                    result=result,
                )

        # Execute query
        response = self._wrapped.query(query, **kwargs)

        # Scan output
        response_text = _extract_response_text(response)
        if response_text:
            out_result = self._guard.scan_output_sync(response_text)
            if out_result.verdict.value == "block":
                raise SecurityError(
                    f"Response blocked: {out_result.events[0].description if out_result.events else 'policy violation'}",
                    result=out_result,
                )
            if out_result.verdict.value == "redact" and out_result.modified_content:
                response = _replace_response_text(response, out_result.modified_content)

        return response

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
        query_text = _extract_query_text(query)

        # Scan input
        if query_text:
            result = await self._guard.scan_input(query_text)
            if result.verdict.value == "block":
                raise SecurityError(
                    f"Query blocked: {result.events[0].description if result.events else 'policy violation'}",
                    result=result,
                )

        # Execute query
        if hasattr(self._wrapped, "aquery"):
            response = await self._wrapped.aquery(query, **kwargs)
        else:
            response = self._wrapped.query(query, **kwargs)

        # Scan output
        response_text = _extract_response_text(response)
        if response_text:
            out_result = await self._guard.scan_output(response_text)
            if out_result.verdict.value == "block":
                raise SecurityError(
                    f"Response blocked: {out_result.events[0].description if out_result.events else 'policy violation'}",
                    result=out_result,
                )
            if out_result.verdict.value == "redact" and out_result.modified_content:
                response = _replace_response_text(response, out_result.modified_content)

        return response

    def __getattr__(self, name: str) -> Any:
        """Proxy all other attribute access to the wrapped engine."""
        return getattr(self._wrapped, name)


# === Internal helpers ===


def _extract_query_text(query: Any) -> str | None:
    """Extract text from a LlamaIndex query (str or QueryBundle)."""
    if isinstance(query, str):
        return query

    # QueryBundle
    if hasattr(query, "query_str"):
        query_str = getattr(query, "query_str")
        if isinstance(query_str, str):
            return query_str

    # Custom query object with text field
    if hasattr(query, "text"):
        text = getattr(query, "text")
        if isinstance(text, str):
            return text

    return None


def _extract_response_text(response: Any) -> str | None:
    """Extract text from a LlamaIndex Response object."""
    if isinstance(response, str):
        return response

    # Response object with .response attribute
    if hasattr(response, "response"):
        resp = getattr(response, "response")
        if isinstance(resp, str):
            return resp

    # StreamingResponse or object with .get_response()
    if hasattr(response, "get_response"):
        try:
            resp = response.get_response()
            if isinstance(resp, str):
                return resp
        except Exception:
            pass

    # Fallback: str() representation if it has meaningful content
    if hasattr(response, "__str__") and not isinstance(response, type):
        text = str(response)
        # Only use if it looks like actual content, not a repr
        if text and not text.startswith("<") and len(text) > 5:
            return text

    return None


def _replace_response_text(response: Any, new_content: str) -> Any:
    """Replace text content in a LlamaIndex Response object."""
    if isinstance(response, str):
        return new_content

    if hasattr(response, "response"):
        try:
            response.response = new_content
        except AttributeError:
            # Immutable response object — wrap in a simple container
            return _SimpleResponse(new_content, response)

    return response


class _SimpleResponse:
    """Minimal response wrapper when the original is immutable."""

    def __init__(self, response: str, original: Any) -> None:
        self.response = response
        self._original = original

    @property
    def source_nodes(self) -> list[Any]:
        """Proxy source_nodes from original response."""
        if hasattr(self._original, "source_nodes"):
            return self._original.source_nodes
        return []

    @property
    def metadata(self) -> dict[str, Any]:
        """Proxy metadata from original response."""
        if hasattr(self._original, "metadata"):
            return self._original.metadata
        return {}

    def __str__(self) -> str:
        return self.response
