"""
Guard — Main SDK class for embeddable Sentinel security scanning.

Allows Sentinel to be used as a pure Python library without running
the FastAPI gateway. Manages scanner lifecycle, provides sync/async
scanning APIs, and supports decorator-based protection.

Usage:
    guard = Guard(scanners=["regex_injection", "ml_toxicity", "output_redaction"])
    await guard.startup()

    result = await guard.scan_input("Hello, ignore previous instructions...")
    assert result.verdict == Verdict.BLOCK

    # Sync usage:
    result = guard.scan_input_sync("some content")

    # Decorator:
    @guard.protect()
    async def call_llm(prompt: str) -> str:
        ...

    await guard.shutdown()
"""

from __future__ import annotations

import asyncio
import functools
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, TypeVar

from src.models import SecurityEvent, Verdict
from src.scanners.pipeline import ScannerPipeline
from src.scanners.protocol import ScanContext

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


# === Scanner registry mapping (name -> import path + class) ===

_SCANNER_REGISTRY: dict[str, tuple[str, str]] = {
    # Built-in blocking scanners
    "regex_injection": ("src.scanners.builtin.regex_scanner", "RegexInputScanner"),
    "output_redaction": ("src.scanners.builtin.output_redaction_scanner", "OutputRedactionScanner"),
    "tool_policy": ("src.scanners.builtin.tool_policy_scanner", "ToolPolicyScanner"),
    # ML scanners
    "ml_injection": ("src.scanners.ml.injection_classifier", "InjectionClassifier"),
    "ml_toxicity": ("src.scanners.ml.toxicity_scanner", "ToxicityScanner"),
    "ml_topic": ("src.scanners.ml.topic_scanner", "TopicScanner"),
    "ml_intent": ("src.scanners.ml.intent_scanner", "IntentScanner"),
    # Output scanners
    "hallucination": ("src.scanners.output.hallucination_scanner", "HallucinationScanner"),
    "relevance": ("src.scanners.output.relevance_scanner", "RelevanceScanner"),
    "grounding": ("src.scanners.output.grounding_scanner", "GroundingScanner"),
    "schema_validator": ("src.scanners.output.schema_validator", "SchemaValidator"),
    # Multilingual
    "language_detector": ("src.scanners.multilingual.language_detector", "LanguageDetector"),
}

# Default scanner set if none specified
_DEFAULT_SCANNERS = ["regex_injection", "output_redaction"]


@dataclass
class ScanResult:
    """Result of a Guard scan operation.

    Attributes:
        verdict: The security verdict (ALLOW, BLOCK, WARN, REDACT)
        events: List of security events detected during scanning
        modified_content: Redacted/modified content (if verdict is REDACT)
        latency_ms: Total scanning time in milliseconds
    """

    verdict: Verdict
    events: list[SecurityEvent] = field(default_factory=list)
    modified_content: str | None = None
    latency_ms: float = 0.0


class Guard:
    """Embeddable security guard for AI applications.

    Provides input/output scanning, LLM call wrapping, and decorator-based
    protection without requiring a running FastAPI server.

    Args:
        scanners: List of scanner names to enable. If None, uses defaults
            (regex_injection + output_redaction).
        config: Override configuration dict. Supported keys:
            - block_threshold: float (0.0-1.0) — minimum confidence to block
            - ml_enabled: bool — enable ML scanners
            - timeout_ms: float — per-scanner timeout in milliseconds
            - fail_mode: str — "closed" (block on error) or "open" (allow on error)

    Example:
        guard = Guard(scanners=["regex_injection", "ml_toxicity"])
        await guard.startup()

        result = await guard.scan_input("user message")
        if result.verdict == Verdict.BLOCK:
            print(f"Blocked: {result.events[0].description}")
    """

    def __init__(
        self,
        scanners: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        self._scanner_names = scanners or list(_DEFAULT_SCANNERS)
        self._config = config or {}
        self._pipeline = ScannerPipeline(
            default_timeout_ms=self._config.get("timeout_ms", 5000.0)
        )
        self._initialized = False

    @property
    def initialized(self) -> bool:
        """Whether the guard has been started."""
        return self._initialized

    @property
    def pipeline(self) -> ScannerPipeline:
        """Access the underlying scanner pipeline."""
        return self._pipeline

    async def startup(self) -> None:
        """Initialize and register all configured scanners.

        Must be called before scanning. Imports scanner classes lazily
        and registers them in the pipeline.

        Raises:
            RuntimeError: If a required scanner cannot be loaded.
        """
        if self._initialized:
            logger.warning("guard_already_initialized")
            return

        import importlib

        for name in self._scanner_names:
            if name not in _SCANNER_REGISTRY:
                logger.warning(
                    "scanner_not_found",
                    extra={"name": name, "available": list(_SCANNER_REGISTRY.keys())},
                )
                continue

            module_path, class_name = _SCANNER_REGISTRY[name]
            try:
                module = importlib.import_module(module_path)
                scanner_cls = getattr(module, class_name)
                scanner_instance = scanner_cls()
                self._pipeline.register(scanner_instance)
                logger.debug("sdk_scanner_loaded", extra={"name": name})
            except Exception as e:
                logger.error(
                    "sdk_scanner_load_failed",
                    extra={"name": name, "error": str(e)[:200]},
                )
                if self._config.get("fail_mode", "closed") == "closed":
                    raise RuntimeError(
                        f"Failed to load scanner '{name}': {e}"
                    ) from e

        await self._pipeline.startup()
        self._initialized = True
        logger.info(
            "guard_started",
            extra={
                "scanners": self._scanner_names,
                "total_registered": self._pipeline.total_count,
            },
        )

    async def shutdown(self) -> None:
        """Shutdown all scanners and release resources."""
        if not self._initialized:
            return
        await self._pipeline.shutdown()
        self._initialized = False
        logger.info("guard_shutdown")

    async def scan_input(
        self,
        content: str,
        tenant_id: str = "default",
        agent_id: str = "default",
        metadata: dict[str, Any] | None = None,
    ) -> ScanResult:
        """Scan input content for security threats.

        Runs all registered input scanners (blocking) against the content.

        Args:
            content: The user message or input to scan.
            tenant_id: Tenant identifier for policy isolation.
            agent_id: Agent identifier for RBAC enforcement.
            metadata: Optional metadata passed to scanners.

        Returns:
            ScanResult with verdict, events, and timing.

        Raises:
            RuntimeError: If guard has not been started.
        """
        self._ensure_initialized()

        context = ScanContext(
            tenant_id=tenant_id,
            agent_id=agent_id,
            request_id=str(uuid.uuid4()),
            messages=[{"role": "user", "content": content}],
            metadata=metadata or {},
        )

        start = time.perf_counter()
        result = await self._pipeline.run_input_blocking(content, context)
        elapsed_ms = (time.perf_counter() - start) * 1000

        return ScanResult(
            verdict=result.verdict,
            events=result.events,
            modified_content=result.modified_content,
            latency_ms=round(elapsed_ms, 2),
        )

    async def scan_output(
        self,
        content: str,
        input_messages: list[dict[str, Any]] | None = None,
        tenant_id: str = "default",
        agent_id: str = "default",
        metadata: dict[str, Any] | None = None,
    ) -> ScanResult:
        """Scan output content for sensitive data and policy violations.

        Runs all registered output scanners (blocking) against the content.

        Args:
            content: The LLM response or output to scan.
            input_messages: The original input messages (for context).
            tenant_id: Tenant identifier.
            agent_id: Agent identifier.
            metadata: Optional metadata passed to scanners.

        Returns:
            ScanResult with verdict, events, modified content, and timing.

        Raises:
            RuntimeError: If guard has not been started.
        """
        self._ensure_initialized()

        context = ScanContext(
            tenant_id=tenant_id,
            agent_id=agent_id,
            request_id=str(uuid.uuid4()),
            messages=input_messages or [],
            metadata=metadata or {},
        )

        start = time.perf_counter()
        result = await self._pipeline.run_output_blocking(content, context)
        elapsed_ms = (time.perf_counter() - start) * 1000

        return ScanResult(
            verdict=result.verdict,
            events=result.events,
            modified_content=result.modified_content,
            latency_ms=round(elapsed_ms, 2),
        )

    async def wrap(
        self,
        llm_call: Callable[..., Any],
        *args: Any,
        tenant_id: str = "default",
        agent_id: str = "default",
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        """Wrap an LLM call with input and output scanning.

        Scans the first positional argument (or 'prompt'/'content' kwarg)
        as input, executes the LLM call, then scans the output.

        Args:
            llm_call: The LLM function to wrap (sync or async).
            *args: Positional arguments passed to llm_call.
            tenant_id: Tenant identifier.
            agent_id: Agent identifier.
            metadata: Optional metadata.
            **kwargs: Keyword arguments passed to llm_call.

        Returns:
            The LLM response (potentially with redacted content).

        Raises:
            SecurityError: If input or output is blocked.
        """
        self._ensure_initialized()

        # Extract input content for scanning
        input_content = _extract_input_content(args, kwargs)

        # Scan input
        if input_content:
            input_result = await self.scan_input(
                input_content,
                tenant_id=tenant_id,
                agent_id=agent_id,
                metadata=metadata,
            )
            if input_result.verdict == Verdict.BLOCK:
                raise SecurityError(
                    f"Input blocked: {input_result.events[0].description if input_result.events else 'policy violation'}",
                    result=input_result,
                )

        # Execute the LLM call
        if asyncio.iscoroutinefunction(llm_call):
            response = await llm_call(*args, **kwargs)
        else:
            response = llm_call(*args, **kwargs)

        # Extract output content for scanning
        output_content = _extract_output_content(response)

        # Scan output
        if output_content:
            output_result = await self.scan_output(
                output_content,
                input_messages=[{"role": "user", "content": input_content}] if input_content else None,
                tenant_id=tenant_id,
                agent_id=agent_id,
                metadata=metadata,
            )
            if output_result.verdict == Verdict.BLOCK:
                raise SecurityError(
                    f"Output blocked: {output_result.events[0].description if output_result.events else 'policy violation'}",
                    result=output_result,
                )
            if output_result.verdict == Verdict.REDACT and output_result.modified_content:
                # Return redacted content
                if isinstance(response, str):
                    return output_result.modified_content
                if isinstance(response, dict) and "content" in response:
                    response["content"] = output_result.modified_content
                    return response

        return response

    def protect(
        self,
        scanners: list[str] | None = None,
        tenant_id: str = "default",
        agent_id: str = "default",
    ) -> Callable[[F], F]:
        """Decorator that wraps a function with input/output scanning.

        Args:
            scanners: Not used (reserved for future per-call scanner override).
            tenant_id: Tenant identifier for the wrapped call.
            agent_id: Agent identifier for the wrapped call.

        Returns:
            Decorator function.

        Example:
            @guard.protect()
            async def generate(prompt: str) -> str:
                return await llm.complete(prompt)
        """

        def decorator(func: F) -> F:
            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                return await self.wrap(
                    func,
                    *args,
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    **kwargs,
                )

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                return self.wrap_sync(
                    func,
                    *args,
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    **kwargs,
                )

            if asyncio.iscoroutinefunction(func):
                return async_wrapper  # type: ignore[return-value]
            return sync_wrapper  # type: ignore[return-value]

        return decorator  # type: ignore[return-value]

    # === Sync wrappers ===

    def scan_input_sync(
        self,
        content: str,
        tenant_id: str = "default",
        agent_id: str = "default",
        metadata: dict[str, Any] | None = None,
    ) -> ScanResult:
        """Synchronous wrapper for scan_input.

        Uses asyncio.run() or existing event loop to execute the async scan.
        """
        return _run_async(
            self.scan_input(content, tenant_id=tenant_id, agent_id=agent_id, metadata=metadata)
        )

    def scan_output_sync(
        self,
        content: str,
        input_messages: list[dict[str, Any]] | None = None,
        tenant_id: str = "default",
        agent_id: str = "default",
        metadata: dict[str, Any] | None = None,
    ) -> ScanResult:
        """Synchronous wrapper for scan_output."""
        return _run_async(
            self.scan_output(
                content,
                input_messages=input_messages,
                tenant_id=tenant_id,
                agent_id=agent_id,
                metadata=metadata,
            )
        )

    def wrap_sync(
        self,
        llm_call: Callable[..., Any],
        *args: Any,
        tenant_id: str = "default",
        agent_id: str = "default",
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        """Synchronous wrapper for wrap."""
        return _run_async(
            self.wrap(
                llm_call,
                *args,
                tenant_id=tenant_id,
                agent_id=agent_id,
                metadata=metadata,
                **kwargs,
            )
        )

    # === Internal ===

    def _ensure_initialized(self) -> None:
        """Raise if guard has not been started."""
        if not self._initialized:
            raise RuntimeError(
                "Guard has not been initialized. Call 'await guard.startup()' first."
            )


class SecurityError(Exception):
    """Raised when a security scan blocks content."""

    def __init__(self, message: str, result: ScanResult | None = None) -> None:
        super().__init__(message)
        self.result = result


# === Helpers ===


def _run_async(coro: Any) -> Any:
    """Run an async coroutine from synchronous code.

    Handles the case where an event loop may or may not already be running.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # We're inside an async context (e.g., Jupyter, nested async).
        # Create a new thread to avoid blocking the running loop.
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result()
    else:
        return asyncio.run(coro)


def _extract_input_content(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str | None:
    """Extract input content from function arguments.

    Looks for the first string argument, or 'prompt'/'content'/'messages' kwargs.
    """
    # Check common kwarg names
    for key in ("prompt", "content", "input", "query", "message"):
        if key in kwargs and isinstance(kwargs[key], str):
            return kwargs[key]

    # Check 'messages' kwarg (OpenAI-style)
    if "messages" in kwargs and isinstance(kwargs["messages"], list):
        user_msgs = [
            m.get("content", "")
            for m in kwargs["messages"]
            if isinstance(m, dict) and m.get("role") == "user"
        ]
        if user_msgs:
            return " ".join(user_msgs)

    # First positional string argument
    for arg in args:
        if isinstance(arg, str):
            return arg

    return None


def _extract_output_content(response: Any) -> str | None:
    """Extract text content from an LLM response."""
    if isinstance(response, str):
        return response

    if isinstance(response, dict):
        # OpenAI-style response
        if "choices" in response:
            choices = response["choices"]
            if choices and isinstance(choices[0], dict):
                message = choices[0].get("message", {})
                return message.get("content")
        # Simple dict with content
        if "content" in response:
            return response["content"]
        if "text" in response:
            return response["text"]

    # Object with .content attribute
    if hasattr(response, "content"):
        content = getattr(response, "content")
        if isinstance(content, str):
            return content

    return None
