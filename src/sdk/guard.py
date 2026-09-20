"""
Guard — Main SDK class for embeddable Bulwark security scanning.

Allows Bulwark to be used as a pure Python library without running
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
import inspect
import logging
import time
import uuid
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, Callable, TypeVar

from src.models import SecurityEvent, Verdict
from src.scanners.pipeline import ScannerPipeline
from src.scanners.protocol import ScanContext

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])
_MAX_WRAP_SNAPSHOT_BYTES = 1024 * 1024
_MAX_WRAP_SNAPSHOT_NODES = 1024
_MAX_WRAP_SNAPSHOT_DEPTH = 32


# === Scanner registry mapping (name -> import path + class) ===

_SCANNER_REGISTRY: dict[str, tuple[str, str]] = {
    # Built-in blocking scanners
    "regex_injection": ("src.scanners.builtin.regex_scanner", "RegexInputScanner"),
    "output_redaction": ("src.scanners.builtin.output_redaction_scanner", "OutputRedactionScanner"),
    "tool_policy": ("src.scanners.builtin.tool_policy_scanner", "ToolPolicyScanner"),
    # ML scanners
    "ml_injection": ("src.scanners.ml.injection_classifier", "InjectionClassifier"),
    "ml_prompt_guard": ("src.scanners.ml.prompt_guard", "PromptGuard2Classifier"),
    "ml_toxicity": ("src.scanners.ml.toxicity_scanner", "ToxicityScanner"),
    # Output scanners
    "hallucination": ("src.scanners.output.hallucination_scanner", "HallucinationScanner"),
    "relevance": ("src.scanners.output.relevance_scanner", "RelevanceScanner"),
    "grounding": ("src.scanners.output.grounding_scanner", "GroundingScanner"),
    "schema_validator": ("src.scanners.output.schema_validator", "SchemaValidator"),
    # Multilingual
    "language_detector": ("src.scanners.multilingual.language_detector", "LanguageDetector"),
    # MCP tool-definition poisoning
    "mcp_tool_scanner": ("src.scanners.mcp.scanner", "McpToolScanner"),
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

        unknown = [name for name in self._scanner_names if name not in _SCANNER_REGISTRY]
        if unknown and self._config.get("fail_mode", "closed") == "closed":
            raise RuntimeError(f"Unknown scanner: {', '.join(unknown)}")
        for name in self._scanner_names:
            if name not in _SCANNER_REGISTRY:
                logger.warning(
                    "scanner_not_found",
                    extra={"scanner": name, "available": list(_SCANNER_REGISTRY.keys())},
                )
                continue

            module_path, class_name = _SCANNER_REGISTRY[name]
            try:
                module = importlib.import_module(module_path)
                scanner_cls = getattr(module, class_name)
                scanner_instance = scanner_cls()
                self._pipeline.register(scanner_instance)
                logger.debug("sdk_scanner_loaded", extra={"scanner": name})
            except Exception as e:
                logger.error(
                    "sdk_scanner_load_failed",
                    extra={"scanner": name, "error_type": type(e).__name__},
                )
                if self._config.get("fail_mode", "closed") == "closed":
                    raise RuntimeError(
                        f"Failed to load scanner '{name}'"
                    ) from e

        await self._pipeline.startup()
        from src.scanners.pipeline import resolve_blocking_readiness
        degraded = await self._pipeline.unhealthy_blocking_scanners()
        action, message = resolve_blocking_readiness(degraded, self._config.get("fail_mode", "closed"))
        if action == "refuse":
            await self._pipeline.shutdown()
            raise RuntimeError(message)
        if action == "degrade":
            for name in degraded:
                self._pipeline.disable(name)
            logger.error("sdk_scanners_degraded", extra={"scanners": degraded})
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

        Scans one scalar prompt or all text-only message roles, executes the LLM
        call, then scans one supported text response. Ambiguous inputs, tools,
        streaming, multimodal blocks and multiple output choices require a
        dedicated adapter and are rejected, not passed through uninspected.

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

        # Capture before any scan await; never forward caller-owned mutable data.
        args, kwargs = _snapshot_wrap_value((args, kwargs))

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
                _reason = input_result.events[0].description if input_result.events else "policy violation"
                raise SecurityError(
                    f"Input blocked: {_reason}",
                    result=input_result,
                )
            if input_result.verdict == Verdict.REDACT:
                replacement = input_result.modified_content
                if replacement is None:
                    raise SecurityError("Input redaction has no replacement", result=input_result)
                # Match the extraction order; never flatten a conversation back
                # into roles or silently send the original after a REDACT.
                for key in ("prompt", "content", "input", "query", "message"):
                    if isinstance(kwargs.get(key), str):
                        kwargs[key] = replacement
                        break
                else:
                    if isinstance(kwargs.get("messages"), list):
                        raise SecurityError("Conversation redaction requires an explicit adapter", result=input_result)
                    for index, arg in enumerate(args):
                        if isinstance(arg, str):
                            args = (*args[:index], replacement, *args[index + 1:])
                            break
                    else:
                        raise SecurityError("Unsupported input redaction shape", result=input_result)
                input_content = replacement

        # Execute the LLM call
        if inspect.iscoroutinefunction(llm_call) or inspect.iscoroutinefunction(type(llm_call).__call__):
            response = await llm_call(*args, **kwargs)
        else:
            response = await asyncio.to_thread(llm_call, *args, **kwargs)
            if inspect.isawaitable(response):
                response = await response

        # The provider may retain and mutate its response during output scanning.
        response = _snapshot_wrap_value(response)

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
                _reason = output_result.events[0].description if output_result.events else "policy violation"
                raise SecurityError(
                    f"Output blocked: {_reason}",
                    result=output_result,
                )
            if output_result.verdict == Verdict.REDACT:
                if output_result.modified_content is None:
                    raise SecurityError("Output redaction has no replacement", result=output_result)
                # Return redacted content
                if isinstance(response, str):
                    return output_result.modified_content
                if isinstance(response, dict) and "choices" in response:
                    raise SecurityError("Choice redaction requires an explicit adapter", result=output_result)
                if isinstance(response, dict) and "content" in response:
                    return {**response, "content": output_result.modified_content}
                if isinstance(response, dict) and "text" in response:
                    return {**response, "text": output_result.modified_content}
                raise SecurityError("Output redaction requires an explicit adapter", result=output_result)

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

            if inspect.iscoroutinefunction(func) or inspect.iscoroutinefunction(type(func).__call__):
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


def _snapshot_wrap_value(value: Any) -> Any:
    """Detach only bounded passive data, without serializers or copy hooks."""
    from src.sdk.integrations._structured import _record_fields

    nodes = 0
    size = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes, size
        nodes += 1
        if nodes > _MAX_WRAP_SNAPSHOT_NODES or depth > _MAX_WRAP_SNAPSHOT_DEPTH:
            raise SecurityError("Wrapper snapshot limit exceeded")
        kind = type(item)
        if type(kind) is not type:
            raise SecurityError("Custom payload metaclasses are unsupported")
        if kind is str:
            text = _bounded_wrap_text(item, _MAX_WRAP_SNAPSHOT_BYTES)
            size += len(text.encode("utf-8"))
            if size > _MAX_WRAP_SNAPSHOT_BYTES:
                raise SecurityError("Wrapper snapshot byte limit exceeded")
            return text
        if item is None or kind in (bool, int, float):
            if kind is int and item.bit_length() > 256:
                raise SecurityError("Numeric snapshot limit exceeded")
            return item
        identity = id(item)
        if identity in active:
            raise SecurityError("Cyclic payload is unsupported")
        active.add(identity)
        try:
            if kind in (list, tuple):
                if len(item) > _MAX_WRAP_SNAPSHOT_NODES - nodes:
                    raise SecurityError("Wrapper snapshot limit exceeded")
                return kind(visit(child, depth + 1) for child in item)
            # SimpleNamespace has a member descriptor on Python 3.13, unlike
            # ordinary passive records. Exact-type access cannot invoke hooks.
            fields = item if kind is dict else vars(item) if kind is SimpleNamespace else _record_fields(item)
            if len(fields) * 2 > _MAX_WRAP_SNAPSHOT_NODES - nodes:
                raise SecurityError("Wrapper snapshot limit exceeded")
            copied = {}
            for key, child in fields.items():
                if type(key) is not str:
                    raise SecurityError("Only string mapping keys are supported")
                copied[visit(key, depth + 1)] = visit(child, depth + 1)
            if kind is dict:
                return copied
            record = SimpleNamespace() if kind is SimpleNamespace else object.__new__(kind)
            vars(kind)["__dict__"].__get__(record, kind).update(copied)
            return record
        finally:
            active.remove(identity)

    try:
        return visit(value, 0)
    except SecurityError:
        raise
    except Exception:
        raise SecurityError("Unable to capture wrapper snapshot") from None


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
    """Select exactly one supported input; bound text before allocating a join."""
    if kwargs.get("stream") or any(kwargs.get(key) for key in ("tools", "functions", "tool_choice", "function_call")):
        raise SecurityError("Tools and streaming require a dedicated adapter")
    keys = [key for key in ("prompt", "content", "input", "query", "message", "messages") if key in kwargs]
    positional = [arg for arg in args if isinstance(arg, str)]
    if len(keys) + len(positional) != 1 or any(isinstance(arg, (dict, list, tuple)) for arg in args):
        raise SecurityError("Ambiguous or unsupported input shape")
    value = kwargs[keys[0]] if keys else positional[0]
    if not keys or keys[0] != "messages":
        return _bounded_wrap_text(value, 16384)
    if not isinstance(value, list) or not 0 < len(value) <= 128:
        raise SecurityError("Expected 1 to 128 text messages")
    texts: list[str] = []
    size = 0
    for message in value:
        if not isinstance(message, dict) or message.get("role") not in (
            "user", "system", "developer", "assistant", "tool", "function",
        ):
            raise SecurityError("Unsupported message shape")
        if any(message.get(key) for key in ("tool_calls", "function_call")):
            raise SecurityError("Tool history requires a dedicated adapter")
        content = message.get("content")
        if isinstance(content, list):
            if len(content) > 128:
                raise SecurityError("Too many text blocks")
            parts = []
            part_bytes = 0
            for block in content:
                if not isinstance(block, dict) or block.get("type") != "text":
                    raise SecurityError("Non-text input requires a dedicated adapter")
                text = _bounded_wrap_text(block.get("text"), 16384)
                part_bytes += len(text.encode("utf-8")) + 1
                if size + part_bytes - (not texts) > 16384:
                    raise SecurityError("Input exceeds generic wrapper inspection budget")
                parts.append(text)
        else:
            parts = [_bounded_wrap_text(content, 16384)]
        for text in parts:
            size += len(text.encode("utf-8")) + bool(texts)
            if size > 16384:
                raise SecurityError("Input exceeds generic wrapper inspection budget")
            texts.append(text)
    return " ".join(texts)


def _extract_output_content(response: Any) -> str | None:
    """Inspect one known text slot; never silently approve an unknown response."""
    if isinstance(response, str):
        return _bounded_wrap_text(response, 65536)

    if isinstance(response, dict):
        keys = [key for key in ("choices", "content", "text") if key in response]
        if len(keys) != 1 or any(response.get(key) for key in ("tool_calls", "function_call")):
            raise SecurityError("Ambiguous or unsupported output shape")
        if keys[0] == "choices":
            choices = response["choices"]
            if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
                raise SecurityError("Multiple or malformed choices require a dedicated adapter")
            message = choices[0].get("message")
            if (not isinstance(message, dict) or "delta" in choices[0]
                    or any(message.get(key) for key in ("tool_calls", "function_call"))):
                raise SecurityError("Tool or streaming response requires a dedicated adapter")
            return _bounded_wrap_text(message.get("content"), 65536)
        return _bounded_wrap_text(response[keys[0]], 65536)
    if hasattr(response, "content") and not any(
        getattr(response, key, None) for key in ("choices", "tool_calls", "function_call")
    ):
        return _bounded_wrap_text(response.content, 65536)
    raise SecurityError("Unsupported output requires a dedicated adapter")


def _bounded_wrap_text(value: Any, max_bytes: int) -> str:
    if not isinstance(value, str) or len(value) > max_bytes:
        raise SecurityError("Unsupported text or inspection budget exceeded")
    try:
        if len(value.encode("utf-8")) > max_bytes:
            raise SecurityError("Inspection budget exceeded")
    except UnicodeError:
        raise SecurityError("Invalid text encoding") from None
    return value
