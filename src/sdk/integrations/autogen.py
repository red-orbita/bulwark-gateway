"""
AutoGen Integration — Wraps AutoGen agents with Bulwark security scanning.

Provides a non-intrusive way to add security guardrails to AutoGen
(and ag2) multi-agent conversations. Does NOT import autogen at module
level. Agent endpoints are duck-typed; message data follows the bounded eager
contracts in docs/ADAPTER-CONTRACTS.md. Tests use doubles without the framework.

Two integration styles are supported:

1. Agent wrapping (intercepts inbound messages + outbound replies)::

       from src.sdk import Guard
       from src.sdk.integrations import AutoGenGuard

       guard = Guard(scanners=["regex_injection", "output_redaction"])
       await guard.startup()

       ag_guard = AutoGenGuard(guard=guard)
       ag_guard.wrap_agent(assistant)   # patches generate_reply in place

2. Explicit message scanning (for custom conversation loops)::

       safe_text = ag_guard.scan_message("ignore previous instructions ...")
       # raises SecurityError if the message is blocked
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from src.sdk.guard import Guard, SecurityError
from src.sdk.integrations._structured import (
    StructuredValue,
    checked_text,
    scan_structure,
    scan_structure_async,
)

logger = logging.getLogger(__name__)


class AutoGenGuard:
    """Wraps AutoGen agents with Bulwark input/output scanning.

    Args:
        guard: An initialized :class:`Guard` instance. If None, a new
            Guard is created with default scanners.
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

    # === Explicit scanning ===

    def scan_message(self, message: Any) -> str | None:
        """Scan a single conversation message (input side).

        Args:
            message: A string, an OpenAI-style ``{"content": ...}`` dict, or
                a supported passive record (see ADAPTER-CONTRACTS.md).

        Returns:
            Scalar text (possibly redacted), or selected text from a fully
            inspected structure. Structured input redaction is rejected.

        Raises:
            SecurityError: If the message is blocked by input guardrails.
        """
        if type(message) is str:
            StructuredValue(message)
            try:
                result = self._guard.scan_input_sync(message, tenant_id=self._tenant_id, agent_id=self._agent_id)
                return checked_text(result, message, output=True)
            except SecurityError:
                raise
            except Exception:
                raise SecurityError("Adapter inspection failed") from None
        message = scan_structure(
            message, self._guard.scan_input_sync, tenant_id=self._tenant_id, agent_id=self._agent_id
        )
        return _extract_message_text(message)

    def scan_reply(self, reply: Any) -> Any:
        """Scan an agent reply (output side).

        Args:
            reply: A supported eager value or passive record.

        Returns:
            A detached reply snapshot, sanitized when needed. Ambiguous or object
            redaction is rejected; the original is never partially mutated.

        Raises:
            SecurityError: If the reply is blocked by output filters.
        """
        return scan_structure(
            reply, self._guard.scan_output_sync, output=True, tenant_id=self._tenant_id, agent_id=self._agent_id
        )

    async def scan_message_async(self, message: Any) -> str | None:
        """Async variant of :meth:`scan_message`."""
        if type(message) is str:
            StructuredValue(message)
            try:
                result = await self._guard.scan_input(message, tenant_id=self._tenant_id, agent_id=self._agent_id)
                return checked_text(result, message, output=True)
            except SecurityError:
                raise
            except Exception:
                raise SecurityError("Adapter inspection failed") from None
        message = await scan_structure_async(
            message, self._guard.scan_input, tenant_id=self._tenant_id, agent_id=self._agent_id
        )
        return _extract_message_text(message)

    async def scan_reply_async(self, reply: Any) -> Any:
        """Async variant of :meth:`scan_reply`."""
        return await scan_structure_async(
            reply, self._guard.scan_output, output=True, tenant_id=self._tenant_id, agent_id=self._agent_id
        )

    # === Agent wrapping ===

    def wrap_agent(self, agent: Any) -> Any:
        """Patch an AutoGen agent so every reply is scanned.

        Intercepts ``generate_reply`` (and ``a_generate_reply`` if present),
        scanning all explicit messages before generation and the produced
        reply afterwards. The agent is mutated in place and also returned
        for convenience.

        This is fully duck-typed: it only requires the agent to expose a
        callable ``generate_reply``. It does not import ``autogen``.

        Args:
            agent: An AutoGen ``ConversableAgent`` (or compatible object).

        Returns:
            The same agent, with scanning hooks installed.

        Raises:
            TypeError: If the object has no ``generate_reply`` method.
        """
        if not hasattr(agent, "generate_reply") or not callable(agent.generate_reply):
            raise TypeError(
                "AutoGenGuard.wrap_agent requires an object with a callable "
                "'generate_reply' method (e.g. autogen.ConversableAgent)."
            )

        if getattr(agent, "_bulwark_wrapped", False):
            logger.debug("autogen_agent_already_wrapped")
            return agent

        original_generate = agent.generate_reply
        guard_self = self

        def guarded_generate_reply(messages: Any = None, sender: Any = None, **kwargs: Any) -> Any:
            _explicit_messages(messages)
            messages, kwargs = scan_structure(
                (messages, kwargs),
                guard_self._guard.scan_input_sync,
                tenant_id=self._tenant_id,
                agent_id=self._agent_id,
            )
            reply = original_generate(messages=messages, sender=sender, **kwargs)
            return guard_self.scan_reply(reply)

        agent.generate_reply = guarded_generate_reply  # type: ignore[assignment]

        # Async path (AutoGen exposes a_generate_reply)
        if hasattr(agent, "a_generate_reply") and callable(agent.a_generate_reply):
            original_a_generate = agent.a_generate_reply

            async def guarded_a_generate_reply(messages: Any = None, sender: Any = None, **kwargs: Any) -> Any:
                _explicit_messages(messages)
                messages, kwargs = await scan_structure_async(
                    (messages, kwargs), guard_self._guard.scan_input, tenant_id=self._tenant_id, agent_id=self._agent_id
                )
                if asyncio.iscoroutinefunction(original_a_generate):
                    reply = await original_a_generate(messages=messages, sender=sender, **kwargs)
                else:
                    reply = await asyncio.to_thread(original_a_generate, messages=messages, sender=sender, **kwargs)
                return await guard_self.scan_reply_async(reply)

            agent.a_generate_reply = guarded_a_generate_reply  # type: ignore[assignment]

        agent._bulwark_wrapped = True  # type: ignore[attr-defined]
        return agent


# === Internal helpers ===


def _extract_message_text(message: Any) -> str | None:
    """Extract text from an AutoGen message (str / dict / object)."""
    tree = StructuredValue(message)
    if message is None:
        return None
    if type(message) is str:
        return message
    if type(message) is dict:
        content = message.get("content")
        if type(content) is str:
            return content
        # Multimodal content: list of {"type": "text", "text": ...}
        if type(content) is list:
            parts = [
                p.get("text", "")
                for p in content
                if type(p) is dict and p.get("type") == "text" and type(p.get("text")) is str
            ]
            if parts:
                return " ".join(parts)
    return tree.text or None


def _replace_message_text(message: Any, new_content: str) -> Any:
    """Replace the text content in an AutoGen message object/dict."""
    if type(message) is str:
        return new_content
    raise SecurityError("Structured redaction requires per-field inspection")


def _explicit_messages(messages: Any) -> list:
    """Implicit agent history cannot be inspected; require explicit bounded input."""
    if type(messages) is str:
        messages = [messages]
    if type(messages) is not list or not 0 < len(messages) <= 128:
        raise SecurityError("Explicit messages are required for guarded generation")
    StructuredValue(messages)
    for message in messages:
        if type(message) is str:
            continue
        if type(message) is not dict or "content" not in message:
            raise SecurityError("Explicit message content is required")
        content = message["content"]
        if type(content) is str:
            continue
        if (
            type(content) is not list
            or not content
            or any(
                type(block) is not dict or block.get("type") != "text" or type(block.get("text")) is not str
                for block in content
            )
        ):
            raise SecurityError("Only explicit text messages are supported")
    return messages
