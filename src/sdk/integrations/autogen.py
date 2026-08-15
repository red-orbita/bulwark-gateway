"""
AutoGen Integration — Wraps AutoGen agents with Bulwark security scanning.

Provides a non-intrusive way to add security guardrails to AutoGen
(and ag2) multi-agent conversations. Does NOT import autogen at module
level — the wrappers are fully duck-typed, so they work with any object
exposing ``generate_reply`` / ``a_generate_reply`` and are testable
without the framework installed.

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
                any object with a ``.content`` attribute.

        Returns:
            The (possibly redacted) message text, or None if there was no
            scannable content.

        Raises:
            SecurityError: If the message is blocked by input guardrails.
        """
        text = _extract_message_text(message)
        if not text:
            return None
        result = self._guard.scan_input_sync(
            text, tenant_id=self._tenant_id, agent_id=self._agent_id
        )
        if result.verdict.value == "block":
            raise SecurityError(
                f"Input blocked: {result.events[0].description if result.events else 'policy violation'}",
                result=result,
            )
        if result.verdict.value == "redact" and result.modified_content:
            return result.modified_content
        return text

    def scan_reply(self, reply: Any) -> Any:
        """Scan an agent reply (output side).

        Args:
            reply: A string, a ``{"content": ...}`` dict, or an object with
                a ``.content`` attribute.

        Returns:
            The reply, with content redacted in place if the output filter
            requires it.

        Raises:
            SecurityError: If the reply is blocked by output filters.
        """
        text = _extract_message_text(reply)
        if not text:
            return reply
        result = self._guard.scan_output_sync(
            text, tenant_id=self._tenant_id, agent_id=self._agent_id
        )
        if result.verdict.value == "block":
            raise SecurityError(
                f"Output blocked: {result.events[0].description if result.events else 'policy violation'}",
                result=result,
            )
        if result.verdict.value == "redact" and result.modified_content:
            return _replace_message_text(reply, result.modified_content)
        return reply

    async def scan_message_async(self, message: Any) -> str | None:
        """Async variant of :meth:`scan_message`."""
        text = _extract_message_text(message)
        if not text:
            return None
        result = await self._guard.scan_input(
            text, tenant_id=self._tenant_id, agent_id=self._agent_id
        )
        if result.verdict.value == "block":
            raise SecurityError(
                f"Input blocked: {result.events[0].description if result.events else 'policy violation'}",
                result=result,
            )
        if result.verdict.value == "redact" and result.modified_content:
            return result.modified_content
        return text

    async def scan_reply_async(self, reply: Any) -> Any:
        """Async variant of :meth:`scan_reply`."""
        text = _extract_message_text(reply)
        if not text:
            return reply
        result = await self._guard.scan_output(
            text, tenant_id=self._tenant_id, agent_id=self._agent_id
        )
        if result.verdict.value == "block":
            raise SecurityError(
                f"Output blocked: {result.events[0].description if result.events else 'policy violation'}",
                result=result,
            )
        if result.verdict.value == "redact" and result.modified_content:
            return _replace_message_text(reply, result.modified_content)
        return reply

    # === Agent wrapping ===

    def wrap_agent(self, agent: Any) -> Any:
        """Patch an AutoGen agent so every reply is scanned.

        Intercepts ``generate_reply`` (and ``a_generate_reply`` if present),
        scanning the last user message before generation and the produced
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

        def guarded_generate_reply(
            messages: Any = None, sender: Any = None, **kwargs: Any
        ) -> Any:
            # Scan the most recent inbound message (input guardrail)
            last = _last_user_message(messages)
            if last is not None:
                guard_self.scan_message(last)  # raises SecurityError on block
            reply = original_generate(messages=messages, sender=sender, **kwargs)
            return guard_self.scan_reply(reply)

        agent.generate_reply = guarded_generate_reply  # type: ignore[assignment]

        # Async path (AutoGen exposes a_generate_reply)
        if hasattr(agent, "a_generate_reply") and callable(agent.a_generate_reply):
            original_a_generate = agent.a_generate_reply

            async def guarded_a_generate_reply(
                messages: Any = None, sender: Any = None, **kwargs: Any
            ) -> Any:
                last = _last_user_message(messages)
                if last is not None:
                    await guard_self.scan_message_async(last)
                if asyncio.iscoroutinefunction(original_a_generate):
                    reply = await original_a_generate(
                        messages=messages, sender=sender, **kwargs
                    )
                else:
                    reply = original_a_generate(
                        messages=messages, sender=sender, **kwargs
                    )
                return await guard_self.scan_reply_async(reply)

            agent.a_generate_reply = guarded_a_generate_reply  # type: ignore[assignment]

        agent._bulwark_wrapped = True  # type: ignore[attr-defined]
        return agent


# === Internal helpers ===


def _extract_message_text(message: Any) -> str | None:
    """Extract text from an AutoGen message (str / dict / object)."""
    if message is None:
        return None
    if isinstance(message, str):
        return message
    if isinstance(message, dict):
        content = message.get("content")
        if isinstance(content, str):
            return content
        # Multimodal content: list of {"type": "text", "text": ...}
        if isinstance(content, list):
            parts = [
                p.get("text", "")
                for p in content
                if isinstance(p, dict) and p.get("type") == "text"
            ]
            if parts:
                return " ".join(parts)
    if hasattr(message, "content"):
        content = message.content
        if isinstance(content, str):
            return content
    return None


def _replace_message_text(message: Any, new_content: str) -> Any:
    """Replace the text content in an AutoGen message object/dict."""
    if isinstance(message, str):
        return new_content
    if isinstance(message, dict):
        if isinstance(message.get("content"), str):
            message["content"] = new_content
        return message
    if hasattr(message, "content"):
        try:
            message.content = new_content
        except AttributeError:
            pass
    return message


def _last_user_message(messages: Any) -> Any:
    """Return the most recent user message from an AutoGen messages list."""
    if messages is None:
        return None
    if isinstance(messages, str):
        return messages
    if isinstance(messages, list) and messages:
        # Prefer the last message whose role is 'user' (or unspecified).
        for msg in reversed(messages):
            if isinstance(msg, dict):
                role = msg.get("role")
                if role in (None, "user"):
                    return msg
            else:
                return msg
        return messages[-1]
    return None
