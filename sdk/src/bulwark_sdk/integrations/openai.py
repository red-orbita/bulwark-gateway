"""
OpenAI integration for Bulwark Gateway SDK.

Provides a drop-in replacement for openai.AsyncOpenAI that routes
all requests through Bulwark Gateway for security scanning.

Usage:
    from bulwark_sdk.integrations.openai import BulwarkOpenAI

    client = BulwarkOpenAI(
        bulwark_url="https://bulwark.company.com",
        api_key="sk-...",
        tenant_id="acme-corp",
        agent_id="support-bot",
    )

    # Same API as openai.AsyncOpenAI
    response = await client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Hello"}],
    )
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class _ChatCompletions:
    """Proxy for OpenAI's chat.completions namespace.

    Routes requests through Bulwark Gateway instead of directly to OpenAI.
    """

    def __init__(self, openai_client: BulwarkOpenAI) -> None:
        self._client = openai_client

    async def create(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        temperature: float | None = None,
        max_tokens: int | None = None,
        stream: bool = False,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: Any | None = None,
        **kwargs: Any,
    ) -> Any:
        """Create a chat completion via Bulwark Gateway.

        This method has the same signature as openai.AsyncOpenAI's
        chat.completions.create(), but routes through the gateway.

        Args:
            model: Model identifier (e.g., "gpt-4", "gpt-3.5-turbo").
            messages: List of message dicts with role and content.
            temperature: Sampling temperature (0-2).
            max_tokens: Maximum tokens in the response.
            stream: Whether to stream (not yet supported via SDK).
            tools: Tool/function definitions.
            tool_choice: Tool choice strategy.
            **kwargs: Additional parameters forwarded to the backend.

        Returns:
            ChatCompletion response object (OpenAI-compatible).

        Raises:
            SecurityError: If input is blocked by Bulwark guardrails.
            ImportError: If the openai package is not installed.
        """
        bulwark_client = self._client._bulwark_client

        response_dict = await bulwark_client.chat_completion(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=stream,
            tools=tools,
            tool_choice=tool_choice,
        )

        # Convert to OpenAI response object if openai is available
        return self._to_openai_response(response_dict)

    def _to_openai_response(self, data: dict[str, Any]) -> Any:
        """Convert a dict response to an OpenAI ChatCompletion object."""
        try:
            from openai.types.chat import ChatCompletion

            return ChatCompletion.model_validate(data)
        except ImportError:
            # If openai is not installed, return the raw dict
            return data
        except Exception:
            # If parsing fails, return raw dict
            return data


class _Chat:
    """Proxy for OpenAI's chat namespace."""

    def __init__(self, openai_client: BulwarkOpenAI) -> None:
        self.completions = _ChatCompletions(openai_client)


class BulwarkOpenAI:
    """Drop-in replacement for openai.AsyncOpenAI that routes through Bulwark Gateway.

    All chat completion requests are sent to the Bulwark Gateway proxy,
    which applies security guardrails before forwarding to the LLM backend.

    Args:
        bulwark_url: Base URL of the Bulwark Gateway.
        api_key: API key for authentication with Bulwark Gateway.
        tenant_id: Tenant identifier for multi-tenant isolation.
        agent_id: Agent identifier for policy resolution.
        timeout: Request timeout in seconds.

    Example:
        from bulwark_sdk.integrations.openai import BulwarkOpenAI

        client = BulwarkOpenAI(
            bulwark_url="https://bulwark.company.com",
            api_key="sk-...",
            tenant_id="acme-corp",
            agent_id="code-assistant",
        )

        response = await client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Write a hello world"}],
        )
        print(response.choices[0].message.content)
    """

    def __init__(
        self,
        bulwark_url: str,
        api_key: str,
        tenant_id: str = "default",
        agent_id: str = "default",
        timeout: float = 120.0,
    ) -> None:
        from bulwark_sdk.client import BulwarkClient

        self._bulwark_client = BulwarkClient(
            base_url=bulwark_url,
            api_key=api_key,
            tenant_id=tenant_id,
            agent_id=agent_id,
            timeout=timeout,
        )
        self.chat = _Chat(self)

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._bulwark_client.close()

    async def __aenter__(self) -> BulwarkOpenAI:
        """Enter async context manager."""
        await self._bulwark_client.__aenter__()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Exit async context manager."""
        await self._bulwark_client.__aexit__(*args)
