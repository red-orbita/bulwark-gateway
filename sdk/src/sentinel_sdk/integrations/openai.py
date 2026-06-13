"""
OpenAI integration for Sentinel Gateway SDK.

Provides a drop-in replacement for openai.AsyncOpenAI that routes
all requests through Sentinel Gateway for security scanning.

Usage:
    from sentinel_sdk.integrations.openai import SentinelOpenAI

    client = SentinelOpenAI(
        sentinel_url="https://sentinel.company.com",
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
from typing import Any, Optional

logger = logging.getLogger(__name__)


class _ChatCompletions:
    """Proxy for OpenAI's chat.completions namespace.

    Routes requests through Sentinel Gateway instead of directly to OpenAI.
    """

    def __init__(self, openai_client: "SentinelOpenAI") -> None:
        self._client = openai_client

    async def create(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        stream: bool = False,
        tools: Optional[list[dict[str, Any]]] = None,
        tool_choice: Optional[Any] = None,
        **kwargs: Any,
    ) -> Any:
        """Create a chat completion via Sentinel Gateway.

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
            SecurityError: If input is blocked by Sentinel guardrails.
            ImportError: If the openai package is not installed.
        """
        sentinel_client = self._client._sentinel_client

        response_dict = await sentinel_client.chat_completion(
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

    def __init__(self, openai_client: "SentinelOpenAI") -> None:
        self.completions = _ChatCompletions(openai_client)


class SentinelOpenAI:
    """Drop-in replacement for openai.AsyncOpenAI that routes through Sentinel Gateway.

    All chat completion requests are sent to the Sentinel Gateway proxy,
    which applies security guardrails before forwarding to the LLM backend.

    Args:
        sentinel_url: Base URL of the Sentinel Gateway.
        api_key: API key for authentication with Sentinel Gateway.
        tenant_id: Tenant identifier for multi-tenant isolation.
        agent_id: Agent identifier for policy resolution.
        timeout: Request timeout in seconds.

    Example:
        from sentinel_sdk.integrations.openai import SentinelOpenAI

        client = SentinelOpenAI(
            sentinel_url="https://sentinel.company.com",
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
        sentinel_url: str,
        api_key: str,
        tenant_id: str = "default",
        agent_id: str = "default",
        timeout: float = 120.0,
    ) -> None:
        from sentinel_sdk.client import SentinelClient

        self._sentinel_client = SentinelClient(
            base_url=sentinel_url,
            api_key=api_key,
            tenant_id=tenant_id,
            agent_id=agent_id,
            timeout=timeout,
        )
        self.chat = _Chat(self)

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._sentinel_client.close()

    async def __aenter__(self) -> "SentinelOpenAI":
        """Enter async context manager."""
        await self._sentinel_client.__aenter__()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Exit async context manager."""
        await self._sentinel_client.__aexit__(*args)
