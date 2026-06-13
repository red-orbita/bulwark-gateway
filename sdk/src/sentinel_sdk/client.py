"""
HTTP client for communicating with a remote Sentinel Gateway instance.

Provides async methods for scanning input/output, proxying chat completions,
and checking gateway health. Handles authentication, retries, and error mapping.

Usage:
    from sentinel_sdk import SentinelClient

    client = SentinelClient(
        base_url="https://sentinel.company.com",
        api_key="sk-...",
        tenant_id="acme-corp",
        agent_id="support-bot",
    )
    result = await client.scan_input("user message")
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

from sentinel_sdk.exceptions import (
    AuthenticationError,
    ConfigurationError,
    ConnectionError,
    GatewayError,
    RateLimitError,
    SecurityError,
)
from sentinel_sdk.models import (
    ChatCompletionRequest,
    HealthStatus,
    Message,
    ScanResult,
    SecurityEvent,
    Severity,
    Verdict,
)

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 30.0


class SentinelClient:
    """Async HTTP client for Sentinel Gateway API.

    Provides methods to scan input/output content, proxy chat completions
    through the gateway, and check service health.

    Args:
        base_url: Base URL of the Sentinel Gateway (e.g., "https://sentinel.company.com").
        api_key: API key or JWT token for authentication.
        tenant_id: Tenant identifier for multi-tenant isolation.
        agent_id: Agent identifier for policy resolution.
        timeout: HTTP request timeout in seconds (default: 30).
        max_retries: Maximum number of retries on transient failures (default: 2).

    Example:
        async with SentinelClient(
            base_url="https://sentinel.company.com",
            api_key="sk-...",
            tenant_id="acme-corp",
            agent_id="support-bot",
        ) as client:
            result = await client.scan_input("hello world")
            assert result.verdict == Verdict.ALLOW
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        tenant_id: str = "default",
        agent_id: str = "default",
        timeout: float = _DEFAULT_TIMEOUT,
        max_retries: int = 2,
    ) -> None:
        if not base_url:
            raise ConfigurationError("base_url is required")
        if not api_key:
            raise ConfigurationError("api_key is required")

        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._tenant_id = tenant_id
        self._agent_id = agent_id
        self._timeout = timeout
        self._max_retries = max_retries
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def base_url(self) -> str:
        """The base URL of the Sentinel Gateway."""
        return self._base_url

    @property
    def tenant_id(self) -> str:
        """The tenant ID used for requests."""
        return self._tenant_id

    @property
    def agent_id(self) -> str:
        """The agent ID used for requests."""
        return self._agent_id

    async def __aenter__(self) -> "SentinelClient":
        """Enter async context manager — creates the HTTP client."""
        self._client = self._create_client()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Exit async context manager — closes the HTTP client."""
        await self.close()

    async def close(self) -> None:
        """Close the underlying HTTP client and release resources."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def scan_input(
        self,
        content: str,
        *,
        tenant_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> ScanResult:
        """Scan user input for security threats via the Sentinel Gateway.

        Sends the content to the gateway's chat completion endpoint with
        a scan-only flag and returns the guardrail verdict.

        Args:
            content: The user message or input text to scan.
            tenant_id: Override the default tenant_id for this request.
            agent_id: Override the default agent_id for this request.

        Returns:
            ScanResult with verdict, events, and timing information.

        Raises:
            SecurityError: If the content is blocked (verdict=BLOCK).
            AuthenticationError: If the API key is invalid.
            RateLimitError: If the request is rate-limited.
            ConnectionError: If the gateway is unreachable.
        """
        response = await self._request(
            "POST",
            "/v1/chat/completions",
            json={
                "model": "scan-only",
                "messages": [{"role": "user", "content": content}],
                "max_tokens": 1,
            },
            tenant_id=tenant_id,
            agent_id=agent_id,
        )
        return self._parse_scan_response(response, content)

    async def scan_output(
        self,
        content: str,
        *,
        input_messages: Optional[list[dict[str, str]]] = None,
        tenant_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> ScanResult:
        """Scan LLM output for sensitive data and policy violations.

        Sends content to the gateway's tool validation endpoint for
        output-only scanning.

        Args:
            content: The LLM response or output text to scan.
            input_messages: Original input messages for context.
            tenant_id: Override the default tenant_id for this request.
            agent_id: Override the default agent_id for this request.

        Returns:
            ScanResult with verdict, events, and modified_content (if redacted).

        Raises:
            AuthenticationError: If the API key is invalid.
            RateLimitError: If the request is rate-limited.
            ConnectionError: If the gateway is unreachable.
        """
        response = await self._request(
            "POST",
            "/v1/tool/validate",
            json={
                "content": content,
                "direction": "output",
                "messages": input_messages or [],
            },
            tenant_id=tenant_id,
            agent_id=agent_id,
        )
        return self._parse_tool_validate_response(response)

    async def chat_completion(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        stream: bool = False,
        tools: Optional[list[dict[str, Any]]] = None,
        tool_choice: Optional[Any] = None,
        tenant_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Proxy a chat completion request through Sentinel Gateway.

        The gateway applies input guardrails, forwards to the configured
        backend LLM, applies output filters, and returns the result.

        Args:
            model: The model identifier to use.
            messages: List of chat messages (OpenAI format).
            temperature: Sampling temperature.
            max_tokens: Maximum tokens to generate.
            stream: Whether to stream the response (not yet supported in SDK).
            tools: Tool definitions for function calling.
            tool_choice: Tool choice strategy.
            tenant_id: Override tenant_id for this request.
            agent_id: Override agent_id for this request.

        Returns:
            The chat completion response dict (OpenAI-compatible format).

        Raises:
            SecurityError: If input is blocked by guardrails.
            AuthenticationError: If the API key is invalid.
            RateLimitError: If the request is rate-limited.
            ConnectionError: If the gateway is unreachable.
            GatewayError: If the backend LLM returns an error.
        """
        if stream:
            raise ConfigurationError(
                "Streaming is not yet supported in the SDK client. "
                "Use stream=False or connect directly to the gateway SSE endpoint."
            )

        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
        }
        if temperature is not None:
            payload["temperature"] = temperature
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        if tools is not None:
            payload["tools"] = tools
        if tool_choice is not None:
            payload["tool_choice"] = tool_choice

        response = await self._request(
            "POST",
            "/v1/chat/completions",
            json=payload,
            tenant_id=tenant_id,
            agent_id=agent_id,
        )
        return response

    async def health(self) -> HealthStatus:
        """Check the health of the Sentinel Gateway.

        Returns:
            HealthStatus with service status and basic metrics.

        Raises:
            ConnectionError: If the gateway is unreachable.
        """
        client = self._get_client()
        try:
            resp = await client.get(f"{self._base_url}/health")
            resp.raise_for_status()
            data = resp.json()
            return HealthStatus(**data)
        except httpx.ConnectError as e:
            raise ConnectionError(
                f"Cannot connect to Sentinel Gateway at {self._base_url}",
                url=self._base_url,
            ) from e
        except httpx.HTTPError as e:
            raise ConnectionError(
                f"Health check failed: {e}",
                url=self._base_url,
            ) from e

    # === Internal methods ===

    def _create_client(self) -> httpx.AsyncClient:
        """Create a new httpx AsyncClient with default configuration."""
        transport = httpx.AsyncHTTPTransport(retries=self._max_retries)
        return httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout),
            transport=transport,
            headers=self._default_headers(),
        )

    def _get_client(self) -> httpx.AsyncClient:
        """Get or lazily create the HTTP client."""
        if self._client is None:
            self._client = self._create_client()
        return self._client

    def _default_headers(self) -> dict[str, str]:
        """Build default headers for all requests."""
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "User-Agent": "sentinel-gateway-sdk/0.1.0",
            "X-Tenant-ID": self._tenant_id,
            "X-Agent-ID": self._agent_id,
        }

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[dict[str, Any]] = None,
        tenant_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Make an authenticated HTTP request to the gateway.

        Handles error mapping for common HTTP status codes.
        """
        client = self._get_client()
        url = f"{self._base_url}{path}"

        headers: dict[str, str] = {}
        if tenant_id:
            headers["X-Tenant-ID"] = tenant_id
        if agent_id:
            headers["X-Agent-ID"] = agent_id

        try:
            resp = await client.request(
                method,
                url,
                json=json,
                headers=headers if headers else None,
            )
        except httpx.ConnectError as e:
            raise ConnectionError(
                f"Cannot connect to Sentinel Gateway at {self._base_url}",
                url=self._base_url,
            ) from e
        except httpx.TimeoutException as e:
            raise ConnectionError(
                f"Request to Sentinel Gateway timed out after {self._timeout}s",
                url=url,
            ) from e
        except httpx.HTTPError as e:
            raise ConnectionError(
                f"HTTP error communicating with Sentinel Gateway: {e}",
                url=url,
            ) from e

        # Map HTTP status codes to exceptions
        if resp.status_code == 401:
            raise AuthenticationError(
                "Invalid API key or expired JWT token"
            )
        elif resp.status_code == 403:
            # 403 from Sentinel means the guardrail blocked the request
            body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            detail = body.get("detail", "Request blocked by security guardrail")
            result = ScanResult(
                verdict=Verdict.BLOCK,
                events=[SecurityEvent(description=detail, severity=Severity.HIGH)],
            )
            raise SecurityError(detail, result=result)
        elif resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After")
            raise RateLimitError(
                "Rate limit exceeded",
                retry_after=float(retry_after) if retry_after else None,
            )
        elif resp.status_code >= 500:
            body_text = resp.text
            raise GatewayError(
                f"Sentinel Gateway returned {resp.status_code}",
                status_code=resp.status_code,
                response_body=body_text,
            )
        elif resp.status_code >= 400:
            body_text = resp.text
            raise GatewayError(
                f"Request failed with status {resp.status_code}: {body_text[:200]}",
                status_code=resp.status_code,
                response_body=body_text,
            )

        return resp.json()

    def _parse_scan_response(self, response: dict[str, Any], content: str) -> ScanResult:
        """Parse a chat completion response into a ScanResult.

        If the gateway returned a normal completion, the input was allowed.
        """
        # The gateway returns a normal response if input passes
        return ScanResult(verdict=Verdict.ALLOW, latency_ms=0.0)

    def _parse_tool_validate_response(self, response: dict[str, Any]) -> ScanResult:
        """Parse a tool/validate response into a ScanResult."""
        verdict_str = response.get("verdict", "allow")
        try:
            verdict = Verdict(verdict_str)
        except ValueError:
            verdict = Verdict.ALLOW

        events = []
        for evt_data in response.get("events", []):
            events.append(SecurityEvent(**evt_data))

        return ScanResult(
            verdict=verdict,
            events=events,
            modified_content=response.get("modified_content"),
            latency_ms=response.get("latency_ms", 0.0),
        )
