"""Agent discovery — probes networks and Kubernetes for LLM API endpoints."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

KNOWN_PORTS = [11434, 8080, 3000, 5000, 8000]

KNOWN_PATHS = [
    "/v1/models",
    "/api/tags",
    "/health",
    "/v1/chat/completions",
]


@dataclass
class DiscoveredAgent:
    """Represents a discovered LLM API endpoint."""

    host: str
    port: int
    service_type: str  # "openai" | "ollama" | "anthropic" | "azure" | "custom"
    confidence: float
    discovered_at: str
    metadata: dict = field(default_factory=dict)


class AgentDiscovery:
    """Discovers LLM agents across networks and Kubernetes clusters."""

    def __init__(self, timeout: float = 5.0) -> None:
        self._timeout = timeout

    async def scan_network(self, targets: list[str]) -> list[DiscoveredAgent]:
        """Probe known LLM API ports/paths on given target hosts.

        Args:
            targets: List of hostnames or IP addresses to scan.

        Returns:
            List of discovered agents.
        """
        discovered: list[DiscoveredAgent] = []
        tasks = []
        for target in targets:
            for port in KNOWN_PORTS:
                tasks.append(self.probe_endpoint(target, port))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, DiscoveredAgent):
                discovered.append(result)
            elif isinstance(result, Exception):
                logger.debug("Probe failed: %s", result)

        return discovered

    async def scan_kubernetes(self, namespace: str = "default") -> list[DiscoveredAgent]:
        """Discover LLM services via Kubernetes API.

        Queries the Kubernetes API for services with common LLM-related labels
        and ports, then probes each candidate.

        Args:
            namespace: Kubernetes namespace to scan.

        Returns:
            List of discovered agents running in the cluster.
        """
        import httpx

        discovered: list[DiscoveredAgent] = []
        k8s_host = "https://kubernetes.default.svc"
        token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

        try:
            with open(token_path) as f:
                token = f.read().strip()
        except OSError:
            logger.warning("Kubernetes service account token not found; skipping K8s scan")
            return discovered

        headers = {"Authorization": f"Bearer {token}"}
        url = f"{k8s_host}/api/v1/namespaces/{namespace}/services"

        try:
            async with httpx.AsyncClient(
                verify=ca_path, timeout=self._timeout
            ) as client:
                resp = await client.get(url, headers=headers)
                resp.raise_for_status()
                data = resp.json()
        except (httpx.HTTPError, OSError, json.JSONDecodeError) as exc:
            logger.warning("Kubernetes API query failed: %s", exc)
            return discovered

        for item in data.get("items", []):
            spec = item.get("spec", {})
            metadata = item.get("metadata", {})
            svc_name = metadata.get("name", "unknown")
            cluster_ip = spec.get("clusterIP")

            if not cluster_ip or cluster_ip == "None":
                continue

            for port_info in spec.get("ports", []):
                port = port_info.get("port", 0)
                if port in KNOWN_PORTS:
                    agent = await self.probe_endpoint(cluster_ip, port)
                    if agent is not None:
                        agent.metadata["k8s_service"] = svc_name
                        agent.metadata["k8s_namespace"] = namespace
                        discovered.append(agent)

        return discovered

    async def probe_endpoint(self, host: str, port: int) -> DiscoveredAgent | None:
        """Check if a host:port is an LLM API endpoint.

        Tries known paths and inspects responses to determine the service type.

        Args:
            host: Target hostname or IP.
            port: Target port.

        Returns:
            DiscoveredAgent if an LLM service is detected, None otherwise.
        """
        import httpx

        base_url = f"http://{host}:{port}"

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                for path in KNOWN_PATHS:
                    try:
                        resp = await client.get(f"{base_url}{path}")
                        if resp.status_code < 500:
                            service_type = self._detect_service_type(
                                dict(resp.headers), resp.text
                            )
                            if service_type != "custom" or resp.status_code == 200:
                                confidence = self._compute_confidence(
                                    resp.status_code, service_type, path
                                )
                                return DiscoveredAgent(
                                    host=host,
                                    port=port,
                                    service_type=service_type,
                                    confidence=confidence,
                                    discovered_at=datetime.now(timezone.utc).isoformat(),
                                    metadata={
                                        "matched_path": path,
                                        "status_code": resp.status_code,
                                    },
                                )
                    except httpx.HTTPError:
                        continue
        except (httpx.HTTPError, OSError) as exc:
            logger.debug("Probe %s:%d failed: %s", host, port, exc)

        return None

    def _detect_service_type(self, response_headers: dict, response_body: str) -> str:
        """Determine the LLM service type from response characteristics.

        Args:
            response_headers: HTTP response headers.
            response_body: HTTP response body text.

        Returns:
            Service type string.
        """
        body_lower = response_body.lower()
        headers_str = json.dumps(response_headers).lower()

        # Ollama detection
        if "ollama" in body_lower or "ollama" in headers_str:
            return "ollama"
        if '"models"' in body_lower and '"name"' in body_lower:
            if "modified_at" in body_lower or "size" in body_lower:
                return "ollama"

        # OpenAI detection
        if "openai" in headers_str or "openai" in body_lower:
            return "openai"
        if '"object"' in body_lower and '"data"' in body_lower:
            if '"model"' in body_lower or '"id"' in body_lower:
                return "openai"

        # Anthropic detection
        if "anthropic" in headers_str or "anthropic" in body_lower:
            return "anthropic"
        if "claude" in body_lower:
            return "anthropic"

        # Azure OpenAI detection
        if "azure" in headers_str or "microsoft" in headers_str:
            return "azure"
        if "azure" in body_lower and "openai" in body_lower:
            return "azure"

        return "custom"

    def _compute_confidence(
        self, status_code: int, service_type: str, matched_path: str
    ) -> float:
        """Compute confidence score for a detection."""
        score = 0.5

        if status_code == 200:
            score += 0.2
        elif status_code in (401, 403):
            # Auth required means something is there
            score += 0.1

        if service_type != "custom":
            score += 0.2

        # Higher confidence for more specific paths
        if matched_path == "/v1/models":
            score += 0.1
        elif matched_path == "/api/tags":
            score += 0.1

        return min(score, 1.0)
