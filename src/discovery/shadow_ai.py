"""Shadow AI detection — identifies unauthorized AI service usage."""

from __future__ import annotations

import asyncio
import logging
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@dataclass
class ShadowAIAlert:
    """Alert raised when shadow AI usage is detected."""

    hostname: str
    service: str
    timestamp: str
    source_ip: str | None = None
    risk_level: str = "medium"  # "low" | "medium" | "high" | "critical"


class ShadowAIMonitor:
    """Detects unauthorized AI service usage in network traffic."""

    KNOWN_AI_ENDPOINTS: list[str] = [
        # OpenAI
        "api.openai.com",
        "platform.openai.com",
        "chat.openai.com",
        # Anthropic
        "api.anthropic.com",
        "claude.ai",
        # Google
        "generativelanguage.googleapis.com",
        "aistudio.google.com",
        "bard.google.com",
        # Microsoft / Azure
        "openai.azure.com",
        "copilot.microsoft.com",
        "api.cognitive.microsofttranslator.com",
        # Cohere
        "api.cohere.ai",
        "dashboard.cohere.ai",
        # Hugging Face
        "api-inference.huggingface.co",
        "huggingface.co",
        # Replicate
        "api.replicate.com",
        # Together AI
        "api.together.xyz",
        # Mistral
        "api.mistral.ai",
        # Perplexity
        "api.perplexity.ai",
        # Stability AI
        "api.stability.ai",
        # AI21
        "api.ai21.com",
        # Groq
        "api.groq.com",
        # DeepSeek
        "api.deepseek.com",
        # Fireworks AI
        "api.fireworks.ai",
        # Anyscale
        "api.endpoints.anyscale.com",
        # Voyage AI
        "api.voyageai.com",
        # Midjourney
        "api.midjourney.com",
        # RunwayML
        "api.runwayml.com",
        # Eleven Labs
        "api.elevenlabs.io",
    ]

    # Map hostname fragments to service names
    _SERVICE_MAP: dict[str, str] = {
        "openai": "OpenAI",
        "anthropic": "Anthropic",
        "claude": "Anthropic",
        "googleapis": "Google AI",
        "aistudio.google": "Google AI Studio",
        "bard.google": "Google Bard",
        "azure": "Azure OpenAI",
        "copilot.microsoft": "Microsoft Copilot",
        "cohere": "Cohere",
        "huggingface": "Hugging Face",
        "replicate": "Replicate",
        "together": "Together AI",
        "mistral": "Mistral AI",
        "perplexity": "Perplexity",
        "stability": "Stability AI",
        "ai21": "AI21 Labs",
        "groq": "Groq",
        "deepseek": "DeepSeek",
        "fireworks": "Fireworks AI",
        "anyscale": "Anyscale",
        "voyageai": "Voyage AI",
        "midjourney": "Midjourney",
        "runwayml": "RunwayML",
        "elevenlabs": "Eleven Labs",
    }

    def __init__(self) -> None:
        self._endpoint_set: set[str] = set(self.KNOWN_AI_ENDPOINTS)

    async def check_dns(self, domain: str) -> bool:
        """Check if a domain resolves via DNS.

        Args:
            domain: Domain name to resolve.

        Returns:
            True if the domain resolves, False otherwise.
        """
        loop = asyncio.get_event_loop()
        try:
            await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyname, domain),
                timeout=5.0,
            )
            return True
        except (socket.gaierror, asyncio.TimeoutError, OSError):
            return False

    def analyze_traffic_log(self, log_entries: list[dict]) -> list[ShadowAIAlert]:
        """Analyze network traffic logs for shadow AI usage.

        Expects log entries with at least a 'hostname' or 'destination' field.
        Optional fields: 'source_ip', 'timestamp'.

        Args:
            log_entries: List of traffic log dicts.

        Returns:
            List of shadow AI alerts.
        """
        alerts: list[ShadowAIAlert] = []
        seen: set[str] = set()

        for entry in log_entries:
            hostname = entry.get("hostname") or entry.get("destination", "")
            if not hostname:
                continue

            hostname_lower = hostname.lower().strip()

            # Check against known endpoints
            if hostname_lower in self._endpoint_set or self._is_ai_subdomain(hostname_lower):
                # Deduplicate by hostname + source_ip
                source_ip = entry.get("source_ip")
                dedup_key = f"{hostname_lower}:{source_ip or ''}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                service = self.classify_endpoint(hostname_lower) or "Unknown AI"
                risk = self._assess_risk(hostname_lower, service)
                timestamp = entry.get(
                    "timestamp", datetime.now(timezone.utc).isoformat()
                )

                alerts.append(
                    ShadowAIAlert(
                        hostname=hostname_lower,
                        service=service,
                        timestamp=timestamp,
                        source_ip=source_ip,
                        risk_level=risk,
                    )
                )

        return alerts

    def get_blocklist(self) -> list[str]:
        """Return domains that should be blocked to prevent shadow AI usage.

        Returns:
            Sorted list of AI API hostnames.
        """
        return sorted(self.KNOWN_AI_ENDPOINTS)

    def classify_endpoint(self, hostname: str) -> str | None:
        """Identify which AI service a hostname belongs to.

        Args:
            hostname: The hostname to classify.

        Returns:
            Service name string or None if unrecognized.
        """
        hostname_lower = hostname.lower()
        for fragment, service in self._SERVICE_MAP.items():
            if fragment in hostname_lower:
                return service
        return None

    def _is_ai_subdomain(self, hostname: str) -> bool:
        """Check if hostname is a subdomain of a known AI endpoint."""
        for endpoint in self.KNOWN_AI_ENDPOINTS:
            if hostname.endswith(f".{endpoint}") or hostname == endpoint:
                return True
        return False

    def _assess_risk(self, hostname: str, service: str) -> str:
        """Assess risk level based on the service type.

        Services with direct model access get higher risk scores.
        """
        high_risk_services = {"OpenAI", "Anthropic", "Azure OpenAI", "Mistral AI"}
        critical_keywords = ["chat", "completions", "generate"]

        if service in high_risk_services:
            # Check if it's a direct API endpoint vs. a docs/marketing page
            if "api" in hostname:
                return "high"
            return "medium"

        for keyword in critical_keywords:
            if keyword in hostname:
                return "high"

        return "medium"
