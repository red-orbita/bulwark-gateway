"""
Webhook Alerts — Send notifications for critical security events.

Supports:
- Generic HTTP webhooks (JSON payload)
- Slack incoming webhooks (formatted blocks)
- Configurable severity threshold and rate limiting (dedup window)

Non-blocking: fires and forgets via asyncio tasks.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

from src.config import settings

logger = logging.getLogger(__name__)


@dataclass
class WebhookConfig:
    """Webhook destination configuration."""
    url: str
    name: str = "default"
    type: str = "generic"  # "generic" | "slack"
    min_severity: str = "high"  # Only alert on this severity or above
    enabled: bool = True
    # Dedup: don't send same alert within this window (seconds)
    dedup_window_seconds: int = 300
    # Headers for generic webhooks
    headers: dict[str, str] = field(default_factory=dict)


# Severity ordering for comparison
_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class WebhookAlerter:
    """Manages webhook destinations and sends alerts."""

    def __init__(self):
        self._webhooks: list[WebhookConfig] = []
        self._recent_alerts: dict[str, float] = {}  # hash -> timestamp
        self._client: Optional[httpx.AsyncClient] = None
        self._load_config()

    def _load_config(self):
        """Load webhook config from settings."""
        webhook_urls = getattr(settings, "webhook_alert_urls", "")
        if not webhook_urls:
            return

        for entry in webhook_urls.split(","):
            entry = entry.strip()
            if not entry:
                continue
            # Format: type:name:url or just url
            parts = entry.split("|", 2)
            if len(parts) == 3:
                wtype, name, url = parts
            elif len(parts) == 2:
                wtype, url = parts
                name = wtype
            else:
                wtype, name, url = "generic", "webhook", parts[0]

            self._webhooks.append(WebhookConfig(url=url, name=name, type=wtype))

    @property
    def configured(self) -> bool:
        return len(self._webhooks) > 0

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=5.0)
        return self._client

    def _should_alert(self, severity: str, dedup_key: str, webhook: WebhookConfig) -> bool:
        """Check if alert should be sent (severity + dedup)."""
        sev_val = _SEVERITY_ORDER.get(severity, 0)
        min_val = _SEVERITY_ORDER.get(webhook.min_severity, 2)
        if sev_val < min_val:
            return False

        # Dedup check
        now = time.time()
        cache_key = f"{webhook.name}:{dedup_key}"
        last_sent = self._recent_alerts.get(cache_key, 0)
        if now - last_sent < webhook.dedup_window_seconds:
            return False

        self._recent_alerts[cache_key] = now
        # Cleanup old entries
        if len(self._recent_alerts) > 1000:
            cutoff = now - 600
            self._recent_alerts = {k: v for k, v in self._recent_alerts.items() if v > cutoff}

        return True

    def _make_dedup_key(self, category: str, tenant_id: str, description: str) -> str:
        raw = f"{category}:{tenant_id}:{description}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    async def send_alert(
        self,
        verdict: str,
        severity: str,
        category: str,
        description: str,
        tenant_id: str = "unknown",
        agent_id: str = "unknown",
        matched_patterns: Optional[list[str]] = None,
    ):
        """Send alert to all configured webhooks (non-blocking)."""
        if not self._webhooks:
            return

        dedup_key = self._make_dedup_key(category, tenant_id, description)

        for webhook in self._webhooks:
            if not webhook.enabled:
                continue
            if not self._should_alert(severity, dedup_key, webhook):
                continue

            asyncio.create_task(self._dispatch(webhook, {
                "verdict": verdict,
                "severity": severity,
                "category": category,
                "description": description,
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "matched_patterns": matched_patterns or [],
                "timestamp": time.time(),
                "source": "sentinel-gateway",
            }))

    async def _dispatch(self, webhook: WebhookConfig, payload: dict):
        """Actually send the webhook."""
        try:
            client = await self._get_client()
            if webhook.type == "slack":
                body = self._format_slack(payload)
            else:
                body = payload

            headers = {"Content-Type": "application/json"}
            headers.update(webhook.headers)

            resp = await client.post(webhook.url, json=body, headers=headers)
            if resp.status_code >= 400:
                logger.warning(f"Webhook {webhook.name} returned {resp.status_code}")
        except Exception as e:
            logger.warning(f"Webhook {webhook.name} failed: {e}")

    def _format_slack(self, payload: dict) -> dict:
        """Format payload as Slack Block Kit message."""
        severity_emoji = {
            "critical": ":rotating_light:",
            "high": ":warning:",
            "medium": ":large_yellow_circle:",
            "low": ":information_source:",
        }
        emoji = severity_emoji.get(payload["severity"], ":bell:")
        patterns_text = ", ".join(payload["matched_patterns"][:3]) if payload["matched_patterns"] else "N/A"

        return {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"{emoji} Sentinel Gateway Alert"}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Verdict:* `{payload['verdict']}`"},
                        {"type": "mrkdwn", "text": f"*Severity:* `{payload['severity']}`"},
                        {"type": "mrkdwn", "text": f"*Category:* `{payload['category']}`"},
                        {"type": "mrkdwn", "text": f"*Tenant:* `{payload['tenant_id']}`"},
                        {"type": "mrkdwn", "text": f"*Agent:* `{payload['agent_id']}`"},
                        {"type": "mrkdwn", "text": f"*Patterns:* {patterns_text}"},
                    ]
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Description:* {payload['description']}"}
                },
            ]
        }

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()


# Singleton
_alerter: Optional[WebhookAlerter] = None


def get_webhook_alerter() -> WebhookAlerter:
    global _alerter
    if _alerter is None:
        _alerter = WebhookAlerter()
    return _alerter
