"""
Notification Engine — Multi-channel alerting for security events.

Supported channels:
  - Slack (Incoming Webhooks + Block Kit)
  - Microsoft Teams (Incoming Webhooks + Adaptive Cards)
  - Discord (Webhooks + Embeds)
  - PagerDuty (Events API v2)
  - Opsgenie (Alert API)
  - Telegram (Bot API)
  - Google Chat (Webhooks)
  - Generic HTTP Webhook (JSON POST)
  - Email/SMTP (SendGrid, Gmail, Office 365, custom relay)

Configuration:
  - YAML file: config/notifications.yaml
  - Admin GUI: /admin/notifications
  - Persistent storage: shared/notifications/channels.json

Non-blocking: all notifications fire-and-forget via asyncio tasks.
Dedup: same alert not sent twice within configurable window.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import smtplib
import ssl
import time
from dataclasses import dataclass, field
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Severity ordering
_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Persistent storage path — uses data/ (mounted as PVC in k8s)
_CHANNELS_FILE = Path(os.environ.get("SENTINEL_NOTIFICATIONS_FILE", "data/notifications_channels.json"))


@dataclass
class NotificationChannel:
    """A single notification destination."""
    id: str
    name: str
    type: str  # slack, teams, discord, pagerduty, opsgenie, telegram, google_chat, email, generic
    enabled: bool = True
    # Routing
    min_severity: str = "high"  # Only alert on this severity or above
    verdicts: list[str] = field(default_factory=lambda: ["block"])  # block, warn, redact
    tenants: list[str] = field(default_factory=list)  # Empty = all tenants
    # Dedup
    dedup_window_seconds: int = 300
    # Connection — fields vary by type
    url: str = ""  # Webhook URL (Slack, Teams, Discord, Google Chat, generic)
    # Email-specific
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_to: list[str] = field(default_factory=list)
    smtp_tls: str = "starttls"  # starttls, ssl, none
    # PagerDuty
    routing_key: str = ""  # Integration key
    # Opsgenie
    api_key: str = ""
    # Telegram
    bot_token: str = ""
    chat_id: str = ""
    # Generic webhook
    headers: dict[str, str] = field(default_factory=dict)
    # Auth for generic webhooks
    auth_type: str = "none"  # none, bearer, basic, api_key
    auth_value: str = ""
    source: str = "config"  # config, env, yaml — indicates where this channel was defined

    def to_dict(self) -> dict:
        """Serialize for JSON storage (masks secrets)."""
        d = {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "enabled": self.enabled,
            "source": self.source,
            "min_severity": self.min_severity,
            "verdicts": self.verdicts,
            "tenants": self.tenants,
            "dedup_window_seconds": self.dedup_window_seconds,
            "url": self.url,
            "smtp_host": self.smtp_host,
            "smtp_port": self.smtp_port,
            "smtp_user": self.smtp_user,
            "smtp_password": self.smtp_password,
            "smtp_from": self.smtp_from,
            "smtp_to": self.smtp_to,
            "smtp_tls": self.smtp_tls,
            "routing_key": self.routing_key,
            "api_key": self.api_key,
            "bot_token": self.bot_token,
            "chat_id": self.chat_id,
            "headers": self.headers,
            "auth_type": self.auth_type,
            "auth_value": self.auth_value,
        }
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "NotificationChannel":
        return cls(
            id=d.get("id", ""),
            name=d.get("name", ""),
            type=d.get("type", "generic"),
            enabled=d.get("enabled", True),
            source=d.get("source", "config"),
            min_severity=d.get("min_severity", "high"),
            verdicts=d.get("verdicts", ["block"]),
            tenants=d.get("tenants", []),
            dedup_window_seconds=d.get("dedup_window_seconds", 300),
            url=d.get("url", ""),
            smtp_host=d.get("smtp_host", ""),
            smtp_port=d.get("smtp_port", 587),
            smtp_user=d.get("smtp_user", ""),
            smtp_password=d.get("smtp_password", ""),
            smtp_from=d.get("smtp_from", ""),
            smtp_to=d.get("smtp_to", []),
            smtp_tls=d.get("smtp_tls", "starttls"),
            routing_key=d.get("routing_key", ""),
            api_key=d.get("api_key", ""),
            bot_token=d.get("bot_token", ""),
            chat_id=d.get("chat_id", ""),
            headers=d.get("headers", {}),
            auth_type=d.get("auth_type", "none"),
            auth_value=d.get("auth_value", ""),
        )


@dataclass
class AlertPayload:
    """Standardized alert data sent to all channels."""
    verdict: str
    severity: str
    category: str
    description: str
    tenant_id: str = "unknown"
    agent_id: str = "unknown"
    source_ip: str = ""
    matched_patterns: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


class NotificationEngine:
    """Manages channels and dispatches alerts."""

    def __init__(self):
        self._channels: list[NotificationChannel] = []
        self._recent_alerts: dict[str, float] = {}
        self._client: Optional[httpx.AsyncClient] = None
        self._load_channels()

    def _load_channels(self):
        """Load channels from persistent storage + YAML config."""
        # Load from JSON (admin-managed)
        if _CHANNELS_FILE.exists():
            try:
                data = json.loads(_CHANNELS_FILE.read_text())
                self._channels = [NotificationChannel.from_dict(d) for d in data]
            except Exception as e:
                logger.error(f"Failed to load notification channels: {e}")

        # Also load from YAML config (GitOps-managed)
        yaml_path = Path("config/notifications.yaml")
        if yaml_path.exists():
            try:
                import yaml
                with open(yaml_path) as f:
                    cfg = yaml.safe_load(f) or {}
                for ch_data in cfg.get("channels", []):
                    # Don't duplicate — skip if ID already loaded from JSON
                    if any(c.id == ch_data.get("id") for c in self._channels):
                        continue
                    self._channels.append(NotificationChannel.from_dict(ch_data))
            except Exception as e:
                logger.error(f"Failed to load notifications YAML: {e}")

        # Legacy: load from env var (backward-compatible with webhook_alert_urls)
        from src.config import settings
        webhook_urls = getattr(settings, "webhook_alert_urls", "")
        if webhook_urls:
            for entry in webhook_urls.split(","):
                entry = entry.strip()
                if not entry:
                    continue
                parts = entry.split("|", 2)
                if len(parts) == 3:
                    wtype, name, url = parts
                elif len(parts) == 2:
                    wtype, url = parts
                    name = wtype
                else:
                    wtype, name, url = "generic", "env-webhook", parts[0]
                ch_id = f"env-{hashlib.sha256(url.encode()).hexdigest()[:8]}"
                if not any(c.id == ch_id for c in self._channels):
                    self._channels.append(NotificationChannel(
                        id=ch_id, name=name, type=wtype, url=url, source="env"
                    ))

    def reload(self):
        """Reload channels from disk."""
        self._channels.clear()
        self._load_channels()

    @property
    def channels(self) -> list[NotificationChannel]:
        return self._channels

    @property
    def configured(self) -> bool:
        return any(c.enabled for c in self._channels)

    def save_channels(self, channels: list[NotificationChannel]):
        """Persist channels to JSON (admin-managed ones only)."""
        self._channels = channels
        _CHANNELS_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = [c.to_dict() for c in channels if not c.id.startswith("env-")]
        _CHANNELS_FILE.write_text(json.dumps(data, indent=2))

    def add_channel(self, channel: NotificationChannel):
        self._channels.append(channel)
        self.save_channels(self._channels)

    def remove_channel(self, channel_id: str):
        self._channels = [c for c in self._channels if c.id != channel_id]
        self.save_channels(self._channels)

    def update_channel(self, channel_id: str, updates: dict):
        for c in self._channels:
            if c.id == channel_id:
                for k, v in updates.items():
                    if hasattr(c, k):
                        setattr(c, k, v)
                break
        self.save_channels(self._channels)

    # --- Alert Dispatch ---

    async def send_alert(self, alert: AlertPayload):
        """Send alert to all matching channels."""
        if not self._channels:
            return

        dedup_key = self._make_dedup_key(alert)

        for channel in self._channels:
            if not channel.enabled:
                continue
            if not self._should_alert(alert, channel, dedup_key):
                continue
            await self._dispatch(channel, alert)

    def _should_alert(self, alert: AlertPayload, channel: NotificationChannel, dedup_key: str) -> bool:
        """Check severity, verdict filter, tenant filter, and dedup."""
        # Severity check
        sev_val = _SEVERITY_ORDER.get(alert.severity, 0)
        min_val = _SEVERITY_ORDER.get(channel.min_severity, 2)
        if sev_val < min_val:
            return False

        # Verdict filter
        if channel.verdicts and alert.verdict not in channel.verdicts:
            return False

        # Tenant filter
        if channel.tenants and alert.tenant_id not in channel.tenants:
            return False

        # Dedup
        now = time.time()
        cache_key = f"{channel.id}:{dedup_key}"
        last_sent = self._recent_alerts.get(cache_key, 0)
        if now - last_sent < channel.dedup_window_seconds:
            return False
        self._recent_alerts[cache_key] = now

        # Cleanup
        if len(self._recent_alerts) > 2000:
            cutoff = now - 600
            self._recent_alerts = {k: v for k, v in self._recent_alerts.items() if v > cutoff}

        return True

    def _make_dedup_key(self, alert: AlertPayload) -> str:
        raw = f"{alert.category}:{alert.tenant_id}:{alert.description}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0, connect=15.0),
                follow_redirects=True,
            )
        return self._client

    async def _dispatch(self, channel: NotificationChannel, alert: AlertPayload):
        """Route to the appropriate formatter/sender with retry."""
        dispatch_map = {
            "slack": self._send_slack,
            "teams": self._send_teams,
            "discord": self._send_discord,
            "pagerduty": self._send_pagerduty,
            "opsgenie": self._send_opsgenie,
            "telegram": self._send_telegram,
            "google_chat": self._send_google_chat,
            "email": self._send_email,
            "generic": self._send_generic,
        }
        sender = dispatch_map.get(channel.type, self._send_generic)

        last_err = None
        for attempt in range(3):
            try:
                await sender(channel, alert)
                logger.warning(f"notification_sent channel='{channel.name}' type={channel.type} category={alert.category} severity={alert.severity}")
                return
            except (httpx.ConnectTimeout, httpx.ConnectError) as e:
                last_err = e
                # Close and recreate client on connection errors
                if self._client and not self._client.is_closed:
                    await self._client.aclose()
                    self._client = None
                if attempt < 2:
                    await asyncio.sleep(1.0 * (attempt + 1))
            except Exception as e:
                logger.warning(f"Notification channel '{channel.name}' ({channel.type}) failed: {type(e).__name__}: {e!r}")
                return

        logger.warning(f"Notification channel '{channel.name}' ({channel.type}) failed after 3 retries: {type(last_err).__name__}: {last_err!r}")

    # --- Channel Formatters ---

    async def _send_slack(self, channel: NotificationChannel, alert: AlertPayload):
        """Slack Incoming Webhook with Block Kit."""
        emoji = {"critical": ":rotating_light:", "high": ":warning:",
                 "medium": ":large_yellow_circle:", "low": ":information_source:"}.get(alert.severity, ":bell:")
        patterns = ", ".join(alert.matched_patterns[:3]) or "N/A"

        body = {
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": f"{emoji} Sentinel Gateway — {alert.verdict.upper()}"}},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:* `{alert.severity}`"},
                    {"type": "mrkdwn", "text": f"*Category:* `{alert.category}`"},
                    {"type": "mrkdwn", "text": f"*Tenant:* `{alert.tenant_id}`"},
                    {"type": "mrkdwn", "text": f"*Agent:* `{alert.agent_id}`"},
                    {"type": "mrkdwn", "text": f"*Source:* `{alert.source_ip or 'N/A'}`"},
                    {"type": "mrkdwn", "text": f"*Patterns:* {patterns}"},
                ]},
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*Description:* {alert.description[:500]}"}},
            ]
        }
        client = await self._get_client()
        await client.post(channel.url, json=body)

    async def _send_teams(self, channel: NotificationChannel, alert: AlertPayload):
        """Microsoft Teams Incoming Webhook with Adaptive Card."""
        patterns = ", ".join(alert.matched_patterns[:3]) or "N/A"

        body = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "msteams": {"width": "Full"},
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": f"🛡️ Sentinel Gateway — {alert.verdict.upper()}",
                            "weight": "Bolder",
                            "size": "Large",
                            "color": "Attention" if alert.severity in ("critical", "high") else "Warning",
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "Severity", "value": alert.severity.upper()},
                                {"title": "Category", "value": alert.category},
                                {"title": "Tenant", "value": alert.tenant_id},
                                {"title": "Agent", "value": alert.agent_id},
                                {"title": "Source IP", "value": alert.source_ip or "N/A"},
                                {"title": "Patterns", "value": patterns},
                            ]
                        },
                        {
                            "type": "TextBlock",
                            "text": alert.description[:500],
                            "wrap": True,
                        },
                    ],
                }
            }]
        }
        client = await self._get_client()
        await client.post(channel.url, json=body)

    async def _send_discord(self, channel: NotificationChannel, alert: AlertPayload):
        """Discord Webhook with embed."""
        color = {"critical": 0xFF0000, "high": 0xFF8C00, "medium": 0xFFD700, "low": 0x4169E1}.get(alert.severity, 0x808080)
        patterns = ", ".join(alert.matched_patterns[:3]) or "N/A"

        body = {
            "embeds": [{
                "title": f"🛡️ Sentinel Gateway — {alert.verdict.upper()}",
                "color": color,
                "fields": [
                    {"name": "Severity", "value": f"`{alert.severity}`", "inline": True},
                    {"name": "Category", "value": f"`{alert.category}`", "inline": True},
                    {"name": "Tenant", "value": f"`{alert.tenant_id}`", "inline": True},
                    {"name": "Agent", "value": f"`{alert.agent_id}`", "inline": True},
                    {"name": "Source", "value": f"`{alert.source_ip or 'N/A'}`", "inline": True},
                    {"name": "Patterns", "value": patterns, "inline": True},
                    {"name": "Description", "value": alert.description[:500], "inline": False},
                ],
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(alert.timestamp)),
            }]
        }
        client = await self._get_client()
        await client.post(channel.url, json=body)

    async def _send_pagerduty(self, channel: NotificationChannel, alert: AlertPayload):
        """PagerDuty Events API v2."""
        pagerduty_severity = {"critical": "critical", "high": "error",
                              "medium": "warning", "low": "info"}.get(alert.severity, "info")
        body = {
            "routing_key": channel.routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": f"[{alert.verdict.upper()}] {alert.description[:250]}",
                "source": f"sentinel-gateway/{alert.tenant_id}",
                "severity": pagerduty_severity,
                "component": "sentinel-gateway",
                "group": alert.tenant_id,
                "class": alert.category,
                "custom_details": {
                    "agent_id": alert.agent_id,
                    "source_ip": alert.source_ip,
                    "matched_patterns": alert.matched_patterns,
                },
            },
        }
        client = await self._get_client()
        await client.post("https://events.pagerduty.com/v2/enqueue", json=body)

    async def _send_opsgenie(self, channel: NotificationChannel, alert: AlertPayload):
        """Opsgenie Alert API."""
        priority = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}.get(alert.severity, "P3")
        body = {
            "message": f"[{alert.verdict.upper()}] {alert.description[:130]}",
            "alias": self._make_dedup_key(alert),
            "priority": priority,
            "source": "sentinel-gateway",
            "tags": ["sentinel-gateway", alert.category, alert.tenant_id],
            "details": {
                "tenant_id": alert.tenant_id,
                "agent_id": alert.agent_id,
                "source_ip": alert.source_ip,
                "category": alert.category,
                "matched_patterns": ", ".join(alert.matched_patterns),
            },
        }
        client = await self._get_client()
        await client.post(
            "https://api.opsgenie.com/v2/alerts",
            json=body,
            headers={"Authorization": f"GenieKey {channel.api_key}"},
        )

    async def _send_telegram(self, channel: NotificationChannel, alert: AlertPayload):
        """Telegram Bot API — uses HTML parse mode to avoid Markdown escaping issues."""
        emoji = {"critical": "\U0001f6a8", "high": "\u26a0\ufe0f", "medium": "\U0001f7e1", "low": "\u2139\ufe0f"}.get(alert.severity, "\U0001f514")
        patterns = ", ".join(alert.matched_patterns[:3]) or "N/A"
        # Escape HTML special chars in user-provided fields
        def esc(s: str) -> str:
            return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        text = (
            f"{emoji} <b>Sentinel Gateway \u2014 {alert.verdict.upper()}</b>\n"
            f"\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
            f"\U0001f4cb <b>Severity:</b> {alert.severity.upper()}\n"
            f"\U0001f3f7 <b>Category:</b> {esc(alert.category)}\n"
            f"\U0001f3e2 <b>Tenant:</b> {esc(alert.tenant_id)}\n"
            f"\U0001f916 <b>Agent:</b> {esc(alert.agent_id)}\n"
            f"\U0001f310 <b>Source IP:</b> {esc(alert.source_ip or 'N/A')}\n"
            f"\U0001f50d <b>Patterns:</b> {esc(patterns)}\n"
            f"\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
            f"<i>{esc(alert.description[:400])}</i>"
        )
        client = await self._get_client()
        resp = await client.post(
            f"https://api.telegram.org/bot{channel.bot_token}/sendMessage",
            json={"chat_id": channel.chat_id, "text": text, "parse_mode": "HTML"},
        )
        if resp.status_code != 200:
            data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            raise RuntimeError(f"Telegram API error ({resp.status_code}): {data.get('description', resp.text[:200])}")

    async def _send_google_chat(self, channel: NotificationChannel, alert: AlertPayload):
        """Google Chat (Workspace) Webhook."""
        patterns = ", ".join(alert.matched_patterns[:3]) or "N/A"
        body = {
            "cards": [{
                "header": {"title": f"🛡️ Sentinel Gateway — {alert.verdict.upper()}", "subtitle": alert.category},
                "sections": [{
                    "widgets": [
                        {"keyValue": {"topLabel": "Severity", "content": alert.severity.upper()}},
                        {"keyValue": {"topLabel": "Tenant", "content": alert.tenant_id}},
                        {"keyValue": {"topLabel": "Agent", "content": alert.agent_id}},
                        {"keyValue": {"topLabel": "Patterns", "content": patterns}},
                        {"textParagraph": {"text": alert.description[:500]}},
                    ]
                }]
            }]
        }
        client = await self._get_client()
        await client.post(channel.url, json=body)

    async def _send_email(self, channel: NotificationChannel, alert: AlertPayload):
        """Send email via SMTP (SendGrid, Gmail, O365, custom relay)."""
        if not channel.smtp_to:
            return

        severity_color = {"critical": "#FF0000", "high": "#FF8C00",
                          "medium": "#FFD700", "low": "#4169E1"}.get(alert.severity, "#808080")
        patterns = ", ".join(alert.matched_patterns[:5]) or "N/A"

        subject = f"[Sentinel Gateway] [{alert.severity.upper()}] {alert.description[:80]}"

        html_body = f"""
<html><body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px;">
<div style="border-left: 4px solid {severity_color}; padding: 16px; margin: 16px 0; background: #f9f9f9;">
  <h2 style="margin: 0 0 12px 0; color: #333;">🛡️ Sentinel Gateway — {alert.verdict.upper()}</h2>
  <table style="border-collapse: collapse; width: 100%;">
    <tr><td style="padding: 4px 12px 4px 0; font-weight: bold; color: #555;">Severity</td>
        <td style="padding: 4px 0;"><span style="background: {severity_color}; color: white; padding: 2px 8px; border-radius: 4px;">{alert.severity.upper()}</span></td></tr>
    <tr><td style="padding: 4px 12px 4px 0; font-weight: bold; color: #555;">Category</td>
        <td style="padding: 4px 0;">{alert.category}</td></tr>
    <tr><td style="padding: 4px 12px 4px 0; font-weight: bold; color: #555;">Tenant</td>
        <td style="padding: 4px 0;"><code>{alert.tenant_id}</code></td></tr>
    <tr><td style="padding: 4px 12px 4px 0; font-weight: bold; color: #555;">Agent</td>
        <td style="padding: 4px 0;"><code>{alert.agent_id}</code></td></tr>
    <tr><td style="padding: 4px 12px 4px 0; font-weight: bold; color: #555;">Source IP</td>
        <td style="padding: 4px 0;"><code>{alert.source_ip or 'N/A'}</code></td></tr>
    <tr><td style="padding: 4px 12px 4px 0; font-weight: bold; color: #555;">Patterns</td>
        <td style="padding: 4px 0;">{patterns}</td></tr>
  </table>
  <hr style="border: none; border-top: 1px solid #ddd; margin: 12px 0;">
  <p style="color: #333; margin: 0;">{alert.description[:1000]}</p>
</div>
<p style="color: #999; font-size: 12px;">Sent by Sentinel Gateway Notification Engine</p>
</body></html>"""

        # Run SMTP in thread to avoid blocking event loop
        await asyncio.to_thread(
            self._send_smtp, channel, subject, html_body
        )

    def _send_smtp(self, channel: NotificationChannel, subject: str, html_body: str):
        """Synchronous SMTP send (called in thread)."""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = channel.smtp_from or channel.smtp_user
        msg["To"] = ", ".join(channel.smtp_to)
        msg.attach(MIMEText(html_body, "html"))

        try:
            if channel.smtp_tls == "ssl":
                # Direct SSL (port 465)
                context = ssl.create_default_context()
                with smtplib.SMTP_SSL(channel.smtp_host, channel.smtp_port, context=context) as server:
                    if channel.smtp_user:
                        server.login(channel.smtp_user, channel.smtp_password)
                    server.sendmail(msg["From"], channel.smtp_to, msg.as_string())
            else:
                # STARTTLS (port 587) or plain (port 25)
                with smtplib.SMTP(channel.smtp_host, channel.smtp_port, timeout=10) as server:
                    server.ehlo()
                    if channel.smtp_tls == "starttls":
                        context = ssl.create_default_context()
                        server.starttls(context=context)
                        server.ehlo()
                    if channel.smtp_user:
                        server.login(channel.smtp_user, channel.smtp_password)
                    server.sendmail(msg["From"], channel.smtp_to, msg.as_string())
        except Exception as e:
            logger.error(f"SMTP send failed ({channel.smtp_host}): {e}")

    async def _send_generic(self, channel: NotificationChannel, alert: AlertPayload):
        """Generic HTTP webhook (JSON POST)."""
        body = {
            "source": "sentinel-gateway",
            "verdict": alert.verdict,
            "severity": alert.severity,
            "category": alert.category,
            "description": alert.description,
            "tenant_id": alert.tenant_id,
            "agent_id": alert.agent_id,
            "source_ip": alert.source_ip,
            "matched_patterns": alert.matched_patterns,
            "timestamp": alert.timestamp,
        }
        headers = {"Content-Type": "application/json"}
        headers.update(channel.headers)

        if channel.auth_type == "bearer":
            headers["Authorization"] = f"Bearer {channel.auth_value}"
        elif channel.auth_type == "api_key":
            headers["X-API-Key"] = channel.auth_value

        client = await self._get_client()
        await client.post(channel.url, json=body, headers=headers)

    # --- Test ---

    async def test_channel(self, channel: NotificationChannel) -> dict:
        """Send a test notification to verify connectivity."""
        test_alert = AlertPayload(
            verdict="block",
            severity="high",
            category="connectivity_test",
            description="Sentinel Gateway notification channel verification. This confirms the integration is operational and alerts will be delivered to this endpoint.",
            tenant_id="system",
            agent_id="sentinel-gateway",
            source_ip="10.0.0.1",
            matched_patterns=["channel_test"],
        )
        try:
            dispatch_map = {
                "slack": self._send_slack,
                "teams": self._send_teams,
                "discord": self._send_discord,
                "pagerduty": self._send_pagerduty,
                "opsgenie": self._send_opsgenie,
                "telegram": self._send_telegram,
                "google_chat": self._send_google_chat,
                "email": self._send_email,
                "generic": self._send_generic,
            }
            sender = dispatch_map.get(channel.type, self._send_generic)
            await sender(channel, test_alert)
            return {"success": True, "message": "Test notification sent successfully"}
        except Exception as e:
            return {"success": False, "message": str(e)}

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()


# Singleton
_engine: Optional[NotificationEngine] = None


def get_notification_engine() -> NotificationEngine:
    global _engine
    if _engine is None:
        _engine = NotificationEngine()
    return _engine
