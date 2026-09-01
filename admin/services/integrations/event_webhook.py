"""Outbound event-webhook emitter — SOAR trigger seed (Investigation Phase 1.3).

A small, dependency-light dispatcher that fires structured JSON to admin-configured
HTTP endpoints on case **lifecycle events** (``case.opened``,
``case.severity_raised``, ``case.resolved``). This is the trigger surface a SOAR
runner (Shuffle / n8n) subscribes to; Phase 3 layers HMAC signing and versioned
payload schemas on top of exactly this shape.

Design mirrors the connector registry:

* **Config persistence** — a list of :class:`WebhookSubscription` records in
  ``data/integration_webhooks.json`` (PVC-mounted in k8s), overridable via
  ``BULWARK_INTEGRATION_WEBHOOKS_FILE``.
* **Event filtering** — a subscription with an empty ``events`` list receives every
  event; otherwise only the named ones.
* **Fail-open** — a slow or dead endpoint never delays or breaks case management.
  Each delivery is bounded by a short timeout, dispatched concurrently, and every
  error is swallowed (logged) rather than raised. A malformed config file degrades
  to no subscriptions.

Deliberately *not* here (Phase 3): HMAC request signing, retry/circuit breaking
(this is best-effort fan-out, not a durable queue), and the inbound action API.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx

from .util import iso_now

logger = logging.getLogger(__name__)

# Persistent storage path — data/ is a PVC in k8s, same convention as the
# integration + notification channel stores.
_CONFIG_FILE = Path(
    os.environ.get(
        "BULWARK_INTEGRATION_WEBHOOKS_FILE", "data/integration_webhooks.json"
    )
)

# Case lifecycle events the admin currently emits. A subscription may still name an
# event outside this set (forward-compatible), but these are what fire today.
EVENT_TYPES = ("case.opened", "case.severity_raised", "case.resolved")

# Per-delivery timeout — best-effort fan-out must never tie up an admin worker.
_DELIVERY_TIMEOUT_SECONDS = 5.0


@dataclass
class WebhookSubscription:
    """A single outbound event-webhook target."""

    id: str
    name: str
    url: str
    events: list[str] = field(default_factory=list)  # empty ⇒ all events
    enabled: bool = True
    verify_tls: bool = True

    def wants(self, event_type: str) -> bool:
        """True if this subscription should receive ``event_type``."""
        return self.enabled and (not self.events or event_type in self.events)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "url": self.url,
            "events": list(self.events),
            "enabled": self.enabled,
            "verify_tls": self.verify_tls,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "WebhookSubscription":
        raw_events = d.get("events") or []
        events = [str(e) for e in raw_events] if isinstance(raw_events, list) else []
        return cls(
            id=str(d.get("id") or ""),
            name=str(d.get("name") or ""),
            url=str(d.get("url") or ""),
            events=events,
            enabled=bool(d.get("enabled", True)),
            verify_tls=bool(d.get("verify_tls", True)),
        )


@dataclass
class DeliveryResult:
    """Outcome of a single webhook POST (surfaced by the test endpoint)."""

    subscription_id: str
    ok: bool
    detail: str = ""


class EventWebhookEmitter:
    """Owns webhook subscriptions and the best-effort lifecycle fan-out."""

    def __init__(self) -> None:
        self._subs: list[WebhookSubscription] = []
        self.reload()

    # ─── Config persistence ───────────────────────────────────────────────────

    def reload(self) -> None:
        """(Re)load subscriptions from disk. A malformed file degrades to empty."""
        self._subs = self._load()

    def _load(self) -> list[WebhookSubscription]:
        if not _CONFIG_FILE.is_file():
            return []
        try:
            raw = json.loads(_CONFIG_FILE.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("event_webhooks_load_failed", extra={"error": str(exc)})
            return []
        items = raw.get("webhooks") if isinstance(raw, dict) else raw
        if not isinstance(items, list):
            return []
        subs: list[WebhookSubscription] = []
        for item in items:
            if isinstance(item, dict) and item.get("id") and item.get("url"):
                subs.append(WebhookSubscription.from_dict(item))
        return subs

    def _save(self) -> None:
        _CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        payload = {"webhooks": [s.to_dict() for s in self._subs]}
        tmp = _CONFIG_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2))
        tmp.replace(_CONFIG_FILE)

    # ─── Reads ────────────────────────────────────────────────────────────────

    @property
    def subscriptions(self) -> list[WebhookSubscription]:
        return list(self._subs)

    def get(self, subscription_id: str) -> Optional[WebhookSubscription]:
        for s in self._subs:
            if s.id == subscription_id:
                return s
        return None

    # ─── Writes ───────────────────────────────────────────────────────────────

    def add(self, sub: WebhookSubscription) -> None:
        if self.get(sub.id) is not None:
            raise ValueError(f"webhook '{sub.id}' already exists")
        self._subs.append(sub)
        self._save()

    def update(
        self, subscription_id: str, fields: dict
    ) -> Optional[WebhookSubscription]:
        sub = self.get(subscription_id)
        if sub is None:
            return None
        merged = sub.to_dict()
        for key, value in fields.items():
            if key in merged and key != "id":
                merged[key] = value
        updated = WebhookSubscription.from_dict(merged)
        self._subs = [updated if s.id == subscription_id else s for s in self._subs]
        self._save()
        return updated

    def remove(self, subscription_id: str) -> bool:
        if self.get(subscription_id) is None:
            return False
        self._subs = [s for s in self._subs if s.id != subscription_id]
        self._save()
        return True

    def toggle(self, subscription_id: str) -> Optional[bool]:
        sub = self.get(subscription_id)
        if sub is None:
            return None
        sub.enabled = not sub.enabled
        self._save()
        return sub.enabled

    # ─── Dispatch ─────────────────────────────────────────────────────────────

    @staticmethod
    def _envelope(event_type: str, tenant: Optional[str], data: Optional[dict]) -> dict:
        """Build the stable event envelope POSTed to every subscriber."""
        return {
            "event": event_type,
            "event_id": f"evt_{uuid.uuid4().hex[:16]}",
            "timestamp": iso_now(),
            "tenant": tenant,
            "data": data or {},
        }

    async def _deliver(
        self, sub: WebhookSubscription, envelope: dict
    ) -> DeliveryResult:
        """POST one envelope to one subscriber. Never raises (fail-open)."""
        try:
            async with httpx.AsyncClient(
                timeout=_DELIVERY_TIMEOUT_SECONDS, verify=sub.verify_tls
            ) as client:
                resp = await client.post(sub.url, json=envelope)
        except (httpx.HTTPError, OSError) as exc:
            detail = f"{type(exc).__name__}: {exc}"
            logger.warning(
                "event_webhook_delivery_failed",
                extra={"subscription": sub.id, "error": detail},
            )
            return DeliveryResult(subscription_id=sub.id, ok=False, detail=detail)
        ok = 200 <= resp.status_code < 300
        return DeliveryResult(
            subscription_id=sub.id, ok=ok, detail=f"HTTP {resp.status_code}"
        )

    async def emit(
        self, event_type: str, *, tenant: Optional[str] = None, data: Optional[dict] = None
    ) -> list[DeliveryResult]:
        """Fan a lifecycle event out to every matching subscription (best-effort).

        Returns immediately with an empty list when no enabled subscription wants
        the event, so the common unconfigured path costs nothing. Otherwise all
        matching deliveries run concurrently under a short timeout; failures are
        swallowed and reported in the result list, never raised.
        """
        targets = [s for s in self._subs if s.wants(event_type)]
        if not targets:
            return []
        envelope = self._envelope(event_type, tenant, data)
        results = await asyncio.gather(
            *(self._deliver(s, envelope) for s in targets)
        )
        return list(results)

    async def test(self, subscription_id: str) -> DeliveryResult:
        """Send a synthetic ``test.ping`` to one subscription (ignores filters)."""
        sub = self.get(subscription_id)
        if sub is None:
            return DeliveryResult(
                subscription_id=subscription_id, ok=False, detail="unknown subscription"
            )
        envelope = self._envelope("test.ping", None, {"message": "bulwark test event"})
        return await self._deliver(sub, envelope)


_emitter: Optional[EventWebhookEmitter] = None


def get_event_webhook_emitter() -> EventWebhookEmitter:
    """Return the process-wide :class:`EventWebhookEmitter` singleton."""
    global _emitter
    if _emitter is None:
        _emitter = EventWebhookEmitter()
    return _emitter
