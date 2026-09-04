"""Integration registry — config store, secret resolution, health cache, factory.

The registry is the admin-facing control surface for outbound integrations. It
owns:

* **Config persistence** — a list of :class:`IntegrationConfig` records in
  ``data/integrations.json`` (PVC-mounted in k8s), mirroring the notification
  channel store. Secrets are masked in every API response.
* **Secret resolution** — an integration's API key may live inline in the config
  or be injected out-of-band via ``BULWARK_INTEGRATION_<ID>_API_KEY`` / its
  ``_FILE`` Docker-secret variant, so operators never have to write a key to
  disk.
* **Connector factory** — turns a config into a live
  :class:`~admin.services.integrations.base.Connector`.
* **Health cache** — short-TTL cache of the last reachability probe so the health
  panel is cheap to render and never hammers a remote platform.

Everything is fail-open: a malformed config file degrades to an empty registry,
and a connector that cannot be built is simply reported unhealthy.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..secrets import read_secret
from .base import Connector, ConnectorHealth
from .cortex import CortexConnector
from .dfir_iris import DfirIrisConnector
from .misp import MispConnector
from .opencti import OpenCTIConnector
from .taxii import TaxiiConnector
from .thehive import TheHiveConnector
from .util import iso_now

logger = logging.getLogger(__name__)

# Persistent storage path — uses data/ (mounted as a PVC in k8s), same convention
# as the notification channel store.
_CONFIG_FILE = Path(
    os.environ.get("BULWARK_INTEGRATIONS_FILE", "data/integrations.json")
)

# Supported connector types. ``thehive`` / ``dfir_iris`` are case *push* targets
# (they implement the ``Connector`` protocol); ``cortex`` and ``opencti`` are
# *enrichment* targets (observable analysis / threat-intel lookup), built via
# :meth:`build_enrichment_connector` / :meth:`build_lookup_connector`. ``misp`` is
# both a *push* target (case → Event) and a *lookup* target (attribute search).
# ``taxii`` is a case *publish* target (case → STIX 2.1 bundle into a writable
# TAXII 2.1 collection), the standards-based counterpart to the vendor push targets.
INTEGRATION_TYPES = ("thehive", "dfir_iris", "cortex", "opencti", "misp", "taxii")

# How long a health probe result is cached before a fresh probe is allowed.
_HEALTH_TTL_SECONDS = 30.0


@dataclass
class IntegrationConfig:
    """A single outbound integration target."""

    id: str
    name: str
    type: str  # thehive | dfir_iris
    enabled: bool = True
    base_url: str = ""
    api_key: str = ""
    verify_tls: bool = True
    timeout: float = 15.0
    # TheHive-specific
    organisation: str = ""
    # DFIR-IRIS-specific
    customer_id: int = 1
    source: str = "config"  # config | env
    # Managed IOC feed (opencti | misp only): when on, this connector's
    # credential is reused to auto-provision an inbound IOC feed in the IOC
    # store (id ``int-<id>``), eliminating a separate feed configuration.
    pull_feed: bool = False
    pull_interval_minutes: int = 1440
    pull_min_confidence: float = 0.7

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "enabled": self.enabled,
            "base_url": self.base_url,
            "api_key": self.api_key,
            "verify_tls": self.verify_tls,
            "timeout": self.timeout,
            "organisation": self.organisation,
            "customer_id": self.customer_id,
            "source": self.source,
            "pull_feed": self.pull_feed,
            "pull_interval_minutes": self.pull_interval_minutes,
            "pull_min_confidence": self.pull_min_confidence,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "IntegrationConfig":
        pmc = d.get("pull_min_confidence")
        return cls(
            id=str(d.get("id") or ""),
            name=str(d.get("name") or ""),
            type=str(d.get("type") or ""),
            enabled=bool(d.get("enabled", True)),
            base_url=str(d.get("base_url") or ""),
            api_key=str(d.get("api_key") or ""),
            verify_tls=bool(d.get("verify_tls", True)),
            timeout=float(d.get("timeout") or 15.0),
            organisation=str(d.get("organisation") or ""),
            customer_id=int(d.get("customer_id") or 1),
            source=str(d.get("source") or "config"),
            pull_feed=bool(d.get("pull_feed", False)),
            pull_interval_minutes=int(d.get("pull_interval_minutes") or 1440),
            pull_min_confidence=float(pmc if pmc is not None else 0.7),
        )


class IntegrationRegistry:
    """Owns integration configs, secret resolution, health cache and the factory."""

    def __init__(self) -> None:
        self._configs: list[IntegrationConfig] = []
        self._health: dict[str, tuple[ConnectorHealth, float]] = {}
        self.reload()

    # ─── Config persistence ───────────────────────────────────────────────────

    def reload(self) -> None:
        """(Re)load configs from disk. A malformed file degrades to empty."""
        self._configs = self._load()

    def _load(self) -> list[IntegrationConfig]:
        if not _CONFIG_FILE.is_file():
            return []
        try:
            raw = json.loads(_CONFIG_FILE.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("integrations_config_load_failed", extra={"error": str(exc)})
            return []
        items = raw.get("integrations") if isinstance(raw, dict) else raw
        if not isinstance(items, list):
            return []
        configs: list[IntegrationConfig] = []
        for item in items:
            if isinstance(item, dict) and item.get("id") and item.get("type"):
                configs.append(IntegrationConfig.from_dict(item))
        return configs

    def _save(self) -> None:
        _CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        payload = {"integrations": [c.to_dict() for c in self._configs]}
        tmp = _CONFIG_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2))
        tmp.replace(_CONFIG_FILE)

    # ─── Reads ────────────────────────────────────────────────────────────────

    @property
    def configs(self) -> list[IntegrationConfig]:
        return list(self._configs)

    def get(self, integration_id: str) -> Optional[IntegrationConfig]:
        for c in self._configs:
            if c.id == integration_id:
                return c
        return None

    # ─── Writes ───────────────────────────────────────────────────────────────

    def add(self, config: IntegrationConfig) -> None:
        if self.get(config.id) is not None:
            raise ValueError(f"integration '{config.id}' already exists")
        self._configs.append(config)
        self._save()

    def update(self, integration_id: str, fields: dict) -> Optional[IntegrationConfig]:
        config = self.get(integration_id)
        if config is None:
            return None
        merged = config.to_dict()
        for key, value in fields.items():
            if key in merged and key != "id":
                merged[key] = value
        updated = IntegrationConfig.from_dict(merged)
        self._configs = [updated if c.id == integration_id else c for c in self._configs]
        self._save()
        self._health.pop(integration_id, None)
        return updated

    def remove(self, integration_id: str) -> bool:
        if self.get(integration_id) is None:
            return False
        self._configs = [c for c in self._configs if c.id != integration_id]
        self._save()
        self._health.pop(integration_id, None)
        return True

    def toggle(self, integration_id: str) -> Optional[bool]:
        config = self.get(integration_id)
        if config is None:
            return None
        config.enabled = not config.enabled
        self._save()
        return config.enabled

    # ─── Secret resolution ────────────────────────────────────────────────────

    def _resolve_api_key(self, config: IntegrationConfig) -> str:
        """Resolve an integration's API key (inline config or Docker secret/env).

        Priority: an out-of-band ``BULWARK_INTEGRATION_<ID>_API_KEY`` (or its
        ``_FILE`` variant) wins over an inline value, so operators can keep the
        secret off disk. Falls back to the inline config value.
        """
        env_name = f"BULWARK_INTEGRATION_{config.id.upper()}_API_KEY"
        resolved = read_secret(env_name, default="")
        return resolved or config.api_key

    # ─── Connector factory ────────────────────────────────────────────────────

    def build_connector(self, config: IntegrationConfig) -> Optional[Connector]:
        """Build a live connector from a config, or ``None`` if not buildable."""
        api_key = self._resolve_api_key(config)
        if not config.base_url or not api_key:
            return None
        if config.type == "thehive":
            return TheHiveConnector(
                base_url=config.base_url,
                api_key=api_key,
                organisation=config.organisation,
                verify_tls=config.verify_tls,
                timeout=config.timeout,
            )
        if config.type == "dfir_iris":
            return DfirIrisConnector(
                base_url=config.base_url,
                api_key=api_key,
                customer_id=config.customer_id,
                verify_tls=config.verify_tls,
                timeout=config.timeout,
            )
        if config.type == "opencti":
            # OpenCTI implements the push protocol (case → SCOs/indicators/report)
            # in addition to lookup, so it is a valid ``/push/case`` target.
            return OpenCTIConnector(
                base_url=config.base_url,
                api_key=api_key,
                verify_tls=config.verify_tls,
                timeout=config.timeout,
            )
        if config.type == "misp":
            # MISP implements the push protocol (case → Event/Attributes) in
            # addition to lookup, so it is a valid ``/push/case`` target.
            return MispConnector(
                base_url=config.base_url,
                api_key=api_key,
                verify_tls=config.verify_tls,
                timeout=config.timeout,
            )
        if config.type == "taxii":
            # TAXII publishes a case as a STIX 2.1 bundle into a writable collection
            # (the "Add Objects" operation), so it is a valid ``/push/case`` target.
            return TaxiiConnector(
                base_url=config.base_url,
                api_key=api_key,
                verify_tls=config.verify_tls,
                timeout=config.timeout,
            )
        return None

    def build_enrichment_connector(
        self, config: IntegrationConfig
    ) -> Optional[CortexConnector]:
        """Build an enrichment connector (Cortex) from a config, or ``None``.

        Enrichment connectors do not implement the ``Connector`` *push* protocol,
        so they are built separately from :meth:`build_connector`. Returns ``None``
        for non-enrichment types or an incompletely configured target.
        """
        if config.type != "cortex":
            return None
        api_key = self._resolve_api_key(config)
        if not config.base_url or not api_key:
            return None
        return CortexConnector(
            base_url=config.base_url,
            api_key=api_key,
            verify_tls=config.verify_tls,
            timeout=config.timeout,
        )

    def build_lookup_connector(
        self, config: IntegrationConfig
    ) -> Optional[OpenCTIConnector | MispConnector]:
        """Build a threat-intel lookup connector (OpenCTI or MISP), or ``None``.

        Both platforms expose an observable ``lookup_observable`` surface. Like the
        enrichment factory, lookup connectors are built separately from
        :meth:`build_connector`. Returns ``None`` for a non-lookup type or an
        incompletely configured target.
        """
        if config.type not in ("opencti", "misp"):
            return None
        api_key = self._resolve_api_key(config)
        if not config.base_url or not api_key:
            return None
        if config.type == "misp":
            return MispConnector(
                base_url=config.base_url,
                api_key=api_key,
                verify_tls=config.verify_tls,
                timeout=config.timeout,
            )
        return OpenCTIConnector(
            base_url=config.base_url,
            api_key=api_key,
            verify_tls=config.verify_tls,
            timeout=config.timeout,
        )

    # ─── Health cache ─────────────────────────────────────────────────────────

    async def health(self, integration_id: str, *, force: bool = False) -> ConnectorHealth:
        """Return a (cached) health snapshot, probing the remote when stale."""
        config = self.get(integration_id)
        if config is None:
            return ConnectorHealth(ok=False, detail="unknown integration", checked_at=iso_now())

        cached = self._health.get(integration_id)
        if cached is not None and not force:
            snapshot, ts = cached
            if time.time() - ts < _HEALTH_TTL_SECONDS:
                return snapshot

        # Probe whichever connector kind this config maps to — push targets via
        # ``build_connector``, enrichment targets (Cortex) via the enrichment
        # factory, lookup targets (OpenCTI) via the lookup factory. All expose
        # ``test_connection``.
        probe = (
            self.build_connector(config)
            or self.build_enrichment_connector(config)
            or self.build_lookup_connector(config)
        )
        if probe is None:
            snapshot = ConnectorHealth(
                ok=False, detail="incomplete configuration", checked_at=iso_now()
            )
        else:
            snapshot = await probe.test_connection()
        self._health[integration_id] = (snapshot, time.time())
        return snapshot


_registry: Optional[IntegrationRegistry] = None


def get_integration_registry() -> IntegrationRegistry:
    """Return the process-wide :class:`IntegrationRegistry` singleton."""
    global _registry
    if _registry is None:
        _registry = IntegrationRegistry()
    return _registry
