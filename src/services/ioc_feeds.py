"""IOC Feed Service — Fetches threat intelligence from multiple sources.

Supports:
- URLhaus (abuse.ch) — malicious URLs → domain extraction
- ThreatFox (abuse.ch) — domain/URL IOCs (last 7 days)
- AlienVault OTX — domain indicators from subscribed pulses
- AbuseIPDB — malicious IPs (confidence >= 90%)

All feeds are independent; failures are non-fatal (logged, skipped).
Results merge into config/iocs.json via IOCManager.
"""

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx
import structlog

logger = structlog.get_logger()

FEED_TIMEOUT = 30.0


@dataclass
class FeedResult:
    """Result from a single feed import."""

    source: str
    success: bool
    domains_added: int = 0
    ips_added: int = 0
    urls_added: int = 0
    error: str | None = None
    duration_ms: float = 0.0


@dataclass
class IOCUpdate:
    """Aggregated IOC update from all feeds."""

    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    results: list[FeedResult] = field(default_factory=list)
    total_domains_added: int = 0
    total_ips_added: int = 0

    @property
    def success(self) -> bool:
        return any(r.success for r in self.results)


def _extract_domain(url: str) -> str | None:
    """Extract domain from URL, skip IPs and hashes."""
    try:
        if "://" in url:
            parsed = urlparse(url)
            host = parsed.hostname or ""
        else:
            host = url.split(":")[0].split("/")[0].strip()

        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
            return None
        if re.match(r"^[a-fA-F0-9]{32,}$", host):
            return None
        if "." in host and len(host) > 3:
            return host.lower()
    except Exception:
        pass
    return None


class IOCFeedService:
    """Fetches IOCs from threat intelligence feeds and merges into local database."""

    def __init__(self, ioc_path: Path, config: dict | None = None):
        self.ioc_path = ioc_path
        self.config = config or {}
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            # SECURITY (C-03 fix): Disable redirect following to prevent SSRF
            # via open redirects in compromised feed endpoints.
            self._client = httpx.AsyncClient(timeout=FEED_TIMEOUT, follow_redirects=False)
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    def _load_iocs(self) -> dict:
        if self.ioc_path.exists():
            with open(self.ioc_path) as f:
                return json.load(f)
        return {"domains": [], "ips": [], "urls": [], "hashes": []}

    def _save_iocs(self, iocs: dict):
        for key in ("domains", "ips", "urls", "hashes"):
            if key in iocs:
                iocs[key] = sorted(set(iocs[key]))
        iocs["_metadata"] = {
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "counts": {k: len(v) for k, v in iocs.items() if k not in ("_metadata",)},
        }
        with open(self.ioc_path, "w") as f:
            json.dump(iocs, f, indent=2)

    async def update_all(self, keys: dict | None = None) -> IOCUpdate:
        """Run all feed importers. keys: {urlhaus_key, threatfox_key, otx_key, abuseipdb_key}."""
        keys = keys or {}
        update = IOCUpdate()

        feeders = [
            ("urlhaus", self._import_urlhaus, keys.get("urlhaus_key")),
            ("threatfox", self._import_threatfox, keys.get("threatfox_key")),
            ("otx", self._import_otx, keys.get("otx_key")),
            ("abuseipdb", self._import_abuseipdb, keys.get("abuseipdb_key")),
        ]

        for name, importer, api_key in feeders:
            if not api_key:
                await logger.ainfo("ioc_feed_skipped", feed=name, reason="no_api_key")
                update.results.append(FeedResult(source=name, success=False, error="no_api_key"))
                continue
            try:
                result = await importer(api_key)
                update.results.append(result)
                update.total_domains_added += result.domains_added
                update.total_ips_added += result.ips_added
            except Exception as e:
                await logger.aerror("ioc_feed_error", feed=name, error=str(e)[:200])
                update.results.append(FeedResult(source=name, success=False, error=str(e)[:200]))

        await self.close()
        return update

    async def _import_urlhaus(self, api_key: str) -> FeedResult:
        """Import from URLhaus — recent malicious URLs."""
        start = time.monotonic()
        client = await self._get_client()
        resp = await client.get(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/",
            headers={"Auth-Key": api_key},
        )
        resp.raise_for_status()
        data = resp.json()

        iocs = self._load_iocs()
        existing = set(iocs.get("domains", []))
        urls_list = data.get("urls", [])

        added = 0
        for entry in urls_list:
            domain = _extract_domain(entry.get("url", ""))
            if domain and domain not in existing:
                iocs.setdefault("domains", []).append(domain)
                existing.add(domain)
                added += 1

        self._save_iocs(iocs)
        await logger.ainfo(
            "ioc_feed_complete", feed="urlhaus", processed=len(urls_list), added=added
        )
        return FeedResult(
            source="urlhaus",
            success=True,
            domains_added=added,
            duration_ms=(time.monotonic() - start) * 1000,
        )

    async def _import_threatfox(self, api_key: str) -> FeedResult:
        """Import from ThreatFox — domain/URL IOCs last 7 days."""
        start = time.monotonic()
        client = await self._get_client()
        resp = await client.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": api_key, "Content-Type": "application/json"},
            json={"query": "get_iocs", "days": 7},
        )
        resp.raise_for_status()
        data = resp.json()

        iocs = self._load_iocs()
        existing = set(iocs.get("domains", []))
        items = data.get("data", [])
        if not isinstance(items, list):
            return FeedResult(source="threatfox", success=False, error="unexpected response format")

        added = 0
        for entry in items:
            if entry.get("ioc_type", "") not in ("domain", "url"):
                continue
            domain = _extract_domain(entry.get("ioc", ""))
            if domain and domain not in existing:
                iocs.setdefault("domains", []).append(domain)
                existing.add(domain)
                added += 1

        self._save_iocs(iocs)
        await logger.ainfo("ioc_feed_complete", feed="threatfox", processed=len(items), added=added)
        return FeedResult(
            source="threatfox",
            success=True,
            domains_added=added,
            duration_ms=(time.monotonic() - start) * 1000,
        )

    async def _import_otx(self, api_key: str) -> FeedResult:
        """Import from AlienVault OTX — domain indicators from subscribed pulses."""
        start = time.monotonic()
        client = await self._get_client()
        resp = await client.get(
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            params={"limit": 50},
            headers={"X-OTX-API-KEY": api_key},
        )
        resp.raise_for_status()
        data = resp.json()

        iocs = self._load_iocs()
        existing = set(iocs.get("domains", []))
        pulses = data.get("results", [])

        added = 0
        for pulse in pulses:
            for ind in pulse.get("indicators", []):
                if ind.get("type") == "domain":
                    value = ind.get("indicator", "").lower()
                    if value and value not in existing:
                        iocs.setdefault("domains", []).append(value)
                        existing.add(value)
                        added += 1

        self._save_iocs(iocs)
        await logger.ainfo("ioc_feed_complete", feed="otx", pulses=len(pulses), added=added)
        return FeedResult(
            source="otx",
            success=True,
            domains_added=added,
            duration_ms=(time.monotonic() - start) * 1000,
        )

    async def _import_abuseipdb(self, api_key: str) -> FeedResult:
        """Import from AbuseIPDB — blacklisted IPs with confidence >= 90%."""
        start = time.monotonic()
        client = await self._get_client()
        resp = await client.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            params={"confidenceMinimum": 90, "limit": 500},
            headers={"Key": api_key, "Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()

        iocs = self._load_iocs()
        existing = set(iocs.get("ips", []))
        items = data.get("data", [])

        added = 0
        for entry in items:
            ip = entry.get("ipAddress", "")
            if ip and entry.get("abuseConfidenceScore", 0) >= 90 and ip not in existing:
                iocs.setdefault("ips", []).append(ip)
                existing.add(ip)
                added += 1

        self._save_iocs(iocs)
        await logger.ainfo("ioc_feed_complete", feed="abuseipdb", processed=len(items), added=added)
        return FeedResult(
            source="abuseipdb",
            success=True,
            ips_added=added,
            duration_ms=(time.monotonic() - start) * 1000,
        )
