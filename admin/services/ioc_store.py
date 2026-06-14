"""IOC Store — Thread-safe IOC management service with backward-compatible persistence."""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import os
import socket
import threading
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from admin.models.iocs import (
    FeedConfig,
    FeedCreate,
    FeedType,
    FeedUpdate,
    IOCCreate,
    IOCEntry,
    IOCSeverity,
    IOCStats,
    IOCType,
    IOCUpdate,
)

_DEFAULT_IOC_PATH = Path(os.environ.get("SENTINEL_IOC_PATH", "data/iocs.json"))
_LEGACY_IOC_PATH = Path("config/iocs.json")
FEED_STATE_PATH = Path("data/feed_state.json")

# SECURITY FIX (C-03): SSRF blocklist for feed URL validation
_BLOCKED_SSRF_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]
_BLOCKED_HOSTNAMES = {"metadata.google.internal", "localhost", "kubernetes.default", "kubernetes.default.svc"}


def _validate_url_no_ssrf(url: str) -> str | None:
    """Returns error message if URL is an SSRF target, None if safe."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        return "Empty hostname"
    if hostname in _BLOCKED_HOSTNAMES:
        return f"Blocked hostname: {hostname}"
    if hostname.endswith(".internal") or hostname.endswith(".local"):
        return f"Blocked internal hostname: {hostname}"
    try:
        addr_infos = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError):
        return f"Cannot resolve hostname: {hostname}"
    for info in addr_infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
            for net in _BLOCKED_SSRF_NETWORKS:
                if ip in net:
                    return f"IP {ip_str} in blocked range {net}"
        except ValueError:
            return f"Invalid IP: {ip_str}"
    return None  # Safe

# Map flat JSON keys to IOCType
_KEY_TO_TYPE: dict[str, IOCType] = {
    "domains": IOCType.DOMAIN,
    "ips": IOCType.IP,
    "urls": IOCType.URL,
    "hashes": IOCType.HASH_SHA256,
}

_TYPE_TO_KEY: dict[IOCType, str] = {
    IOCType.DOMAIN: "domains",
    IOCType.IP: "ips",
    IOCType.URL: "urls",
    IOCType.HASH_MD5: "hashes",
    IOCType.HASH_SHA256: "hashes",
}


def _generate_id(ioc_type: str, value: str) -> str:
    """Deterministic ID from type+value."""
    digest = hashlib.sha256(f"{ioc_type}:{value}".encode()).hexdigest()[:12]
    return f"ioc-{digest}"


class IOCStore:
    """Thread-safe IOC management with flat-file persistence."""

    def __init__(self, ioc_path: Path = _DEFAULT_IOC_PATH, feed_state_path: Path = FEED_STATE_PATH):
        self._ioc_path = ioc_path
        self._feed_state_path = feed_state_path
        self._lock = threading.RLock()
        self._entries: dict[str, IOCEntry] = {}
        self._feed_state: dict[str, dict] = {}
        self._migrate_legacy()
        self._load()

    def _migrate_legacy(self) -> None:
        """Migrate IOCs from legacy config/ path to writable data/ path (K8s fix)."""
        if self._ioc_path.exists():
            return  # Already have data at target path
        if _LEGACY_IOC_PATH.exists():
            try:
                self._ioc_path.parent.mkdir(parents=True, exist_ok=True)
                import shutil
                shutil.copy2(_LEGACY_IOC_PATH, self._ioc_path)
            except OSError:
                pass  # Legacy path may also be read-only; _load() handles missing file

    def _load(self) -> None:
        """Load flat iocs.json and convert to structured entries."""
        if not self._ioc_path.exists():
            return

        with open(self._ioc_path) as f:
            raw = json.load(f)

        now = datetime.now(timezone.utc)
        for key, ioc_type in _KEY_TO_TYPE.items():
            for value in raw.get(key, []):
                entry_id = _generate_id(ioc_type.value, value)
                if entry_id not in self._entries:
                    self._entries[entry_id] = IOCEntry(
                        id=entry_id,
                        type=ioc_type,
                        value=value,
                        source="legacy",
                        severity=IOCSeverity.HIGH,
                        confidence=1.0,
                        first_seen=now,
                        last_seen=now,
                        active=True,
                    )

        # Load feed state
        if self._feed_state_path.exists():
            with open(self._feed_state_path) as f:
                self._feed_state = json.load(f)

    def _persist(self) -> None:
        """Write back to flat iocs.json format for proxy compatibility."""
        flat: dict[str, list[str]] = {"domains": [], "ips": [], "urls": [], "hashes": []}
        for entry in self._entries.values():
            if not entry.active:
                continue
            key = _TYPE_TO_KEY.get(entry.type)
            if key and entry.value not in flat[key]:
                flat[key].append(entry.value)

        for key in flat:
            flat[key] = sorted(set(flat[key]))

        self._ioc_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._ioc_path, "w") as f:
            json.dump(flat, f, indent=2)

    def _save_feed_state(self) -> None:
        self._feed_state_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._feed_state_path, "w") as f:
            json.dump(self._feed_state, f, indent=2)

    # --- CRUD ---

    def create(self, req: IOCCreate, source: str = "manual") -> IOCEntry:
        now = datetime.now(timezone.utc)
        entry_id = _generate_id(req.type.value, req.value)
        with self._lock:
            if entry_id in self._entries:
                # Update last_seen if already exists
                self._entries[entry_id].last_seen = now
                self._entries[entry_id].active = True
                self._persist()
                return self._entries[entry_id]
            entry = IOCEntry(
                id=entry_id,
                type=req.type,
                value=req.value,
                source=source,
                severity=req.severity,
                confidence=req.confidence,
                first_seen=now,
                last_seen=now,
                notes=req.notes,
                active=True,
                tags=req.tags,
            )
            self._entries[entry_id] = entry
            self._persist()
            return entry

    def get(self, ioc_id: str) -> Optional[IOCEntry]:
        with self._lock:
            return self._entries.get(ioc_id)

    def list(
        self,
        ioc_type: Optional[IOCType] = None,
        source: Optional[str] = None,
        severity: Optional[IOCSeverity] = None,
        active: Optional[bool] = None,
        search: Optional[str] = None,
        page: int = 1,
        per_page: int = 50,
    ) -> tuple[list[IOCEntry], int]:
        """Return paginated, filtered IOC list and total count."""
        with self._lock:
            results = list(self._entries.values())

        if ioc_type:
            results = [e for e in results if e.type == ioc_type]
        if source:
            results = [e for e in results if e.source == source]
        if severity:
            results = [e for e in results if e.severity == severity]
        if active is not None:
            results = [e for e in results if e.active == active]
        if search:
            q = search.lower()
            results = [e for e in results if q in e.value.lower()]

        total = len(results)
        results.sort(key=lambda e: e.last_seen, reverse=True)
        start = (page - 1) * per_page
        return results[start : start + per_page], total

    def update(self, ioc_id: str, req: IOCUpdate) -> Optional[IOCEntry]:
        with self._lock:
            entry = self._entries.get(ioc_id)
            if not entry:
                return None
            if req.severity is not None:
                entry.severity = req.severity
            if req.confidence is not None:
                entry.confidence = req.confidence
            if req.notes is not None:
                entry.notes = req.notes
            if req.active is not None:
                entry.active = req.active
            if req.tags is not None:
                entry.tags = req.tags
            entry.last_seen = datetime.now(timezone.utc)
            self._persist()
            return entry

    def delete(self, ioc_id: str) -> bool:
        with self._lock:
            if ioc_id not in self._entries:
                return False
            del self._entries[ioc_id]
            self._persist()
            return True

    def bulk_import(self, entries: list[IOCCreate], source: str = "bulk") -> list[IOCEntry]:
        results = []
        with self._lock:
            for req in entries:
                now = datetime.now(timezone.utc)
                entry_id = _generate_id(req.type.value, req.value)
                if entry_id in self._entries:
                    self._entries[entry_id].last_seen = now
                    self._entries[entry_id].active = True
                    results.append(self._entries[entry_id])
                else:
                    entry = IOCEntry(
                        id=entry_id,
                        type=req.type,
                        value=req.value,
                        source=source,
                        severity=req.severity,
                        confidence=req.confidence,
                        first_seen=now,
                        last_seen=now,
                        notes=req.notes,
                        active=True,
                        tags=req.tags,
                    )
                    self._entries[entry_id] = entry
                    results.append(entry)
            self._persist()
        return results

    def search(self, query: str) -> list[IOCEntry]:
        """Partial match search across all IOC values."""
        q = query.lower()
        with self._lock:
            return [e for e in self._entries.values() if q in e.value.lower()]

    def stats(self) -> IOCStats:
        with self._lock:
            entries = list(self._entries.values())
        by_type: dict[str, int] = defaultdict(int)
        by_source: dict[str, int] = defaultdict(int)
        by_severity: dict[str, int] = defaultdict(int)
        active = 0
        inactive = 0
        for e in entries:
            by_type[e.type.value] += 1
            by_source[e.source] += 1
            by_severity[e.severity.value] += 1
            if e.active:
                active += 1
            else:
                inactive += 1
        return IOCStats(
            total=len(entries),
            by_type=dict(by_type),
            by_source=dict(by_source),
            by_severity=dict(by_severity),
            active=active,
            inactive=inactive,
        )

    def export_json(self) -> str:
        with self._lock:
            entries = list(self._entries.values())
        return json.dumps([e.model_dump(mode="json") for e in entries], indent=2)

    def export_csv(self) -> str:
        with self._lock:
            entries = list(self._entries.values())
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["id", "type", "value", "source", "severity", "confidence", "active", "first_seen", "last_seen", "notes", "tags"])
        for e in entries:
            writer.writerow([
                e.id, e.type.value, e.value, e.source, e.severity.value,
                e.confidence, e.active, e.first_seen.isoformat(), e.last_seen.isoformat(),
                e.notes, ";".join(e.tags),
            ])
        return output.getvalue()

    # --- Feed management (dynamic CRUD) ---

    # Default feed definitions (seeded on first load if no state exists)
    _DEFAULT_FEEDS = [
        {"id": "urlhaus", "name": "URLhaus", "feed_type": "urlhaus", "url": "https://urlhaus.abuse.ch/downloads/csv_recent/", "auth_header": "", "enabled": True},
        {"id": "threatfox", "name": "ThreatFox", "feed_type": "threatfox", "url": "https://threatfox.abuse.ch/downloads/hostfile/", "auth_header": "", "enabled": True},
        {"id": "otx", "name": "AlienVault OTX", "feed_type": "otx", "url": "https://otx.alienvault.com/api/v1/pulses/subscribed", "auth_header": "X-OTX-API-KEY", "enabled": True},
        {"id": "abuseipdb", "name": "AbuseIPDB", "feed_type": "abuseipdb", "url": "https://api.abuseipdb.com/api/v2/blacklist", "auth_header": "Key", "enabled": True},
    ]

    def _ensure_default_feeds(self) -> None:
        """Seed default feeds if feed_state has no 'feeds' key."""
        if "feeds" not in self._feed_state:
            self._feed_state["feeds"] = {}
            for fd in self._DEFAULT_FEEDS:
                self._feed_state["feeds"][fd["id"]] = {
                    "id": fd["id"],
                    "name": fd["name"],
                    "feed_type": fd["feed_type"],
                    "url": fd["url"],
                    "auth_header": fd["auth_header"],
                    "api_key": "",
                    "enabled": fd["enabled"],
                    "interval_minutes": 1440,
                    "min_confidence": 0.7,
                    "ioc_types": ["domain", "ip", "url", "hash_sha256"],
                    "last_run": None,
                    "last_count": 0,
                    "last_error": "",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
            # Migrate legacy env-based API keys
            env_map = {"otx": "SENTINEL_OTX_KEY", "abuseipdb": "SENTINEL_ABUSEIPDB_KEY",
                       "urlhaus": "SENTINEL_URLHAUS_KEY", "threatfox": "SENTINEL_THREATFOX_KEY"}
            for fid, env_var in env_map.items():
                key = os.environ.get(env_var, "")
                if key and fid in self._feed_state["feeds"]:
                    self._feed_state["feeds"][fid]["api_key"] = key
            self._save_feed_state()

    def list_feeds(self) -> list[FeedConfig]:
        self._ensure_default_feeds()
        feeds = []
        for fid, state in self._feed_state.get("feeds", {}).items():
            feeds.append(FeedConfig(
                id=fid,
                name=state.get("name", fid),
                feed_type=FeedType(state.get("feed_type", "custom")),
                enabled=state.get("enabled", True),
                url=state.get("url", ""),
                api_key_configured=bool(state.get("api_key")),
                auth_header=state.get("auth_header", ""),
                last_run=datetime.fromisoformat(state["last_run"]) if state.get("last_run") else None,
                last_count=state.get("last_count", 0),
                last_error=state.get("last_error", ""),
                interval_minutes=state.get("interval_minutes", 1440),
                min_confidence=state.get("min_confidence", 0.7),
                ioc_types=state.get("ioc_types", ["domain", "ip", "url", "hash_sha256"]),
                created_at=datetime.fromisoformat(state["created_at"]) if state.get("created_at") else None,
            ))
        return sorted(feeds, key=lambda f: f.name)

    def get_feed(self, feed_id: str) -> Optional[FeedConfig]:
        feeds = self.list_feeds()
        return next((f for f in feeds if f.id == feed_id), None)

    def create_feed(self, req: FeedCreate) -> FeedConfig:
        self._ensure_default_feeds()
        feed_id = req.name.lower().replace(" ", "_").replace("-", "_")[:32]
        # Ensure unique id
        base_id = feed_id
        counter = 1
        while feed_id in self._feed_state["feeds"]:
            feed_id = f"{base_id}_{counter}"
            counter += 1

        with self._lock:
            self._feed_state["feeds"][feed_id] = {
                "id": feed_id,
                "name": req.name,
                "feed_type": req.feed_type.value,
                "url": req.url,
                "auth_header": req.auth_header,
                "api_key": req.api_key,
                "enabled": req.enabled,
                "interval_minutes": req.interval_minutes,
                "min_confidence": req.min_confidence,
                "ioc_types": req.ioc_types,
                "last_run": None,
                "last_count": 0,
                "last_error": "",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            self._save_feed_state()
        return self.get_feed(feed_id)  # type: ignore

    def update_feed(self, feed_id: str, req: FeedUpdate) -> Optional[FeedConfig]:
        self._ensure_default_feeds()
        if feed_id not in self._feed_state.get("feeds", {}):
            return None
        with self._lock:
            state = self._feed_state["feeds"][feed_id]
            if req.name is not None:
                state["name"] = req.name
            if req.enabled is not None:
                state["enabled"] = req.enabled
            if req.url is not None:
                state["url"] = req.url
            if req.api_key is not None:
                state["api_key"] = req.api_key
            if req.auth_header is not None:
                state["auth_header"] = req.auth_header
            if req.interval_minutes is not None:
                state["interval_minutes"] = req.interval_minutes
            if req.min_confidence is not None:
                state["min_confidence"] = req.min_confidence
            if req.ioc_types is not None:
                state["ioc_types"] = req.ioc_types
            self._save_feed_state()
        return self.get_feed(feed_id)

    def delete_feed(self, feed_id: str) -> bool:
        self._ensure_default_feeds()
        if feed_id not in self._feed_state.get("feeds", {}):
            return False
        with self._lock:
            del self._feed_state["feeds"][feed_id]
            self._save_feed_state()
        return True

    def toggle_feed(self, feed_id: str) -> Optional[FeedConfig]:
        self._ensure_default_feeds()
        if feed_id not in self._feed_state.get("feeds", {}):
            return None
        with self._lock:
            state = self._feed_state["feeds"][feed_id]
            state["enabled"] = not state.get("enabled", True)
            self._save_feed_state()
        return self.get_feed(feed_id)

    def trigger_feed_update(self, feed_id: Optional[str] = None) -> dict:
        """Fetch IOCs from enabled feeds (or a specific one) and persist."""
        results = {}
        feeds = self.list_feeds()
        if feed_id:
            feeds = [f for f in feeds if f.id == feed_id]

        for feed in feeds:
            if not feed.enabled and not feed_id:
                results[feed.id] = {"status": "disabled", "count": 0}
                continue
            try:
                count = self._fetch_feed_by_type(feed)
                with self._lock:
                    state = self._feed_state["feeds"][feed.id]
                    state["last_run"] = datetime.now(timezone.utc).isoformat()
                    state["last_count"] = count
                    state["last_error"] = ""
                    self._save_feed_state()
                results[feed.id] = {"status": "ok", "count": count}
            except Exception as e:
                with self._lock:
                    state = self._feed_state["feeds"].get(feed.id, {})
                    state["last_error"] = str(e)[:200]
                    state["last_run"] = datetime.now(timezone.utc).isoformat()
                    self._save_feed_state()
                results[feed.id] = {"status": "error", "error": str(e)[:200], "count": 0}

        self._persist()
        return results

    def _get_feed_api_key(self, feed: FeedConfig) -> str:
        """Get API key for a feed from stored state."""
        self._ensure_default_feeds()
        state = self._feed_state.get("feeds", {}).get(feed.id, {})
        return state.get("api_key", "")

    def _fetch_feed_by_type(self, feed: FeedConfig) -> int:
        """Route to appropriate fetcher based on feed type."""
        ft = feed.feed_type.value
        if ft == "urlhaus":
            return self._fetch_urlhaus(feed)
        elif ft == "threatfox":
            return self._fetch_threatfox(feed)
        elif ft == "otx":
            return self._fetch_otx(feed)
        elif ft == "abuseipdb":
            return self._fetch_abuseipdb(feed)
        elif ft == "misp":
            return self._fetch_misp(feed)
        elif ft == "opencti":
            return self._fetch_opencti(feed)
        elif ft == "virustotal":
            return self._fetch_virustotal(feed)
        elif ft == "custom":
            return self._fetch_custom(feed)
        return 0

    def _fetch_urlhaus(self, feed: FeedConfig) -> int:
        """Fetch recent malware URLs from URLhaus CSV dump (public, no key needed)."""
        import httpx

        url = feed.url or "https://urlhaus.abuse.ch/downloads/csv_recent/"
        resp = httpx.get(url, timeout=30, follow_redirects=True)
        if resp.status_code != 200:
            raise RuntimeError(f"URLhaus returned {resp.status_code}")

        count = 0
        for line in resp.text.splitlines():
            if line.startswith("#") or line.startswith('"id"') or not line.strip():
                continue
            parts = line.strip().split('","')
            if len(parts) < 7:
                continue
            url_val = parts[2].strip('"')
            threat = parts[5].strip('"')
            tags = parts[6].strip('"')
            if not url_val or any(e.value == url_val for e in self._entries.values()):
                continue
            ioc = IOCCreate(
                type=IOCType.URL, value=url_val, severity=IOCSeverity.HIGH,
                confidence=0.9, tags=["malware"] + [t.strip() for t in tags.split(",") if t.strip()][:3],
                notes=f"URLhaus — {threat}",
            )
            self.create(ioc, source="urlhaus")
            count += 1
            if count >= 100:
                break
        return count

    def _fetch_threatfox(self, feed: FeedConfig) -> int:
        """Fetch recent IOCs from ThreatFox hostfile."""
        import httpx

        url = feed.url or "https://threatfox.abuse.ch/downloads/hostfile/"
        resp = httpx.get(url, timeout=30, follow_redirects=True)
        if resp.status_code != 200:
            raise RuntimeError(f"ThreatFox returned {resp.status_code}")

        count = 0
        for line in resp.text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            domain = parts[1].strip()
            if not domain or domain == "localhost" or any(e.value == domain for e in self._entries.values()):
                continue
            ioc = IOCCreate(
                type=IOCType.DOMAIN, value=domain, severity=IOCSeverity.HIGH,
                confidence=0.85, tags=["malware", "c2"], notes="ThreatFox hostfile",
            )
            self.create(ioc, source="threatfox")
            count += 1
            if count >= 100:
                break
        return count

    def _fetch_otx(self, feed: FeedConfig) -> int:
        """Fetch from AlienVault OTX."""
        import httpx

        api_key = self._get_feed_api_key(feed)
        if not api_key:
            raise RuntimeError("OTX API key not configured")

        url = feed.url or "https://otx.alienvault.com/api/v1/pulses/subscribed"
        resp = httpx.get(
            url, headers={"X-OTX-API-KEY": api_key},
            params={"limit": 5, "modified_since": "2024-01-01"}, timeout=30,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"OTX returned {resp.status_code}")

        data = resp.json()
        count = 0
        type_map = {"domain": IOCType.DOMAIN, "IPv4": IOCType.IP, "URL": IOCType.URL, "FileHash-SHA256": IOCType.HASH_SHA256}
        for pulse in data.get("results", [])[:5]:
            for indicator in pulse.get("indicators", [])[:20]:
                ioc_type = type_map.get(indicator.get("type"))
                if not ioc_type:
                    continue
                value = indicator.get("indicator", "")
                if not value or any(e.value == value for e in self._entries.values()):
                    continue
                ioc = IOCCreate(
                    type=ioc_type, value=value, severity=IOCSeverity.MEDIUM,
                    confidence=0.8, tags=["otx", pulse.get("name", "")[:30]],
                )
                self.create(ioc, source="otx")
                count += 1
        return count

    def _fetch_abuseipdb(self, feed: FeedConfig) -> int:
        """Fetch from AbuseIPDB blacklist."""
        import httpx

        api_key = self._get_feed_api_key(feed)
        if not api_key:
            raise RuntimeError("AbuseIPDB API key not configured")

        url = feed.url or "https://api.abuseipdb.com/api/v2/blacklist"
        resp = httpx.get(
            url, headers={"Key": api_key, "Accept": "application/json"},
            params={"confidenceMinimum": 90, "limit": 100}, timeout=30,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"AbuseIPDB returned {resp.status_code}")

        data = resp.json()
        count = 0
        for entry in data.get("data", [])[:100]:
            ip = entry.get("ipAddress", "")
            if not ip or any(e.value == ip for e in self._entries.values()):
                continue
            ioc = IOCCreate(
                type=IOCType.IP, value=ip, severity=IOCSeverity.HIGH,
                confidence=entry.get("abuseConfidenceScore", 90) / 100.0,
                tags=["abuse", "blacklist"],
            )
            self.create(ioc, source="abuseipdb")
            count += 1
        return count

    def _fetch_misp(self, feed: FeedConfig) -> int:
        """Fetch from MISP instance (attributes endpoint)."""
        import httpx

        api_key = self._get_feed_api_key(feed)
        if not api_key or not feed.url:
            raise RuntimeError("MISP URL and API key required")

        url = feed.url.rstrip("/") + "/attributes/restSearch"
        resp = httpx.post(
            url,
            headers={"Authorization": api_key, "Accept": "application/json", "Content-Type": "application/json"},
            json={"limit": 100, "published": True, "enforceWarninglist": True,
                  "type": {"OR": ["ip-dst", "ip-src", "domain", "url", "sha256"]}},
            timeout=60,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"MISP returned {resp.status_code}")

        data = resp.json()
        count = 0
        type_map = {"ip-dst": IOCType.IP, "ip-src": IOCType.IP, "domain": IOCType.DOMAIN,
                    "url": IOCType.URL, "sha256": IOCType.HASH_SHA256}
        for attr in data.get("response", {}).get("Attribute", [])[:200]:
            ioc_type = type_map.get(attr.get("type"))
            if not ioc_type:
                continue
            value = attr.get("value", "")
            if not value or any(e.value == value for e in self._entries.values()):
                continue
            ioc = IOCCreate(
                type=ioc_type, value=value, severity=IOCSeverity.HIGH,
                confidence=feed.min_confidence, tags=["misp"],
                notes=f"MISP event {attr.get('event_id', '')}",
            )
            self.create(ioc, source="misp")
            count += 1
        return count

    def _fetch_opencti(self, feed: FeedConfig) -> int:
        """Fetch from OpenCTI via GraphQL."""
        import httpx

        api_key = self._get_feed_api_key(feed)
        if not api_key or not feed.url:
            raise RuntimeError("OpenCTI URL and API key required")

        url = feed.url.rstrip("/") + "/graphql"
        query = """
        query {
            stixCyberObservables(first: 100, orderBy: created_at, orderMode: desc) {
                edges { node { observable_value entity_type } }
            }
        }
        """
        resp = httpx.post(
            url, headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"query": query}, timeout=60,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"OpenCTI returned {resp.status_code}")

        data = resp.json()
        count = 0
        type_map = {"IPv4-Addr": IOCType.IP, "Domain-Name": IOCType.DOMAIN,
                    "Url": IOCType.URL, "StixFile": IOCType.HASH_SHA256}
        edges = data.get("data", {}).get("stixCyberObservables", {}).get("edges", [])
        for edge in edges:
            node = edge.get("node", {})
            ioc_type = type_map.get(node.get("entity_type"))
            if not ioc_type:
                continue
            value = node.get("observable_value", "")
            if not value or any(e.value == value for e in self._entries.values()):
                continue
            ioc = IOCCreate(
                type=ioc_type, value=value, severity=IOCSeverity.HIGH,
                confidence=feed.min_confidence, tags=["opencti"],
            )
            self.create(ioc, source="opencti")
            count += 1
        return count

    def _fetch_virustotal(self, feed: FeedConfig) -> int:
        """Fetch from VirusTotal hunting notifications or popular threat IOCs."""
        import httpx

        api_key = self._get_feed_api_key(feed)
        if not api_key:
            raise RuntimeError("VirusTotal API key not configured")

        # Fetch popular threat actors' IOCs via VT hunting livehunt
        url = feed.url or "https://www.virustotal.com/api/v3/intelligence/hunting_notification_files"
        resp = httpx.get(
            url, headers={"x-apikey": api_key}, params={"limit": 50}, timeout=30,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"VirusTotal returned {resp.status_code}")

        data = resp.json()
        count = 0
        for item in data.get("data", [])[:50]:
            attrs = item.get("attributes", {})
            sha256 = attrs.get("sha256", "")
            if not sha256 or any(e.value == sha256 for e in self._entries.values()):
                continue
            ioc = IOCCreate(
                type=IOCType.HASH_SHA256, value=sha256, severity=IOCSeverity.HIGH,
                confidence=0.95, tags=["virustotal", "malware"],
                notes=f"VT detection: {attrs.get('meaningful_name', '')}",
            )
            self.create(ioc, source="virustotal")
            count += 1
        return count

    def _fetch_custom(self, feed: FeedConfig) -> int:
        """Fetch from a custom feed URL (expects JSON array of IOCs or newline-delimited values)."""
        import httpx

        if not feed.url:
            raise RuntimeError("Custom feed URL not configured")

        # SECURITY FIX (C-03): Validate feed URLs against SSRF blocklist
        ssrf_error = _validate_url_no_ssrf(feed.url)
        if ssrf_error:
            raise RuntimeError(f"Feed URL blocked (SSRF protection): {ssrf_error}")

        headers = {}
        api_key = self._get_feed_api_key(feed)
        if api_key and feed.auth_header:
            headers[feed.auth_header] = api_key

        resp = httpx.get(feed.url, headers=headers, timeout=30, follow_redirects=True)
        if resp.status_code != 200:
            raise RuntimeError(f"Custom feed returned {resp.status_code}")

        count = 0
        # Try JSON first
        try:
            data = resp.json()
            items = data if isinstance(data, list) else data.get("data", data.get("indicators", data.get("iocs", [])))
            for item in items[:200]:
                if isinstance(item, str):
                    value = item.strip()
                    ioc_type = self._guess_ioc_type(value)
                elif isinstance(item, dict):
                    value = item.get("value", item.get("indicator", ""))
                    ioc_type = self._type_from_string(item.get("type", ""))
                else:
                    continue
                if not value or not ioc_type or any(e.value == value for e in self._entries.values()):
                    continue
                ioc = IOCCreate(
                    type=ioc_type, value=value, severity=IOCSeverity.MEDIUM,
                    confidence=feed.min_confidence, tags=["custom", feed.name.lower()[:20]],
                )
                self.create(ioc, source=feed.id)
                count += 1
        except (json.JSONDecodeError, ValueError):
            # Fallback: line-delimited
            for line in resp.text.splitlines()[:200]:
                value = line.strip()
                if not value or value.startswith("#") or any(e.value == value for e in self._entries.values()):
                    continue
                ioc_type = self._guess_ioc_type(value)
                if not ioc_type:
                    continue
                ioc = IOCCreate(
                    type=ioc_type, value=value, severity=IOCSeverity.MEDIUM,
                    confidence=feed.min_confidence, tags=["custom"],
                )
                self.create(ioc, source=feed.id)
                count += 1
        return count

    @staticmethod
    def _guess_ioc_type(value: str) -> Optional[IOCType]:
        """Heuristic to determine IOC type from value."""
        import re
        if re.match(r"^https?://", value):
            return IOCType.URL
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
            return IOCType.IP
        if re.match(r"^[a-fA-F0-9]{64}$", value):
            return IOCType.HASH_SHA256
        if re.match(r"^[a-fA-F0-9]{32}$", value):
            return IOCType.HASH_MD5
        if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$", value):
            return IOCType.DOMAIN
        return None

    @staticmethod
    def _type_from_string(type_str: str) -> Optional[IOCType]:
        """Map common type strings to IOCType."""
        mapping = {
            "domain": IOCType.DOMAIN, "ip": IOCType.IP, "ipv4": IOCType.IP,
            "url": IOCType.URL, "sha256": IOCType.HASH_SHA256, "md5": IOCType.HASH_MD5,
            "hash": IOCType.HASH_SHA256, "ip-dst": IOCType.IP, "ip-src": IOCType.IP,
        }
        return mapping.get(type_str.lower())


_store: Optional[IOCStore] = None


def get_ioc_store() -> IOCStore:
    global _store
    if _store is None:
        _store = IOCStore()
    return _store
