"""
IOC Manager — Loads and queries Indicators of Compromise.

Features:
- mtime-based caching: zero disk I/O on hot path when file hasn't changed
- Subdomain-aware domain matching (prevents bypass via substring embedding)
- Supports both flat and categorized IOC formats
- Compatible with opencode-security-agent IOC format
"""

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import structlog

logger = structlog.get_logger()

# Pre-compiled regexes for content extraction (avoid re-compilation in hot path)
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.[a-z]{2,}\b")


@dataclass
class IOCDatabase:
    domains: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)


class IOCManager:
    """Manages IOC database with mtime-based caching for zero hot-path I/O."""

    def __init__(self, ioc_path: Path):
        self.ioc_path = ioc_path
        self.db = IOCDatabase()
        self._cached_mtime: float = 0.0

    @property
    def count(self) -> int:
        return len(self.db.domains) + len(self.db.ips) + len(self.db.urls)

    def _file_changed(self) -> bool:
        """Check if IOC file has been modified since last load (mtime-based)."""
        try:
            current_mtime = os.path.getmtime(self.ioc_path)
            return current_mtime != self._cached_mtime
        except OSError:
            return False

    async def load(self):
        """Load IOCs from JSON file. Skips if file hasn't changed (mtime cache)."""
        if not self.ioc_path.exists():
            await logger.awarn("ioc_file_missing", path=str(self.ioc_path))
            return

        if not self._file_changed() and self.db.domains:
            return  # Cache hit — no I/O needed

        try:
            current_mtime = os.path.getmtime(self.ioc_path)
            with open(self.ioc_path) as f:
                data = json.load(f)

            new_db = IOCDatabase()

            # Support flat format: {"domains": [...], "ips": [...]}
            if "domains" in data:
                new_db.domains = set(data["domains"])
            if "ips" in data:
                new_db.ips = set(data["ips"])
            if "urls" in data:
                new_db.urls = set(data["urls"])
            if "hashes" in data:
                new_db.hashes = set(data["hashes"])

            # Support opencode-security-agent format: {"indicators": [...]}
            if "indicators" in data:
                for ioc in data["indicators"]:
                    ioc_type = ioc.get("type", "")
                    value = ioc.get("value", "")
                    if ioc_type == "domain":
                        new_db.domains.add(value)
                    elif ioc_type == "ip":
                        new_db.ips.add(value)
                    elif ioc_type == "url":
                        new_db.urls.add(value)
                    elif ioc_type in ("sha256", "md5", "sha1"):
                        new_db.hashes.add(value)

            # Atomic swap
            self.db = new_db
            self._cached_mtime = current_mtime

            await logger.ainfo(
                "ioc_loaded",
                domains=len(self.db.domains),
                ips=len(self.db.ips),
                urls=len(self.db.urls),
                hashes=len(self.db.hashes),
            )
        except Exception as e:
            await logger.aerror("ioc_load_error", error=str(e))

    def reload_sync(self) -> bool:
        """Synchronous reload for hot-reload polling. Returns True if reloaded."""
        if not self.ioc_path.exists() or not self._file_changed():
            return False
        try:
            current_mtime = os.path.getmtime(self.ioc_path)
            with open(self.ioc_path) as f:
                data = json.load(f)

            new_db = IOCDatabase()
            if "domains" in data:
                new_db.domains = set(data["domains"])
            if "ips" in data:
                new_db.ips = set(data["ips"])
            if "urls" in data:
                new_db.urls = set(data["urls"])
            if "hashes" in data:
                new_db.hashes = set(data["hashes"])

            self.db = new_db
            self._cached_mtime = current_mtime
            return True
        except Exception:
            return False

    def check_domain(self, domain: str) -> bool:
        """Check if domain matches IOC list (subdomain-aware).

        Prevents bypass via substring embedding:
        - "evil.com" matches "sub.evil.com" (subdomain)
        - "evil.com" does NOT match "notevil.com" (suffix-safe)
        """
        domain = domain.lower().strip()
        if domain in self.db.domains:
            return True
        # Check if any IOC domain is a parent of the given domain
        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self.db.domains:
                return True
        return False

    def check_ip(self, ip: str) -> bool:
        """Returns True if IP is in IOC database."""
        return ip.strip() in self.db.ips

    def check_url(self, url: str) -> bool:
        """Returns True if URL or its domain is malicious."""
        url_lower = url.lower().strip()
        if url_lower in self.db.urls:
            return True
        match = re.search(r"https?://([^/:]+)", url_lower)
        if match:
            return self.check_domain(match.group(1))
        return False

    def check_content(self, content: str) -> list[str]:
        """Check content for any IOC matches. Returns list of matched IOCs.

        Uses pre-compiled regexes for extraction — ~0.1ms for typical inputs.
        """
        matches = []

        # Extract and check URLs
        for url in _URL_RE.findall(content):
            if self.check_url(url):
                matches.append(f"url:{url}")

        # Extract and check IPs
        for ip in _IP_RE.findall(content):
            if self.check_ip(ip):
                matches.append(f"ip:{ip}")

        # Extract and check domains
        for domain in _DOMAIN_RE.findall(content.lower()):
            if self.check_domain(domain):
                matches.append(f"domain:{domain}")

        return matches
