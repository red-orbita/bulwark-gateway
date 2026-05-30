"""
IOC Manager — Loads and queries Indicators of Compromise.

Supports domains, IPs, URLs, and file hashes from threat intel feeds.
Compatible with the IOC format from opencode-security-agent.
"""
import json
import structlog
from pathlib import Path
from dataclasses import dataclass, field

logger = structlog.get_logger()


@dataclass
class IOCDatabase:
    domains: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)


class IOCManager:
    """Manages IOC database for domain/IP blocking."""

    def __init__(self, ioc_path: Path):
        self.ioc_path = ioc_path
        self.db = IOCDatabase()

    @property
    def count(self) -> int:
        return len(self.db.domains) + len(self.db.ips) + len(self.db.urls)

    async def load(self):
        """Load IOCs from JSON file."""
        if not self.ioc_path.exists():
            await logger.awarn("ioc_file_missing", path=str(self.ioc_path))
            return

        try:
            with open(self.ioc_path) as f:
                data = json.load(f)

            # Support both flat and categorized formats
            if "domains" in data:
                self.db.domains = set(data["domains"])
            if "ips" in data:
                self.db.ips = set(data["ips"])
            if "urls" in data:
                self.db.urls = set(data["urls"])
            if "hashes" in data:
                self.db.hashes = set(data["hashes"])

            # Support opencode-security-agent format (list of objects)
            if "indicators" in data:
                for ioc in data["indicators"]:
                    ioc_type = ioc.get("type", "")
                    value = ioc.get("value", "")
                    if ioc_type == "domain":
                        self.db.domains.add(value)
                    elif ioc_type == "ip":
                        self.db.ips.add(value)
                    elif ioc_type == "url":
                        self.db.urls.add(value)
                    elif ioc_type in ("sha256", "md5", "sha1"):
                        self.db.hashes.add(value)

            await logger.ainfo(
                "ioc_loaded",
                domains=len(self.db.domains),
                ips=len(self.db.ips),
                urls=len(self.db.urls),
            )
        except Exception as e:
            await logger.aerror("ioc_load_error", error=str(e))

    def check_domain(self, domain: str) -> bool:
        """Returns True if domain is malicious."""
        domain = domain.lower().strip()
        # Check exact match and parent domain
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in self.db.domains:
                return True
        return False

    def check_ip(self, ip: str) -> bool:
        """Returns True if IP is malicious."""
        return ip.strip() in self.db.ips

    def check_url(self, url: str) -> bool:
        """Returns True if URL is malicious."""
        url_lower = url.lower().strip()
        if url_lower in self.db.urls:
            return True
        # Extract domain from URL
        import re
        match = re.search(r"https?://([^/:]+)", url_lower)
        if match:
            return self.check_domain(match.group(1))
        return False

    def check_content(self, content: str) -> list[str]:
        """Check content for any IOC matches. Returns list of matched IOCs."""
        import re
        matches = []

        # Extract URLs
        urls = re.findall(r"https?://[^\s\"'<>]+", content)
        for url in urls:
            if self.check_url(url):
                matches.append(f"url:{url}")

        # Extract IPs
        ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", content)
        for ip in ips:
            if self.check_ip(ip):
                matches.append(f"ip:{ip}")

        # Extract domains (simplified)
        domains = re.findall(r"\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.[a-z]{2,}\b", content.lower())
        for domain in domains:
            if self.check_domain(domain):
                matches.append(f"domain:{domain}")

        return matches
