"""
Domain Intelligence — Typosquatting detection and subdomain-aware matching.

Ported and enhanced from opencode-security-agent/plugins/sentinel_preflight.py.
Used by ToolPolicyEngine to validate URLs in tool call arguments.
"""

import re
from urllib.parse import urlparse

# Homoglyph substitution map for typosquatting detection
_HOMOGLYPHS: dict[str, list[str]] = {
    "a": ["4", "@", "à", "á", "â", "ã"],
    "b": ["8", "ß"],
    "c": ["(", "ç", "¢"],
    "e": ["3", "è", "é", "ê"],
    "g": ["9", "q"],
    "i": ["1", "l", "!", "í", "ì"],
    "l": ["1", "i", "|"],
    "o": ["0", "ö", "ó", "ò"],
    "s": ["5", "$", "ş"],
    "t": ["7", "+"],
    "u": ["ü", "ú", "ù"],
    "z": ["2"],
}

# Common TLD swaps for typosquatting
_TLD_SWAPS = ("com", "net", "org", "io", "co", "club", "xyz", "info", "biz", "app", "dev")


def extract_domain_from_url(url_or_value: str) -> str | None:
    """Extract hostname from URL or domain:port string."""
    value = url_or_value.strip()
    if not value:
        return None

    if "://" in value:
        try:
            parsed = urlparse(value)
            host = parsed.hostname
            if host:
                return host.lower()
        except Exception:
            pass
        return None

    # Handle domain:port
    host = value.split(":")[0].split("/")[0].strip().lower()
    # Skip IPs
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
        return None
    if "." in host and len(host) > 3:
        return host
    return None


def is_subdomain_of(hostname: str, parent: str) -> bool:
    """Check if hostname is a subdomain of parent (suffix-safe).

    Prevents bypass: "evil.com.attacker.com" does NOT match "evil.com"
    Only "sub.evil.com" matches "evil.com".
    """
    hostname = hostname.lower().rstrip(".")
    parent = parent.lower().rstrip(".")
    if hostname == parent:
        return True
    return hostname.endswith("." + parent)


def is_allowlisted(hostname: str, allowlist: set[str]) -> bool:
    """Check if hostname matches allowlist (exact or subdomain)."""
    hostname = hostname.lower().rstrip(".")
    for allowed in allowlist:
        if is_subdomain_of(hostname, allowed):
            return True
    return False


def generate_typosquat_variants(domain: str, max_variants: int = 50) -> set[str]:
    """Generate typosquatting variants of a domain for detection.

    Methods:
    1. Homoglyph substitution (single char)
    2. Character deletion
    3. Adjacent transposition
    4. Hyphen insertion/removal
    5. TLD swaps
    """
    variants: set[str] = set()
    parts = domain.rsplit(".", 1)
    if len(parts) != 2:
        return variants
    name, tld = parts

    # 1. Homoglyph substitution (one char at a time)
    for i, char in enumerate(name):
        for replacement in _HOMOGLYPHS.get(char, []):
            variant = name[:i] + replacement + name[i + 1 :]
            variants.add(f"{variant}.{tld}")
            if len(variants) >= max_variants:
                return variants

    # 2. Single character deletion
    for i in range(len(name)):
        variant = name[:i] + name[i + 1 :]
        if variant:
            variants.add(f"{variant}.{tld}")

    # 3. Adjacent character transposition
    for i in range(len(name) - 1):
        variant = name[:i] + name[i + 1] + name[i] + name[i + 2 :]
        variants.add(f"{variant}.{tld}")

    # 4. Hyphen insertion/removal
    if "-" in name:
        variants.add(f"{name.replace('-', '')}.{tld}")
    else:
        for i in range(1, len(name)):
            variants.add(f"{name[:i]}-{name[i:]}.{tld}")
            if len(variants) >= max_variants:
                return variants

    # 5. TLD swaps
    for swap_tld in _TLD_SWAPS:
        if swap_tld != tld:
            variants.add(f"{name}.{swap_tld}")

    return variants


def check_typosquat_match(domain: str, known_malicious: set[str]) -> str | None:
    """Check if domain is a typosquat of a known malicious domain.

    Returns the matched malicious domain if typosquat detected, None otherwise.
    """
    domain = domain.lower().rstrip(".")
    for malicious in known_malicious:
        variants = generate_typosquat_variants(malicious, max_variants=30)
        if domain in variants:
            return malicious
    return None


# Pre-compiled regex for extracting URLs from text
_URL_EXTRACT_RE = re.compile(r"https?://[^\s\"'<>\])+,]+")


def extract_urls_from_args(arguments: dict) -> list[str]:
    """Recursively extract all URLs from tool call arguments."""
    urls: list[str] = []

    def _walk(obj):
        if isinstance(obj, str):
            urls.extend(_URL_EXTRACT_RE.findall(obj))
        elif isinstance(obj, dict):
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)

    _walk(arguments)
    return urls
