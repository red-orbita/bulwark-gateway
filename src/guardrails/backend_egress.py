"""Exact operator-configured origin allowlists, complementary to SSRF checks."""

import ipaddress
import re
from typing import Annotated
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator


def canonical_origin(url: str, *, origin_only: bool = False) -> str:
    if (not isinstance(url, str) or not 0 < len(url) <= 2048
            or any(ord(ch) <= 32 or ord(ch) == 127 for ch in url) or "\\" in url):
        raise ValueError("Invalid destination URL")
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("HTTP(S) destination required")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError("Credentials and fragments are forbidden in destinations")
    if origin_only and (parsed.path not in ("", "/") or parsed.query):
        raise ValueError("Allowlist entries must be origins, not URL paths")
    host = parsed.hostname
    if "%" in host or "*" in host:
        raise ValueError("Wildcards and escaped hosts are not supported")
    try:
        address = ipaddress.ip_address(host)
        host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    except ValueError:
        # Use the sending client's IDNA2008 rules, not Python's IDNA2003 codec
        # (e.g. sharp-s must not turn an unapproved host into an approved one).
        try:
            host = httpx.URL(url).raw_host.decode("ascii").lower().rstrip(".")
        except (httpx.InvalidURL, UnicodeError):
            raise ValueError("Invalid destination hostname") from None
        if (not host or len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                             for label in host.split("."))):
            raise ValueError("Invalid destination hostname") from None
    port = parsed.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid destination port")
    default = 443 if parsed.scheme == "https" else 80
    return f"{parsed.scheme}://{host}" + (f":{port}" if port is not None and port != default else "")


class BackendEgressPolicy(BaseModel):
    """No suffix or wildcard matching; every fallback requires its own approval."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    enabled: StrictBool = False
    allowed_origins: tuple[Annotated[str, Field(strict=True, min_length=1, max_length=2048)], ...] = Field(
        default=(), max_length=32,
    )

    @field_validator("allowed_origins")
    @classmethod
    def normalize_origins(cls, origins: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(canonical_origin(origin, origin_only=True) for origin in origins))

    @model_validator(mode="after")
    def require_destination(self) -> "BackendEgressPolicy":
        if self.enabled and not self.allowed_origins:
            raise ValueError("Enabled egress policy requires an explicit destination")
        return self

    def permits(self, url: str) -> bool:
        if not self.enabled:
            return True
        try:
            return canonical_origin(url) in self.allowed_origins
        except (ValueError, UnicodeError):
            return False
