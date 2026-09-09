"""SSRF DNS-rebinding pinning + scheme allowlist regression tests (S-09, S-18).

These cover the backend SSRF SSOT introduced to close the DNS-rebinding TOCTOU
window: ``_resolve_pinned_backend`` resolves + validates a backend URL ONCE and
returns a target whose connection is pinned to the exact validated IP literal, so
httpcore cannot re-resolve (and be rebound to) a blocked address between the check
and the connect. It also enforces the http/https scheme allowlist and rejects
empty authorities (S-18) before any resolution.

DNS is stubbed deterministically by pre-seeding the module's short-TTL
``_DNS_CACHE`` so no real network lookup happens.
"""

import socket

import pytest

import src.routes.proxy as proxy


def _ipv4_addrinfo(ip: str, port: int) -> tuple:
    return (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))


def _ipv6_addrinfo(ip: str, port: int) -> tuple:
    return (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port, 0, 0))


@pytest.fixture(autouse=True)
def _clear_dns_cache():
    proxy._DNS_CACHE.clear()
    yield
    proxy._DNS_CACHE.clear()


def _seed(hostname: str, port: int, *addr_infos: tuple) -> None:
    """Seed the resolver cache so _resolve_pinned_backend skips real DNS."""
    proxy._DNS_CACHE[(hostname, port)] = list(addr_infos)


# ─── S-09: connection pinning ────────────────────────────────────────────────

async def test_pins_to_validated_public_ip():
    _seed("backend.example", 11434, _ipv4_addrinfo("93.184.216.34", 11434))
    pinned = await proxy._resolve_pinned_backend(
        "http://backend.example:11434/v1/chat/completions", allow_private=True
    )
    assert pinned is not None
    # URL host rewritten to the validated IP literal — no hostname to re-resolve.
    assert pinned.url == "http://93.184.216.34:11434/v1/chat/completions"
    # Original authority preserved for HTTP routing + TLS verification.
    assert pinned.host_header == "backend.example:11434"
    assert pinned.sni_hostname == "backend.example"


async def test_pins_ipv6_bracketed():
    _seed("v6.example", 443, _ipv6_addrinfo("2606:2800:220:1:248:1893:25c8:1946", 443))
    pinned = await proxy._resolve_pinned_backend(
        "https://v6.example/v1/chat/completions", allow_private=False
    )
    assert pinned is not None
    assert pinned.url.startswith("https://[2606:2800:220:1:248:1893:25c8:1946]/")
    # No explicit port in the source URL ⇒ none injected into Host/authority.
    assert pinned.host_header == "v6.example"


async def test_default_port_uses_scheme_default_for_resolution():
    # https with no explicit port → resolver keys on 443; Host carries no port.
    _seed("plain.example", 443, _ipv4_addrinfo("93.184.216.34", 443))
    pinned = await proxy._resolve_pinned_backend(
        "https://plain.example/v1", allow_private=False
    )
    assert pinned is not None
    assert pinned.url == "https://93.184.216.34/v1"
    assert pinned.host_header == "plain.example"
    assert pinned.sni_hostname == "plain.example"


async def test_request_overrides_sets_host_and_sni():
    pinned = proxy._PinnedBackend(
        url="http://93.184.216.34:11434/v1/chat/completions",
        host_header="backend.example:11434",
        sni_hostname="backend.example",
    )
    headers, extensions = pinned.request_overrides({"Authorization": "Bearer x"})
    assert headers["Authorization"] == "Bearer x"
    assert headers["Host"] == "backend.example:11434"
    assert extensions == {"sni_hostname": "backend.example"}


# ─── S-09: rebinding / dangerous-IP rejection (fail-closed) ───────────────────

async def test_blocks_cloud_metadata_ip():
    _seed("evil.example", 80, _ipv4_addrinfo("169.254.169.254", 80))
    assert (
        await proxy._resolve_pinned_backend(
            "http://evil.example/latest/meta-data", allow_private=True
        )
        is None
    )


async def test_blocks_loopback_even_with_allow_private():
    _seed("rebind.example", 11434, _ipv4_addrinfo("127.0.0.1", 11434))
    assert (
        await proxy._resolve_pinned_backend(
            "http://rebind.example:11434/v1", allow_private=True
        )
        is None
    )


async def test_private_ip_gated_on_allow_private():
    _seed("internal.example", 9200, _ipv4_addrinfo("10.0.0.5", 9200))
    # User content: private ranges are blocked.
    assert (
        await proxy._resolve_pinned_backend(
            "http://internal.example:9200/", allow_private=False
        )
        is None
    )
    # Operator backend: private cluster IPs are allowed and pinned.
    proxy._DNS_CACHE.clear()
    _seed("internal.example", 9200, _ipv4_addrinfo("10.0.0.5", 9200))
    pinned = await proxy._resolve_pinned_backend(
        "http://internal.example:9200/", allow_private=True
    )
    assert pinned is not None
    assert pinned.url == "http://10.0.0.5:9200/"


async def test_fail_closed_when_any_resolved_ip_is_dangerous():
    # A rebinding resolver that returns one safe + one metadata IP must be rejected
    # wholesale (fail-closed) rather than pinning the safe one and racing.
    _seed(
        "mixed.example",
        11434,
        _ipv4_addrinfo("93.184.216.34", 11434),
        _ipv4_addrinfo("169.254.169.254", 11434),
    )
    assert (
        await proxy._resolve_pinned_backend(
            "http://mixed.example:11434/v1", allow_private=True
        )
        is None
    )


async def test_blocked_hostname_rejected():
    # localhost is in the always-blocked hostname set — rejected pre-resolution.
    assert (
        await proxy._resolve_pinned_backend(
            "http://localhost:11434/v1", allow_private=True
        )
        is None
    )


async def test_unresolvable_host_fails_closed():
    # No cache seed and a name that will not resolve → fail-closed (None).
    assert (
        await proxy._resolve_pinned_backend(
            "http://nonexistent.invalid:11434/v1", allow_private=True
        )
        is None
    )


# ─── S-18: scheme allowlist + empty authority ────────────────────────────────

@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://127.0.0.1:11211/_stats",
        "ftp://internal.example/secret",
        "dict://127.0.0.1:6379/info",
        "://backend.example/v1",
    ],
)
async def test_rejects_non_http_scheme(url):
    # Rejected purely on scheme, before any DNS resolution is attempted.
    assert await proxy._resolve_pinned_backend(url, allow_private=True) is None


async def test_rejects_empty_hostname():
    assert (
        await proxy._resolve_pinned_backend("http:///v1/chat", allow_private=True)
        is None
    )


# ─── bool wrapper delegates to the SSOT ──────────────────────────────────────

async def test_async_is_ssrf_target_true_when_blocked():
    _seed("evil.example", 80, _ipv4_addrinfo("169.254.169.254", 80))
    assert await proxy._async_is_ssrf_target(
        "http://evil.example/", allow_private=True
    ) is True


async def test_async_is_ssrf_target_false_when_safe():
    _seed("ok.example", 443, _ipv4_addrinfo("93.184.216.34", 443))
    assert await proxy._async_is_ssrf_target(
        "https://ok.example/", allow_private=False
    ) is False
