"""Telemetry Transports — plug-and-play SIEM connectors."""

import ipaddress
import logging
import os
import socket
from typing import Optional

logger = logging.getLogger(__name__)

# Shared SSRF protection for all transports (H-06 fix).
# TCP/syslog/HTTP transports must validate the destination before connecting.
#
# The blocklist is split into two tiers, mirroring the request-path idiom in
# src/routes/proxy.py (_ALWAYS_BLOCKED_NETWORKS / _USER_CONTENT_BLOCKED_NETWORKS):
#
#   _ALWAYS_BLOCKED_NETWORKS  — loopback, link-local (cloud metadata lives at
#       169.254.169.254), unspecified. NEVER reachable, even for an operator-
#       configured SIEM collector.
#   _PRIVATE_NETWORKS         — RFC1918 / CGNAT / IPv6-ULA. Blocked by default
#       (fail-closed), but a real SIEM collector often lives on an internal
#       network. Setting BULWARK_SIEM_SSRF_ALLOW_PRIVATE=true opts a deployment
#       into allowing these ranges for the (operator-configured) SIEM export
#       path — used for local/dev E2E validation against a containerised SIEM.
#       The always-blocked tier still applies, so metadata/loopback stay off
#       limits regardless.
_ALWAYS_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local / cloud metadata
    ipaddress.ip_network("0.0.0.0/8"),         # Unspecified
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("::/128"),           # IPv6 unspecified
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
]

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),        # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),     # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),    # RFC1918
    ipaddress.ip_network("100.64.0.0/10"),     # CGNAT
    ipaddress.ip_network("fc00::/7"),          # IPv6 ULA
]

_BLOCKED_HOSTNAMES = frozenset({
    "metadata.google.internal", "metadata.google.internal.",
    "metadata", "localhost",
    "kubernetes.default", "kubernetes.default.svc",
    "kubernetes.default.svc.cluster.local",
})


def _allow_private_siem_targets() -> bool:
    """Whether the deployment opts into private-range SIEM destinations.

    Read per-call (not at import) so the toggle takes effect without a process
    restart and is testable via monkeypatch/env. Default OFF (fail-closed).
    """
    return os.getenv("BULWARK_SIEM_SSRF_ALLOW_PRIVATE", "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def is_ssrf_target_host(host: str, port: Optional[int] = None) -> bool:
    """Validate a hostname:port against SSRF targets.

    SECURITY (H-06): Fail-closed — if DNS resolution fails or any resolved
    IP is in a blocked network, returns True (connection should be blocked).

    Loopback / link-local / metadata are always blocked. RFC1918 / CGNAT /
    IPv6-ULA are blocked unless BULWARK_SIEM_SSRF_ALLOW_PRIVATE is enabled
    (opt-in, for an operator-configured SIEM collector on an internal network).

    Used by the TCP/TLS, Syslog, and HTTP/REST transports before connecting.
    """
    if not host:
        return True

    if host.lower().rstrip(".") in _BLOCKED_HOSTNAMES:
        return True

    blocked_networks = list(_ALWAYS_BLOCKED_NETWORKS)
    if not _allow_private_siem_targets():
        blocked_networks += _PRIVATE_NETWORKS

    try:
        addrs = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return True  # Fail-closed: unresolvable = blocked

    if not addrs:
        return True

    for _family, _, _, _, sockaddr in addrs:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
                ip = ip.ipv4_mapped
            for network in blocked_networks:
                if ip in network:
                    return True
        except ValueError:
            return True  # Fail-closed on unparseable address

    return False
