"""Telemetry Transports — plug-and-play SIEM connectors."""

import ipaddress
import logging
import socket
from typing import Optional

logger = logging.getLogger(__name__)

# Shared SSRF protection for all transports (H-06 fix).
# TCP/syslog transports must validate destination before connecting.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("10.0.0.0/8"),        # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),     # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),    # RFC1918
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local / cloud metadata
    ipaddress.ip_network("100.64.0.0/10"),     # CGNAT
    ipaddress.ip_network("0.0.0.0/8"),         # Unspecified
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
]

_BLOCKED_HOSTNAMES = frozenset({
    "metadata.google.internal", "metadata.google.internal.",
    "metadata", "localhost",
    "kubernetes.default", "kubernetes.default.svc",
    "kubernetes.default.svc.cluster.local",
})


def is_ssrf_target_host(host: str, port: Optional[int] = None) -> bool:
    """Validate a hostname:port against SSRF targets.

    SECURITY (H-06): Fail-closed — if DNS resolution fails or any resolved
    IP is in a blocked network, returns True (connection should be blocked).

    Used by TCP/TLS and Syslog transports before connecting.
    """
    if not host:
        return True

    if host.lower() in _BLOCKED_HOSTNAMES:
        return True

    try:
        addrs = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return True  # Fail-closed: unresolvable = blocked

    for family, _, _, _, sockaddr in addrs:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
            for network in _BLOCKED_NETWORKS:
                if ip in network:
                    return True
        except ValueError:
            return True  # Fail-closed on unparseable address

    return False
