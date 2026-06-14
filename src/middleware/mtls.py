"""
mTLS (mutual TLS) verification middleware for inter-service communication.

Enforces client certificate validation on internal API paths (admin↔proxy),
while allowing external clients to continue using JWT/API key authentication
on public endpoints.

Security model: fail-closed. If mTLS is enabled and an internal path is
accessed without a valid client certificate, the request is rejected with 403.

Trust chain:
  - A shared internal CA (sentinel-internal-ca) signs all service certificates
  - Each service presents its client cert when calling another service
  - The receiving service verifies the client cert against the trusted CA
  - Service identity is extracted from the certificate CN or SAN

SECURITY (CRIT-01 fix):
  - X-Client-Cert-* headers are ONLY trusted if the request originates from
    a known reverse proxy CIDR (SENTINEL_MTLS_TRUSTED_PROXY_CIDRS).
  - If the request comes from an untrusted IP, headers are stripped/ignored
    and only direct TLS cert verification (Method 2/3) is used.
  - If no trusted proxy CIDRs are configured, header-based extraction is
    completely disabled.

Paths requiring mTLS (when enabled):
  - /admin/policies/reload    (admin→proxy)
  - /internal/*               (any inter-service call)

Paths NOT requiring mTLS (use JWT/API key):
  - /v1/chat/completions      (external clients)
  - /v2/scan                  (external clients)
  - /health, /ready           (probes, unauthenticated)
"""

import ipaddress
import logging
import ssl
from pathlib import Path
from typing import Optional, Set

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from src.config import settings

logger = logging.getLogger(__name__)

# Internal paths that require mTLS when enabled.
# These are only accessed by other Sentinel services, never by external clients.
MTLS_REQUIRED_PREFIXES = (
    "/admin/policies/reload",
    "/internal/",
)

# Trusted service identities (CN values from client certificates).
# Only these services are allowed to make internal calls.
# SECURITY (H-01 fix): No wildcard matching. Only exact identities.
TRUSTED_SERVICE_IDENTITIES = {
    "proxy.sentinel-gateway.svc.cluster.local",
    "admin.sentinel-gateway.svc.cluster.local",
    "proxy.sentinel-gateway",
    "admin.sentinel-gateway",
    # Development/localhost identities
    "sentinel-proxy",
    "sentinel-admin",
}

# SECURITY (CRIT-01 fix): Parse trusted proxy CIDRs at module load.
# Only requests from these networks can set X-Client-Cert-* headers.
_TRUSTED_PROXY_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []


def _parse_trusted_proxy_cidrs() -> list:
    """Parse SENTINEL_MTLS_TRUSTED_PROXY_CIDRS into network objects."""
    raw = settings.mtls_trusted_proxy_cidrs.strip()
    if not raw:
        return []
    networks = []
    for cidr in raw.split(","):
        cidr = cidr.strip()
        if not cidr:
            continue
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError as e:
            logger.error("Invalid trusted proxy CIDR '%s': %s", cidr, e)
    return networks


def _is_from_trusted_proxy(request: Request) -> bool:
    """Check if the request originates from a trusted reverse proxy.

    Returns True only if:
      1. Trusted proxy CIDRs are configured (non-empty)
      2. The request's client IP is within one of those CIDRs

    If no CIDRs are configured, returns False (header-based cert
    extraction is disabled entirely).
    """
    global _TRUSTED_PROXY_NETWORKS
    if not _TRUSTED_PROXY_NETWORKS:
        # Lazy initialization (settings available after app startup)
        _TRUSTED_PROXY_NETWORKS = _parse_trusted_proxy_cidrs()
        if not _TRUSTED_PROXY_NETWORKS:
            return False

    client_host = request.client.host if request.client else None
    if not client_host:
        return False

    try:
        client_ip = ipaddress.ip_address(client_host)
    except ValueError:
        return False

    return any(client_ip in network for network in _TRUSTED_PROXY_NETWORKS)


class MTLSError(Exception):
    """Raised when mTLS verification fails."""

    pass


def build_ssl_context() -> Optional[ssl.SSLContext]:
    """Build an SSL context for verifying client certificates.

    Returns None if mTLS is not configured (paths will be unprotected
    by this middleware — they still have JWT/API key auth).

    The context:
      - Loads the trusted CA certificate
      - Requires client certificates (CERT_REQUIRED)
      - Verifies the client cert chain against the CA
    """
    if not settings.mtls_enabled:
        return None

    ca_path = settings.mtls_ca_cert_path
    if not ca_path:
        logger.warning(
            "mTLS enabled but no CA certificate configured "
            "(SENTINEL_MTLS_CA_CERT_PATH). Internal paths will reject all requests."
        )
        return None

    ca_file = Path(ca_path)
    if not ca_file.is_file():
        logger.error(
            "mTLS CA certificate not found: %s. "
            "Internal paths will reject all requests.",
            ca_path,
        )
        return None

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=str(ca_file))

        # Load server cert/key if configured (for TLS termination at app level)
        server_cert = settings.mtls_server_cert_path
        server_key = settings.mtls_server_key_path
        if server_cert and server_key:
            cert_file = Path(server_cert)
            key_file = Path(server_key)
            if cert_file.is_file() and key_file.is_file():
                ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))

        # Security hardening
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers(
            "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
        )

        # SECURITY (M-13 fix): Enable CRL checking if CRL file is configured.
        # This rejects certificates that have been revoked by the CA.
        crl_path = getattr(settings, "mtls_crl_path", None)
        if crl_path:
            crl_file = Path(crl_path)
            if crl_file.is_file():
                ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
                ctx.load_verify_locations(cafile=str(crl_file))
                logger.info("mTLS CRL checking enabled (CRL: %s)", crl_path)
            else:
                logger.warning("mTLS CRL path configured but file not found: %s", crl_path)

        logger.info(
            "mTLS SSL context initialized successfully (CA: %s)", ca_path
        )
        return ctx

    except ssl.SSLError as e:
        logger.error("Failed to build mTLS SSL context: %s", e)
        return None
    except Exception as e:
        logger.error("Unexpected error building mTLS SSL context: %s", e)
        return None


def _path_requires_mtls(path: str) -> bool:
    """Check if the request path requires mTLS verification.

    Args:
        path: The URL path from the request.

    Returns:
        True if the path is an internal endpoint requiring mTLS.
    """
    for prefix in MTLS_REQUIRED_PREFIXES:
        if path.startswith(prefix):
            return True
    return False


def _extract_client_identity(request: Request) -> Optional[str]:
    """Extract the client service identity from the request.

    SECURITY (CRIT-01 fix): Header-based extraction (Method 1) is ONLY used
    if the request comes from a trusted reverse proxy CIDR. This prevents
    attackers from spoofing X-Client-Cert-* headers when the gateway is
    directly accessible.

    In production (behind nginx/envoy with mTLS termination), the client
    certificate info is passed via headers:
      - X-Client-Cert-CN: Common Name from the client certificate
      - X-Client-Cert-SAN: Subject Alternative Names (DNS)
      - X-Client-Cert-Verified: "SUCCESS" if the proxy verified the cert

    In direct TLS mode (app-level termination), the cert is available
    from the transport layer (ASGI scope).

    Returns:
        The service identity (CN or SAN DNS name), or None if not available.
    """
    # Method 1: Headers from reverse proxy (nginx, envoy, istio)
    # SECURITY: Only trust these headers if request is from a known proxy IP.
    if _is_from_trusted_proxy(request):
        cert_verified = request.headers.get("X-Client-Cert-Verified", "")
        if cert_verified.upper() == "SUCCESS":
            # CN from verified certificate
            cn = request.headers.get("X-Client-Cert-CN", "")
            if cn:
                return cn

            # SAN DNS names (comma-separated)
            san = request.headers.get("X-Client-Cert-SAN", "")
            if san:
                # Return first DNS SAN
                for name in san.split(","):
                    name = name.strip()
                    if name:
                        return name
    else:
        # Log spoofing attempt if headers are present but source is untrusted
        if request.headers.get("X-Client-Cert-Verified"):
            client_host = request.client.host if request.client else "unknown"
            logger.warning(
                "mTLS header spoofing attempt: X-Client-Cert-* headers from "
                "untrusted source %s (not in SENTINEL_MTLS_TRUSTED_PROXY_CIDRS)",
                client_host,
            )

    # Method 2: Direct TLS (app-level termination)
    # Available when uvicorn is running with ssl_certfile + ssl_ca_certs
    transport = getattr(request.scope.get("transport"), "get_extra_info", None)
    if transport:
        peercert = transport("peercert")
        if peercert:
            # Extract CN from subject
            subject = peercert.get("subject", ())
            for rdn in subject:
                for attr_type, attr_value in rdn:
                    if attr_type == "commonName":
                        return attr_value
            # Extract DNS from subjectAltName
            san_entries = peercert.get("subjectAltName", ())
            for san_type, san_value in san_entries:
                if san_type == "DNS":
                    return san_value

    # Method 3: ASGI extensions (some servers expose client cert here)
    extensions = request.scope.get("extensions", {})
    if extensions:
        tls_info = extensions.get("tls") or {}
        peercert = tls_info.get("peercert")
        if peercert:
            subject = peercert.get("subject", ())
            for rdn in subject:
                for attr_type, attr_value in rdn:
                    if attr_type == "commonName":
                        return attr_value

    return None


def _is_trusted_identity(identity: str) -> bool:
    """Verify the client identity is a known Sentinel service.

    SECURITY (H-01 fix): Only exact matches against known identities.
    No wildcard/suffix matching — a compromised service in the same
    namespace could forge a certificate with a matching suffix.

    Args:
        identity: The CN or SAN extracted from the client certificate.

    Returns:
        True if the identity belongs to a trusted Sentinel service.
    """
    if not identity:
        return False

    # Exact match only — no wildcard patterns
    return identity in TRUSTED_SERVICE_IDENTITIES


class MTLSMiddleware(BaseHTTPMiddleware):
    """Middleware that enforces mTLS on internal service-to-service paths.

    When mTLS is enabled:
      - Internal paths (/internal/*, /admin/policies/reload) require a valid
        client certificate from a trusted Sentinel service.
      - External paths (/v1/*, /v2/*) are unaffected — they use JWT/API key.
      - Health/readiness probes are always allowed through.

    When mTLS is disabled:
      - All paths pass through without certificate checks.
      - Internal paths are still protected by JWT/API key auth.
    """

    def __init__(self, app, **kwargs):
        super().__init__(app, **kwargs)
        self._enabled = settings.mtls_enabled
        self._ssl_context = build_ssl_context() if self._enabled else None

        if self._enabled:
            logger.info(
                "mTLS middleware active — internal paths require client certificate"
            )
        else:
            logger.debug("mTLS middleware disabled — all paths use standard auth")

    async def dispatch(self, request: Request, call_next):
        # Skip if mTLS is disabled globally
        if not self._enabled:
            return await call_next(request)

        path = request.url.path

        # Only enforce mTLS on internal paths
        if not _path_requires_mtls(path):
            return await call_next(request)

        # Internal path — require valid client certificate
        identity = _extract_client_identity(request)

        if not identity:
            logger.warning(
                "mTLS required but no client certificate presented",
                extra={
                    "path": path,
                    "remote": request.client.host if request.client else "unknown",
                },
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "mTLS required for internal endpoints",
                    "detail": "A valid client certificate signed by the Sentinel internal CA is required.",
                    "path": path,
                },
            )

        if not _is_trusted_identity(identity):
            logger.warning(
                "mTLS client certificate has untrusted identity: %s",
                identity,
                extra={
                    "path": path,
                    "identity": identity,
                    "remote": request.client.host if request.client else "unknown",
                },
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "mTLS required for internal endpoints",
                    "detail": f"Client identity '{identity}' is not a trusted Sentinel service.",
                    "path": path,
                },
            )

        # Certificate valid and identity trusted — attach to request state
        request.state.mtls_identity = identity
        logger.debug(
            "mTLS verified: %s → %s",
            identity,
            path,
        )

        return await call_next(request)


def create_client_ssl_context() -> Optional[ssl.SSLContext]:
    """Create an SSL context for outbound inter-service calls.

    Used by the proxy/admin when making HTTP calls to the other service.
    Loads the client certificate + key and the trusted CA.

    Returns:
        SSLContext configured for client-side mTLS, or None if not configured.
    """
    if not settings.mtls_enabled:
        return None

    client_cert = settings.mtls_client_cert_path
    client_key = settings.mtls_client_key_path
    ca_cert = settings.mtls_ca_cert_path

    if not all([client_cert, client_key, ca_cert]):
        logger.debug(
            "mTLS client context not configured — outbound calls will not use mTLS"
        )
        return None

    # Verify files exist
    for label, path in [("client cert", client_cert), ("client key", client_key), ("CA cert", ca_cert)]:
        if not Path(path).is_file():
            logger.error("mTLS %s file not found: %s", label, path)
            return None

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(certfile=client_cert, keyfile=client_key)
        ctx.load_verify_locations(cafile=ca_cert)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        logger.info("mTLS client SSL context initialized (cert: %s)", client_cert)
        return ctx

    except ssl.SSLError as e:
        logger.error("Failed to build mTLS client SSL context: %s", e)
        return None
    except Exception as e:
        logger.error("Unexpected error building mTLS client SSL context: %s", e)
        return None
