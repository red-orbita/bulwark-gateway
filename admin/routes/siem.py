"""SIEM/Export configuration routes."""

from __future__ import annotations

import ipaddress
import json
import socket
import uuid
from pathlib import Path
from urllib.parse import urlparse

import yaml
from fastapi import APIRouter, Body, Depends, HTTPException

from ..models.auth import TokenPayload
from ..models.config import SIEMTestResult
from ..services.audit_logger import get_audit_logger
from ..services.auth_service import require_permission

router = APIRouter()

SIEM_CONFIG_DIR = Path("config/siem")
_TRANSPORTS_FILE = Path("shared/siem/siem_transports.json")

# SECURITY FIX (C-07): SSRF blocklist for SIEM transport endpoint validation
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

# In-memory transport registry (loaded from disk)
_transports: list[dict] = []


def _load_transports() -> None:
    """Load transports from persistent storage."""
    global _transports
    if _TRANSPORTS_FILE.exists():
        try:
            _transports = json.loads(_TRANSPORTS_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            _transports = []


def _save_transports() -> None:
    """Persist transports to disk."""
    _TRANSPORTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    _TRANSPORTS_FILE.write_text(json.dumps(_transports, indent=2))


# Load on module import
_load_transports()


@router.get("/platforms")
async def list_platforms(user: TokenPayload = Depends(require_permission("siem:read"))):
    """List available SIEM platform templates."""
    platforms = []
    for path in sorted(SIEM_CONFIG_DIR.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text())
            platforms.append({
                "name": path.stem,
                "platform": data.get("platform", path.stem),
                "transport": data.get("transport", "unknown"),
            })
        except Exception:  # noqa: S110 - skip an unreadable SIEM config file; list is advisory
            pass
    return platforms


@router.get("/config")
async def get_all_config(user: TokenPayload = Depends(require_permission("siem:read"))):
    """Get all configured transports."""
    return {"transports": _transports}


@router.get("/config/{platform}")
async def get_siem_config(platform: str, user: TokenPayload = Depends(require_permission("siem:read"))):
    """Get SIEM configuration template."""
    path = SIEM_CONFIG_DIR / f"{platform}.yaml"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Platform '{platform}' not found")
    return {"platform": platform, "config": yaml.safe_load(path.read_text()), "raw": path.read_text()}


@router.get("/status")
async def siem_status(user: TokenPayload = Depends(require_permission("siem:read"))):
    """Get current SIEM export status from Redis (multi-pod safe) or file fallback."""
    # Try Redis first (aggregated across all pods)
    try:
        from ..services.redis_sync import get_redis_client
        r = get_redis_client(timeout=1.0)
        if r:
            batches = int(r.get("bulwark:siem:batches_sent") or 0)
            events = int(r.get("bulwark:siem:events_exported") or 0)
            errors = int(r.get("bulwark:siem:export_errors") or 0)
            queue = int(r.get("bulwark:siem:queue_memory_depth") or 0)
            transports_raw = r.get("bulwark:siem:transports")
            transports = json.loads(transports_raw) if transports_raw else []
            updated = float(r.get("bulwark:siem:updated_at") or 0)
            if batches or events or errors or transports:
                return {
                    "batches_sent": batches,
                    "events_exported": events,
                    "export_errors": errors,
                    "queue_memory_depth": queue,
                    "transports": transports,
                    "updated_at": updated,
                }
    except Exception:  # noqa: S110 - best-effort stats read; dashboard must still render
        pass
    # Fallback: read from shared stats file
    stats_file = Path("shared/siem/siem_stats.json")
    try:
        if stats_file.exists():
            data = json.loads(stats_file.read_text())
            return data
    except Exception:  # noqa: S110 - best-effort stats read; returns empty on failure
        pass
    return {
        "status": "not_configured",
        "events_exported": 0,
        "batches_sent": 0,
        "queue_memory_depth": 0,
        "export_errors": 0,
    }


def _mask_transport(t: dict) -> dict:
    """H-07: Mask sensitive fields in transport responses."""
    masked = dict(t)
    if masked.get("wazuh_password"):
        masked["wazuh_password"] = "***"  # noqa: S105 - masking placeholder, redacts the real secret  # nosemgrep: bulwark-no-hardcoded-jwt-secret
    return masked


@router.post("/transport")
async def create_transport(
    config: dict = Body(...),
    user: TokenPayload = Depends(require_permission("siem:write")),
):
    """Add a new SIEM transport."""
    # SECURITY FIX (C-07): Validate SIEM transport endpoints against SSRF blocklist
    endpoint = config.get("endpoint", "")
    if endpoint:
        ssrf_error = _validate_url_no_ssrf(endpoint)
        if ssrf_error:
            raise HTTPException(status_code=400, detail=f"Endpoint blocked (SSRF protection): {ssrf_error}")
    wazuh_api_url = config.get("wazuh_api_url", "")
    if wazuh_api_url:
        ssrf_error = _validate_url_no_ssrf(wazuh_api_url)
        if ssrf_error:
            raise HTTPException(status_code=400, detail=f"Wazuh API URL blocked (SSRF protection): {ssrf_error}")

    transport = {
        "id": str(uuid.uuid4())[:8],
        "platform": config.get("platform", "custom"),
        "transport_type": config.get("transport_type", "http_rest"),
        "endpoint": endpoint,
        "port": config.get("port", 514),
        "auth_type": config.get("auth_type", "none"),
        "batch_size": config.get("batch_size", 100),
        "flush_interval": config.get("flush_interval", 1.0),
        "format": config.get("format", "ecs_json"),
        "enabled": True,
        "circuit_state": "closed",
        "wazuh_api_url": wazuh_api_url,
        "wazuh_user": config.get("wazuh_user", ""),
        "wazuh_password": config.get("wazuh_password", ""),
    }
    _transports.append(transport)
    _save_transports()
    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="siem_create", resource_type="transport", resource_id=transport["id"])
    return _mask_transport(transport)


@router.put("/transport/{transport_id}")
async def update_transport(
    transport_id: str,
    config: dict = Body(...),
    user: TokenPayload = Depends(require_permission("siem:write")),
):
    """Update a SIEM transport."""
    # SECURITY FIX (C-07): Validate SIEM transport endpoints against SSRF blocklist
    if "endpoint" in config and config["endpoint"]:
        ssrf_error = _validate_url_no_ssrf(config["endpoint"])
        if ssrf_error:
            raise HTTPException(status_code=400, detail=f"Endpoint blocked (SSRF protection): {ssrf_error}")
    if "wazuh_api_url" in config and config["wazuh_api_url"]:
        ssrf_error = _validate_url_no_ssrf(config["wazuh_api_url"])
        if ssrf_error:
            raise HTTPException(status_code=400, detail=f"Wazuh API URL blocked (SSRF protection): {ssrf_error}")

    for t in _transports:
        if t["id"] == transport_id:
            for key in (
                "platform",
                "transport_type",
                "endpoint",
                "port",
                "auth_type",
                "batch_size",
                "flush_interval",
                "format",
                "wazuh_api_url",
                "wazuh_user",
                "wazuh_password",
            ):
                if key in config:
                    t[key] = config[key]
            _save_transports()
            audit = get_audit_logger()
            await audit.log(actor=user.sub, action="siem_update", resource_type="transport", resource_id=transport_id)
            return t
    raise HTTPException(status_code=404, detail="Transport not found")


@router.post("/transport/{transport_id}/toggle")
async def toggle_transport(
    transport_id: str,
    user: TokenPayload = Depends(require_permission("siem:write")),
):
    """Toggle transport enabled/disabled."""
    for t in _transports:
        if t["id"] == transport_id:
            t["enabled"] = not t["enabled"]
            _save_transports()
            audit = get_audit_logger()
            await audit.log(actor=user.sub, action="siem_toggle", resource_type="transport", resource_id=transport_id)
            return {"id": transport_id, "enabled": t["enabled"]}
    raise HTTPException(status_code=404, detail="Transport not found")


@router.delete("/transport/{transport_id}")
async def delete_transport(
    transport_id: str,
    user: TokenPayload = Depends(require_permission("siem:write")),
):
    """Delete a SIEM transport."""
    global _transports
    for t in _transports:
        if t["id"] == transport_id:
            _transports = [x for x in _transports if x["id"] != transport_id]
            _save_transports()
            audit = get_audit_logger()
            await audit.log(actor=user.sub, action="siem_delete", resource_type="transport", resource_id=transport_id)
            return {"id": transport_id, "deleted": True}
    raise HTTPException(status_code=404, detail="Transport not found")


@router.post("/test")
async def test_siem_connection(
    config: dict = Body(...),
    user: TokenPayload = Depends(require_permission("siem:test")),
):
    """Test SIEM connectivity with a real probe (no fabricated results).

    Wazuh runs a full API/analysisd check. Every other transport runs a real
    connectivity probe appropriate to its protocol (HTTP request, TCP/TLS
    handshake, UDP datagram, or filesystem writability) with measured latency.
    """
    audit = get_audit_logger()
    platform = config.get("platform", config.get("transport_id", "unknown"))
    await audit.log(actor=user.sub, action="siem_test", resource_type="siem", resource_id=platform)

    # Wazuh: real API test
    if platform == "wazuh":
        return await _test_wazuh_connection(config)

    return await _probe_transport(config)


async def _probe_transport(config: dict) -> SIEMTestResult:
    """Dispatch a real connectivity probe based on the transport type."""
    ttype = config.get("transport_type", "http_rest")
    platform = config.get("platform", "unknown")
    endpoint = config.get("endpoint", "")

    if not endpoint:
        return SIEMTestResult(
            success=False, platform=platform, transport=ttype,
            latency_ms=0.0, error="No endpoint specified",
        )

    if ttype == "file":
        return _probe_file(config, platform, ttype)
    if ttype == "http_rest":
        return await _probe_http(config, platform, ttype)
    if ttype == "syslog_udp":
        return await _probe_udp(config, platform, ttype)
    # syslog_tcp, syslog_tls, tcp_tls → TCP connect (TLS variants add a handshake)
    use_tls = ttype in ("syslog_tls", "tcp_tls")
    return await _probe_tcp(config, platform, ttype, use_tls=use_tls)


# ─── Real connectivity probes ────────────────────────────────────────────────

# Networks that remain blocked even for the authenticated admin connectivity
# test. Loopback and link-local (cloud metadata lives at 169.254.169.254) are
# always off-limits. RFC1918/CGNAT private ranges are intentionally NOT blocked
# here: real SIEM collectors live on internal networks and this is an
# authenticated, dedicated ``siem:test`` action. The export path
# (create_transport) keeps the stricter full blocklist.
_TEST_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
]


def _check_probe_host(hostname: str, port: int) -> str | None:
    """Resolve a bare host and reject loopback/link-local targets. None = safe."""
    hostname = (hostname or "").lower().rstrip(".")
    if not hostname:
        return "Empty hostname"
    if hostname in _BLOCKED_HOSTNAMES:
        return f"Blocked hostname: {hostname}"
    if hostname.endswith(".internal"):
        return f"Blocked internal hostname: {hostname}"
    try:
        addr_infos = socket.getaddrinfo(hostname, port or 0, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError):
        return f"Cannot resolve hostname: {hostname}"
    for info in addr_infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return f"Invalid IP: {ip_str}"
        for net in _TEST_BLOCKED_NETWORKS:
            if ip in net:
                return f"IP {ip_str} in blocked range {net}"
    return None


def _endpoint_host_port(endpoint: str, default_port: int) -> tuple[str, int]:
    """Extract (host, port) from an endpoint that may be a URL, host, or host:port."""
    if "://" in endpoint:
        parsed = urlparse(endpoint)
        return (parsed.hostname or ""), (parsed.port or default_port)
    # Bare "host" or "host:port" (ignore bracketed IPv6 for simplicity)
    if endpoint.count(":") == 1 and not endpoint.startswith("["):
        host, _, port_str = endpoint.partition(":")
        return host, int(port_str) if port_str.isdigit() else default_port
    return endpoint, default_port


def _probe_file(config: dict, platform: str, ttype: str) -> SIEMTestResult:
    """Verify the target NDJSON path's directory exists and is writable."""
    import os
    import time

    path = config.get("endpoint", "")
    start = time.time()
    parent = os.path.dirname(path) or "."
    latency = (time.time() - start) * 1000
    if not os.path.isdir(parent):
        return SIEMTestResult(
            success=False, platform=platform, transport=ttype, latency_ms=round(latency, 2),
            error=f"Directory does not exist on gateway host: {parent}",
        )
    if not os.access(parent, os.W_OK):
        return SIEMTestResult(
            success=False, platform=platform, transport=ttype, latency_ms=round(latency, 2),
            error=f"Directory not writable on gateway host: {parent}",
        )
    return SIEMTestResult(
        success=True, platform=platform, transport=ttype, latency_ms=round(latency, 2),
        detail=f"Directory writable: {parent}",
    )


async def _probe_http(config: dict, platform: str, ttype: str) -> SIEMTestResult:
    """Confirm the HTTP(S) endpoint is reachable (any HTTP response = up)."""
    import time

    import httpx

    endpoint = config.get("endpoint", "")
    default_port = int(config.get("port", 443) or 443)
    host, port = _endpoint_host_port(endpoint, default_port)

    ssrf_error = _check_probe_host(host, port)
    if ssrf_error:
        return SIEMTestResult(
            success=False, platform=platform, transport=ttype, latency_ms=0.0,
            error=f"Endpoint blocked (SSRF protection): {ssrf_error}",
        )

    if "://" in endpoint:
        url = endpoint
    else:
        scheme = "http" if port in (80, 8080) else "https"
        url = f"{scheme}://{host}:{port}"

    start = time.time()
    try:
        async with httpx.AsyncClient(verify=True, timeout=10.0, follow_redirects=False) as client:
            resp = await client.request("HEAD", url)
        latency = (time.time() - start) * 1000
        return SIEMTestResult(
            success=True, platform=platform, transport=ttype, latency_ms=round(latency, 2),
            detail=f"Reachable (HTTP {resp.status_code})",
        )
    except httpx.ConnectTimeout:
        latency = (time.time() - start) * 1000
        return SIEMTestResult(
            success=False, platform=platform, transport=ttype, latency_ms=round(latency, 2),
            error=f"Connection to {url} timed out",
        )
    except httpx.ConnectError as e:
        latency = (time.time() - start) * 1000
        return SIEMTestResult(
            success=False, platform=platform, transport=ttype, latency_ms=round(latency, 2),
            error=f"Cannot connect to {url}: {e}",
        )
    except Exception as e:
        latency = (time.time() - start) * 1000
        return SIEMTestResult(
            success=False, platform=platform, transport=ttype, latency_ms=round(latency, 2),
            error=f"Probe failed: {e}",
        )


async def _probe_tcp(config: dict, platform: str, ttype: str, *, use_tls: bool) -> SIEMTestResult:
    """Open a TCP connection (and TLS handshake for TLS variants)."""
    import asyncio
    import contextlib
    import ssl
    import time

    endpoint = config.get("endpoint", "")
    default_port = int(config.get("port", 514) or 514)
    host, port = _endpoint_host_port(endpoint, default_port)

    ssrf_error = _check_probe_host(host, port)
    if ssrf_error:
        return SIEMTestResult(
            success=False, platform=platform, transport=ttype, latency_ms=0.0,
            error=f"Endpoint blocked (SSRF protection): {ssrf_error}",
        )

    ssl_context = None
    if use_tls:
        # Connectivity probe: confirm the port is open and TLS handshakes. The
        # certificate is not verified here (collectors are often self-signed);
        # the detail message states this explicitly so the result is honest.
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    start = time.time()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_context), timeout=10.0
        )
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        latency = (time.time() - start) * 1000
        detail = (
            f"TLS handshake OK to {host}:{port} (certificate not verified)"
            if use_tls else f"TCP connect OK to {host}:{port}"
        )
        return SIEMTestResult(
            success=True, platform=platform, transport=ttype,
            latency_ms=round(latency, 2), detail=detail,
        )
    except asyncio.TimeoutError:
        latency = (time.time() - start) * 1000
        return SIEMTestResult(
            success=False, platform=platform, transport=ttype, latency_ms=round(latency, 2),
            error=f"Connection to {host}:{port} timed out",
        )
    except (OSError, ssl.SSLError) as e:
        latency = (time.time() - start) * 1000
        return SIEMTestResult(
            success=False, platform=platform, transport=ttype, latency_ms=round(latency, 2),
            error=f"Cannot connect to {host}:{port}: {e}",
        )


async def _probe_udp(config: dict, platform: str, ttype: str) -> SIEMTestResult:
    """Send a datagram over UDP. Delivery is not confirmable (connectionless)."""
    import socket as _socket
    import time

    endpoint = config.get("endpoint", "")
    default_port = int(config.get("port", 514) or 514)
    host, port = _endpoint_host_port(endpoint, default_port)

    ssrf_error = _check_probe_host(host, port)
    if ssrf_error:
        return SIEMTestResult(
            success=False, platform=platform, transport=ttype, latency_ms=0.0,
            error=f"Endpoint blocked (SSRF protection): {ssrf_error}",
        )

    start = time.time()
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.settimeout(5.0)
        sock.connect((host, port))  # resolves + sets default peer
        sock.send(b"<134>bulwark-gateway siem connectivity probe\n")
        latency = (time.time() - start) * 1000
        return SIEMTestResult(
            success=True, platform=platform, transport=ttype, latency_ms=round(latency, 2),
            detail=f"UDP datagram sent to {host}:{port} — delivery not confirmable (connectionless)",
        )
    except (OSError, _socket.gaierror) as e:
        latency = (time.time() - start) * 1000
        return SIEMTestResult(
            success=False, platform=platform, transport=ttype, latency_ms=round(latency, 2),
            error=f"UDP probe to {host}:{port} failed: {e}",
        )
    finally:
        if sock is not None:
            sock.close()


async def _test_wazuh_connection(config: dict) -> SIEMTestResult:
    """Test Wazuh integration: API reachability + analysisd status + log file access."""
    import ipaddress
    import socket
    import time
    from urllib.parse import urlparse

    import httpx

    wazuh_url = config.get("wazuh_api_url", "https://localhost:55000")
    wazuh_user = config.get("wazuh_user", "wazuh-wui")
    wazuh_password = config.get("wazuh_password", "wazuh-wui")
    log_path = config.get("endpoint", "/var/log/bulwark-gateway/events.ndjson")

    # H-02: SSRF validation on wazuh_api_url
    try:
        parsed = urlparse(wazuh_url)
        hostname = parsed.hostname or ""
        _blocked_hosts = {"metadata.google.internal", "localhost", "127.0.0.1",
                          "kubernetes.default", "kubernetes.default.svc"}
        _blocked_nets = [
            ipaddress.ip_network("169.254.0.0/16"),
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
        ]
        # Allow "wazuh" and "wazuh-manager" service names (internal K8s services)
        _allowed_hosts = {"wazuh", "wazuh-manager", "wazuh.bulwark-siem.svc.cluster.local"}

        if hostname.lower() in _blocked_hosts:
            return SIEMTestResult(
                success=False, platform="wazuh", transport="file",
                latency_ms=0, error=f"SSRF blocked: {hostname} is not allowed",
            )

        if hostname.lower() not in _allowed_hosts:
            try:
                addrs = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                for _family, _, _, _, sockaddr in addrs:
                    ip = ipaddress.ip_address(sockaddr[0])
                    for net in _blocked_nets:
                        if ip in net:
                            return SIEMTestResult(
                                success=False, platform="wazuh", transport="file",
                                latency_ms=0, error=f"SSRF blocked: {hostname} resolves to private IP",
                            )
            except (socket.gaierror, OSError):
                pass  # Allow unresolvable for Wazuh (may be K8s service DNS)
    except Exception:
        return SIEMTestResult(
            success=False, platform="wazuh", transport="file",
            latency_ms=0, error="Invalid wazuh_api_url",
        )

    results = {
        "api_reachable": False,
        "authenticated": False,
        "analysisd_running": False,
        "logcollector_running": False,
        "log_file_exists": False,
    }
    start = time.time()

    try:
        # SECURITY FIX (APT-07): Enable TLS verification by default.
        # Use BULWARK_WAZUH_TLS_VERIFY=false only for self-signed certs in dev.
        import os
        _tls_verify = os.getenv("BULWARK_WAZUH_TLS_VERIFY", "true").lower() not in ("false", "0", "no")
        async with httpx.AsyncClient(verify=_tls_verify, timeout=10.0) as client:
            # Step 1: Authenticate
            auth_resp = await client.post(
                f"{wazuh_url}/security/user/authenticate",
                auth=(wazuh_user, wazuh_password),
            )
            results["api_reachable"] = True

            if auth_resp.status_code != 200:
                latency = (time.time() - start) * 1000
                return SIEMTestResult(
                    success=False, platform="wazuh", transport="file",
                    latency_ms=round(latency, 1),
                    error=f"Authentication failed (HTTP {auth_resp.status_code}). Check credentials.",
                )

            token = auth_resp.json().get("data", {}).get("token", "")
            results["authenticated"] = True
            headers = {"Authorization": f"Bearer {token}"}

            # Step 2: Check manager status (daemons)
            status_resp = await client.get(f"{wazuh_url}/manager/status", headers=headers)
            if status_resp.status_code == 200:
                daemons = status_resp.json().get("data", {}).get("affected_items", [{}])
                if daemons:
                    daemon_map = daemons[0] if isinstance(daemons, list) and daemons else daemons
                    results["analysisd_running"] = daemon_map.get("wazuh-analysisd") == "running"
                    results["logcollector_running"] = daemon_map.get("wazuh-logcollector") == "running"

            # Step 3: Check if log file path is monitored
            logcol_resp = await client.get(
                f"{wazuh_url}/manager/configuration",
                headers=headers,
                params={"section": "localfile"},
            )
            if logcol_resp.status_code == 200:
                items = logcol_resp.json().get("data", {}).get("affected_items", [])
                for item in items:
                    localfiles = item.get("localfile", []) if isinstance(item, dict) else []
                    for lf in localfiles:
                        if lf.get("location", "") == log_path:
                            results["log_file_exists"] = True
                            break

    except httpx.ConnectError:
        latency = (time.time() - start) * 1000
        return SIEMTestResult(
            success=False, platform="wazuh", transport="file",
            latency_ms=round(latency, 1),
            error=f"Cannot connect to Wazuh API at {wazuh_url}. Is the manager running?",
        )
    except Exception as e:
        latency = (time.time() - start) * 1000
        return SIEMTestResult(
            success=False, platform="wazuh", transport="file",
            latency_ms=round(latency, 1),
            error=f"Unexpected error: {str(e)}",
        )

    latency = (time.time() - start) * 1000

    # Build result summary
    issues = []
    if not results["analysisd_running"]:
        issues.append("wazuh-analysisd not running")
    if not results["logcollector_running"]:
        issues.append("wazuh-logcollector not running")
    if not results["log_file_exists"]:
        issues.append(f"'{log_path}' not found in localfile config")

    if issues:
        return SIEMTestResult(
            success=False, platform="wazuh", transport="file",
            latency_ms=round(latency, 1),
            error=f"Wazuh reachable but: {'; '.join(issues)}",
        )

    return SIEMTestResult(
        success=True, platform="wazuh", transport="file",
        latency_ms=round(latency, 1),
        error=None,
    )
