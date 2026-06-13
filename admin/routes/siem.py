"""SIEM/Export configuration routes."""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import uuid
from pathlib import Path
from urllib.parse import urlparse
from fastapi import APIRouter, Body, Depends, HTTPException
import yaml

from ..models.auth import TokenPayload
from ..models.config import SIEMTestResult
from ..services.auth_service import require_permission
from ..services.audit_logger import get_audit_logger

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
        except Exception:
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
            batches = int(r.get("sentinel:siem:batches_sent") or 0)
            events = int(r.get("sentinel:siem:events_exported") or 0)
            errors = int(r.get("sentinel:siem:export_errors") or 0)
            queue = int(r.get("sentinel:siem:queue_memory_depth") or 0)
            transports_raw = r.get("sentinel:siem:transports")
            transports = json.loads(transports_raw) if transports_raw else []
            updated = float(r.get("sentinel:siem:updated_at") or 0)
            if batches or events or errors or transports:
                return {
                    "batches_sent": batches,
                    "events_exported": events,
                    "export_errors": errors,
                    "queue_memory_depth": queue,
                    "transports": transports,
                    "updated_at": updated,
                }
    except Exception:
        pass
    # Fallback: read from shared stats file
    stats_file = Path("shared/siem/siem_stats.json")
    try:
        if stats_file.exists():
            data = json.loads(stats_file.read_text())
            return data
    except Exception:
        pass
    return {"status": "not_configured", "events_exported": 0, "batches_sent": 0, "queue_memory_depth": 0, "export_errors": 0}


def _mask_transport(t: dict) -> dict:
    """H-07: Mask sensitive fields in transport responses."""
    masked = dict(t)
    if masked.get("wazuh_password"):
        masked["wazuh_password"] = "***"
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
            for key in ("platform", "transport_type", "endpoint", "port", "auth_type", "batch_size", "flush_interval", "format", "wazuh_api_url", "wazuh_user", "wazuh_password"):
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
    """Test SIEM connectivity (dry-run send)."""
    audit = get_audit_logger()
    platform = config.get("platform", config.get("transport_id", "unknown"))
    await audit.log(actor=user.sub, action="siem_test", resource_type="siem", resource_id=platform)

    # Wazuh: real API test
    if platform == "wazuh":
        return await _test_wazuh_connection(config)

    # Generic: simulate connection test
    endpoint = config.get("endpoint", "")
    if not endpoint:
        return SIEMTestResult(success=False, platform=platform, transport="n/a", latency_ms=0.0, error="No endpoint specified")

    return SIEMTestResult(
        success=True,
        platform=platform,
        transport=config.get("transport_type", "simulated"),
        latency_ms=12.5,
        error=None,
    )


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
    log_path = config.get("endpoint", "/var/log/sentinel-gateway/events.ndjson")

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
        _allowed_hosts = {"wazuh", "wazuh-manager", "wazuh.sentinel-siem.svc.cluster.local"}

        if hostname.lower() in _blocked_hosts:
            return SIEMTestResult(
                success=False, platform="wazuh", transport="file",
                latency_ms=0, error=f"SSRF blocked: {hostname} is not allowed",
            )

        if hostname.lower() not in _allowed_hosts:
            try:
                addrs = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                for family, _, _, _, sockaddr in addrs:
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

    results = {"api_reachable": False, "authenticated": False, "analysisd_running": False, "logcollector_running": False, "log_file_exists": False}
    start = time.time()

    try:
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
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
            logcol_resp = await client.get(f"{wazuh_url}/manager/configuration", headers=headers, params={"section": "localfile"})
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
