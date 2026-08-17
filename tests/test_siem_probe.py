"""Tests for the real SIEM connectivity probes (admin/routes/siem.py).

These validate the honest connectivity test that replaced the fabricated
``latency_ms=12.5`` success. Coverage includes host parsing, the SSRF guard
tuned for internal collectors, and per-transport probe behaviour (file / TCP /
TLS / UDP / HTTP) with positive and negative cases.

No external network is used: TCP/UDP positives run against ephemeral local
servers with the loopback SSRF guard patched off (loopback is otherwise blocked
by design), and negatives use closed ports / blocked hosts.
"""

from __future__ import annotations

import asyncio

from admin.routes import siem

# ─── _endpoint_host_port ─────────────────────────────────────────────────────


def test_endpoint_host_port_full_url():
    host, port = siem._endpoint_host_port("https://splunk.example.com:8088/services/collector", 443)
    assert host == "splunk.example.com"
    assert port == 8088


def test_endpoint_host_port_url_default_port():
    host, port = siem._endpoint_host_port("https://splunk.example.com/collector", 443)
    assert host == "splunk.example.com"
    assert port == 443


def test_endpoint_host_port_bare_host_port():
    host, port = siem._endpoint_host_port("collector.corp.net:6514", 514)
    assert host == "collector.corp.net"
    assert port == 6514


def test_endpoint_host_port_bare_host_default():
    host, port = siem._endpoint_host_port("syslog.corp.net", 514)
    assert host == "syslog.corp.net"
    assert port == 514


# ─── _check_probe_host (SSRF guard) ──────────────────────────────────────────


def test_check_probe_host_empty():
    assert siem._check_probe_host("", 514) == "Empty hostname"


def test_check_probe_host_blocked_hostname():
    err = siem._check_probe_host("localhost", 514)
    assert err is not None and "Blocked hostname" in err


def test_check_probe_host_internal_suffix():
    err = siem._check_probe_host("collector.internal", 514)
    assert err is not None and "internal" in err


def test_check_probe_host_loopback_ip():
    err = siem._check_probe_host("127.0.0.1", 514)
    assert err is not None and "blocked range" in err


def test_check_probe_host_metadata_ip():
    err = siem._check_probe_host("169.254.169.254", 80)
    assert err is not None and "blocked range" in err


def test_check_probe_host_ipv6_loopback():
    err = siem._check_probe_host("::1", 514)
    assert err is not None and "blocked range" in err


def test_check_probe_host_allows_rfc1918():
    # Real SIEM collectors live on internal networks — these must be allowed.
    assert siem._check_probe_host("10.0.0.5", 514) is None
    assert siem._check_probe_host("192.168.1.10", 6514) is None
    assert siem._check_probe_host("172.16.4.20", 514) is None


def test_check_probe_host_unresolvable():
    # .invalid is a reserved TLD guaranteed to fail resolution (RFC 6761).
    err = siem._check_probe_host("nonexistent-host.invalid", 514)
    assert err is not None and "Cannot resolve" in err


# ─── _probe_transport dispatch ───────────────────────────────────────────────


async def test_probe_transport_no_endpoint():
    result = await siem._probe_transport({"transport_type": "http_rest", "endpoint": ""})
    assert result.success is False
    assert "No endpoint specified" in result.error


async def test_probe_transport_ssrf_blocked_http():
    result = await siem._probe_transport(
        {"transport_type": "http_rest", "endpoint": "http://localhost:8088", "platform": "splunk"}
    )
    assert result.success is False
    assert "SSRF" in result.error


# ─── _probe_file ─────────────────────────────────────────────────────────────


def test_probe_file_writable(tmp_path):
    endpoint = str(tmp_path / "events.ndjson")
    result = siem._probe_file({"endpoint": endpoint}, "elastic", "file")
    assert result.success is True
    assert "writable" in result.detail.lower()


def test_probe_file_missing_directory():
    result = siem._probe_file(
        {"endpoint": "/nonexistent-dir-xyz-123/events.ndjson"}, "elastic", "file"
    )
    assert result.success is False
    assert "does not exist" in result.error


# ─── _probe_tcp ──────────────────────────────────────────────────────────────


async def test_probe_tcp_success(monkeypatch):
    # Patch off the loopback guard so we can exercise a real local server.
    monkeypatch.setattr(siem, "_check_probe_host", lambda h, p: None)

    async def _handle(reader, writer):
        writer.close()

    server = await asyncio.start_server(_handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        result = await siem._probe_tcp(
            {"endpoint": "127.0.0.1", "port": port}, "qradar", "syslog_tcp", use_tls=False
        )
    finally:
        server.close()
        await server.wait_closed()

    assert result.success is True
    assert "TCP connect OK" in result.detail
    assert result.latency_ms >= 0.0


async def test_probe_tcp_connection_refused(monkeypatch):
    monkeypatch.setattr(siem, "_check_probe_host", lambda h, p: None)
    # Bind then close to obtain a port that is guaranteed closed.
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()

    result = await siem._probe_tcp(
        {"endpoint": "127.0.0.1", "port": port}, "qradar", "syslog_tcp", use_tls=False
    )
    assert result.success is False
    assert "Cannot connect" in result.error


async def test_probe_tcp_ssrf_blocked():
    result = await siem._probe_tcp(
        {"endpoint": "localhost", "port": 514}, "qradar", "syslog_tcp", use_tls=False
    )
    assert result.success is False
    assert "SSRF" in result.error


async def test_probe_tcp_tls_handshake_fails_on_plain_server(monkeypatch):
    # Exercises the use_tls branch: a plain TCP server cannot complete a TLS
    # handshake, so the probe must report failure (not a fabricated success).
    monkeypatch.setattr(siem, "_check_probe_host", lambda h, p: None)

    async def _handle(reader, writer):
        await asyncio.sleep(0.05)
        writer.close()

    server = await asyncio.start_server(_handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        result = await siem._probe_tcp(
            {"endpoint": "127.0.0.1", "port": port}, "custom", "tcp_tls", use_tls=True
        )
    finally:
        server.close()
        await server.wait_closed()

    assert result.success is False
    assert "Cannot connect" in result.error


# ─── _probe_udp ──────────────────────────────────────────────────────────────


async def test_probe_udp_success(monkeypatch):
    monkeypatch.setattr(siem, "_check_probe_host", lambda h, p: None)
    result = await siem._probe_udp(
        {"endpoint": "127.0.0.1", "port": 51999}, "qradar", "syslog_udp"
    )
    # UDP is connectionless: sending succeeds locally and the detail is honest.
    assert result.success is True
    assert "not confirmable" in result.detail


async def test_probe_udp_ssrf_blocked():
    result = await siem._probe_udp(
        {"endpoint": "localhost", "port": 514}, "qradar", "syslog_udp"
    )
    assert result.success is False
    assert "SSRF" in result.error


# ─── _probe_http ─────────────────────────────────────────────────────────────


async def test_probe_http_ssrf_blocked():
    result = await siem._probe_http(
        {"endpoint": "https://localhost:8088", "platform": "splunk"}, "splunk", "http_rest"
    )
    assert result.success is False
    assert "SSRF" in result.error


async def test_probe_http_connect_error(monkeypatch):
    # Allowed host but nothing listening on a closed loopback port → ConnectError.
    monkeypatch.setattr(siem, "_check_probe_host", lambda h, p: None)
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()

    result = await siem._probe_http(
        {"endpoint": f"http://127.0.0.1:{port}", "platform": "elastic"}, "elastic", "http_rest"
    )
    assert result.success is False
    assert result.error  # some connection error surfaced honestly
