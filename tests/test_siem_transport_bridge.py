"""Tests for the admin→proxy SIEM transport-config bridge.

The admin UI persists a transport dict in its own vocabulary; the proxy's
``load_transports_from_config`` (src/telemetry/exporter.py) is the single place
that maps that vocabulary onto the concrete transport config objects. These
tests lock down that normalization (transport_type / auth_method / format), the
shared SSRF allowlist (``is_ssrf_target_host`` + the HTTP transport's
``_is_ssrf_target``), and the admin-side masking / SSRF-validation / masked-secret
round-trip guard.

Offline by design: SSRF cases use IP literals (``getaddrinfo`` parses these
locally, no DNS) or blocked hostnames; no transport is ever opened.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from admin.models.auth import TokenPayload, UserRole
from admin.routes import siem
from src.telemetry import exporter as exporter_mod
from src.telemetry.exporter import (
    TelemetryExporter,
    _add_transport_from_config,
    _build_http_auth,
    _default_api_key_header,
    _map_http_format,
    _map_syslog_format,
    _map_tcp_format,
    load_transports_from_config,
)
from src.telemetry.transports import is_ssrf_target_host
from src.telemetry.transports.http_rest import HttpAuthMethod, _is_ssrf_target
from src.telemetry.transports.syslog import SyslogFormat, SyslogProtocol

_ALLOW_ENV = "BULWARK_SIEM_SSRF_ALLOW_PRIVATE"


def _only_config(exp: TelemetryExporter):
    """Return the single registered transport's (name, config)."""
    assert len(exp._transports) == 1
    tw = exp._transports[0]
    return tw.transport.name, tw.transport._config


# ─── format mappers ──────────────────────────────────────────────────────────


def test_map_http_format():
    assert _map_http_format("ndjson") == "ndjson"
    assert _map_http_format("custom_json") == "ndjson"
    assert _map_http_format("ecs_json") == "json"
    assert _map_http_format("json") == "json"
    assert _map_http_format("") == "json"  # default
    assert _map_http_format("unknown") == "json"


def test_map_syslog_format():
    assert _map_syslog_format("cef") is SyslogFormat.CEF
    assert _map_syslog_format("leef") is SyslogFormat.LEEF
    assert _map_syslog_format("rfc5424") is SyslogFormat.RFC5424
    assert _map_syslog_format("ecs_json") is SyslogFormat.JSON
    assert _map_syslog_format("json") is SyslogFormat.JSON
    assert _map_syslog_format("") is SyslogFormat.JSON  # default
    assert _map_syslog_format("bogus") is SyslogFormat.JSON


def test_map_tcp_format():
    assert _map_tcp_format("cef") == "cef"
    assert _map_tcp_format("leef") == "leef"
    assert _map_tcp_format("json") == "json"
    assert _map_tcp_format("ndjson") == "ndjson"
    assert _map_tcp_format("ecs_json") == "json"
    assert _map_tcp_format("") == "cef"  # default


def test_default_api_key_header():
    assert _default_api_key_header("datadog") == "DD-API-KEY"
    assert _default_api_key_header("DATADOG") == "DD-API-KEY"
    assert _default_api_key_header("elastic") == "Authorization"
    assert _default_api_key_header("") == "Authorization"


# ─── _build_http_auth ────────────────────────────────────────────────────────


def test_build_http_auth_none():
    auth = _build_http_auth({"auth_type": "none"})
    assert auth == {"auth_method": HttpAuthMethod.NONE}


def test_build_http_auth_missing_defaults_to_none():
    assert _build_http_auth({})["auth_method"] is HttpAuthMethod.NONE


def test_build_http_auth_bearer():
    auth = _build_http_auth({"auth_type": "bearer", "auth_value": "tok-123"})
    assert auth["auth_method"] is HttpAuthMethod.BEARER
    assert auth["token"] == "tok-123"


def test_build_http_auth_oauth2_maps_to_bearer():
    auth = _build_http_auth({"auth_type": "oauth2", "auth_value": "tok-9"})
    assert auth["auth_method"] is HttpAuthMethod.BEARER
    assert auth["token"] == "tok-9"


def test_build_http_auth_legacy_auth_key_field():
    # Back-compat: the old ``auth_key`` field is still honoured.
    auth = _build_http_auth({"auth_type": "bearer", "auth_key": "legacy"})
    assert auth["token"] == "legacy"


def test_build_http_auth_api_key_default_header():
    auth = _build_http_auth({"auth_type": "api_key", "auth_value": "k"})
    assert auth["auth_method"] is HttpAuthMethod.API_KEY
    assert auth["api_key"] == "k"
    assert auth["api_key_header"] == "Authorization"


def test_build_http_auth_api_key_datadog_header():
    auth = _build_http_auth(
        {"auth_type": "api_key", "auth_value": "k", "platform": "datadog"}
    )
    assert auth["api_key_header"] == "DD-API-KEY"


def test_build_http_auth_api_key_explicit_header_wins():
    auth = _build_http_auth(
        {"auth_type": "api_key", "auth_value": "k", "api_key_header": "X-Custom"}
    )
    assert auth["api_key_header"] == "X-Custom"


def test_build_http_auth_basic_splits_credentials():
    auth = _build_http_auth({"auth_type": "basic", "auth_value": "alice:s3cret"})
    assert auth["auth_method"] is HttpAuthMethod.BASIC
    assert auth["username"] == "alice"
    assert auth["password"] == "s3cret"


def test_build_http_auth_hmac():
    auth = _build_http_auth(
        {"auth_type": "hmac", "auth_value": "sharedkey", "workspace_id": "ws1"}
    )
    assert auth["auth_method"] is HttpAuthMethod.HMAC
    assert auth["workspace_id"] == "ws1"
    assert auth["shared_key"] == "sharedkey"


def test_build_http_auth_mtls():
    auth = _build_http_auth(
        {
            "auth_type": "mtls",
            "tls_ca": "/ca.pem",
            "tls_cert": "/c.pem",
            "tls_key": "/k.pem",
        }
    )
    assert auth["auth_method"] is HttpAuthMethod.MTLS
    assert auth["tls_ca"] == "/ca.pem"
    assert auth["tls_cert"] == "/c.pem"
    assert auth["tls_key"] == "/k.pem"


def test_build_http_auth_splunk_hec_scheme():
    # Splunk HEC uses the "Splunk <token>" Authorization scheme, not Bearer.
    auth = _build_http_auth(
        {"auth_type": "bearer", "auth_value": "abcd", "platform": "splunk"}
    )
    assert auth["auth_method"] is HttpAuthMethod.API_KEY
    assert auth["api_key"] == "Splunk abcd"
    assert auth["api_key_header"] == "Authorization"


def test_build_http_auth_splunk_not_double_prefixed():
    auth = _build_http_auth(
        {"auth_type": "bearer", "auth_value": "Splunk abcd", "platform": "splunk"}
    )
    assert auth["api_key"] == "Splunk abcd"


# ─── _add_transport_from_config (transport_type normalization) ───────────────


def test_add_file_transport():
    exp = TelemetryExporter()
    _add_transport_from_config(exp, {"transport_type": "file", "endpoint": "/tmp/e.ndjson"})
    name, cfg = _only_config(exp)
    assert name == "file_shipper"
    assert cfg.path == "/tmp/e.ndjson"


def test_add_http_rest_transport_wires_auth_and_format():
    exp = TelemetryExporter()
    _add_transport_from_config(
        exp,
        {
            "transport_type": "http_rest",
            "endpoint": "https://splunk.example.com:8088/collector",
            "format": "ndjson",
            "verify_ssl": False,
            "platform": "splunk",
            "auth_type": "bearer",
            "auth_value": "hectoken",
        },
    )
    name, cfg = _only_config(exp)
    assert name == "http_rest"
    assert cfg.url == "https://splunk.example.com:8088/collector"
    assert cfg.format == "ndjson"
    assert cfg.verify_ssl is False
    # GAP 1 regression: auth_method must actually be set so the token is sent.
    assert cfg.auth_method is HttpAuthMethod.API_KEY
    assert cfg.api_key == "Splunk hectoken"


def test_add_legacy_http_alias():
    exp = TelemetryExporter()
    _add_transport_from_config(exp, {"transport_type": "http", "endpoint": "https://x.example.com"})
    name, _ = _only_config(exp)
    assert name == "http_rest"


@pytest.mark.parametrize(
    "ttype,expected",
    [
        ("syslog_udp", SyslogProtocol.UDP),
        ("syslog_tcp", SyslogProtocol.TCP),
        ("syslog_tls", SyslogProtocol.TLS),
        ("syslog", SyslogProtocol.TCP),  # legacy alias → TCP
    ],
)
def test_add_syslog_transport_protocol(ttype, expected):
    exp = TelemetryExporter()
    _add_transport_from_config(
        exp,
        {"transport_type": ttype, "endpoint": "collector.example.com", "port": 5514, "format": "leef"},
    )
    name, cfg = _only_config(exp)
    assert name == "syslog"
    assert cfg.protocol is expected
    assert cfg.port == 5514
    assert cfg.format is SyslogFormat.LEEF


def test_add_tcp_tls_transport():
    exp = TelemetryExporter()
    _add_transport_from_config(
        exp,
        {"transport_type": "tcp_tls", "endpoint": "collector.example.com", "port": 6514, "format": "cef"},
    )
    name, cfg = _only_config(exp)
    assert name == "tcp_tls"
    assert cfg.use_tls is True
    assert cfg.format == "cef"


def test_add_legacy_tcp_alias_no_tls():
    exp = TelemetryExporter()
    _add_transport_from_config(
        exp, {"transport_type": "tcp", "endpoint": "collector.example.com", "port": 601}
    )
    name, cfg = _only_config(exp)
    assert name == "tcp_tls"
    assert cfg.use_tls is False  # ttype != tcp_tls


def test_add_unknown_transport_type_registers_nothing():
    exp = TelemetryExporter()
    _add_transport_from_config(exp, {"transport_type": "carrier-pigeon", "endpoint": "x"})
    assert exp._transports == []


# ─── load_transports_from_config (file-driven) ───────────────────────────────


def test_load_transports_skips_disabled_and_unknown(tmp_path, monkeypatch):
    config = [
        {"transport_type": "file", "endpoint": str(tmp_path / "a.ndjson"), "enabled": True},
        {"transport_type": "http_rest", "endpoint": "https://x.example.com", "enabled": False},
        {"transport_type": "bogus", "endpoint": "x", "enabled": True},
    ]
    cfg_file = tmp_path / "siem_transports.json"
    import json

    cfg_file.write_text(json.dumps(config))
    monkeypatch.setenv("BULWARK_SIEM_TRANSPORTS_FILE", str(cfg_file))

    exp = TelemetryExporter()
    load_transports_from_config(exp)

    # Only the enabled file transport is registered.
    assert len(exp._transports) == 1
    assert exp._transports[0].transport.name == "file_shipper"


def test_load_transports_missing_file_no_autoseed_when_disabled(tmp_path, monkeypatch):
    missing = tmp_path / "does-not-exist.json"
    monkeypatch.setenv("BULWARK_SIEM_TRANSPORTS_FILE", str(missing))
    monkeypatch.setattr(exporter_mod, "EXPORTER_ENABLED", False)

    exp = TelemetryExporter()
    load_transports_from_config(exp)

    assert exp._transports == []
    assert not missing.exists()  # not auto-seeded when telemetry disabled


# ─── shared SSRF allowlist: is_ssrf_target_host ──────────────────────────────


def test_ssrf_public_ip_allowed(monkeypatch):
    monkeypatch.delenv(_ALLOW_ENV, raising=False)
    assert is_ssrf_target_host("8.8.8.8", 443) is False


def test_ssrf_private_blocked_by_default(monkeypatch):
    monkeypatch.delenv(_ALLOW_ENV, raising=False)
    assert is_ssrf_target_host("10.0.0.5", 9200) is True
    assert is_ssrf_target_host("192.168.1.10", 514) is True
    assert is_ssrf_target_host("172.16.4.20", 514) is True


def test_ssrf_private_allowed_with_flag(monkeypatch):
    monkeypatch.setenv(_ALLOW_ENV, "true")
    assert is_ssrf_target_host("10.0.0.5", 9200) is False
    assert is_ssrf_target_host("192.168.1.10", 514) is False
    assert is_ssrf_target_host("172.16.4.20", 514) is False


def test_ssrf_flag_accepts_common_truthy(monkeypatch):
    for val in ("1", "yes", "on", "TRUE"):
        monkeypatch.setenv(_ALLOW_ENV, val)
        assert is_ssrf_target_host("10.0.0.5", 9200) is False


def test_ssrf_loopback_always_blocked(monkeypatch):
    monkeypatch.setenv(_ALLOW_ENV, "true")
    assert is_ssrf_target_host("127.0.0.1", 9200) is True
    assert is_ssrf_target_host("::1", 9200) is True


def test_ssrf_metadata_always_blocked(monkeypatch):
    monkeypatch.setenv(_ALLOW_ENV, "true")
    assert is_ssrf_target_host("169.254.169.254", 80) is True


def test_ssrf_blocked_hostname(monkeypatch):
    monkeypatch.setenv(_ALLOW_ENV, "true")
    assert is_ssrf_target_host("localhost", 514) is True
    assert is_ssrf_target_host("metadata.google.internal", 80) is True


def test_ssrf_empty_host_blocked():
    assert is_ssrf_target_host("", 514) is True


# ─── HTTP transport _is_ssrf_target delegates to the SSOT ────────────────────


def test_http_is_ssrf_target_private_default(monkeypatch):
    monkeypatch.delenv(_ALLOW_ENV, raising=False)
    assert _is_ssrf_target("http://10.0.0.5:9200") is True


def test_http_is_ssrf_target_private_allowed_with_flag(monkeypatch):
    monkeypatch.setenv(_ALLOW_ENV, "true")
    assert _is_ssrf_target("http://10.0.0.5:9200") is False


def test_http_is_ssrf_target_metadata_always_blocked(monkeypatch):
    monkeypatch.setenv(_ALLOW_ENV, "true")
    assert _is_ssrf_target("http://169.254.169.254/latest/meta-data") is True


def test_http_is_ssrf_target_public_allowed(monkeypatch):
    monkeypatch.delenv(_ALLOW_ENV, raising=False)
    assert _is_ssrf_target("https://8.8.8.8:443") is False


# ─── admin _mask_transport ───────────────────────────────────────────────────


def test_mask_transport_masks_secrets():
    t = {
        "id": "abc",
        "endpoint": "https://x.example.com",
        "auth_value": "super-secret",
        "wazuh_password": "pw",
        "password": "pw2",
        "shared_key": "sk",
        "auth_type": "bearer",
    }
    masked = siem._mask_transport(t)
    assert masked["auth_value"] == siem._SECRET_MASK
    assert masked["wazuh_password"] == siem._SECRET_MASK
    assert masked["password"] == siem._SECRET_MASK
    assert masked["shared_key"] == siem._SECRET_MASK
    # Non-secret fields untouched.
    assert masked["endpoint"] == "https://x.example.com"
    assert masked["auth_type"] == "bearer"
    # Original not mutated.
    assert t["auth_value"] == "super-secret"


def test_mask_transport_empty_secret_not_masked():
    masked = siem._mask_transport({"auth_value": "", "endpoint": "x"})
    assert masked["auth_value"] == ""


# ─── admin _validate_url_no_ssrf ─────────────────────────────────────────────


def test_validate_url_empty_hostname():
    assert siem._validate_url_no_ssrf("not-a-url") == "Empty hostname"


def test_validate_url_blocked_hostname():
    err = siem._validate_url_no_ssrf("https://localhost:8088")
    assert err is not None and "Blocked hostname" in err


def test_validate_url_internal_suffix():
    err = siem._validate_url_no_ssrf("https://collector.internal:9200")
    assert err is not None and "internal" in err


def test_validate_url_private_blocked_default(monkeypatch):
    monkeypatch.delenv(_ALLOW_ENV, raising=False)
    err = siem._validate_url_no_ssrf("http://10.0.0.5:9200")
    assert err is not None and "blocked range" in err


def test_validate_url_private_allowed_with_flag(monkeypatch):
    monkeypatch.setenv(_ALLOW_ENV, "true")
    assert siem._validate_url_no_ssrf("http://10.0.0.5:9200") is None


def test_validate_url_loopback_always_blocked(monkeypatch):
    monkeypatch.setenv(_ALLOW_ENV, "true")
    err = siem._validate_url_no_ssrf("http://127.0.0.1:9200")
    assert err is not None and "blocked range" in err


def test_validate_url_metadata_always_blocked(monkeypatch):
    monkeypatch.setenv(_ALLOW_ENV, "true")
    err = siem._validate_url_no_ssrf("http://169.254.169.254/latest")
    assert err is not None and "blocked range" in err


def test_validate_url_public_ip_ok(monkeypatch):
    monkeypatch.delenv(_ALLOW_ENV, raising=False)
    assert siem._validate_url_no_ssrf("https://8.8.8.8:443") is None


# ─── admin update_transport: masked-secret round-trip guard ──────────────────


def _admin_user() -> TokenPayload:
    now = datetime.now(timezone.utc)
    return TokenPayload(sub="tester", role=UserRole.ADMIN, exp=now + timedelta(hours=1), iat=now)


async def test_update_transport_preserves_masked_secret(monkeypatch):
    """A masked sentinel round-tripped from a read must NOT clobber the secret."""
    monkeypatch.setattr(siem, "_save_transports", lambda: None)

    class _FakeAudit:
        async def log(self, **kwargs):
            return None

    monkeypatch.setattr(siem, "get_audit_logger", lambda: _FakeAudit())
    monkeypatch.setattr(
        siem,
        "_transports",
        [
            {
                "id": "t1",
                "endpoint": "https://x.example.com",
                "auth_type": "bearer",
                "auth_value": "real-secret",
                "format": "ecs_json",
            }
        ],
    )

    result = await siem.update_transport(
        "t1",
        {"auth_value": siem._SECRET_MASK, "format": "leef"},
        user=_admin_user(),
    )

    stored = siem._transports[0]
    # Secret preserved (sentinel ignored), non-secret field updated.
    assert stored["auth_value"] == "real-secret"
    assert stored["format"] == "leef"
    # Response is masked.
    assert result["auth_value"] == siem._SECRET_MASK


async def test_update_transport_sets_new_secret(monkeypatch):
    """A real (non-sentinel) secret value must overwrite the stored one."""
    monkeypatch.setattr(siem, "_save_transports", lambda: None)

    class _FakeAudit:
        async def log(self, **kwargs):
            return None

    monkeypatch.setattr(siem, "get_audit_logger", lambda: _FakeAudit())
    monkeypatch.setattr(
        siem,
        "_transports",
        [{"id": "t1", "endpoint": "https://x.example.com", "auth_value": "old"}],
    )

    await siem.update_transport(
        "t1", {"auth_value": "rotated-secret"}, user=_admin_user()
    )
    assert siem._transports[0]["auth_value"] == "rotated-secret"
