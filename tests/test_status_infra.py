"""Tests for the admin Status page infrastructure endpoint.

Covers:
  - ``_summarize_scanners`` — condenses the proxy /internal/scanners/status
    payload into the real, source-attributed fields the Status panel renders
    (never fabricating values; degrading missing fields to None/0).
  - ``GET /admin/health/infra`` — aggregates ONLY cached, real data
    (admin snapshot + Redis health + proxy counters + scanner pipeline),
    with zero blocking I/O in the request path.
  - RBAC wiring: the endpoint requires ``admin:read``.

The route reads exclusively from module-level cache getters, so tests
monkeypatch those to feed deterministic fixtures — mirroring the real
background-refresh contract without any network or event-loop dependency.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from admin.models.auth import ROLE_PERMISSIONS, TokenPayload, UserRole

# ═══════════════════════════════════════════════════════════════════════
# Fixtures / helpers
# ═══════════════════════════════════════════════════════════════════════


def _token(role: UserRole) -> TokenPayload:
    now = datetime.now(timezone.utc)
    return TokenPayload(sub=f"{role.value}-user", role=role, exp=now + timedelta(hours=1), iat=now)


def _admin() -> TokenPayload:
    return _token(UserRole.ADMIN)


def _fake_request(version: str = "0.2.0") -> SimpleNamespace:
    """Minimal stand-in for a FastAPI Request exposing ``request.app.version``."""
    return SimpleNamespace(app=SimpleNamespace(version=version))


_RAW_SCANNER_STATUS = {
    "status": "ok",
    "ml_enabled": True,
    "ml_blocking": False,
    "ml_timeout_ms": 150,
    "rag_enabled": True,
    "multilingual_enabled": False,
    "lanes": {
        "input_blocking": 3,
        "input_async": 2,
        "output_blocking": 1,
        "output_async": 1,
        "total": 7,
    },
    "scanners": [
        {"name": "regex_input", "version": "1.0", "type": "input", "enabled": True, "healthy": True},
        {"name": "ml_injection", "version": "2.1", "type": "input", "enabled": True, "healthy": False},
        {"name": "output_secrets", "version": "1.0", "type": "output", "enabled": False, "healthy": False},
    ],
}

_PROXY_STATS = {
    "uptime_seconds": 1234.5,
    "requests_total": 42,
    "requests_per_second": 0.03,
    "blocked": 5,
    "warned": 2,
    "allowed": 34,
    "redacted": 1,
    "errors": 0,
    "latency_p50_ms": 3.1,
    "latency_p95_ms": 9.4,
    "latency_p99_ms": 21.0,
}

_REDIS_HEALTH = {
    "status": "connected",
    "latency_ms": 0.4,
    "version": "7.2.4",
    "memory": "1.2M",
}


# ═══════════════════════════════════════════════════════════════════════
# _summarize_scanners
# ═══════════════════════════════════════════════════════════════════════


class TestSummarizeScanners:
    def test_summarizes_real_fields(self):
        from admin.routes.health import _summarize_scanners

        out = _summarize_scanners(_RAW_SCANNER_STATUS)
        assert out["available"] is True
        assert out["ml_enabled"] is True
        assert out["ml_blocking"] is False
        assert out["ml_timeout_ms"] == 150
        assert out["rag_enabled"] is True
        assert out["multilingual_enabled"] is False
        assert out["lanes"]["total"] == 7
        assert out["scanner_total"] == 3
        # only the first scanner is healthy
        assert out["scanner_healthy"] == 1

    def test_per_scanner_shape_uses_only_real_keys(self):
        from admin.routes.health import _summarize_scanners

        out = _summarize_scanners(_RAW_SCANNER_STATUS)
        first = out["scanners"][0]
        assert set(first) == {"name", "type", "version", "enabled", "healthy"}
        assert first["name"] == "regex_input"
        assert first["type"] == "input"
        assert first["enabled"] is True
        assert first["healthy"] is True

    def test_empty_payload_degrades_safely(self):
        from admin.routes.health import _summarize_scanners

        out = _summarize_scanners({})
        assert out["available"] is True
        assert out["scanner_total"] == 0
        assert out["scanner_healthy"] == 0
        assert out["scanners"] == []
        assert out["lanes"]["total"] == 0
        assert out["ml_enabled"] is False

    def test_none_payload_does_not_raise(self):
        from admin.routes.health import _summarize_scanners

        out = _summarize_scanners(None)  # type: ignore[arg-type]
        assert out["scanner_total"] == 0


# ═══════════════════════════════════════════════════════════════════════
# GET /admin/health/infra
# ═══════════════════════════════════════════════════════════════════════


class TestHealthInfraEndpoint:
    @pytest.fixture
    def wired(self, monkeypatch):
        import admin.routes.health as health

        monkeypatch.setattr(health, "_ensure_bg_task", lambda: None)
        monkeypatch.setattr(health, "_get_cached_telemetry", lambda: (dict(_PROXY_STATS), {}))
        monkeypatch.setattr(health, "_get_cached_redis_health", lambda: dict(_REDIS_HEALTH))
        monkeypatch.setattr(
            health, "_get_cached_scanners", lambda: health._summarize_scanners(_RAW_SCANNER_STATUS)
        )
        monkeypatch.setattr(
            health, "get_metrics", lambda: SimpleNamespace(snapshot=lambda: SimpleNamespace(uptime_seconds=99.0))
        )
        return health

    async def test_admin_block_source_attributed(self, wired):
        out = await wired.health_infra(request=_fake_request("0.2.0"), _user=_admin())
        assert out["admin"]["version"] == "0.2.0"
        assert out["admin"]["uptime_seconds"] == 99.0
        assert "generated_at" in out

    async def test_redis_block_real_values(self, wired):
        out = await wired.health_infra(request=_fake_request(), _user=_admin())
        assert out["redis"]["status"] == "connected"
        assert out["redis"]["version"] == "7.2.4"
        assert out["redis"]["memory"] == "1.2M"
        assert out["redis"]["latency_ms"] == 0.4

    async def test_proxy_block_reachable_counters(self, wired):
        out = await wired.health_infra(request=_fake_request(), _user=_admin())
        proxy = out["proxy"]
        assert proxy["reachable"] is True
        assert proxy["requests_total"] == 42
        assert proxy["verdicts"]["blocked"] == 5
        assert proxy["verdicts"]["warned"] == 2
        assert proxy["latency"]["p95_ms"] == 9.4
        assert proxy["latency"]["p99_ms"] == 21.0

    async def test_scanner_block_rolls_up_health(self, wired):
        out = await wired.health_infra(request=_fake_request(), _user=_admin())
        sc = out["scanners"]
        assert sc["available"] is True
        assert sc["scanner_total"] == 3
        assert sc["scanner_healthy"] == 1
        assert sc["lanes"]["total"] == 7

    async def test_proxy_unreachable_marks_not_reachable(self, wired, monkeypatch):
        monkeypatch.setattr(wired, "_get_cached_telemetry", lambda: ({}, {}))
        out = await wired.health_infra(request=_fake_request(), _user=_admin())
        assert out["proxy"]["reachable"] is False
        assert out["proxy"]["requests_total"] == 0

    async def test_scanners_unavailable_when_proxy_internal_down(self, wired, monkeypatch):
        monkeypatch.setattr(wired, "_get_cached_scanners", lambda: {"available": False})
        out = await wired.health_infra(request=_fake_request(), _user=_admin())
        assert out["scanners"]["available"] is False

    async def test_runtime_block_exposes_config(self, wired):
        out = await wired.health_infra(request=_fake_request(), _user=_admin())
        assert "proxy_url" in out["runtime"]
        assert "sse_interval_seconds" in out["runtime"]


# ═══════════════════════════════════════════════════════════════════════
# RBAC
# ═══════════════════════════════════════════════════════════════════════


class TestInfraRBAC:
    def test_all_roles_have_admin_read(self):
        # Status/infra is a read-only view — every role may read it.
        for role in (UserRole.ADMIN, UserRole.SECURITY, UserRole.AUDITOR, UserRole.VIEWER):
            assert "admin:read" in ROLE_PERMISSIONS[role]
