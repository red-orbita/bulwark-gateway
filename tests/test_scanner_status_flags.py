"""Tests for opt-in capability master flags surfaced through scanner status.

Covers:
  - Proxy ``GET /internal/scanners/status`` exposes every opt-in capability
    master flag (schema/relevance/hallucination/grounding/image_hygiene/vision)
    so the admin UI can honestly show which graduated scanners are registered
    vs dormant.
  - Admin ``ml_scanner_status`` threads those flags into ``global.capability_flags``,
    preferring the proxy's authoritative state over the admin-pod env fallback.

Neither test loads a model — the flags are pure Settings booleans and the admin
route is exercised with a mocked proxy payload.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

_CAPABILITY_FLAGS = (
    "schema_validation_enabled",
    "relevance_scanning_enabled",
    "hallucination_scanning_enabled",
    "grounding_scanning_enabled",
    "image_hygiene_scanning_enabled",
    "vision_scanning_enabled",
)


# ═══════════════════════════════════════════════════════════════════════
# Proxy /internal/scanners/status
# ═══════════════════════════════════════════════════════════════════════


class TestInternalStatusExposesFlags:
    async def test_all_capability_flags_present(self):
        from src.routes.health import internal_scanner_status

        resp = await internal_scanner_status(request=SimpleNamespace())
        import json

        body = json.loads(resp.body)
        for flag in _CAPABILITY_FLAGS:
            assert flag in body, f"missing capability flag {flag}"
            assert isinstance(body[flag], bool)

    async def test_flags_reflect_settings(self, monkeypatch):
        from src.config import settings
        from src.routes.health import internal_scanner_status

        monkeypatch.setattr(settings, "image_hygiene_scanning_enabled", True)
        monkeypatch.setattr(settings, "vision_scanning_enabled", False)

        import json

        resp = await internal_scanner_status(request=SimpleNamespace())
        body = json.loads(resp.body)
        assert body["image_hygiene_scanning_enabled"] is True
        assert body["vision_scanning_enabled"] is False


# ═══════════════════════════════════════════════════════════════════════
# Admin ml_scanner_status → global.capability_flags
# ═══════════════════════════════════════════════════════════════════════


class TestAdminCapabilityFlags:
    @pytest.fixture
    def user(self):
        from admin.models.auth import TokenPayload, UserRole

        now = datetime.now(timezone.utc)
        return TokenPayload(
            sub="admin-user", role=UserRole.ADMIN, exp=now + timedelta(hours=1), iat=now
        )

    async def test_env_fallback_when_proxy_unreachable(self, monkeypatch, user):
        import admin.routes.ml_scanners as ml

        monkeypatch.setattr(ml, "_query_proxy_scanner_status", lambda: _async_none())
        monkeypatch.setenv("BULWARK_IMAGE_HYGIENE_SCANNING_ENABLED", "true")
        monkeypatch.setenv("BULWARK_VISION_SCANNING_ENABLED", "false")

        out = await ml.ml_scanner_status(_user=user)
        flags = out["global"]["capability_flags"]
        for flag in _CAPABILITY_FLAGS:
            assert flag in flags
        assert flags["image_hygiene_scanning_enabled"] is True
        assert flags["vision_scanning_enabled"] is False

    async def test_proxy_state_overrides_env(self, monkeypatch, user):
        import admin.routes.ml_scanners as ml

        # Env says off, but the authoritative proxy says image hygiene is on.
        monkeypatch.setenv("BULWARK_IMAGE_HYGIENE_SCANNING_ENABLED", "false")
        proxy_payload = {
            "ml_enabled": False,
            "lanes": {},
            "scanners": [],
            "image_hygiene_scanning_enabled": True,
            "vision_scanning_enabled": True,
        }
        monkeypatch.setattr(
            ml, "_query_proxy_scanner_status", lambda: _async_value(proxy_payload)
        )

        out = await ml.ml_scanner_status(_user=user)
        flags = out["global"]["capability_flags"]
        assert flags["image_hygiene_scanning_enabled"] is True
        assert flags["vision_scanning_enabled"] is True


def _async_none():
    async def _c():
        return None

    return _c()


def _async_value(value):
    async def _c():
        return value

    return _c()
