"""Tests for the config validation surface (settings.html "Validate" button).

Regression: the Validate button used to POST ``/admin/config/validate`` with no
body, so the endpoint (which requires ``section`` + ``data``) always returned
422 — a dead control. These tests pin the real behaviour and guard the template
against reverting to a body-less request.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

os.environ.setdefault("ADMIN_JWT_SECRET", "test-secret-that-is-at-least-32-characters-long-xx")
os.environ.setdefault("BULWARK_JWT_SECRET", "test-secret-that-is-at-least-32-characters-long-xx")

from admin.models.auth import TokenPayload, UserRole  # noqa: E402
from admin.services.config_manager import get_config_manager  # noqa: E402

_SETTINGS_HTML = Path(__file__).resolve().parent.parent / "admin" / "templates" / "pages" / "settings.html"


def _admin() -> TokenPayload:
    now = datetime.now(timezone.utc)
    return TokenPayload(sub="admin-user", role=UserRole.ADMIN, exp=now + timedelta(hours=1), iat=now)


# ─── ConfigManager.validate_config ───────────────────────────────────────────


class TestValidateConfig:
    def test_valid_section_and_types(self):
        mgr = get_config_manager()
        out = mgr.validate_config("logging", {"log_level": "DEBUG", "log_format": "json"})
        assert out["valid"] is True
        assert out["errors"] == []

    def test_unknown_section(self):
        mgr = get_config_manager()
        out = mgr.validate_config("does_not_exist", {"x": 1})
        assert out["valid"] is False
        assert any("Unknown section" in e for e in out["errors"])

    def test_field_not_in_section(self):
        mgr = get_config_manager()
        out = mgr.validate_config("logging", {"backend_url": "http://x"})
        assert out["valid"] is False
        assert any("not in section" in e for e in out["errors"])

    def test_type_mismatch_flagged(self):
        mgr = get_config_manager()
        # rate_limit_rpm is an int; a string must be rejected.
        out = mgr.validate_config("rate_limiting", {"rate_limit_rpm": "not-an-int"})
        assert out["valid"] is False
        assert any("Type mismatch" in e for e in out["errors"])


# ─── Route: POST /admin/config/validate ──────────────────────────────────────


class TestValidateRoute:
    async def test_route_accepts_section_and_data(self):
        from admin.routes.config import validate_config

        out = await validate_config(section="logging", data={"log_level": "INFO"}, user=_admin())
        assert out["valid"] is True

    async def test_route_reports_errors(self):
        from admin.routes.config import validate_config

        out = await validate_config(
            section="rate_limiting", data={"rate_limit_rpm": "bad"}, user=_admin()
        )
        assert out["valid"] is False
        assert out["errors"]


# ─── Template guard: Validate must send a body with section + data ───────────


class TestSettingsTemplateWiring:
    def test_validate_posts_section_and_data(self):
        html = _SETTINGS_HTML.read_text()
        assert "validateSection()" in html, "Validate button must call validateSection()"
        # The fetch must include both the section and the edited data in the body.
        assert "section: this.activeTab" in html
        assert "data: this.sectionData" in html

    def test_no_bodyless_validate_regression(self):
        html = _SETTINGS_HTML.read_text()
        # Guard against the old dead control: a POST to /validate with only a method.
        assert "fetch('/admin/config/validate', { method: 'POST' })" not in html
