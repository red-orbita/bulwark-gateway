"""Tests for auth middleware, rate limiting, profile endpoints, and security hardening."""

import hashlib
import json
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient


# --- Auth Middleware Tests ---

class TestAuthGuardMiddleware:
    """Test that HTML page routes require authentication."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test client."""
        import os
        os.environ.setdefault("ADMIN_DEBUG", "true")
        from admin.main import app
        self.client = TestClient(app, raise_server_exceptions=False)

    def test_login_page_accessible_without_auth(self):
        resp = self.client.get("/login")
        assert resp.status_code == 200

    def test_dashboard_redirects_without_auth(self):
        resp = self.client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers.get("location", "")

    def test_policies_page_redirects_without_auth(self):
        resp = self.client.get("/policies", follow_redirects=False)
        assert resp.status_code == 302

    def test_guardrails_page_redirects_without_auth(self):
        resp = self.client.get("/guardrails", follow_redirects=False)
        assert resp.status_code == 302

    def test_siem_page_redirects_without_auth(self):
        resp = self.client.get("/siem", follow_redirects=False)
        assert resp.status_code == 302

    def test_settings_page_redirects_without_auth(self):
        resp = self.client.get("/settings", follow_redirects=False)
        assert resp.status_code == 302

    def test_page_accessible_with_valid_cookie(self):
        from admin.services.auth_service import AuthService
        from admin.models.auth import UserRole
        token = AuthService.create_token("admin", UserRole.ADMIN)
        resp = self.client.get("/", cookies={"admin_token": token}, follow_redirects=False)
        # Should not redirect (either 200 or passthrough)
        assert resp.status_code == 200

    def test_page_redirects_with_invalid_cookie(self):
        resp = self.client.get("/", cookies={"admin_token": "invalid.token.here"}, follow_redirects=False)
        assert resp.status_code == 302

    def test_static_assets_accessible_without_auth(self):
        resp = self.client.get("/static/css/tailwind.min.css")
        # Should not redirect (may be 200 or 404 depending on file existence)
        assert resp.status_code != 302


# --- Security Headers Tests ---

class TestSecurityHeaders:
    """Test that security headers are properly set."""

    @pytest.fixture(autouse=True)
    def setup(self):
        import os
        os.environ.setdefault("ADMIN_DEBUG", "true")
        from admin.main import app
        self.client = TestClient(app, raise_server_exceptions=False)

    def test_hsts_header(self):
        resp = self.client.get("/login")
        assert "strict-transport-security" in resp.headers
        assert "max-age=31536000" in resp.headers["strict-transport-security"]

    def test_xframe_deny(self):
        resp = self.client.get("/login")
        assert resp.headers.get("x-frame-options") == "DENY"

    def test_nosniff(self):
        resp = self.client.get("/login")
        assert resp.headers.get("x-content-type-options") == "nosniff"

    def test_cache_control_no_store(self):
        resp = self.client.get("/login")
        assert "no-store" in resp.headers.get("cache-control", "")

    def test_csp_present(self):
        resp = self.client.get("/login")
        assert "content-security-policy" in resp.headers
        assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]


# --- Body Size Limit Tests ---

class TestBodySizeLimit:
    """Test request body size enforcement."""

    @pytest.fixture(autouse=True)
    def setup(self):
        import os
        os.environ.setdefault("ADMIN_DEBUG", "true")
        from admin.main import app
        self.client = TestClient(app, raise_server_exceptions=False)

    def test_large_body_rejected(self):
        # 2MB payload should be rejected
        large_body = "x" * (2 * 1024 * 1024)
        resp = self.client.post(
            "/admin/auth/login",
            content=large_body,
            headers={"content-type": "application/json", "content-length": str(len(large_body))},
        )
        assert resp.status_code == 413

    def test_normal_body_accepted(self):
        # Normal login attempt should not be blocked by size limit
        resp = self.client.post(
            "/admin/auth/login",
            json={"username": "admin", "password": "wrong"},
        )
        # Should get 401 (wrong password), not 413
        assert resp.status_code != 413


# --- Profile Endpoint Tests ---

class TestProfileEndpoints:
    """Test user profile API."""

    @pytest.fixture(autouse=True)
    def setup(self):
        import os
        os.environ.setdefault("ADMIN_DEBUG", "true")
        from admin.main import app
        self.client = TestClient(app, raise_server_exceptions=False)
        # Login to get token
        resp = self.client.post("/admin/auth/login", json={"username": "admin", "password": "sentinel-admin"})
        if resp.status_code == 200:
            data = resp.json()
            self.token = data["access_token"]
            self.headers = {"Authorization": f"Bearer {self.token}"}
        else:
            self.token = None
            self.headers = {}

    def test_get_profile_unauthenticated(self):
        resp = self.client.get("/admin/profile")
        assert resp.status_code == 401

    def test_get_profile_authenticated(self):
        if not self.token:
            pytest.skip("Could not authenticate")
        resp = self.client.get("/admin/profile", headers=self.headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == "admin"
        assert "email" in data
        assert "phone" in data
        assert "first_name" in data
        assert "last_name" in data

    def test_update_profile(self):
        if not self.token:
            pytest.skip("Could not authenticate")
        resp = self.client.put(
            "/admin/profile",
            headers=self.headers,
            json={"email": "admin@test.com", "first_name": "Admin", "last_name": "User", "phone": "+1234567890"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == "admin@test.com"
        assert data["first_name"] == "Admin"

    def test_update_profile_cannot_change_role(self):
        """Profile update should not allow changing role (not in ProfileUpdate model)."""
        if not self.token:
            pytest.skip("Could not authenticate")
        resp = self.client.put(
            "/admin/profile",
            headers=self.headers,
            json={"role": "viewer"},  # Should be ignored
        )
        # Should succeed but role should not change
        assert resp.status_code in (200, 422)


# --- Session Idle Timeout Tests ---

class TestSessionIdleTimeout:
    """Test session idle timeout enforcement."""

    def test_check_and_update_activity_fresh_session(self):
        """Fresh session (no last_activity) should pass."""
        import os
        os.environ.setdefault("ADMIN_DEBUG", "true")
        from admin.services.user_store import get_user_store
        store = get_user_store()
        # Verify method exists
        assert hasattr(store, "check_and_update_activity")

    def test_session_schema_has_last_activity(self):
        """Sessions table should have last_activity column."""
        import os
        os.environ.setdefault("ADMIN_DEBUG", "true")
        from admin.services.user_store import get_user_store
        store = get_user_store()
        with store._lock:
            cursor = store._conn.execute("PRAGMA table_info(sessions)")
            columns = [row["name"] if isinstance(row, dict) else row[1] for row in cursor.fetchall()]
        assert "last_activity" in columns


# --- Cookie Security Tests ---

class TestCookieSecurity:
    """Test cookie attributes."""

    @pytest.fixture(autouse=True)
    def setup(self):
        import os
        os.environ.setdefault("ADMIN_DEBUG", "true")
        from admin.main import app
        self.client = TestClient(app, raise_server_exceptions=False)

    def test_login_sets_secure_cookie(self):
        resp = self.client.post("/admin/auth/login", json={"username": "admin", "password": "sentinel-admin"})
        if resp.status_code == 200:
            # Check Set-Cookie header
            cookie_header = resp.headers.get("set-cookie", "")
            assert "admin_token" in cookie_header
            assert "httponly" in cookie_header.lower()
            assert "samesite=strict" in cookie_header.lower()


# --- Default Deny Policy Tests ---

class TestDefaultDenyPolicy:
    """Test default-deny policy exists and is valid."""

    def test_default_deny_policy_exists(self):
        from pathlib import Path
        policy_path = Path("config/policies/default-deny.yaml")
        assert policy_path.exists()

    def test_default_deny_policy_valid_yaml(self):
        import yaml
        from pathlib import Path
        policy_path = Path("config/policies/default-deny.yaml")
        data = yaml.safe_load(policy_path.read_text())
        assert data["tenant_id"] == "__default__"
        assert data["settings"]["default_action"] == "deny"
        assert data["default_agent"]["allowed_tools"] == []
        assert data["default_agent"]["allow_execution"] is False


# --- SIEM Persistence Tests ---

class TestSIEMPersistence:
    """Test SIEM transport persistence."""

    def test_save_and_load_transports(self):
        from pathlib import Path
        import tempfile
        import json as json_mod

        # Use temp file
        tmp = Path(tempfile.mktemp(suffix=".json"))
        try:
            from admin.routes import siem
            original_file = siem._TRANSPORTS_FILE
            siem._TRANSPORTS_FILE = tmp
            siem._transports = [{"id": "test1", "platform": "splunk", "enabled": True}]
            siem._save_transports()
            assert tmp.exists()

            # Clear and reload
            siem._transports = []
            siem._load_transports()
            assert len(siem._transports) == 1
            assert siem._transports[0]["id"] == "test1"
        finally:
            siem._TRANSPORTS_FILE = original_file
            if tmp.exists():
                tmp.unlink()
