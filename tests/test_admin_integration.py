"""Integration tests for admin portal API flows."""

import os
import subprocess
import sys

import pytest
from httpx import ASGITransport, AsyncClient

from admin.main import app

# Default password used when ADMIN_PASSWORD env not set during DB seed
_ADMIN_PW = "bulwark-admin"


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
async def auth_client(client):
    """Client with admin auth token."""
    resp = await client.post(
        "/admin/auth/login",
        json={"username": "admin", "password": _ADMIN_PW},
    )
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    client.headers["Authorization"] = f"Bearer {token}"
    yield client


class TestAuthFlow:
    async def test_login_success(self, client):
        resp = await client.post(
            "/admin/auth/login",
            json={"username": "admin", "password": _ADMIN_PW},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["username"] == "admin"
        assert data["role"] == "admin"

    async def test_login_bad_password(self, client):
        resp = await client.post(
            "/admin/auth/login",
            json={"username": "admin", "password": "wrong"},
        )
        assert resp.status_code == 401

    async def test_unauthenticated_access(self, client):
        resp = await client.get("/admin/users")
        assert resp.status_code in (401, 403)


class TestUsersFlow:
    async def test_list_users(self, auth_client):
        resp = await auth_client.get("/admin/users")
        assert resp.status_code == 200
        users = resp.json()
        assert isinstance(users, list)
        assert any(u["username"] == "admin" for u in users)

    async def test_create_and_delete_user(self, auth_client):
        # Create
        resp = await auth_client.post(
            "/admin/users",
            json={"username": "testuser", "password": "TestPass123!", "role": "viewer"},
        )
        assert resp.status_code == 201
        user = resp.json()
        assert user["username"] == "testuser"
        user_id = user["id"]

        # Verify in list
        resp = await auth_client.get("/admin/users")
        assert any(u["id"] == user_id for u in resp.json())

        # Delete
        resp = await auth_client.delete(f"/admin/users/{user_id}")
        assert resp.status_code == 200

        # Verify gone
        resp = await auth_client.get("/admin/users")
        assert not any(u["id"] == user_id for u in resp.json())

    async def test_create_duplicate_user(self, auth_client):
        resp = await auth_client.post(
            "/admin/users",
            json={"username": "admin", "password": "Pass1234!x", "role": "viewer"},
        )
        assert resp.status_code in (400, 409, 422)

    async def test_reset_password(self, auth_client):
        # Create temp user
        resp = await auth_client.post(
            "/admin/users",
            json={"username": "pwtest", "password": "OldPass123!", "role": "viewer"},
        )
        user_id = resp.json()["id"]

        # Reset
        resp = await auth_client.post(
            f"/admin/users/{user_id}/reset-password",
            json={"new_password": "NewPass456!"},
        )
        assert resp.status_code == 200

        # Cleanup
        await auth_client.delete(f"/admin/users/{user_id}")


class TestTenantsFlow:
    async def test_list_tenants(self, auth_client):
        resp = await auth_client.get("/admin/tenants")
        assert resp.status_code == 200
        tenants = resp.json()
        assert isinstance(tenants, list)
        assert len(tenants) >= 1

    async def test_pause_unpause(self, auth_client):
        resp = await auth_client.get("/admin/tenants")
        tenant_id = resp.json()[0]["id"]

        # Pause
        resp = await auth_client.patch(f"/admin/tenants/{tenant_id}/pause")
        assert resp.status_code == 200
        assert resp.json()["status"] == "paused"

        # Unpause
        resp = await auth_client.patch(f"/admin/tenants/{tenant_id}/pause")
        assert resp.status_code == 200
        assert resp.json()["status"] == "active"


class TestIOCsFlow:
    async def test_list_iocs(self, auth_client):
        resp = await auth_client.get("/admin/iocs")
        assert resp.status_code == 200
        data = resp.json()
        # Paginated response
        assert "items" in data or isinstance(data, list)

    async def test_ioc_stats(self, auth_client):
        resp = await auth_client.get("/admin/iocs/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "by_type" in data

    async def test_create_and_delete_ioc(self, auth_client):
        resp = await auth_client.post(
            "/admin/iocs",
            json={
                "type": "domain",
                "value": "test-evil-domain.example.com",
                "source": "test",
                "severity": "high",
                "confidence": 0.95,
                "tags": ["test"],
            },
        )
        assert resp.status_code == 201
        ioc_id = resp.json()["id"]

        # Delete
        resp = await auth_client.delete(f"/admin/iocs/{ioc_id}")
        assert resp.status_code in (200, 204)

    async def test_feeds_list(self, auth_client):
        resp = await auth_client.get("/admin/iocs/feeds")
        assert resp.status_code == 200
        feeds = resp.json()
        assert len(feeds) == 4
        assert all("name" in f for f in feeds)


class TestGuardrailsFlow:
    async def test_list_patterns(self, auth_client):
        resp = await auth_client.get("/admin/guardrails/patterns")
        assert resp.status_code == 200
        patterns = resp.json()
        assert len(patterns) > 100
        # Check layers present
        layers = {p["layer"] for p in patterns}
        assert "input" in layers
        assert "output" in layers
        assert "tool_policy" in layers

    async def test_pattern_stats(self, auth_client):
        resp = await auth_client.get("/admin/guardrails/stats")
        assert resp.status_code == 200
        data = resp.json()
        # May have "total" or "total_patterns" depending on endpoint
        total = data.get("total") or data.get("total_patterns") or data.get("count", 0)
        assert total > 100


class TestHealthFlow:
    async def test_health(self, client):
        resp = await client.get("/admin/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("healthy", "ok")

    async def test_pages_accessible(self, client):
        """All HTML pages should return 200 with valid auth, or redirect to login without auth."""
        from admin.services.auth_service import AuthService
        from admin.models.auth import UserRole
        token = AuthService.create_token("admin", UserRole.ADMIN)
        headers = {"Authorization": f"Bearer {token}"}

        # Login page accessible without auth
        resp = await client.get("/login")
        assert resp.status_code == 200, f"Page /login returned {resp.status_code}"

        # Protected pages need auth
        pages = ["/", "/tenants", "/agents", "/iocs",
                 "/guardrails", "/policies", "/settings", "/coverage"]
        for page in pages:
            resp = await client.get(page, headers=headers)
            assert resp.status_code == 200, f"Page {page} returned {resp.status_code}"

        # /users redirects to /rbac
        resp = await client.get("/users", headers=headers, follow_redirects=False)
        assert resp.status_code == 302


class TestSecurityHeaders:
    """Regression tests for the admin security-headers middleware (H-1, H-4)."""

    async def test_baseline_headers_present(self, client):
        resp = await client.get("/admin/health")
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert "Strict-Transport-Security" in resp.headers

    async def test_xss_protection_disabled(self, client):
        # H-4: deprecated header must be '0', not the legacy '1; mode=block'.
        resp = await client.get("/admin/health")
        assert resp.headers["X-XSS-Protection"] == "0"

    async def test_csp_hardening_directives(self, client):
        # H-1: object-src/base-uri/form-action close base-tag injection,
        # form hijacking and plugin-injection XSS vectors.
        resp = await client.get("/admin/health")
        csp = resp.headers["Content-Security-Policy"]
        assert "object-src 'none'" in csp
        assert "base-uri 'self'" in csp
        assert "form-action 'self'" in csp
        assert "frame-ancestors 'none'" in csp

    async def test_csp_still_allows_required_ui_sources(self, client):
        # H-1: script-src is nonce-based (inline <script> blocks authenticate via
        # a per-request nonce), so 'unsafe-inline' is GONE from script-src. Two
        # 'unsafe-*' remain, honestly scoped and documented in admin/main.py:
        #   • script-src 'unsafe-eval' — Alpine.js evaluates expressions via
        #     new Function(); removal needs the Alpine CSP build.
        #   • style-src 'unsafe-inline' — static style="" attributes; CSP nonces
        #     cannot cover attributes, so removal needs a class migration.
        # All third-party origins are vendored (no CDN, air-gap safe).
        resp = await client.get("/admin/health")
        csp = resp.headers["Content-Security-Policy"]
        script_src = next(
            (p.strip() for p in csp.split(";") if p.strip().startswith("script-src")),
            "",
        )
        assert "'nonce-" in script_src, f"script-src is not nonce-based: {script_src}"
        assert "'unsafe-inline'" not in script_src, (
            f"script-src still allows 'unsafe-inline': {script_src}"
        )
        assert "'unsafe-eval'" in script_src
        assert "style-src 'self' 'unsafe-inline'" in csp
        # No remote origin may appear (air-gap posture).
        assert "https://" not in csp


class TestAdminJwtSecretValidation:
    """Regression tests for ADMIN_JWT_SECRET strength validation (H-2).

    The check runs at module import time, so each case is exercised in an
    isolated subprocess (a plain `python -c`, so the pytest/unittest bypass
    does not apply and production behaviour is validated).
    """

    def _import_auth_service(self, secret: str, debug: str = "false") -> subprocess.CompletedProcess:
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env = {
            **os.environ,
            "ADMIN_JWT_SECRET": secret,
            "ADMIN_DEBUG": debug,
            "PYTHONPATH": repo_root,
        }
        # Drop inherited pytest markers so the module's `_testing` bypass is off
        env.pop("PYTEST_CURRENT_TEST", None)
        return subprocess.run(
            [sys.executable, "-c", "import admin.services.auth_service"],
            capture_output=True, text=True, env=env, cwd=repo_root, timeout=30,
        )

    def test_short_nondefault_secret_aborts(self):
        # A short but non-blocklisted secret must now be rejected.
        result = self._import_auth_service("abc123")
        assert result.returncode != 0
        assert "ADMIN_JWT_SECRET is insecure" in result.stderr

    def test_known_default_secret_aborts(self):
        result = self._import_auth_service("bulwark-admin-change-me-in-production")
        assert result.returncode != 0
        assert "ADMIN_JWT_SECRET is insecure" in result.stderr

    def test_strong_secret_is_accepted(self):
        # 40-char high-entropy secret must import cleanly.
        result = self._import_auth_service("s3cure-" + "x" * 40)
        assert result.returncode == 0, result.stderr

    def test_debug_mode_allows_weak_secret(self):
        # In debug mode a weak secret only warns, does not abort.
        result = self._import_auth_service("weak", debug="true")
        assert result.returncode == 0, result.stderr


