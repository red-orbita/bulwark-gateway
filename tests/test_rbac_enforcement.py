"""RBAC end-to-end enforcement tests for the admin API.

Audit finding closed here: the RBAC permission matrix existed
(``ROLE_PERMISSIONS`` in ``admin/models/auth.py``) and every write route
*declared* a ``require_permission(...)`` dependency, but there was no test
proving the wiring actually rejects an under-privileged caller at the HTTP
boundary. Without that proof, a single forgotten dependency (or a permission
typo) would silently grant a viewer write access — a textbook broken-access-
control vulnerability (OWASP A01).

These tests exercise the *real* dependency graph through the *real* ASGI app:

  * ``get_current_user`` is overridden to mint a caller with a chosen role
    (this bypasses ONLY the JWT/session plumbing — the genuine
    ``require_permission`` check still runs against the genuine
    ``ROLE_PERMISSIONS`` matrix).
  * A ``viewer`` MUST be rejected with ``403 Missing permission`` on every
    state-changing endpoint. If a route forgot to guard itself, the viewer
    would reach the handler and this test would fail — exactly the regression
    we want to catch.
  * An ``admin`` MUST NOT be rejected by RBAC (any non-403 outcome is fine —
    the handler may still 400/404/503 on payload/availability).
  * The ``security`` role proves *fine-grained* enforcement: it is denied
    ``vkeys:write`` (secret material — admin only) yet permitted the security
    write scopes (iocs/siem/quotas/guardrails).
  * With NO override at all and no credentials, every endpoint returns 401 —
    proving the surface is authenticated, not open.

Positive AND negative cases are covered per project convention.
"""

from __future__ import annotations

import os

# Test-safe environment MUST be set before importing admin.* modules.
os.environ.setdefault("ADMIN_DEBUG", "true")
os.environ.setdefault("ADMIN_JWT_SECRET", "rbac-enforcement-test-secret-32chars-min!!")
os.environ.setdefault("BULWARK_JWT_SECRET", "rbac-enforcement-test-secret-32chars-min!!")
os.environ.setdefault("BULWARK_KEY_ENCRYPTION_KEY", "rbac-enforcement-encryption-32chars-min!")

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from admin.main import app
from admin.models.auth import ROLE_PERMISSIONS, TokenPayload, UserRole
from admin.services.auth_service import get_current_user

# --------------------------------------------------------------------------- #
# Endpoint inventory: every state-changing admin route and the permission it
# is expected to enforce. Path params use throwaway-but-syntactically-valid
# values so the request reaches (and is stopped by) the RBAC dependency.
# --------------------------------------------------------------------------- #

WRITE_ENDPOINTS: list[tuple[str, str, str]] = [
    # Virtual Keys — handle plaintext backend secrets (admin only).
    ("POST", "/admin/virtual-keys/", "vkeys:write"),
    ("POST", "/admin/virtual-keys/default/rotate", "vkeys:write"),
    ("DELETE", "/admin/virtual-keys/default/vk_0123456789abcdef", "vkeys:write"),
    # Per-tenant quotas.
    ("PUT", "/admin/quotas/default", "quotas:write"),
    ("DELETE", "/admin/quotas/default", "quotas:write"),
    # IOC database.
    ("POST", "/admin/iocs", "iocs:write"),
    ("POST", "/admin/iocs/bulk", "iocs:write"),
    ("PUT", "/admin/iocs/some-ioc-id", "iocs:write"),
    ("DELETE", "/admin/iocs/some-ioc-id", "iocs:write"),
    ("POST", "/admin/iocs/feeds", "iocs:write"),
    # SIEM transports.
    ("POST", "/admin/siem/transport", "siem:write"),
    ("PUT", "/admin/siem/transport/t1", "siem:write"),
    ("DELETE", "/admin/siem/transport/t1", "siem:write"),
    # ML scanner controls (guardrail surface).
    ("POST", "/admin/ml-scanners/toggle", "guardrails:write"),
    ("POST", "/admin/ml-scanners/configure", "guardrails:write"),
    ("POST", "/admin/ml-scanners/reset", "guardrails:write"),
    # Enrichment — reviewing a regex candidate approves/rejects a pattern that
    # is promoted into the live guardrail set, so it is a guardrail write.
    ("POST", "/admin/enrichment/regex-candidates/review", "guardrails:write"),
]


# Read endpoints that expose sensitive enrichment telemetry (raw attack
# payloads that bypassed regex, evasion attempts, regex-candidate lifecycle).
# Before v1.0.0 the entire enrichment router carried NO auth dependency — an
# unauthenticated caller could browse captured attack traffic and even approve
# candidates. These are guarded with ``guardrails:read`` (auditor and above;
# viewer, the least-privileged role, is intentionally excluded from raw
# attack-payload access under least-privilege).
ENRICHMENT_READ_ENDPOINTS: list[tuple[str, str]] = [
    ("GET", "/admin/enrichment/status"),
    ("GET", "/admin/enrichment/stats"),
    ("GET", "/admin/enrichment/evasions"),
    ("GET", "/admin/enrichment/entries"),
    ("GET", "/admin/enrichment/regex-candidates"),
]


def _fake_user(role: UserRole) -> TokenPayload:
    now = datetime.now(timezone.utc)
    return TokenPayload(
        sub=f"test-{role.value}",
        role=role,
        exp=now + timedelta(hours=1),
        iat=now,
    )


def _override_role(role: UserRole) -> None:
    """Force get_current_user to return a caller with the given role."""
    app.dependency_overrides[get_current_user] = lambda: _fake_user(role)


# A matching cookie/header pair satisfies the app's CSRF middleware so that
# requests reach the RBAC layer under test (the middleware runs first and would
# otherwise 403 every state-changing call regardless of role).
_CSRF = "rbac-enforcement-test-csrf-token"


def _request(client: TestClient, method: str, path: str):
    # Empty JSON body: the security sub-dependency runs before body validation,
    # so RBAC-denied callers are rejected regardless of payload shape.
    return client.request(
        method, path, json={}, headers={"x-csrf-token": _CSRF}
    )


@pytest.fixture
def client():
    # raise_server_exceptions=False: this suite asserts the RBAC *decision*
    # (403 vs not). Once a privileged caller passes RBAC the handler runs for
    # real and may fail on sandbox-only persistence paths — surfaced as a 500,
    # which correctly reads as "RBAC did not block" without masking the check.
    with TestClient(app, raise_server_exceptions=False) as c:
        c.cookies.set("_csrf_token", _CSRF)
        yield c
    app.dependency_overrides.pop(get_current_user, None)


# --------------------------------------------------------------------------- #
# Matrix invariant — the safety net behind the HTTP tests.
# --------------------------------------------------------------------------- #


class TestPermissionMatrixInvariants:
    def test_viewer_holds_no_write_permissions(self):
        viewer_perms = ROLE_PERMISSIONS[UserRole.VIEWER]
        offending = {p for p in viewer_perms if p.endswith((":write", ":delete"))}
        assert offending == set(), f"viewer must never hold write scopes: {offending}"

    def test_security_denied_vkeys_write_but_granted_security_writes(self):
        sec = ROLE_PERMISSIONS[UserRole.SECURITY]
        assert "vkeys:write" not in sec  # secret material is admin-only
        for scope in ("iocs:write", "siem:write", "quotas:write", "guardrails:write"):
            assert scope in sec, f"security role should hold {scope}"

    def test_admin_is_a_superset_of_every_role(self):
        admin_perms = ROLE_PERMISSIONS[UserRole.ADMIN]
        for role in (UserRole.SECURITY, UserRole.AUDITOR, UserRole.VIEWER):
            missing = ROLE_PERMISSIONS[role] - admin_perms
            assert missing == set(), f"admin missing perms held by {role}: {missing}"


# --------------------------------------------------------------------------- #
# Negative: an under-privileged caller is rejected at the HTTP boundary.
# --------------------------------------------------------------------------- #


class TestViewerIsDenied:
    @pytest.mark.parametrize("method,path,permission", WRITE_ENDPOINTS)
    def test_viewer_gets_403_on_write_endpoints(self, client, method, path, permission):
        _override_role(UserRole.VIEWER)
        resp = _request(client, method, path)
        assert resp.status_code == 403, (
            f"{method} {path} did not enforce RBAC for viewer "
            f"(got {resp.status_code}; expected 403 for {permission})"
        )
        assert "Missing permission" in resp.text
        assert permission in resp.text


# --------------------------------------------------------------------------- #
# Positive: a properly-privileged caller is NOT blocked by RBAC.
# --------------------------------------------------------------------------- #


class TestAdminIsAllowedThroughRbac:
    @pytest.mark.parametrize("method,path,permission", WRITE_ENDPOINTS)
    def test_admin_not_403(self, client, method, path, permission):
        _override_role(UserRole.ADMIN)
        resp = _request(client, method, path)
        assert resp.status_code != 403, (
            f"{method} {path} wrongly blocked an admin "
            f"(403) despite holding {permission}"
        )


# --------------------------------------------------------------------------- #
# Fine-grained: the security role sits between admin and viewer.
# --------------------------------------------------------------------------- #


class TestSecurityRoleFineGrained:
    def test_security_denied_virtual_key_write(self, client):
        _override_role(UserRole.SECURITY)
        resp = _request(client, "POST", "/admin/virtual-keys/")
        assert resp.status_code == 403
        assert "vkeys:write" in resp.text

    @pytest.mark.parametrize(
        "method,path",
        [
            ("POST", "/admin/iocs"),
            ("POST", "/admin/siem/transport"),
            ("PUT", "/admin/quotas/default"),
            ("POST", "/admin/ml-scanners/toggle"),
        ],
    )
    def test_security_allowed_through_its_write_scopes(self, client, method, path):
        _override_role(UserRole.SECURITY)
        resp = _request(client, method, path)
        assert resp.status_code != 403, (
            f"security role wrongly blocked on {method} {path}"
        )


# --------------------------------------------------------------------------- #
# Surface is authenticated (no override, no credentials → 401 everywhere).
# --------------------------------------------------------------------------- #


class TestUnauthenticatedIsRejected:
    @pytest.mark.parametrize("method,path,permission", WRITE_ENDPOINTS)
    def test_no_credentials_gets_401(self, client, method, path, permission):
        # Ensure the real dependency is in force for this check.
        app.dependency_overrides.pop(get_current_user, None)
        resp = _request(client, method, path)
        assert resp.status_code == 401, (
            f"{method} {path} is not authenticated (got {resp.status_code})"
        )


# --------------------------------------------------------------------------- #
# Enrichment read surface — regression for the pre-v1.0.0 gap where the whole
# enrichment router shipped with NO auth dependency (unauthenticated read of
# captured attack payloads / evasion telemetry).
# --------------------------------------------------------------------------- #


class TestEnrichmentReadSurfaceIsGuarded:
    @pytest.mark.parametrize("method,path", ENRICHMENT_READ_ENDPOINTS)
    def test_no_credentials_gets_401(self, client, method, path):
        app.dependency_overrides.pop(get_current_user, None)
        resp = client.request(method, path, headers={"x-csrf-token": _CSRF})
        assert resp.status_code == 401, (
            f"{method} {path} exposes enrichment data unauthenticated "
            f"(got {resp.status_code})"
        )

    @pytest.mark.parametrize("method,path", ENRICHMENT_READ_ENDPOINTS)
    def test_viewer_denied_raw_attack_payloads(self, client, method, path):
        # Least privilege: the viewer role does not hold guardrails:read and
        # must not reach raw attack-payload telemetry.
        _override_role(UserRole.VIEWER)
        resp = client.request(method, path, headers={"x-csrf-token": _CSRF})
        assert resp.status_code == 403, (
            f"{method} {path} leaked enrichment data to viewer "
            f"(got {resp.status_code}; expected 403 for guardrails:read)"
        )
        assert "guardrails:read" in resp.text

    @pytest.mark.parametrize("method,path", ENRICHMENT_READ_ENDPOINTS)
    def test_auditor_allowed_through_rbac(self, client, method, path):
        # auditor holds guardrails:read — RBAC must not block it (handler may
        # still 404/503 when the replay DB is absent in the sandbox).
        _override_role(UserRole.AUDITOR)
        resp = client.request(method, path, headers={"x-csrf-token": _CSRF})
        assert resp.status_code != 403, (
            f"{method} {path} wrongly blocked auditor holding guardrails:read"
        )
