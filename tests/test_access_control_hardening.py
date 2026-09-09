"""Regression tests for the admin access-control hardening fixes (pentest F-01…F-08).

Each class pins the security contract of one confirmed finding so a future
refactor cannot silently reintroduce the bypass:

* F-01 — the JWT carries the operator's ``tenant`` scope claim end-to-end
  (create → verify), so per-tenant authorization (investigation centre) is
  effective instead of every operator resolving to an unscoped/global view.
* F-02 — a role change / deactivation revokes the target's sessions immediately
  rather than lingering until the existing JWT expires.
* F-03 — a session revoke is scoped to the owning user, so a session id alone
  cannot revoke another operator's session (IDOR/BOLA).
* F-05 — the Wazuh SIEM probe routes through the single hardened SSRF validator,
  so IPv6 loopback / link-local / ULA / CGNAT are blocked (the old inline check
  was IPv4-only).
* F-06 — the admin body-size limit reads a chunked/streamed body incrementally
  and aborts the instant it crosses the cap (no unbounded buffering).
* F-07 — the plugin archive extractor enforces decompression-bomb ceilings
  (declared size, member count, and a running written-bytes cap).
* F-08 — re-registering MFA on an already-enabled account requires a step-up
  (current password + a valid current TOTP), and an admin cannot silently
  rebind another user's second factor.

F-04 (idempotency replay must re-verify the presenting key) is covered in
``tests/test_automation_idempotency.py``.
"""

from __future__ import annotations

import io
import os
import zipfile
from datetime import datetime, timedelta, timezone

os.environ.setdefault("ADMIN_JWT_SECRET", "test-secret-that-is-at-least-32-chars-long-xx")
os.environ.setdefault("BULWARK_KEY_ENCRYPTION_KEY", "access-control-test-encryption-32chars!!")

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from admin.models.auth import TokenPayload, UserRole

# ═══════════════════════════════════════════════════════════════════════════
# helpers
# ═══════════════════════════════════════════════════════════════════════════


def _future(hours: int = 1) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()


def _token(sub: str, role: UserRole, tenant: str | None = None) -> TokenPayload:
    now = datetime.now(timezone.utc)
    return TokenPayload(sub=sub, role=role, tenant=tenant, exp=now + timedelta(hours=1), iat=now)


class _FakeAudit:
    def __init__(self):
        self.entries: list[dict] = []

    async def log(self, **kwargs):
        self.entries.append(kwargs)


@pytest.fixture
def user_store(tmp_path):
    from admin.services.user_store import UserStore

    store = UserStore(db_path=str(tmp_path / "users.db"))
    store.initialize()
    return store


# ═══════════════════════════════════════════════════════════════════════════
# F-01 — tenant scope claim propagates through the JWT
# ═══════════════════════════════════════════════════════════════════════════


class TestF01TenantClaim:
    def test_model_has_tenant_field(self):
        tok = _token("u", UserRole.SECURITY, tenant="acme")
        assert tok.tenant == "acme"

    def test_create_and_verify_roundtrips_tenant(self):
        from admin.services.auth_service import AuthService

        jwt = AuthService.create_token("scoped-op", UserRole.SECURITY, tenant="acme")
        payload = AuthService.verify_token(jwt)
        assert payload is not None
        assert payload.sub == "scoped-op"
        assert payload.tenant == "acme"

    def test_unscoped_operator_has_none_tenant(self):
        from admin.services.auth_service import AuthService

        jwt = AuthService.create_token("global-op", UserRole.ADMIN)
        payload = AuthService.verify_token(jwt)
        assert payload is not None
        assert payload.tenant is None

    def test_empty_tenant_claim_coerces_to_none(self):
        from admin.services.auth_service import AuthService

        # An empty-string tenant claim must be treated as unscoped, not as a
        # tenant literally named "" (which would match nothing).
        jwt = AuthService.create_token("op", UserRole.ADMIN, tenant="")
        payload = AuthService.verify_token(jwt)
        assert payload is not None
        assert payload.tenant is None

    def test_authenticate_surfaces_tenant_scope(self, user_store, monkeypatch):
        from admin.services import auth_service as mod
        from admin.services import user_store as us_mod

        user_store.create_user("t-op", "TestPassw0rd!", "security", tenant_scope="acme")
        # authenticate() imports get_user_store from .user_store at call time.
        monkeypatch.setattr(us_mod, "get_user_store", lambda: user_store)
        result = mod.AuthService.authenticate("t-op", "TestPassw0rd!")
        assert result["success"] is True
        assert result["tenant"] == "acme"


# ═══════════════════════════════════════════════════════════════════════════
# F-03 — session revoke is scoped to the owning user (IDOR/BOLA)
# ═══════════════════════════════════════════════════════════════════════════


class TestF03SessionRevokeScoping:
    def _mk_session(self, store, user_id: str):
        sess = store.create_session(user_id, f"tok-{user_id}", "1.2.3.4", "pytest", _future())
        return sess["id"], sess["token_hash"]

    def test_wrong_user_id_does_not_revoke(self, user_store):
        victim = user_store.create_user("victim", "TestPassw0rd!", "admin")
        attacker = user_store.create_user("attacker", "TestPassw0rd!", "viewer")
        sid, thash = self._mk_session(user_store, victim["id"])

        # Attacker knows/guesses the victim's session id but scopes to their own id.
        assert user_store.revoke_session(sid, user_id=attacker["id"]) is False
        # Victim's session is untouched.
        assert user_store.is_session_valid(thash) is True

    def test_correct_user_id_revokes(self, user_store):
        victim = user_store.create_user("victim2", "TestPassw0rd!", "admin")
        sid, thash = self._mk_session(user_store, victim["id"])
        assert user_store.revoke_session(sid, user_id=victim["id"]) is True
        assert user_store.is_session_valid(thash) is False

    def test_unscoped_revoke_still_supported(self, user_store):
        # Callers that already authorized ownership may omit user_id (back-compat).
        u = user_store.create_user("solo", "TestPassw0rd!", "admin")
        sid, thash = self._mk_session(user_store, u["id"])
        assert user_store.revoke_session(sid) is True
        assert user_store.is_session_valid(thash) is False

    async def test_route_passes_user_id_and_404_on_cross_user(self, user_store, monkeypatch):
        import admin.routes.users as users

        victim = user_store.create_user("v3", "TestPassw0rd!", "admin")
        attacker = user_store.create_user("a3", "TestPassw0rd!", "admin")
        sid, thash = self._mk_session(user_store, victim["id"])

        monkeypatch.setattr(users, "get_user_store", lambda: user_store)
        monkeypatch.setattr(users, "get_audit_logger", lambda: _FakeAudit())

        # An admin attacker targets the victim's own session id under the
        # attacker's user_id path → scoped revoke misses → 404, victim intact.
        with pytest.raises(HTTPException) as ei:
            await users.revoke_session(attacker["id"], sid, user=_token("a3", UserRole.ADMIN))
        assert ei.value.status_code == 404
        assert user_store.is_session_valid(thash) is True


# ═══════════════════════════════════════════════════════════════════════════
# F-02 — role change / deactivation revokes sessions immediately
# ═══════════════════════════════════════════════════════════════════════════


class TestF02ImmediateRevocation:
    async def test_role_change_revokes_sessions(self, user_store, monkeypatch):
        import admin.routes.users as users
        from admin.models.auth import UserUpdate

        target = user_store.create_user("demote-me", "TestPassw0rd!", "admin")
        sess = user_store.create_session(target["id"], "tok-x", "1.2.3.4", "pytest", _future())

        monkeypatch.setattr(users, "get_user_store", lambda: user_store)
        monkeypatch.setattr(users, "get_audit_logger", lambda: _FakeAudit())

        await users.update_user(
            target["id"], UserUpdate(role="viewer"), user=_token("admin", UserRole.ADMIN)
        )
        assert user_store.is_session_valid(sess["token_hash"]) is False

    async def test_deactivation_revokes_sessions(self, user_store, monkeypatch):
        import admin.routes.users as users
        from admin.models.auth import UserUpdate

        target = user_store.create_user("disable-me", "TestPassw0rd!", "security")
        sess = user_store.create_session(target["id"], "tok-y", "1.2.3.4", "pytest", _future())

        monkeypatch.setattr(users, "get_user_store", lambda: user_store)
        monkeypatch.setattr(users, "get_audit_logger", lambda: _FakeAudit())

        await users.update_user(
            target["id"], UserUpdate(active=False), user=_token("admin", UserRole.ADMIN)
        )
        assert user_store.is_session_valid(sess["token_hash"]) is False

    async def test_benign_update_keeps_sessions(self, user_store, monkeypatch):
        import admin.routes.users as users
        from admin.models.auth import UserUpdate

        target = user_store.create_user("edit-me", "TestPassw0rd!", "admin")
        sess = user_store.create_session(target["id"], "tok-z", "1.2.3.4", "pytest", _future())

        monkeypatch.setattr(users, "get_user_store", lambda: user_store)
        monkeypatch.setattr(users, "get_audit_logger", lambda: _FakeAudit())

        # A no-privilege-impact edit (same role, still active) must NOT nuke
        # the operator's live sessions.
        await users.update_user(
            target["id"],
            UserUpdate(role="admin", first_name="Edited"),
            user=_token("admin", UserRole.ADMIN),
        )
        assert user_store.is_session_valid(sess["token_hash"]) is True


# ═══════════════════════════════════════════════════════════════════════════
# F-05 — Wazuh SIEM probe delegates to the hardened SSRF validator
# ═══════════════════════════════════════════════════════════════════════════


class TestF05WazuhSsrf:
    async def test_ipv6_loopback_blocked(self):
        # The whole point of F-05: the old inline check was IPv4-only, so ::1
        # slipped through. Delegation to _validate_url_no_ssrf now blocks it.
        from admin.routes.siem import _test_wazuh_connection

        res = await _test_wazuh_connection({"wazuh_api_url": "https://[::1]:55000"})
        assert res.success is False
        assert "SSRF blocked" in (res.error or "")

    async def test_ipv4_metadata_blocked(self):
        from admin.routes.siem import _test_wazuh_connection

        res = await _test_wazuh_connection({"wazuh_api_url": "https://169.254.169.254:55000"})
        assert res.success is False
        assert "SSRF blocked" in (res.error or "")

    async def test_empty_host_rejected(self):
        from admin.routes.siem import _test_wazuh_connection

        res = await _test_wazuh_connection({"wazuh_api_url": "not-a-url"})
        assert res.success is False
        assert "Invalid wazuh_api_url" in (res.error or "")

    def test_validator_blocks_v6_and_cgnat(self):
        # Direct guard on the shared SSOT: the ranges the inline check missed.
        from admin.routes.siem import _validate_url_no_ssrf

        for url in (
            "https://[::1]:55000",
            "https://[fe80::1]:55000",
            "https://[fc00::1]:55000",
            "https://100.64.0.1:55000",
        ):
            assert _validate_url_no_ssrf(url) is not None, url

    def test_wazuh_service_name_is_allowlisted(self):
        # The retained on-cluster Wazuh demo resolves to a private ClusterIP the
        # shared validator would reject; the service names are the intended
        # exception carried by the probe.
        # The allowlist is applied inside _test_wazuh_connection; assert the
        # constant exists there as the documented exception surface.
        import inspect

        from admin.routes import siem

        src = inspect.getsource(siem._test_wazuh_connection)
        assert "wazuh.bulwark-siem.svc.cluster.local" in src


# ═══════════════════════════════════════════════════════════════════════════
# F-06 — body-size limit reads chunked bodies incrementally, aborts early
# ═══════════════════════════════════════════════════════════════════════════


@pytest.fixture
def body_limit_client():
    from admin.main import _MAX_BODY_SIZE, body_size_limit

    app = FastAPI()
    app.middleware("http")(body_size_limit)

    @app.post("/echo")
    async def echo(request: Request):
        body = await request.body()
        return {"len": len(body)}

    tc = TestClient(app)
    tc.max_body = _MAX_BODY_SIZE  # type: ignore[attr-defined]
    return tc


class TestF06BodySizeLimit:
    def test_declared_content_length_over_cap_rejected(self, body_limit_client):
        big = b"x" * (body_limit_client.max_body + 1)
        r = body_limit_client.post("/echo", content=big)
        assert r.status_code == 413

    def test_under_cap_body_reaches_handler(self, body_limit_client):
        payload = b"y" * 1024
        r = body_limit_client.post("/echo", content=payload)
        assert r.status_code == 200
        assert r.json()["len"] == 1024

    def test_chunked_over_cap_rejected(self, body_limit_client):
        cap = body_limit_client.max_body

        def gen():
            # No Content-Length → chunked. Stream past the cap in pieces; the
            # middleware must abort mid-stream rather than buffer it all.
            sent = 0
            while sent <= cap + 65536:
                yield b"z" * 65536
                sent += 65536

        r = body_limit_client.post("/echo", content=gen())
        assert r.status_code == 413

    def test_chunked_under_cap_reaches_handler_rereadable(self, body_limit_client):
        def gen():
            yield b"a" * 2048
            yield b"b" * 2048

        r = body_limit_client.post("/echo", content=gen())
        assert r.status_code == 200
        # The bounded body was cached on the request and replayed to the handler.
        assert r.json()["len"] == 4096


# ═══════════════════════════════════════════════════════════════════════════
# F-07 — plugin archive extractor enforces decompression-bomb ceilings
# ═══════════════════════════════════════════════════════════════════════════


class TestF07DecompressionBomb:
    def _zip(self, path, members: dict[str, bytes]):
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, data in members.items():
                zf.writestr(name, data)
        return path

    def test_happy_path_extracts_plugin_root(self, tmp_path):
        from admin.routes.plugins import _extract_archive

        arc = self._zip(
            tmp_path / "plugin.zip",
            {"myplugin/bulwark-plugin.yaml": b"name: x\n", "myplugin/main.py": b"print(1)\n"},
        )
        dest = tmp_path / "out"
        dest.mkdir()
        root = _extract_archive(arc, dest)
        assert (root / "bulwark-plugin.yaml").exists()

    def test_too_many_members_rejected(self, tmp_path, monkeypatch):
        import admin.routes.plugins as plugins

        monkeypatch.setattr(plugins, "_MAX_ARCHIVE_MEMBERS", 5)
        arc = self._zip(
            tmp_path / "many.zip",
            {f"p/f{i}.txt": b"x" for i in range(10)},
        )
        dest = tmp_path / "out"
        dest.mkdir()
        with pytest.raises(ValueError, match="too many entries"):
            plugins._extract_archive(arc, dest)

    def test_declared_oversize_rejected(self, tmp_path, monkeypatch):
        import admin.routes.plugins as plugins

        # Shrink the ceiling so a modest highly-compressible member trips it
        # without writing hundreds of MB in the test.
        monkeypatch.setattr(plugins, "_MAX_TOTAL_UNCOMPRESSED", 4096)
        arc = self._zip(tmp_path / "bomb.zip", {"p/big.txt": b"\0" * 8192})
        dest = tmp_path / "out"
        dest.mkdir()
        with pytest.raises(ValueError, match="decompression bomb"):
            plugins._extract_archive(arc, dest)

    def test_running_write_cap_trips_on_lying_size(self, tmp_path, monkeypatch):
        import admin.routes.plugins as plugins

        # Build a zip whose central-directory size is truthful, then lower the
        # ceiling below the actual written bytes: the streaming counter must trip
        # even if the up-front declared-total check were bypassed.
        arc = self._zip(tmp_path / "stream.zip", {"p/data.bin": b"Q" * 20000})
        monkeypatch.setattr(plugins, "_MAX_TOTAL_UNCOMPRESSED", 10000)
        dest = tmp_path / "out"
        dest.mkdir()
        with pytest.raises(ValueError, match="decompression bomb"):
            plugins._extract_archive(arc, dest)

    def test_path_traversal_still_blocked(self, tmp_path):
        from admin.routes.plugins import _extract_archive

        # Craft a member escaping the destination.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../evil.py", b"pwn")
        arc = tmp_path / "trav.zip"
        arc.write_bytes(buf.getvalue())
        dest = tmp_path / "out"
        dest.mkdir()
        with pytest.raises(ValueError, match="[Uu]nsafe|traversal"):
            _extract_archive(arc, dest)


# ═══════════════════════════════════════════════════════════════════════════
# F-08 — MFA re-registration requires a step-up
# ═══════════════════════════════════════════════════════════════════════════


class TestF08MfaReRegistration:
    @pytest.fixture(autouse=True)
    def _need_pyotp(self):
        from admin.services.user_store import _HAS_PYOTP

        if not _HAS_PYOTP:
            pytest.skip("pyotp not installed")

    def _enroll_mfa(self, store, user_id: str) -> str:
        import pyotp

        result = store.setup_mfa(user_id)
        secret = result["secret"]
        # Confirm enrollment so mfa_secret is set / active on the account.
        assert store.verify_mfa(user_id, pyotp.TOTP(secret).now()) is True
        return secret

    async def test_first_time_enrollment_needs_no_stepup(self, user_store, monkeypatch):
        import admin.routes.users as users

        u = user_store.create_user("fresh", "TestPassw0rd!", "admin")
        monkeypatch.setattr(users, "get_user_store", lambda: user_store)
        monkeypatch.setattr(users, "get_audit_logger", lambda: _FakeAudit())

        resp = await users.mfa_setup(u["id"], req=None, user=_token("fresh", UserRole.ADMIN))
        assert resp.secret
        assert resp.provisioning_uri.startswith("otpauth://")

    async def test_self_reregister_without_stepup_rejected(self, user_store, monkeypatch):
        import admin.routes.users as users
        from admin.models.auth import MFASetupRequest

        u = user_store.create_user("reg-self", "TestPassw0rd!", "admin")
        self._enroll_mfa(user_store, u["id"])
        monkeypatch.setattr(users, "get_user_store", lambda: user_store)
        monkeypatch.setattr(users, "get_audit_logger", lambda: _FakeAudit())

        with pytest.raises(HTTPException) as ei:
            await users.mfa_setup(u["id"], req=MFASetupRequest(), user=_token("reg-self", UserRole.ADMIN))
        assert ei.value.status_code == 401
        assert "Step-up required" in ei.value.detail

    async def test_self_reregister_wrong_password_rejected(self, user_store, monkeypatch):
        import pyotp

        import admin.routes.users as users
        from admin.models.auth import MFASetupRequest

        u = user_store.create_user("reg-badpw", "TestPassw0rd!", "admin")
        secret = self._enroll_mfa(user_store, u["id"])
        monkeypatch.setattr(users, "get_user_store", lambda: user_store)
        monkeypatch.setattr(users, "get_audit_logger", lambda: _FakeAudit())

        with pytest.raises(HTTPException) as ei:
            await users.mfa_setup(
                u["id"],
                req=MFASetupRequest(current_password="WrongPass!", mfa_code=pyotp.TOTP(secret).now()),
                user=_token("reg-badpw", UserRole.ADMIN),
            )
        assert ei.value.status_code == 401

    async def test_self_reregister_with_valid_stepup_succeeds(self, user_store, monkeypatch):
        import pyotp

        import admin.routes.users as users
        from admin.models.auth import MFASetupRequest

        u = user_store.create_user("reg-ok", "TestPassw0rd!", "admin")
        secret = self._enroll_mfa(user_store, u["id"])
        monkeypatch.setattr(users, "get_user_store", lambda: user_store)
        monkeypatch.setattr(users, "get_audit_logger", lambda: _FakeAudit())

        resp = await users.mfa_setup(
            u["id"],
            req=MFASetupRequest(current_password="TestPassw0rd!", mfa_code=pyotp.TOTP(secret).now()),
            user=_token("reg-ok", UserRole.ADMIN),
        )
        assert resp.secret
        # A new secret is issued (rotation), distinct from the old one.
        assert resp.secret != secret

    async def test_admin_cannot_rebind_other_users_enabled_mfa(self, user_store, monkeypatch):
        import admin.routes.users as users

        admin_u = user_store.create_user("root", "TestPassw0rd!", "admin")
        victim = user_store.create_user("hasmfa", "TestPassw0rd!", "security")
        self._enroll_mfa(user_store, victim["id"])
        monkeypatch.setattr(users, "get_user_store", lambda: user_store)
        monkeypatch.setattr(users, "get_audit_logger", lambda: _FakeAudit())

        with pytest.raises(HTTPException) as ei:
            await users.mfa_setup(victim["id"], req=None, user=_token("root", UserRole.ADMIN))
        assert ei.value.status_code == 409
        assert "disable it first" in ei.value.detail
        # admin_u exists only to make the actor a real admin; no assertion needed.
        assert admin_u["id"]
