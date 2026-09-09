"""LOW cluster regression tests: admin secrets / auth hygiene (S-26, S-27, S-28).

* S-26 — bcrypt silently ignores bytes past 72, so two distinct long passphrases
  sharing a 72-byte prefix collide. The complexity validator now rejects
  over-length input and ``_hash_password`` refuses to hash it.
* S-27 — an explicitly-configured ``*_FILE`` secret that exists is authoritative:
  a blank file must NOT silently fall through to a plain env var / default, and
  internal whitespace must be preserved (only a single trailing newline stripped).
* S-28 — the logout cookie-delete flags must match the login set flags, so a
  cookie set over plain HTTP (secure=False/lax) is actually cleared.
"""

from __future__ import annotations

import os

os.environ.setdefault("ADMIN_JWT_SECRET", "test-secret-that-is-at-least-32-characters-long-xx")

from types import SimpleNamespace

import pytest
from starlette.requests import Request
from starlette.responses import Response

from admin.services.user_store import (
    _MAX_PASSWORD_BYTES,
    _hash_password,
    validate_password_complexity,
)


# ==============================================================================
# S-26 — bcrypt 72-byte truncation guard
# ==============================================================================
class TestPasswordLengthGuard:
    def test_validator_accepts_max_length(self):
        # Exactly 72 bytes with all complexity classes → valid.
        pw = "Aa1!" + "x" * 68  # 72 chars == 72 bytes (all ASCII)
        assert len(pw.encode()) == _MAX_PASSWORD_BYTES
        valid, err = validate_password_complexity(pw)
        assert valid, err

    def test_validator_rejects_over_length(self):
        pw = "Aa1!" + "x" * 69  # 73 bytes
        valid, err = validate_password_complexity(pw)
        assert valid is False
        assert "72" in err

    def test_validator_counts_utf8_bytes_not_chars(self):
        # 40 emoji × 4 bytes each = 160 bytes but only 40 chars → must be rejected.
        pw = "Aa1!" + ("\U0001f600" * 40)
        assert len(pw) < 72  # char count is under the limit...
        assert len(pw.encode()) > _MAX_PASSWORD_BYTES  # ...byte count is over
        valid, _ = validate_password_complexity(pw)
        assert valid is False

    def test_hash_password_refuses_over_length(self):
        with pytest.raises(ValueError, match="72"):
            _hash_password("x" * 73)

    def test_hash_password_accepts_max_length(self):
        # Backstop must not reject a legitimate 72-byte password.
        digest = _hash_password("y" * 72)
        assert digest.startswith("$2")


# ==============================================================================
# S-27 — read_secret: authoritative *_FILE, fail-closed on blank
# ==============================================================================
class TestReadSecretFileAuthoritative:
    def test_blank_file_does_not_fall_through_to_env(self, tmp_path, monkeypatch):
        from admin.services.secrets import read_secret

        secret_file = tmp_path / "jwt"
        secret_file.write_text("   \n")  # whitespace-only
        monkeypatch.setenv("MY_SECRET_FILE", str(secret_file))
        monkeypatch.setenv("MY_SECRET", "env-fallback-should-be-ignored")

        # File is authoritative but blank → return "" (never the env fallback).
        assert read_secret("MY_SECRET", default="def") == ""

    def test_blank_file_required_fails_closed(self, tmp_path, monkeypatch):
        from admin.services.secrets import read_secret

        secret_file = tmp_path / "jwt"
        secret_file.write_text("")
        monkeypatch.setenv("MY_SECRET_FILE", str(secret_file))
        monkeypatch.setenv("MY_SECRET", "env-fallback-should-be-ignored")

        with pytest.raises(SystemExit):
            read_secret("MY_SECRET", required=True)

    def test_internal_whitespace_preserved(self, tmp_path, monkeypatch):
        from admin.services.secrets import read_secret

        secret_file = tmp_path / "jwt"
        # Legitimate secret with internal + surrounding whitespace; only ONE
        # trailing newline should be stripped.
        secret_file.write_text("  pa ss\tword  \n")
        monkeypatch.setenv("MY_SECRET_FILE", str(secret_file))

        assert read_secret("MY_SECRET") == "  pa ss\tword  "

    def test_crlf_trailing_stripped_once(self, tmp_path, monkeypatch):
        from admin.services.secrets import read_secret

        secret_file = tmp_path / "jwt"
        secret_file.write_text("value\r\n")
        monkeypatch.setenv("MY_SECRET_FILE", str(secret_file))
        assert read_secret("MY_SECRET") == "value"

    def test_populated_file_wins_over_env(self, tmp_path, monkeypatch):
        from admin.services.secrets import read_secret

        secret_file = tmp_path / "jwt"
        secret_file.write_text("from-file\n")
        monkeypatch.setenv("MY_SECRET_FILE", str(secret_file))
        monkeypatch.setenv("MY_SECRET", "from-env")
        assert read_secret("MY_SECRET") == "from-file"

    def test_missing_file_falls_through_to_env(self, tmp_path, monkeypatch):
        from admin.services.secrets import read_secret

        # *_FILE points at a non-existent path → not authoritative, env is used.
        monkeypatch.setenv("MY_SECRET_FILE", str(tmp_path / "nope"))
        monkeypatch.setenv("MY_SECRET", "from-env")
        assert read_secret("MY_SECRET") == "from-env"


# ==============================================================================
# S-28 — logout cookie-delete flags mirror login
# ==============================================================================
def _make_request(scheme: str, headers: list[tuple[bytes, bytes]] | None = None) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/admin/auth/logout",
            "scheme": scheme,
            "headers": headers or [(b"host", b"localhost")],
            "client": ("127.0.0.1", 12345),
            "query_string": b"",
        }
    )


class _AsyncAudit:
    async def log(self, **kwargs):  # noqa: ANN003, ANN201
        return None


@pytest.mark.asyncio
class TestLogoutCookieFlags:
    async def test_http_logout_clears_without_secure(self, monkeypatch):
        from admin.routes import auth

        monkeypatch.delenv("BULWARK_HTTPS", raising=False)
        monkeypatch.setattr(auth, "get_audit_logger", lambda: _AsyncAudit())

        resp = Response()
        await auth.logout(
            _make_request("http"), resp, user=SimpleNamespace(sub="admin")
        )
        set_cookie = resp.headers.get("set-cookie", "").lower()
        assert "admin_token=" in set_cookie
        assert "secure" not in set_cookie
        assert "samesite=lax" in set_cookie

    async def test_https_logout_clears_with_secure_strict(self, monkeypatch):
        from admin.routes import auth

        monkeypatch.setenv("BULWARK_HTTPS", "true")
        monkeypatch.setattr(auth, "get_audit_logger", lambda: _AsyncAudit())

        resp = Response()
        await auth.logout(
            _make_request("https"), resp, user=SimpleNamespace(sub="admin")
        )
        set_cookie = resp.headers.get("set-cookie", "").lower()
        assert "admin_token=" in set_cookie
        assert "secure" in set_cookie
        assert "samesite=strict" in set_cookie
