"""Regression tests for admin session provenance (IP address + device).

The RBAC "Active Sessions" panel is a security/forensics control: an operator
reviews it to spot logins from unexpected source IPs or devices. The panel
template previously bound the IP column to a non-existent property (``s.ip``)
while the API returns ``ip_address`` — so the "IP Address" column ALWAYS
rendered "Unknown" even though a valid client IP was captured and stored. That
is a dead/misleading control: it implies no source IP is known for any session.

These tests pin the fixed behaviour end-to-end:

* backend contract — ``UserStore`` round-trips ``ip_address``/``user_agent`` and
  ``SessionResponse`` serialises them under those exact JSON keys.
* template binding — ``rbac.html`` binds ``s.ip_address``/``s.user_agent`` and
  no longer references the broken ``s.ip`` property.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from admin.models.auth import SessionResponse, UserResponse
from admin.services.user_store import UserStore

REPO_ROOT = Path(__file__).resolve().parent.parent
RBAC_TEMPLATE = REPO_ROOT / "admin" / "templates" / "pages" / "rbac.html"


@pytest.fixture
def store(tmp_path):
    s = UserStore(db_path=str(tmp_path / "users.db"))
    s.initialize()
    return s


# ─── Backend contract ────────────────────────────────────────────────────────


class TestSessionBackendContract:
    """The stored session must expose ip_address + user_agent to the UI."""

    def test_create_and_fetch_roundtrips_ip_and_device(self, store):
        expires = (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat()
        store.create_session(
            user_id="admin",
            token="tok-abc",  # noqa: S106
            ip="203.0.113.7",
            user_agent="Mozilla/5.0 (X11; Linux x86_64) TestBrowser/1.0",
            expires_at=expires,
        )

        sessions = store.get_active_sessions("admin")
        assert len(sessions) == 1
        row = sessions[0]
        # The DB row must carry the fields under the API key names.
        assert row["ip_address"] == "203.0.113.7"
        assert "TestBrowser" in row["user_agent"]

    def test_session_response_serializes_expected_json_keys(self, store):
        expires = (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat()
        store.create_session(
            user_id="admin",
            token="tok-def",  # noqa: S106
            ip="198.51.100.42",
            user_agent="curl/8.5.0",
            expires_at=expires,
        )
        row = store.get_active_sessions("admin")[0]

        payload = SessionResponse(**row).model_dump()
        # These are the exact keys the template binds against.
        assert payload["ip_address"] == "198.51.100.42"
        assert payload["user_agent"] == "curl/8.5.0"
        # The broken template referenced `s.ip`; there is no such field.
        assert "ip" not in payload

    def test_missing_ip_is_preserved_as_none_not_fabricated(self, store):
        """A session with no captured IP must surface None (UI shows 'Unknown'),
        never a fabricated address."""
        expires = (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat()
        store.create_session(
            user_id="admin",
            token="tok-ghi",  # noqa: S106
            ip=None,
            user_agent=None,
            expires_at=expires,
        )
        payload = SessionResponse(**store.get_active_sessions("admin")[0]).model_dump()
        assert payload["ip_address"] is None
        assert payload["user_agent"] is None


# ─── Template binding regression guard ───────────────────────────────────────


class TestSessionTemplateBinding:
    """The RBAC template must bind the real response fields, not the phantom one."""

    @pytest.fixture(scope="class")
    def template_src(self):
        return RBAC_TEMPLATE.read_text(encoding="utf-8")

    def test_binds_real_ip_address_field(self, template_src):
        assert "s.ip_address" in template_src

    def test_does_not_reference_broken_ip_property(self, template_src):
        # The regression was `x-text="s.ip || 'Unknown'"`. Guard against its return.
        assert "s.ip " not in template_src
        assert "s.ip|" not in template_src
        assert 's.ip ||' not in template_src

    def test_surfaces_captured_device_user_agent(self, template_src):
        assert "s.user_agent" in template_src


# ─── Cross-backend timestamp contract ────────────────────────────────────────


class TestResponseTimestampCoercion:
    """The PostgreSQL admin backend returns native ``datetime`` objects for
    timestamp columns, whereas SQLite persists ISO strings. ``UserResponse`` and
    ``SessionResponse`` declare these fields as ``str``; without coercion the
    ``GET /admin/users`` and session endpoints 500 on Postgres only ("Couldn't
    load users"). These tests pin the coercion so the API shape is identical
    across both storage backends.
    """

    def test_user_response_accepts_datetime_and_emits_iso_string(self):
        now = datetime(2026, 6, 25, 9, 58, 44, tzinfo=timezone.utc)
        resp = UserResponse(
            id="u-1",
            username="admin",
            role="admin",
            active=True,
            created_at=now,
            last_login=now,
        )
        assert isinstance(resp.created_at, str)
        assert resp.created_at == now.isoformat()
        assert isinstance(resp.last_login, str)
        assert resp.last_login == now.isoformat()

    def test_user_response_still_accepts_iso_strings_and_none(self):
        resp = UserResponse(
            id="u-2",
            username="viewer",
            role="viewer",
            active=True,
            created_at="2026-01-01T00:00:00+00:00",
            last_login=None,
        )
        assert resp.created_at == "2026-01-01T00:00:00+00:00"
        assert resp.last_login is None

    def test_session_response_accepts_datetime_timestamps(self):
        created = datetime(2026, 6, 25, 9, 58, 44, tzinfo=timezone.utc)
        expires = datetime(2026, 6, 25, 17, 58, 44, tzinfo=timezone.utc)
        resp = SessionResponse(id="s-1", created_at=created, expires_at=expires)
        assert resp.created_at == created.isoformat()
        assert resp.expires_at == expires.isoformat()
