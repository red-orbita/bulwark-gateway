"""Regression tests for A4: SSE token scope confinement.

The admin dashboard mints a short-lived ``purpose="sse"`` token that is placed
in the EventSource URL query string (``?token=...``) because ``EventSource``
cannot send an ``Authorization`` header. Such a token therefore leaks into
access logs, proxy logs and ``Referer`` headers. Before the fix the generic
``verify_token`` (behind ``get_current_user`` and every bearer-authenticated
admin endpoint) did not inspect the ``purpose`` claim, so a leaked SSE URL token
was a full session credential and could be replayed against any admin API.

The fix scopes the two verifiers:
  * ``verify_token``     — rejects ANY purpose-scoped token (session-only).
  * ``verify_sse_token`` — REQUIRES ``purpose == "sse"``.

The SSE endpoint accepts either kind (SSE token via query, session via header).
"""

from admin.models.auth import UserRole
from admin.services.auth_service import AuthService


class TestSseTokenScope:
    def test_session_token_rejected_by_sse_verifier(self):
        """A full-session token carries no purpose and is NOT an SSE token."""
        token = AuthService.create_token("admin", UserRole.ADMIN)
        assert AuthService.verify_sse_token(token) is None

    def test_session_token_accepted_by_session_verifier(self):
        """Baseline: a normal session token still validates normally."""
        token = AuthService.create_token("admin", UserRole.ADMIN)
        payload = AuthService.verify_token(token)
        assert payload is not None
        assert payload.sub == "admin"
        assert payload.role == UserRole.ADMIN

    def test_sse_token_rejected_by_session_verifier(self):
        """CORE A4: an SSE URL token must NOT be usable as a session credential."""
        sse_token = AuthService.create_sse_token("admin", UserRole.ADMIN)
        assert AuthService.verify_token(sse_token) is None

    def test_sse_token_accepted_by_sse_verifier(self):
        """The SSE token is valid for its intended narrow scope."""
        sse_token = AuthService.create_sse_token("admin", UserRole.ADMIN)
        payload = AuthService.verify_sse_token(sse_token)
        assert payload is not None
        assert payload.sub == "admin"
        assert payload.role == UserRole.ADMIN

    def test_sse_endpoint_helper_accepts_both_kinds(self):
        """The SSE endpoint's ``verify_sse_token(t) or verify_token(t)`` chain
        accepts exactly the two intended token kinds and nothing else."""
        sse_token = AuthService.create_sse_token("admin", UserRole.ADMIN)
        session_token = AuthService.create_token("admin", UserRole.ADMIN)

        # SSE token → resolved by the sse verifier (first in the chain)
        assert (AuthService.verify_sse_token(sse_token)
                or AuthService.verify_token(sse_token)) is not None
        # Session token → falls through to the session verifier
        assert (AuthService.verify_sse_token(session_token)
                or AuthService.verify_token(session_token)) is not None

    def test_garbage_token_rejected_by_both(self):
        assert AuthService.verify_token("not-a-jwt") is None
        assert AuthService.verify_sse_token("not-a-jwt") is None

    def test_sse_token_preserves_role_scope(self):
        """An SSE token minted for a low-privilege role does not elevate."""
        sse_token = AuthService.create_sse_token("viewer", UserRole.VIEWER)
        payload = AuthService.verify_sse_token(sse_token)
        assert payload is not None
        assert payload.role == UserRole.VIEWER
        # And it is still not a session credential.
        assert AuthService.verify_token(sse_token) is None
