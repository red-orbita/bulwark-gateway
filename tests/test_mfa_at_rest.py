"""MFA secret at-rest encryption + PostgreSQL MFA parity.

The SQLite/SQLCipher backend encrypts the entire user database at rest, so
``mfa_secret`` is protected transparently. The PostgreSQL backend stores columns
in the clear, so the *reversible* TOTP shared secret — whose leak lets an
attacker forge valid MFA codes — is encrypted at the application layer
(``_encrypt_mfa_secret``). Everything else (email/phone/name PII) is delegated to
the provider's at-rest encryption (TDE), documented in ``docs/DEPLOYMENT.md``.

These tests lock down:

* the encrypt/decrypt helpers (roundtrip, prefix, plaintext passthrough,
  fail-closed on a rotated/absent key, plaintext fallback when unconfigured);
* that the base SQLite ``UserStore`` MFA flow still round-trips (regression guard
  — there was previously *zero* MFA coverage);
* that ``PostgreSQLUserStore.setup_mfa/verify_mfa/disable_mfa`` work at all — the
  inherited base methods use ``self._cx`` (the SQLite connection, absent on the
  PostgreSQL store) and were therefore latently broken — AND that the secret is
  stored as ciphertext at rest on PostgreSQL.
"""

from __future__ import annotations

import os

# A deterministic key so the default cipher is available even when this module is
# run in isolation (other suites set the same var via setdefault at import time).
os.environ.setdefault("BULWARK_KEY_ENCRYPTION_KEY", "mfa-at-rest-test-encryption-32chars-min!")

import pytest

from admin.services import user_store as us
from admin.services.user_store import (
    _HAS_PYOTP,
    _MFA_CIPHER_PREFIX,
    _decrypt_mfa_secret,
    _encrypt_mfa_secret,
)

# ─── Encryption-helper unit tests (no DB, no pyotp) ─────────────────────────────


def test_mfa_secret_encrypt_decrypt_roundtrip():
    secret = "JBSWY3DPEHPK3PXP"
    token = _encrypt_mfa_secret(secret)
    assert token.startswith(_MFA_CIPHER_PREFIX)
    assert secret not in token  # never stored in the clear
    assert _decrypt_mfa_secret(token) == secret


def test_mfa_decrypt_passes_through_legacy_plaintext():
    # A row written before a key was configured carries no prefix — returned as-is.
    assert _decrypt_mfa_secret("PLAINTEXTSECRET") == "PLAINTEXTSECRET"


def test_mfa_decrypt_empty_is_none():
    assert _decrypt_mfa_secret(None) is None
    assert _decrypt_mfa_secret("") is None


def test_mfa_decrypt_wrong_key_fails_closed(monkeypatch):
    token = _encrypt_mfa_secret("JBSWY3DPEHPK3PXP")
    assert token.startswith(_MFA_CIPHER_PREFIX)
    # Rotate the key underneath: the old ciphertext must fail closed (None), never
    # crash the login path.
    monkeypatch.setenv("BULWARK_KEY_ENCRYPTION_KEY", "an-entirely-different-key-9999999999")
    monkeypatch.setenv("KEY_ENCRYPTION_KEY", "an-entirely-different-key-9999999999")
    assert _decrypt_mfa_secret(token) is None


def test_mfa_no_key_falls_back_to_plaintext(monkeypatch):
    # No key / no cryptography → store plaintext (parity with SQLCipher's
    # unencrypted fallback); a prefixed token can no longer be decrypted.
    monkeypatch.setattr(us, "_mfa_cipher", lambda: None)
    assert _encrypt_mfa_secret("SECRET") == "SECRET"
    assert _decrypt_mfa_secret(_MFA_CIPHER_PREFIX + "x") is None


# ─── Base SQLite UserStore MFA regression guard ─────────────────────────────────


def test_sqlite_userstore_mfa_roundtrip(tmp_path):
    if not _HAS_PYOTP:
        pytest.skip("pyotp not installed")
    import pyotp

    from admin.services.user_store import UserStore

    store = UserStore(db_path=str(tmp_path / "users.db"))
    store.initialize()
    user = store.create_user("bob", "TestPassw0rd!", "admin")

    result = store.setup_mfa(user["id"])
    assert result["provisioning_uri"].startswith("otpauth://")

    code = pyotp.TOTP(result["secret"]).now()
    assert store.verify_mfa(user["id"], code) is True

    assert store.disable_mfa(user["id"]) is True
    assert store.get_user_by_id(user["id"]).get("mfa_secret") is None


# ─── PostgreSQL MFA parity + at-rest encryption (live PG only) ───────────────────


@pytest.mark.asyncio
async def test_pg_mfa_roundtrip_and_at_rest_encryption(pg_engine):
    if not _HAS_PYOTP:
        pytest.skip("pyotp not installed")
    import pyotp

    from admin.services.user_store import PostgreSQLUserStore

    store = PostgreSQLUserStore()
    store._db = pg_engine  # wire the throwaway engine directly (bypass get_database)

    user = store.create_user("mfauser", "TestPassw0rd!", "admin")
    uid = user["id"]

    # setup_mfa previously raised on PG (base method uses self._cx). It must now
    # succeed and return a usable secret + provisioning URI.
    result = store.setup_mfa(uid)
    secret = result["secret"]
    assert result["provisioning_uri"].startswith("otpauth://")

    # At rest the raw column is Fernet ciphertext, NOT the plaintext secret — this
    # is the SQLCipher-parity guarantee for the PostgreSQL backend.
    raw = pg_engine.sync_fetch_one("SELECT mfa_secret FROM users WHERE id = ?", (uid,))
    stored = raw["mfa_secret"]
    assert stored.startswith(_MFA_CIPHER_PREFIX)
    assert secret not in stored

    # verify_mfa decrypts and validates a live TOTP code.
    assert store.verify_mfa(uid, pyotp.TOTP(secret).now()) is True

    # disable_mfa clears the secret.
    assert store.disable_mfa(uid) is True
    raw_after = pg_engine.sync_fetch_one("SELECT mfa_secret FROM users WHERE id = ?", (uid,))
    assert raw_after["mfa_secret"] is None
    assert store.verify_mfa(uid, pyotp.TOTP(secret).now()) is False
