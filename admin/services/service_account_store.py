"""Service accounts — scoped, non-interactive automation credentials.

A *service account* is the credential a SOAR/playbook runner (Shuffle, n8n, a
custom automation) presents to call back into the admin automation surface,
distinct from an operator's interactive session cookie. Where a human logs in
and receives a role-derived permission set, a service account carries an
**explicit, least-privilege permission list** (a whitelisted subset of the RBAC
namespaces plus the dedicated ``automation:*`` verbs — see
``AUTOMATION_GRANTABLE_PERMISSIONS``), never a role. A leaked playbook key can
therefore do exactly what it was minted for and nothing more.

Security model (mirrors the session-token scheme):

* The raw key is ``bwk_sa_<hex>`` with 192 bits of entropy. It is shown **exactly
  once** at mint and is unrecoverable thereafter — only its SHA-256
  (``key_hash``) is persisted, so a database read never yields a usable key.
* A short, non-secret ``key_prefix`` fragment is stored so the UI can identify a
  key (e.g. ``bwk_sa_ab12cd34…``) without ever holding the secret.
* Verification hashes the presented key and does an indexed ``key_hash`` lookup
  (same one-way path as ``user_store.is_session_valid``), then enforces the
  ``enabled`` flag and an optional hard ``expires_at``.

Persisted in the ``service_account`` table (migration v10) via the shared
``DatabaseEngine`` so it survives restarts and behaves identically on SQLite and
PostgreSQL. Volume is low (a handful of automation keys), so reads/writes are
plain parameterised statements — no backend-specific UPSERT.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets
from datetime import datetime, timezone
from typing import Optional

from ..models.auth import AUTOMATION_GRANTABLE_PERMISSIONS
from .database import get_database

logger = logging.getLogger(__name__)

# Raw-key scheme. ``bwk_sa_`` namespaces the credential; 24 random bytes → 48 hex
# chars → 192 bits of entropy, comfortably beyond guessing. The stored display
# prefix keeps the namespace plus the first 8 hex chars so a key is recognisable
# without exposing the secret.
KEY_PREFIX = "bwk_sa_"
_KEY_ENTROPY_BYTES = 24
_PREFIX_DISPLAY_LEN = len(KEY_PREFIX) + 8

# Accepted shape of an OPERATOR-SUPPLIED seed key (Phase 3.2d). Same namespace as
# a minted key, and at least 32 lowercase-hex chars (128 bits) so a weak/guessable
# seed value is rejected outright — the operator's IaC/Docker-secret must carry
# real entropy just like a generated key.
_SEED_KEY_RE = re.compile(r"^bwk_sa_[0-9a-f]{32,}$")

# Bounds so a single account can never carry unbounded metadata.
_MAX_NAME_LEN = 128
_MAX_CREATED_BY_LEN = 128


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_account_id() -> str:
    """Generate an opaque, collision-resistant, URL-safe account id."""
    return "sa_" + secrets.token_hex(8)


def _hash_key(raw_key: str) -> str:
    """One-way hash of a raw key (SHA-256, hex) — the only form ever stored."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _to_epoch(value: object) -> Optional[float]:
    """Parse a stored timestamp (ISO string on SQLite, datetime on PG) to epoch.

    Returns ``None`` when the value is empty or unparseable, so a malformed row
    never crashes an expiry check (it is simply treated as "no expiry parsed").
    """
    if not value:
        return None
    if isinstance(value, datetime):
        return value.timestamp()
    try:
        return datetime.fromisoformat(str(value)).timestamp()
    except (TypeError, ValueError):
        return None


def normalise_permissions(permissions: object) -> list[str]:
    """Validate + normalise a requested permission list.

    Trims, dedupes (order-preserving) and rejects any permission outside the
    automation grantable whitelist. Raises ``ValueError`` on an empty result or a
    non-grantable permission, so an account can never be minted with a privilege
    an automation playbook has no business holding.
    """
    if not isinstance(permissions, (list, tuple, set)):
        raise ValueError("permissions must be a list")
    out: list[str] = []
    seen: set[str] = set()
    for perm in permissions:
        norm = str(perm).strip()
        if not norm or norm in seen:
            continue
        if norm not in AUTOMATION_GRANTABLE_PERMISSIONS:
            raise ValueError(f"permission not grantable to a service account: {norm}")
        seen.add(norm)
        out.append(norm)
    if not out:
        raise ValueError("at least one grantable permission is required")
    return out


def _load_permissions(raw: object) -> list[str]:
    """Parse the stored permissions JSON into a list (never raises)."""
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(p) for p in raw]
    if isinstance(raw, (str, bytes, bytearray)):
        try:
            parsed = json.loads(raw)
            return [str(p) for p in parsed] if isinstance(parsed, list) else []
        except (json.JSONDecodeError, TypeError):
            return []
    return []


def _coerce_rate_limit(value: object) -> Optional[int]:
    """Normalise a requested per-key rate limit (RPM) override.

    Returns ``None`` (no override — the account inherits the environment default)
    when the value is absent/blank/unparseable, otherwise a non-negative int.
    A value of ``0`` is a deliberate, explicit "unlimited for this key" opt-out;
    negatives are clamped to ``0``. Raises nothing, so a caller can pass raw input.
    """
    if value is None or value == "":
        return None
    if not isinstance(value, (int, float, str)):
        return None
    try:
        rpm = int(value)
    except (TypeError, ValueError):
        return None
    return max(0, rpm)


def _row_to_account(row) -> dict:
    """Convert a DB row into the PUBLIC account dict (never exposes ``key_hash``)."""
    d = row.to_dict() if hasattr(row, "to_dict") else dict(row)
    return {
        "account_id": d.get("account_id"),
        "name": d.get("name") or "",
        "key_prefix": d.get("key_prefix") or "",
        "permissions": _load_permissions(d.get("permissions")),
        "enabled": bool(d.get("enabled")),
        "created_by": d.get("created_by") or "",
        "created_at": d.get("created_at"),
        "last_used_at": d.get("last_used_at"),
        "expires_at": d.get("expires_at"),
        # Per-key RPM override (Phase 3.2c). ``None`` ⇒ inherit env default.
        "rate_limit_rpm": _coerce_rate_limit(d.get("rate_limit_rpm")),
    }


class ServiceAccountStore:
    """Async CRUD over the ``service_account`` table."""

    def _db(self):
        return get_database()

    # ─── Reads ───────────────────────────────────────────────────────────────

    async def list_accounts(self) -> list[dict]:
        """Return all service accounts (metadata only — never the key hash)."""
        rows = await self._db().fetch_all(
            "SELECT * FROM service_account ORDER BY created_at DESC"
        )
        return [_row_to_account(r) for r in rows]

    async def get(self, account_id: str) -> Optional[dict]:
        """Return one service account by id, or ``None`` if absent."""
        if not account_id:
            return None
        row = await self._db().fetch_one(
            "SELECT * FROM service_account WHERE account_id = ?", [account_id]
        )
        return _row_to_account(row) if row else None

    # ─── Mint ────────────────────────────────────────────────────────────────

    async def mint(
        self,
        *,
        name: str,
        permissions: object,
        created_by: str,
        expires_at: Optional[str] = None,
        rate_limit_rpm: object = None,
    ) -> dict:
        """Create a new service account and return it WITH the raw key (once).

        The returned dict includes a ``key`` field carrying the plaintext
        ``bwk_sa_…`` credential. This is the ONLY time it is ever available —
        callers must surface it to the operator immediately; it cannot be
        recovered afterwards. Raises ``ValueError`` on invalid input.

        ``rate_limit_rpm`` is an optional per-key requests-per-minute override
        (Phase 3.2c): ``None`` inherits the environment default, a positive int
        caps this key, and ``0`` explicitly opts the key out of throttling.
        """
        clean_name = (name or "").strip()[:_MAX_NAME_LEN]
        if not clean_name:
            raise ValueError("name is required")
        perms = normalise_permissions(permissions)
        clean_created_by = (created_by or "").strip()[:_MAX_CREATED_BY_LEN]
        clean_rate_limit = _coerce_rate_limit(rate_limit_rpm)

        clean_expires: Optional[str] = None
        if expires_at:
            if _to_epoch(expires_at) is None:
                raise ValueError("expires_at must be an ISO-8601 timestamp")
            clean_expires = str(expires_at)

        raw_key = KEY_PREFIX + secrets.token_hex(_KEY_ENTROPY_BYTES)
        account_id = _new_account_id()
        now = _iso_now()

        await self._db().execute(
            "INSERT INTO service_account "
            "(account_id, name, key_prefix, key_hash, permissions, enabled, "
            "created_by, created_at, last_used_at, expires_at, rate_limit_rpm) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                account_id,
                clean_name,
                raw_key[:_PREFIX_DISPLAY_LEN],
                _hash_key(raw_key),
                json.dumps(perms),
                1,
                clean_created_by,
                now,
                None,
                clean_expires,
                clean_rate_limit,
            ],
        )
        logger.info(
            "service account minted: id=%s name=%s perms=%s by=%s rpm=%s",
            account_id, clean_name, ",".join(perms), clean_created_by, clean_rate_limit,
        )

        account = {
            "account_id": account_id,
            "name": clean_name,
            "key_prefix": raw_key[:_PREFIX_DISPLAY_LEN],
            "permissions": perms,
            "enabled": True,
            "created_by": clean_created_by,
            "created_at": now,
            "last_used_at": None,
            "expires_at": clean_expires,
            "rate_limit_rpm": clean_rate_limit,
            # Shown exactly once — never persisted in plaintext.
            "key": raw_key,
        }
        return account

    # ─── Seed (declarative provisioning) ─────────────────────────────────────

    async def seed_from_spec(
        self,
        *,
        name: str,
        permissions: object,
        raw_key: str,
        created_by: str = "startup-seed",
        expires_at: Optional[str] = None,
        rate_limit_rpm: object = None,
    ) -> Optional[str]:
        """Provision a service account from an OPERATOR-SUPPLIED key (idempotent).

        Unlike :meth:`mint`, the caller supplies the plaintext ``bwk_sa_…`` key
        (from IaC / a Docker secret) so a SOAR runner configured out-of-band with
        that exact value authenticates immediately after a fresh deploy. Only the
        SHA-256 is stored — the raw key is never persisted or logged.

        Idempotent by ``key_hash``: if an account already carries this key the
        call is a no-op and returns ``None`` (so re-running the seed on every boot
        is safe). Returns the new ``account_id`` when a row is created. Raises
        ``ValueError`` on an invalid key shape or permission list, so the seed
        driver can skip a bad entry without aborting the rest.
        """
        clean_key = (raw_key or "").strip()
        if not _SEED_KEY_RE.match(clean_key):
            raise ValueError(
                "seed key must match bwk_sa_<hex> with at least 128 bits of entropy"
            )
        clean_name = (name or "").strip()[:_MAX_NAME_LEN]
        if not clean_name:
            raise ValueError("name is required")
        perms = normalise_permissions(permissions)
        clean_created_by = (created_by or "startup-seed").strip()[:_MAX_CREATED_BY_LEN]
        clean_rate_limit = _coerce_rate_limit(rate_limit_rpm)

        clean_expires: Optional[str] = None
        if expires_at:
            if _to_epoch(expires_at) is None:
                raise ValueError("expires_at must be an ISO-8601 timestamp")
            clean_expires = str(expires_at)

        key_hash = _hash_key(clean_key)

        # Idempotency: never create a duplicate for a key that already exists.
        existing = await self._db().fetch_one(
            "SELECT account_id FROM service_account WHERE key_hash = ?", [key_hash]
        )
        if existing is not None:
            return None

        account_id = _new_account_id()
        now = _iso_now()
        await self._db().execute(
            "INSERT INTO service_account "
            "(account_id, name, key_prefix, key_hash, permissions, enabled, "
            "created_by, created_at, last_used_at, expires_at, rate_limit_rpm) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                account_id,
                clean_name,
                clean_key[:_PREFIX_DISPLAY_LEN],
                key_hash,
                json.dumps(perms),
                1,
                clean_created_by,
                now,
                None,
                clean_expires,
                clean_rate_limit,
            ],
        )
        logger.info(
            "service account seeded: id=%s name=%s perms=%s by=%s rpm=%s",
            account_id, clean_name, ",".join(perms), clean_created_by, clean_rate_limit,
        )
        return account_id

    # ─── Verify (auth hot-path) ──────────────────────────────────────────────

    async def verify(self, raw_key: str) -> Optional[dict]:
        """Resolve a presented raw key to its account, or ``None`` if invalid.

        Returns the public account dict (with ``permissions``) when the key
        matches an ``enabled`` account that has not expired, and best-effort
        stamps ``last_used_at``. Returns ``None`` for an unknown, disabled or
        expired key — the caller treats that as unauthenticated.
        """
        if not raw_key or not raw_key.startswith(KEY_PREFIX):
            return None
        row = await self._db().fetch_one(
            "SELECT * FROM service_account WHERE key_hash = ?",
            [_hash_key(raw_key)],
        )
        if row is None:
            return None
        account = _row_to_account(row)
        if not account["enabled"]:
            return None
        expiry = _to_epoch(account.get("expires_at"))
        if expiry is not None and expiry <= datetime.now(timezone.utc).timestamp():
            return None

        # Best-effort last-used stamp; a failure here must never break auth.
        try:
            await self._db().execute(
                "UPDATE service_account SET last_used_at = ? WHERE account_id = ?",
                [_iso_now(), account["account_id"]],
            )
        except Exception:  # noqa: S110 - last_used_at is advisory telemetry, not auth
            pass
        return account

    # ─── Mutations ───────────────────────────────────────────────────────────

    async def set_enabled(self, account_id: str, enabled: bool) -> bool:
        """Enable/disable an account. Returns ``True`` if a row was updated."""
        if not account_id:
            return False
        affected = await self._db().execute(
            "UPDATE service_account SET enabled = ? WHERE account_id = ?",
            [1 if enabled else 0, account_id],
        )
        return affected > 0

    async def delete(self, account_id: str) -> bool:
        """Permanently delete an account. Returns ``True`` if a row was removed."""
        if not account_id:
            return False
        affected = await self._db().execute(
            "DELETE FROM service_account WHERE account_id = ?", [account_id]
        )
        return affected > 0
