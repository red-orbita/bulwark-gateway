"""SQLite-based user store for admin portal with optional SQLCipher encryption.

If DB_ENCRYPTION_KEY is provided (via Docker secret or env var), the database
is encrypted at rest using SQLCipher (AES-256). Without it, falls back to
standard SQLite (for development).
"""

from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

try:
    import bcrypt
    _HAS_BCRYPT = True
except ImportError:
    _HAS_BCRYPT = False

try:
    import pyotp
    _HAS_PYOTP = True
except ImportError:
    _HAS_PYOTP = False

try:
    from pysqlcipher3 import dbapi2 as sqlcipher  # type: ignore
    _HAS_SQLCIPHER = True
except ImportError:
    _HAS_SQLCIPHER = False

from ..models.auth import UserRole

USER_DB_PATH = "data/users.db"

# Minimum password complexity requirements
_MIN_PASSWORD_LENGTH = 10
_PASSWORD_REQUIREMENTS = (
    "Password must be at least 10 characters with uppercase, lowercase, digit, and special character."
)


def validate_password_complexity(password: str) -> tuple[bool, str]:
    """Validate password meets complexity requirements.

    Returns (valid, error_message).
    """
    import re
    if len(password) < _MIN_PASSWORD_LENGTH:
        return False, _PASSWORD_REQUIREMENTS
    if not re.search(r"[A-Z]", password):
        return False, _PASSWORD_REQUIREMENTS
    if not re.search(r"[a-z]", password):
        return False, _PASSWORD_REQUIREMENTS
    if not re.search(r"\d", password):
        return False, _PASSWORD_REQUIREMENTS
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, _PASSWORD_REQUIREMENTS
    return True, ""


def _get_db_encryption_key() -> str | None:
    """Read DB encryption key from Docker secret or env var."""
    from .secrets import read_secret
    key = read_secret("DB_ENCRYPTION_KEY", default="")
    return key if key else None


def _hash_password(password: str) -> str:
    """Hash password using bcrypt (mandatory)."""
    if not _HAS_BCRYPT:
        raise SystemExit("FATAL: bcrypt is required for password hashing. Install: pip install bcrypt")
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _verify_password(password: str, password_hash: str) -> bool:
    """Verify password against stored hash. Supports legacy for migration."""
    if _HAS_BCRYPT and password_hash.startswith("$2"):
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    elif password_hash.startswith("sha256$"):
        # L-02: Accept legacy but flag for rehash
        _, salt, h = password_hash.split("$", 2)
        return hashlib.sha256((salt + password).encode()).hexdigest() == h
    else:
        # Legacy plain sha256 — accept for migration only
        return hashlib.sha256(password.encode()).hexdigest() == password_hash


# Pre-computed dummy bcrypt hash for constant-time comparison on invalid usernames
_DUMMY_HASH = "$2b$12$wQ49rPAhU6G0aaA8PvClWuA3jblHcpGq20yiUYC.QLygheF42V.gO"


class UserStore:
    """Thread-safe SQLite user store with optional SQLCipher encryption."""

    def __init__(self, db_path: str = USER_DB_PATH):
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.Lock()
        self._encrypted = False

    def initialize(self) -> None:
        """Create tables and seed default users if empty.

        Uses SQLCipher (AES-256) if:
          1. pysqlcipher3 is installed
          2. DB_ENCRYPTION_KEY is provided (via Docker secret or env var)
        Otherwise falls back to standard SQLite.
        """
        encryption_key = _get_db_encryption_key()

        if encryption_key and _HAS_SQLCIPHER:
            # Use encrypted database
            # C-06: Validate key is safe (hex/base64 only) to prevent PRAGMA injection
            import re as _re
            if not _re.match(r'^[a-zA-Z0-9+/=\-_]+$', encryption_key):
                raise SystemExit("FATAL: DB_ENCRYPTION_KEY contains invalid characters (must be hex/base64)")
            self._conn = sqlcipher.connect(str(self._path), check_same_thread=False)
            self._conn.execute(f"PRAGMA key = \"x'{encryption_key}'\"")
            self._conn.execute("PRAGMA cipher_page_size = 4096")
            self._conn.execute("PRAGMA kdf_iter = 256000")
            self._encrypted = True
            import logging
            logging.getLogger(__name__).info("User database: SQLCipher encryption ACTIVE")
        else:
            # Unencrypted fallback
            self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
            if encryption_key and not _HAS_SQLCIPHER:
                import logging
                logging.getLogger(__name__).warning(
                    "DB_ENCRYPTION_KEY set but pysqlcipher3 not installed — database is NOT encrypted"
                )

        if self._encrypted:
            # pysqlcipher3 doesn't support sqlite3.Row; use a dict factory
            def dict_row_factory(cursor, row):
                columns = [col[0] for col in cursor.description]
                return dict(zip(columns, row))
            self._conn.row_factory = dict_row_factory
        else:
            self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")

        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    tenant_scope TEXT,
                    mfa_secret TEXT,
                    active INTEGER NOT NULL DEFAULT 1,
                    force_password_change INTEGER NOT NULL DEFAULT 0,
                    email TEXT,
                    phone TEXT,
                    first_name TEXT,
                    last_name TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_login TEXT
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    token_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    ip_address TEXT,
                    user_agent TEXT,
                    last_activity TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
                CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
            """)

            # Migrate: add new profile columns if they don't exist (for existing DBs)
            for col in ("email", "phone", "first_name", "last_name"):
                try:
                    self._conn.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT")
                except Exception:
                    pass  # Column already exists

            # Migrate: add last_activity to sessions
            try:
                self._conn.execute("ALTER TABLE sessions ADD COLUMN last_activity TEXT")
            except Exception:
                pass

            # Seed default users if table is empty
            count = self._conn.execute("SELECT COUNT(*) as cnt FROM users").fetchone()["cnt"]
            if count == 0:
                self._seed_defaults()
            else:
                # Sync passwords: if secret changed since last seed, update the hash
                self._sync_passwords()

    def _seed_defaults(self) -> None:
        """Seed admin/security/auditor from Docker secrets or env vars. Mark as requiring password change."""
        from .secrets import read_secret
        now = datetime.now(timezone.utc).isoformat()
        defaults = [
            ("admin", read_secret("ADMIN_PASSWORD", default="sentinel-admin"), UserRole.ADMIN),
            ("security", read_secret("SECURITY_PASSWORD", default="sentinel-security"), UserRole.SECURITY),
            ("auditor", read_secret("AUDITOR_PASSWORD", default="sentinel-auditor"), UserRole.AUDITOR),
        ]
        for username, password, role in defaults:
            self._conn.execute(
                "INSERT INTO users (id, username, password_hash, role, active, created_at, updated_at, force_password_change) VALUES (?, ?, ?, ?, 1, ?, ?, 1)",
                (str(uuid4()), username, _hash_password(password), role.value, now, now),
            )
        self._conn.commit()

    def _sync_passwords(self) -> None:
        """Sync default user passwords with current secrets.

        If the secret value changed (e.g. K8s secret rotated), update the stored hash.
        Only syncs built-in accounts (admin, security, auditor) and only if the
        current secret doesn't match the stored hash.
        """
        import logging
        log = logging.getLogger(__name__)
        from .secrets import read_secret

        sync_targets = [
            ("admin", "ADMIN_PASSWORD", "sentinel-admin"),
            ("security", "SECURITY_PASSWORD", "sentinel-security"),
            ("auditor", "AUDITOR_PASSWORD", "sentinel-auditor"),
        ]

        for username, secret_key, fallback in sync_targets:
            current_secret = read_secret(secret_key, default=fallback)
            # Skip if using default (no explicit secret configured)
            if current_secret == fallback:
                continue

            row = self._conn.execute(
                "SELECT password_hash FROM users WHERE username = ?", (username,)
            ).fetchone()
            if not row:
                continue

            stored_hash = row["password_hash"]
            # Check if current secret already matches stored hash
            if _verify_password(current_secret, stored_hash):
                continue

            # Secret changed — update hash
            new_hash = _hash_password(current_secret)
            now = datetime.now(timezone.utc).isoformat()
            self._conn.execute(
                "UPDATE users SET password_hash = ?, updated_at = ? WHERE username = ?",
                (new_hash, now, username),
            )
            self._conn.commit()
            log.info(f"Password synced for user '{username}' (secret rotation detected)")

    def create_user(self, username: str, password: str, role: str, tenant_scope: Optional[str] = None,
                    email: Optional[str] = None, phone: Optional[str] = None,
                    first_name: Optional[str] = None, last_name: Optional[str] = None) -> dict:
        """Create a new user. Returns user dict."""
        valid, err = validate_password_complexity(password)
        if not valid:
            raise ValueError(err)
        now = datetime.now(timezone.utc).isoformat()
        user_id = str(uuid4())
        with self._lock:
            self._conn.execute(
                "INSERT INTO users (id, username, password_hash, role, tenant_scope, email, phone, first_name, last_name, active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
                (user_id, username, _hash_password(password), role, tenant_scope, email, phone, first_name, last_name, now, now),
            )
            self._conn.commit()
        return self.get_user_by_id(user_id)

    def get_user(self, username: str) -> Optional[dict]:
        """Get user by username."""
        with self._lock:
            row = self._conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None

    def get_user_by_id(self, user_id: str) -> Optional[dict]:
        """Get user by ID."""
        with self._lock:
            row = self._conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None

    def list_users(self) -> list[dict]:
        """List all users."""
        with self._lock:
            rows = self._conn.execute("SELECT * FROM users ORDER BY created_at").fetchall()
        return [dict(r) for r in rows]

    def update_user(self, user_id: str, **fields) -> Optional[dict]:
        """Update user fields."""
        allowed = {"role", "tenant_scope", "active", "last_login", "email", "phone", "first_name", "last_name"}
        updates = {k: v for k, v in fields.items() if k in allowed and v is not None}
        if not updates:
            return self.get_user_by_id(user_id)
        updates["updated_at"] = datetime.now(timezone.utc).isoformat()
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [user_id]
        with self._lock:
            self._conn.execute(f"UPDATE users SET {set_clause} WHERE id = ?", values)
            self._conn.commit()
        return self.get_user_by_id(user_id)

    def delete_user(self, user_id: str) -> bool:
        """Hard-delete user from database."""
        with self._lock:
            # Also delete related sessions
            self._conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            cur = self._conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            self._conn.commit()
        return cur.rowcount > 0

    def change_password(self, user_id: str, new_password: str) -> bool:
        """Change user password and clear force_password_change flag."""
        valid, err = validate_password_complexity(new_password)
        if not valid:
            raise ValueError(err)
        with self._lock:
            cur = self._conn.execute(
                "UPDATE users SET password_hash = ?, force_password_change = 0, updated_at = ? WHERE id = ?",
                (_hash_password(new_password), datetime.now(timezone.utc).isoformat(), user_id),
            )
            self._conn.commit()
        return cur.rowcount > 0

    def verify_password(self, username: str, password: str) -> Optional[dict]:
        """Verify credentials. Returns user dict if valid, None otherwise.
        
        Uses constant-time comparison to prevent username enumeration via timing.
        """
        user = self.get_user(username)
        if not user or not user["active"]:
            # Perform dummy hash comparison to prevent timing oracle
            _verify_password(password, _DUMMY_HASH)
            return None
        if _verify_password(password, user["password_hash"]):
            # L-02: Rehash legacy passwords to bcrypt on successful login
            if not user["password_hash"].startswith("$2"):
                new_hash = _hash_password(password)
                with self._lock:
                    self._conn.execute(
                        "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
                        (new_hash, datetime.now(timezone.utc).isoformat(), user["id"]),
                    )
                    self._conn.commit()
            # Update last_login
            self.update_user(user["id"], last_login=datetime.now(timezone.utc).isoformat())
            return user
        return None

    # --- MFA ---

    def setup_mfa(self, user_id: str) -> dict:
        """Generate TOTP secret for user. Returns secret + provisioning URI."""
        if not _HAS_PYOTP:
            raise RuntimeError("pyotp is not installed — MFA unavailable")
        secret = pyotp.random_base32()
        with self._lock:
            self._conn.execute(
                "UPDATE users SET mfa_secret = ?, updated_at = ? WHERE id = ?",
                (secret, datetime.now(timezone.utc).isoformat(), user_id),
            )
            self._conn.commit()
        user = self.get_user_by_id(user_id)
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=user["username"], issuer_name="SentinelGateway")
        return {"secret": secret, "provisioning_uri": uri}

    def verify_mfa(self, user_id: str, code: str) -> bool:
        """Verify TOTP code for user."""
        if not _HAS_PYOTP:
            raise RuntimeError("pyotp is not installed — MFA unavailable")
        user = self.get_user_by_id(user_id)
        if not user or not user.get("mfa_secret"):
            return False
        totp = pyotp.TOTP(user["mfa_secret"])
        return totp.verify(code)

    def disable_mfa(self, user_id: str) -> bool:
        """Remove MFA secret from user."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE users SET mfa_secret = NULL, updated_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), user_id),
            )
            self._conn.commit()
        return cur.rowcount > 0

    # --- Sessions ---

    def create_session(self, user_id: str, token: str, ip: Optional[str], user_agent: Optional[str], expires_at: str) -> dict:
        """Create a new session record."""
        # SECURITY FIX (M-06): Limit sessions per user to prevent session flood DoS.
        MAX_SESSIONS_PER_USER = 10

        session_id = str(uuid4())
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            # Before creating new session, count existing and delete oldest if over limit:
            cursor = self._conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE user_id = ?", (user_id,)
            )
            existing_count = cursor.fetchone()[0]
            if existing_count >= MAX_SESSIONS_PER_USER:
                # Delete oldest sessions to make room
                self._conn.execute(
                    "DELETE FROM sessions WHERE id IN (SELECT id FROM sessions WHERE user_id = ? ORDER BY created_at ASC LIMIT ?)",
                    (user_id, existing_count - MAX_SESSIONS_PER_USER + 1),
                )
            self._conn.execute(
                "INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, revoked, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, 0, ?, ?)",
                (session_id, user_id, token_hash, now, expires_at, ip, user_agent),
            )
            self._conn.commit()
        return {"id": session_id, "token_hash": token_hash, "created_at": now, "expires_at": expires_at}

    def revoke_session(self, session_id: str) -> bool:
        """Revoke a session by ID."""
        with self._lock:
            cur = self._conn.execute("UPDATE sessions SET revoked = 1 WHERE id = ?", (session_id,))
            self._conn.commit()
        return cur.rowcount > 0

    def revoke_all_sessions(self, user_id: str) -> int:
        """Revoke all sessions for a user."""
        with self._lock:
            cur = self._conn.execute("UPDATE sessions SET revoked = 1 WHERE user_id = ? AND revoked = 0", (user_id,))
            self._conn.commit()
        return cur.rowcount

    def get_active_sessions(self, user_id: str) -> list[dict]:
        """Get all non-revoked, non-expired sessions for user."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM sessions WHERE user_id = ? AND revoked = 0 AND expires_at > ? ORDER BY created_at DESC",
                (user_id, now),
            ).fetchall()
        return [dict(r) for r in rows]

    def is_session_valid(self, token_hash: str) -> bool:
        """Check if a session with this token hash is active."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM sessions WHERE token_hash = ? AND revoked = 0 AND expires_at > ?",
                (token_hash, now),
            ).fetchone()
        return row is not None

    def check_and_update_activity(self, token_hash: str, idle_timeout_minutes: int) -> bool:
        """Check if session is within idle timeout and update last_activity.

        Returns True if session is active (within idle timeout), False if timed out.
        Activity is only written to DB if last update was >60s ago (reduces writes).
        """
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        with self._lock:
            row = self._conn.execute(
                "SELECT id, last_activity FROM sessions WHERE token_hash = ? AND revoked = 0",
                (token_hash,),
            ).fetchone()
            if not row:
                return False
            # Extract last_activity — handle both dict and sqlite3.Row
            try:
                last_activity = row["last_activity"]
            except (KeyError, TypeError, IndexError):
                last_activity = None
            if last_activity:
                try:
                    last_dt = datetime.fromisoformat(last_activity)
                    age_seconds = (now - last_dt).total_seconds()
                    if age_seconds > idle_timeout_minutes * 60:
                        # Idle timeout exceeded — revoke session
                        self._conn.execute("UPDATE sessions SET revoked = 1 WHERE token_hash = ?", (token_hash,))
                        self._conn.commit()
                        return False
                    # Throttle: skip write if last activity was within 60s
                    if age_seconds < 60:
                        return True
                except (ValueError, TypeError):
                    pass
            # Update last_activity
            self._conn.execute("UPDATE sessions SET last_activity = ? WHERE token_hash = ?", (now_iso, token_hash))
            self._conn.commit()
        return True


# Singleton
_store: Optional[UserStore] = None
_store_lock = threading.Lock()


def get_user_store() -> UserStore:
    """Get or create the singleton user store instance (M-01: thread-safe)."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                store = UserStore()
                store.initialize()
                _store = store
    return _store
