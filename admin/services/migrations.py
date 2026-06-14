"""Schema migration system for admin database.

Supports both SQLite and PostgreSQL backends. Migrations are version-tracked,
forward-only, and run automatically on startup.

Design:
- Migrations stored as Python objects with version number and SQL
- A `schema_migrations` table tracks which versions have been applied
- PostgreSQL uses advisory locks to prevent concurrent migrations
- SQLite uses file-based locking (inherent single-writer)
- Migrations are idempotent (IF NOT EXISTS, safe re-runs)

Usage:
    from admin.services.database import get_database
    from admin.services.migrations import run_migrations

    db = get_database()
    await run_migrations(db)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional

from .database import DatabaseEngine

logger = logging.getLogger(__name__)

# Advisory lock ID for PostgreSQL migration coordination
# (arbitrary constant, unique within the application)
MIGRATION_LOCK_ID = 0x7365746E  # "sent" in hex = 1936027758


@dataclass
class Migration:
    """A single schema migration step."""
    version: int
    description: str
    # SQL for SQLite backend
    sqlite_sql: str
    # SQL for PostgreSQL backend (if different)
    postgresql_sql: Optional[str] = None

    def get_sql(self, backend: str) -> str:
        """Get the appropriate SQL for the given backend."""
        if backend == "postgresql" and self.postgresql_sql:
            return self.postgresql_sql
        return self.sqlite_sql


# ─── Migration Definitions ────────────────────────────────────────────────────

MIGRATIONS: list[Migration] = [
    # Version 1: Initial schema — creates all tables from existing services
    Migration(
        version=1,
        description="Initial schema: users, sessions, audit_log, config, gdpr_requests",
        sqlite_sql="""
            -- Users table (from user_store.py)
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

            -- Sessions table (from user_store.py)
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
            CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

            -- Audit log table (from audit_logger.py)
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                result TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                rollback_ref TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor);
            CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);

            -- Config table (key-value store for persisted admin settings)
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT
            );

            -- GDPR requests table (from gdpr.py)
            CREATE TABLE IF NOT EXISTS gdpr_requests (
                id TEXT PRIMARY KEY,
                request_type TEXT NOT NULL,
                subject_id TEXT,
                requested_by TEXT NOT NULL,
                requested_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                records_affected INTEGER DEFAULT 0,
                details TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_gdpr_subject ON gdpr_requests(subject_id);
            CREATE INDEX IF NOT EXISTS idx_gdpr_type ON gdpr_requests(request_type);
            CREATE INDEX IF NOT EXISTS idx_gdpr_requested_at ON gdpr_requests(requested_at DESC);
        """,
        postgresql_sql="""
            -- Users table
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
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL,
                last_login TIMESTAMPTZ
            );

            -- Sessions table
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                ip_address TEXT,
                user_agent TEXT,
                last_activity TIMESTAMPTZ
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
            CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

            -- Audit log table
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                result TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                rollback_ref TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor);
            CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);

            -- Config table (key-value store)
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL,
                updated_by TEXT
            );

            -- GDPR requests table
            CREATE TABLE IF NOT EXISTS gdpr_requests (
                id TEXT PRIMARY KEY,
                request_type TEXT NOT NULL,
                subject_id TEXT,
                requested_by TEXT NOT NULL,
                requested_at TIMESTAMPTZ NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                records_affected INTEGER DEFAULT 0,
                details TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_gdpr_subject ON gdpr_requests(subject_id);
            CREATE INDEX IF NOT EXISTS idx_gdpr_type ON gdpr_requests(request_type);
            CREATE INDEX IF NOT EXISTS idx_gdpr_requested_at ON gdpr_requests(requested_at DESC);
        """,
    ),

    # Version 2: Add performance indexes for common query patterns
    Migration(
        version=2,
        description="Add performance indexes for enterprise query patterns",
        sqlite_sql="""
            -- Composite index for session validation (hot path)
            CREATE INDEX IF NOT EXISTS idx_sessions_token_revoked_expires
                ON sessions(token_hash, revoked, expires_at);

            -- Index for user lookup by role (RBAC queries)
            CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

            -- Index for active user listing
            CREATE INDEX IF NOT EXISTS idx_users_active ON users(active);

            -- Index for audit log time-range queries with actor filter
            CREATE INDEX IF NOT EXISTS idx_audit_actor_timestamp
                ON audit_log(actor, timestamp DESC);

            -- Index for audit log resource queries
            CREATE INDEX IF NOT EXISTS idx_audit_resource
                ON audit_log(resource_type, resource_id);
        """,
        postgresql_sql="""
            -- Composite index for session validation (hot path)
            CREATE INDEX IF NOT EXISTS idx_sessions_token_revoked_expires
                ON sessions(token_hash, revoked, expires_at);

            -- Index for user lookup by role (RBAC queries)
            CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

            -- Index for active user listing
            CREATE INDEX IF NOT EXISTS idx_users_active ON users(active)
                WHERE active = 1;

            -- Index for audit log time-range queries with actor filter
            CREATE INDEX IF NOT EXISTS idx_audit_actor_timestamp
                ON audit_log(actor, timestamp DESC);

            -- Index for audit log resource queries
            CREATE INDEX IF NOT EXISTS idx_audit_resource
                ON audit_log(resource_type, resource_id);

            -- Partial index for non-revoked sessions (PostgreSQL only)
            CREATE INDEX IF NOT EXISTS idx_sessions_active
                ON sessions(user_id, expires_at DESC)
                WHERE revoked = 0;
        """,
    ),

    # Version 3: Add session and config extensions for HA
    Migration(
        version=3,
        description="HA extensions: session replication support, config versioning",
        sqlite_sql="""
            -- Config version tracking for cache invalidation across replicas
            CREATE TABLE IF NOT EXISTS config_versions (
                namespace TEXT PRIMARY KEY,
                version INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL
            );

            -- Insert default namespace version
            INSERT OR IGNORE INTO config_versions (namespace, version, updated_at)
            VALUES ('global', 1, datetime('now'));
        """,
        postgresql_sql="""
            -- Config version tracking for cache invalidation across replicas
            CREATE TABLE IF NOT EXISTS config_versions (
                namespace TEXT PRIMARY KEY,
                version INTEGER NOT NULL DEFAULT 1,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );

            -- Insert default namespace version
            INSERT INTO config_versions (namespace, version, updated_at)
            VALUES ('global', 1, NOW())
            ON CONFLICT (namespace) DO NOTHING;
        """,
    ),
]


# ─── Migration Runner ─────────────────────────────────────────────────────────

async def run_migrations(engine: DatabaseEngine) -> None:
    """Run all pending migrations against the database.

    This function:
    1. Creates the schema_migrations tracking table if needed
    2. Acquires a migration lock (advisory lock for PG, inherent for SQLite)
    3. Determines which migrations have already been applied
    4. Applies pending migrations in order
    5. Releases the lock

    Safe for concurrent startup (e.g., multiple pods starting simultaneously):
    - PostgreSQL: Uses pg_try_advisory_lock (non-blocking)
    - SQLite: Single-writer, lock handled by engine's asyncio.Lock
    """
    backend = engine.backend
    logger.info("Running schema migrations (backend=%s)...", backend)

    # Acquire migration lock for PostgreSQL
    lock_acquired = True
    if backend == "postgresql":
        from .database import PostgreSQLEngine
        assert isinstance(engine, PostgreSQLEngine)
        lock_acquired = await engine.acquire_advisory_lock(MIGRATION_LOCK_ID)
        if not lock_acquired:
            logger.info("Another instance is running migrations, waiting...")
            # Wait and retry (up to 30s)
            for _ in range(30):
                await _async_sleep(1.0)
                lock_acquired = await engine.acquire_advisory_lock(MIGRATION_LOCK_ID)
                if lock_acquired:
                    break
            if not lock_acquired:
                logger.warning(
                    "Could not acquire migration lock after 30s. "
                    "Proceeding without lock (migrations may have been applied by another instance)."
                )

    try:
        # Ensure schema_migrations table exists
        await _ensure_migrations_table(engine)

        # Get current version
        current_version = await _get_current_version(engine)
        logger.info("Current schema version: %d", current_version)

        # Apply pending migrations
        pending = [m for m in MIGRATIONS if m.version > current_version]
        if not pending:
            logger.info("Schema is up to date (version %d)", current_version)
            return

        logger.info("Applying %d pending migration(s)...", len(pending))
        for migration in pending:
            start = time.monotonic()
            sql = migration.get_sql(backend)

            try:
                await _apply_migration(engine, migration, sql)
                elapsed = (time.monotonic() - start) * 1000
                logger.info(
                    "  Applied migration v%d: %s (%.1fms)",
                    migration.version, migration.description, elapsed
                )
            except Exception as e:
                logger.error(
                    "MIGRATION FAILED at v%d (%s): %s",
                    migration.version, migration.description, e
                )
                raise RuntimeError(
                    f"Migration v{migration.version} failed: {e}. "
                    f"Database may be in an inconsistent state. "
                    f"Manual intervention required."
                ) from e

        final_version = await _get_current_version(engine)
        logger.info("Migrations complete. Schema version: %d", final_version)

    finally:
        # Release PostgreSQL advisory lock
        if backend == "postgresql" and lock_acquired:
            from .database import PostgreSQLEngine
            assert isinstance(engine, PostgreSQLEngine)
            await engine.release_advisory_lock(MIGRATION_LOCK_ID)


async def _ensure_migrations_table(engine: DatabaseEngine) -> None:
    """Create the schema_migrations tracking table if it doesn't exist."""
    if engine.backend == "postgresql":
        await engine.execute_script("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                description TEXT NOT NULL,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                execution_ms INTEGER
            );
        """)
    else:
        await engine.execute_script("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                description TEXT NOT NULL,
                applied_at TEXT NOT NULL,
                execution_ms INTEGER
            );
        """)


async def _get_current_version(engine: DatabaseEngine) -> int:
    """Get the latest applied migration version."""
    try:
        row = await engine.fetch_one(
            "SELECT MAX(version) as max_version FROM schema_migrations"
        )
        if row is None:
            return 0
        return row["max_version"] or 0
    except Exception:
        # Table might not exist yet
        return 0


async def _apply_migration(engine: DatabaseEngine, migration: Migration, sql: str) -> None:
    """Apply a single migration and record it in schema_migrations.

    For SQLite, we use execute_script for multi-statement SQL.
    For PostgreSQL, we wrap in a transaction for atomicity.
    """
    import time as _time
    from datetime import datetime, timezone

    start = _time.monotonic()

    if engine.backend == "postgresql":
        # PostgreSQL: execute within transaction for atomicity
        # Note: DDL in PostgreSQL IS transactional (unlike MySQL)
        from .database import PostgreSQLEngine
        assert isinstance(engine, PostgreSQLEngine)

        # Split and filter out empty statements
        statements = [s.strip() for s in sql.split(";") if s.strip()]

        async with engine.transaction() as tx:
            for stmt in statements:
                if stmt:
                    await tx.execute(stmt)

            # Record migration
            # asyncpg requires native datetime objects for TIMESTAMPTZ columns
            elapsed_ms = int((_time.monotonic() - start) * 1000)
            now = datetime.now(timezone.utc)
            await tx.execute(
                "INSERT INTO schema_migrations (version, description, applied_at, execution_ms) "
                "VALUES ($1, $2, $3, $4)",
                (migration.version, migration.description, now, elapsed_ms),
            )
    else:
        # SQLite: use executescript (implicitly commits)
        await engine.execute_script(sql)

        # Record migration
        elapsed_ms = int((_time.monotonic() - start) * 1000)
        now = datetime.now(timezone.utc).isoformat()
        await engine.execute(
            "INSERT INTO schema_migrations (version, description, applied_at, execution_ms) "
            "VALUES (?, ?, ?, ?)",
            (migration.version, migration.description, now, elapsed_ms),
        )


async def get_migration_status(engine: DatabaseEngine) -> dict:
    """Get migration status for health/admin endpoint.

    Returns:
        dict with current_version, latest_available, pending_count, history
    """
    current = await _get_current_version(engine)
    latest = MIGRATIONS[-1].version if MIGRATIONS else 0
    pending = [m for m in MIGRATIONS if m.version > current]

    history = []
    try:
        rows = await engine.fetch_all(
            "SELECT version, description, applied_at, execution_ms "
            "FROM schema_migrations ORDER BY version DESC"
        )
        history = [row.to_dict() for row in rows]
    except Exception:
        pass

    return {
        "current_version": current,
        "latest_available": latest,
        "pending_count": len(pending),
        "pending_migrations": [
            {"version": m.version, "description": m.description}
            for m in pending
        ],
        "applied_history": history,
        "backend": engine.backend,
    }


async def _async_sleep(seconds: float) -> None:
    """Async sleep wrapper (avoids import at module level)."""
    import asyncio
    await asyncio.sleep(seconds)
