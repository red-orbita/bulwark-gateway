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
from typing import Optional, cast

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

    # Version 4: Hash-chain columns for the tamper-evident audit log.
    #
    # v1 created audit_log with the original 11-column shape. The hash-chain
    # fields (sequence_id / previous_hash / entry_hash) were only ever added by
    # the SQLite AuditLogger's runtime _migrate_chain_columns() against its own
    # separate db file — the PostgreSQL backend has no such self-migration and
    # relies solely on this system, so on PostgreSQL every chained INSERT failed
    # with 'column "sequence_id" of relation "audit_log" does not exist'.
    # This migration brings the shared schema in line with what both loggers
    # write, unbreaking audit persistence on PostgreSQL/HA deployments.
    Migration(
        version=4,
        description="Add hash-chain columns to audit_log (sequence_id, previous_hash, entry_hash)",
        sqlite_sql="""
            -- SQLite has no ADD COLUMN IF NOT EXISTS; this migration is
            -- version-tracked so it runs exactly once against the v1 table.
            ALTER TABLE audit_log ADD COLUMN sequence_id INTEGER;
            ALTER TABLE audit_log ADD COLUMN previous_hash TEXT;
            ALTER TABLE audit_log ADD COLUMN entry_hash TEXT;
            CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_sequence
                ON audit_log(sequence_id) WHERE sequence_id IS NOT NULL;
        """,
        postgresql_sql="""
            -- IF NOT EXISTS makes this self-healing on clusters whose audit_log
            -- was already created (broken) at schema v3 without these columns.
            ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS sequence_id INTEGER;
            ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS previous_hash TEXT;
            ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS entry_hash TEXT;
            CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_sequence
                ON audit_log(sequence_id) WHERE sequence_id IS NOT NULL;
        """,
    ),

    # Version 5: Durable security-events history. The proxy writes a capped LIVE
    # buffer to Redis (bulwark:recent_blocks:* / recent_allowed:*); the admin syncs
    # that buffer into this table so the Security Events viewer has a real,
    # queryable history that survives Redis flushes/restarts and is not bounded by
    # the Redis cap. Retention (age-based) is enforced by the sync task.
    Migration(
        version=5,
        description="Add security_events durable history table",
        sqlite_sql="""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                ts REAL NOT NULL,
                occurred_at TEXT,
                tenant TEXT NOT NULL,
                agent TEXT,
                verdict TEXT NOT NULL,
                category TEXT,
                severity TEXT,
                description TEXT,
                source TEXT,
                pattern TEXT,
                request_id TEXT,
                tool_name TEXT,
                snippet TEXT,
                input_hash TEXT,
                metadata TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_secevents_ts ON security_events(ts DESC);
            CREATE INDEX IF NOT EXISTS idx_secevents_tenant ON security_events(tenant);
            CREATE INDEX IF NOT EXISTS idx_secevents_verdict ON security_events(verdict);
            CREATE INDEX IF NOT EXISTS idx_secevents_category ON security_events(category);
            CREATE INDEX IF NOT EXISTS idx_secevents_severity ON security_events(severity);
            CREATE INDEX IF NOT EXISTS idx_secevents_tenant_ts
                ON security_events(tenant, ts DESC);
        """,
        postgresql_sql="""
            CREATE TABLE IF NOT EXISTS security_events (
                id SERIAL PRIMARY KEY,
                event_id TEXT NOT NULL UNIQUE,
                ts DOUBLE PRECISION NOT NULL,
                occurred_at TIMESTAMPTZ,
                tenant TEXT NOT NULL,
                agent TEXT,
                verdict TEXT NOT NULL,
                category TEXT,
                severity TEXT,
                description TEXT,
                source TEXT,
                pattern TEXT,
                request_id TEXT,
                tool_name TEXT,
                snippet TEXT,
                input_hash TEXT,
                metadata TEXT,
                created_at TIMESTAMPTZ NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_secevents_ts ON security_events(ts DESC);
            CREATE INDEX IF NOT EXISTS idx_secevents_tenant ON security_events(tenant);
            CREATE INDEX IF NOT EXISTS idx_secevents_verdict ON security_events(verdict);
            CREATE INDEX IF NOT EXISTS idx_secevents_category ON security_events(category);
            CREATE INDEX IF NOT EXISTS idx_secevents_severity ON security_events(severity);
            CREATE INDEX IF NOT EXISTS idx_secevents_tenant_ts
                ON security_events(tenant, ts DESC);
        """,
    ),

    # Version 6: Investigation Center. Two additions on top of the durable event
    # history (v5) so an analyst can pivot a correlated alert to its full chain
    # and drive a triage workflow — all reconstructed from durable rows, with no
    # new hot-path Redis structures:
    #   1. Two indexed pivot columns on security_events, populated by the sync
    #      task from correlation metadata: `incident_id` (join a confirmed
    #      exfiltration incident to its contributing detections) and
    #      `scope_digests` (space-joined "scope_type:digest" tokens — the same
    #      digests the admin /correlation/origins view shows — so an origin's
    #      decayed risk score can be traced back to the events that drove it).
    #   2. `investigation_triage`: per-subject (incident|origin) analyst workflow
    #      state (status/assignee/notes) keyed by a stable subject identifier.
    Migration(
        version=6,
        description="Investigation Center: event pivot columns + triage workflow table",
        sqlite_sql="""
            ALTER TABLE security_events ADD COLUMN incident_id TEXT;
            ALTER TABLE security_events ADD COLUMN scope_digests TEXT;
            CREATE INDEX IF NOT EXISTS idx_secevents_incident
                ON security_events(incident_id);

            CREATE TABLE IF NOT EXISTS investigation_triage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject_type TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                tenant TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                assignee TEXT,
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(subject_type, subject_key)
            );
            CREATE INDEX IF NOT EXISTS idx_triage_status ON investigation_triage(status);
            CREATE INDEX IF NOT EXISTS idx_triage_tenant ON investigation_triage(tenant);
            CREATE INDEX IF NOT EXISTS idx_triage_updated
                ON investigation_triage(updated_at DESC);
        """,
        postgresql_sql="""
            ALTER TABLE security_events ADD COLUMN IF NOT EXISTS incident_id TEXT;
            ALTER TABLE security_events ADD COLUMN IF NOT EXISTS scope_digests TEXT;
            CREATE INDEX IF NOT EXISTS idx_secevents_incident
                ON security_events(incident_id);

            CREATE TABLE IF NOT EXISTS investigation_triage (
                id SERIAL PRIMARY KEY,
                subject_type TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                tenant TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                assignee TEXT,
                notes TEXT,
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL,
                UNIQUE(subject_type, subject_key)
            );
            CREATE INDEX IF NOT EXISTS idx_triage_status ON investigation_triage(status);
            CREATE INDEX IF NOT EXISTS idx_triage_tenant ON investigation_triage(tenant);
            CREATE INDEX IF NOT EXISTS idx_triage_updated
                ON investigation_triage(updated_at DESC);
        """,
    ),

    # Version 7: Investigation Cases. A case groups several triage subjects
    # (incidents/origins/sessions) under one analyst-owned investigation with its
    # own status/severity/assignee and an append-only, actor-stamped note trail —
    # the same self-auditing pattern as investigation_triage (v6). Two tables:
    #   1. `investigation_case`: the case record, keyed by an app-generated opaque
    #      `case_id` (dialect-neutral — no reliance on backend lastrowid/RETURNING).
    #   2. `investigation_case_subject`: the N:M link between a case and the
    #      subjects it collects, UNIQUE per (case, subject) so a subject is linked
    #      at most once, and indexed both ways (by case, and by subject so a
    #      drill-down can show which case a subject belongs to).
    Migration(
        version=7,
        description="Investigation Cases: case record + case↔subject link table",
        sqlite_sql="""
            CREATE TABLE IF NOT EXISTS investigation_case (
                case_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                severity TEXT NOT NULL DEFAULT 'medium',
                tenant TEXT,
                assignee TEXT,
                summary TEXT,
                notes TEXT,
                created_by TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_case_status ON investigation_case(status);
            CREATE INDEX IF NOT EXISTS idx_case_tenant ON investigation_case(tenant);
            CREATE INDEX IF NOT EXISTS idx_case_updated
                ON investigation_case(updated_at DESC);

            CREATE TABLE IF NOT EXISTS investigation_case_subject (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                subject_type TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                added_by TEXT,
                added_at TEXT NOT NULL,
                UNIQUE(case_id, subject_type, subject_key)
            );
            CREATE INDEX IF NOT EXISTS idx_case_subject_case
                ON investigation_case_subject(case_id);
            CREATE INDEX IF NOT EXISTS idx_case_subject_subject
                ON investigation_case_subject(subject_type, subject_key);
        """,
        postgresql_sql="""
            CREATE TABLE IF NOT EXISTS investigation_case (
                case_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                severity TEXT NOT NULL DEFAULT 'medium',
                tenant TEXT,
                assignee TEXT,
                summary TEXT,
                notes TEXT,
                created_by TEXT,
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_case_status ON investigation_case(status);
            CREATE INDEX IF NOT EXISTS idx_case_tenant ON investigation_case(tenant);
            CREATE INDEX IF NOT EXISTS idx_case_updated
                ON investigation_case(updated_at DESC);

            CREATE TABLE IF NOT EXISTS investigation_case_subject (
                id SERIAL PRIMARY KEY,
                case_id TEXT NOT NULL,
                subject_type TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                added_by TEXT,
                added_at TIMESTAMPTZ NOT NULL,
                UNIQUE(case_id, subject_type, subject_key)
            );
            CREATE INDEX IF NOT EXISTS idx_case_subject_case
                ON investigation_case_subject(case_id);
            CREATE INDEX IF NOT EXISTS idx_case_subject_subject
                ON investigation_case_subject(subject_type, subject_key);
        """,
    ),

    # Version 8: Investigation Center — Phase 0. Promotes observables and tasks to
    # first-class, case-scoped records and adds a free-form tag list to cases.
    #   1. `investigation_observable`: an atomic indicator collected under a case
    #      (ip/domain/url/hash/email/filename/user/other), with a normalized value,
    #      an `is_ioc` flag (INTEGER 0/1 — kept as INTEGER in BOTH backends to avoid
    #      BOOLEAN coercion across dialects), TLP/PAP handling markers, a JSON tag
    #      list, a provenance `source`, and a JSON `enrichment` blob reserved for
    #      Phase 2. UNIQUE(case_id, type, value) dedupes an indicator per case.
    #   2. `investigation_task`: an analyst checklist item under a case with a
    #      status lifecycle (todo/in_progress/done/cancelled), an optional assignee,
    #      an `order_index` (INTEGER, max+1 on insert) for manual ordering, an
    #      optional due timestamp, and an append-only JSON note trail.
    #   3. `investigation_case.tags`: a JSON tag list on the case record itself
    #      (TTP/label badges), added non-destructively with a NULL default.
    Migration(
        version=8,
        description="Investigation Center Phase 0: observables + tasks tables + case tags",
        sqlite_sql="""
            CREATE TABLE IF NOT EXISTS investigation_observable (
                observable_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                is_ioc INTEGER NOT NULL DEFAULT 0,
                tlp TEXT NOT NULL DEFAULT 'amber',
                pap TEXT NOT NULL DEFAULT 'amber',
                tags TEXT,
                source TEXT NOT NULL DEFAULT 'manual',
                enrichment TEXT,
                added_by TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                UNIQUE(case_id, type, value)
            );
            CREATE INDEX IF NOT EXISTS idx_observable_case
                ON investigation_observable(case_id);
            CREATE INDEX IF NOT EXISTS idx_observable_type
                ON investigation_observable(type, value);

            CREATE TABLE IF NOT EXISTS investigation_task (
                task_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'todo',
                assignee TEXT,
                order_index INTEGER NOT NULL DEFAULT 0,
                due_at TEXT,
                notes TEXT,
                created_by TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_task_case
                ON investigation_task(case_id);
            CREATE INDEX IF NOT EXISTS idx_task_status
                ON investigation_task(status);

            ALTER TABLE investigation_case ADD COLUMN tags TEXT;
        """,
        postgresql_sql="""
            CREATE TABLE IF NOT EXISTS investigation_observable (
                observable_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                is_ioc INTEGER NOT NULL DEFAULT 0,
                tlp TEXT NOT NULL DEFAULT 'amber',
                pap TEXT NOT NULL DEFAULT 'amber',
                tags TEXT,
                source TEXT NOT NULL DEFAULT 'manual',
                enrichment TEXT,
                added_by TEXT,
                first_seen TIMESTAMPTZ NOT NULL,
                last_seen TIMESTAMPTZ NOT NULL,
                UNIQUE(case_id, type, value)
            );
            CREATE INDEX IF NOT EXISTS idx_observable_case
                ON investigation_observable(case_id);
            CREATE INDEX IF NOT EXISTS idx_observable_type
                ON investigation_observable(type, value);

            CREATE TABLE IF NOT EXISTS investigation_task (
                task_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'todo',
                assignee TEXT,
                order_index INTEGER NOT NULL DEFAULT 0,
                due_at TIMESTAMPTZ,
                notes TEXT,
                created_by TEXT,
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_task_case
                ON investigation_task(case_id);
            CREATE INDEX IF NOT EXISTS idx_task_status
                ON investigation_task(status);

            ALTER TABLE investigation_case ADD COLUMN IF NOT EXISTS tags TEXT;
        """,
    ),
    # Version 9: Integrations subsystem (Phase 1) — remote-object link table.
    #
    # ``integration_link`` is the idempotency map that lets an outbound connector
    # (TheHive / DFIR-IRIS / …) know whether a local object has already been pushed
    # to a remote platform, so a re-push *updates* the remote record instead of
    # creating a duplicate. Keyed by the composite (connector, local_type, local_id)
    # — e.g. ("thehive", "case", "case_ab12…") — mapping to the ``remote_id`` the
    # platform assigned, plus provenance (``last_synced_at``) and an optional
    # ``etag`` for conditional updates. The composite PRIMARY KEY doubles as the
    # uniqueness guarantee (identical syntax on both backends; no surrogate id, so
    # no AUTOINCREMENT/SERIAL divergence). Only ``last_synced_at`` differs by
    # dialect (TEXT ISO string on SQLite, TIMESTAMPTZ on PostgreSQL).
    Migration(
        version=9,
        description="Integrations Phase 1: integration_link table (connector↔local↔remote id map)",
        sqlite_sql="""
            CREATE TABLE IF NOT EXISTS integration_link (
                connector TEXT NOT NULL,
                local_type TEXT NOT NULL,
                local_id TEXT NOT NULL,
                remote_id TEXT,
                remote_url TEXT,
                last_synced_at TEXT,
                etag TEXT,
                PRIMARY KEY (connector, local_type, local_id)
            );
            CREATE INDEX IF NOT EXISTS idx_integration_link_remote
                ON integration_link(connector, remote_id);
            CREATE INDEX IF NOT EXISTS idx_integration_link_local
                ON integration_link(local_type, local_id);
        """,
        postgresql_sql="""
            CREATE TABLE IF NOT EXISTS integration_link (
                connector TEXT NOT NULL,
                local_type TEXT NOT NULL,
                local_id TEXT NOT NULL,
                remote_id TEXT,
                remote_url TEXT,
                last_synced_at TIMESTAMPTZ,
                etag TEXT,
                PRIMARY KEY (connector, local_type, local_id)
            );
            CREATE INDEX IF NOT EXISTS idx_integration_link_remote
                ON integration_link(connector, remote_id);
            CREATE INDEX IF NOT EXISTS idx_integration_link_local
                ON integration_link(local_type, local_id);
        """,
    ),
    # Version 10: Automation service accounts (Phase 3.2a). A service account is a
    # scoped, non-interactive credential a SOAR/playbook (Shuffle, n8n, …) presents
    # to call back into the admin automation surface — distinct from an operator's
    # session cookie. It carries an explicit, least-privilege permission set (a
    # whitelisted subset of the RBAC namespaces + the dedicated ``automation:*``
    # verbs), never a role, so a leaked playbook key can do exactly what it was
    # minted for and nothing more.
    #
    # Only the SHA-256 of the raw key is stored (``key_hash`` — the same one-way
    # scheme used for session tokens; the raw ``bwk_sa_…`` key is shown exactly once
    # at mint and is unrecoverable thereafter). ``key_prefix`` keeps a short,
    # non-secret display fragment so the UI can identify a key without ever holding
    # the secret. ``permissions`` is a JSON array; ``enabled`` is an INTEGER 0/1 flag
    # (kept INTEGER on BOTH backends to avoid BOOLEAN coercion divergence, matching
    # the observable ``is_ioc`` precedent); ``expires_at`` is an optional hard expiry.
    # Indexed by ``key_hash`` (the auth hot-path lookup) and ``enabled``.
    Migration(
        version=10,
        description="Automation Phase 3.2a: service_account table (scoped API-key credential)",
        sqlite_sql="""
            CREATE TABLE IF NOT EXISTS service_account (
                account_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                key_prefix TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                permissions TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_by TEXT,
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                expires_at TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_service_account_key_hash
                ON service_account(key_hash);
            CREATE INDEX IF NOT EXISTS idx_service_account_enabled
                ON service_account(enabled);
        """,
        postgresql_sql="""
            CREATE TABLE IF NOT EXISTS service_account (
                account_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                key_prefix TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                permissions TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_by TEXT,
                created_at TIMESTAMPTZ NOT NULL,
                last_used_at TIMESTAMPTZ,
                expires_at TIMESTAMPTZ
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_service_account_key_hash
                ON service_account(key_hash);
            CREATE INDEX IF NOT EXISTS idx_service_account_enabled
                ON service_account(enabled);
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
        engine = cast(PostgreSQLEngine, engine)  # narrowing: branch guarantees PostgreSQL
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
            engine = cast(PostgreSQLEngine, engine)  # narrowing: branch guarantees PostgreSQL
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
        engine = cast(PostgreSQLEngine, engine)  # narrowing: branch guarantees PostgreSQL

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
        now_iso = datetime.now(timezone.utc).isoformat()
        await engine.execute(
            "INSERT INTO schema_migrations (version, description, applied_at, execution_ms) "
            "VALUES (?, ?, ?, ?)",
            (migration.version, migration.description, now_iso, elapsed_ms),
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
    except Exception:  # noqa: S110 - migration history is advisory; return empty on read failure
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
