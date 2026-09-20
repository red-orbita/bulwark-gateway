"""Versioned attachment schema, independent of admin and outbox migrations."""

from src.storage.database import DatabaseEngine

SQLITE_V1 = (
    "CREATE TABLE attachment_documents ("
    "id TEXT PRIMARY KEY, tenant TEXT NOT NULL, agent TEXT NOT NULL, owner TEXT NOT NULL, "
    "mime TEXT NOT NULL, policy_revision TEXT NOT NULL, sha256 TEXT NOT NULL, "
    "state TEXT NOT NULL CHECK(state IN "
    "('queued','processing','approved','blocked','review_required','failed')), "
    "raw_base64 TEXT, text_json TEXT, text_sha256 TEXT, reason TEXT NOT NULL DEFAULT '\"\"', "
    "raw_size INTEGER NOT NULL, size_bytes BIGINT NOT NULL CHECK(size_bytes >= 0), "
    "created_at REAL NOT NULL, expires_at REAL NOT NULL, "
    "lease_token TEXT NOT NULL DEFAULT '', lease_until REAL NOT NULL DEFAULT 0, "
    "attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 3))",
    "CREATE INDEX attachment_scope ON attachment_documents (tenant, agent, owner)",
    "CREATE INDEX attachment_expiry ON attachment_documents (expires_at, id)",
    "CREATE INDEX attachment_claim ON attachment_documents (state, lease_until, created_at)",
)
POSTGRESQL_V1 = tuple(sql.replace(" REAL ", " DOUBLE PRECISION ") for sql in SQLITE_V1)


async def migrate_attachments(
    db: DatabaseEngine, max_documents: int, max_bytes: int,
    max_per_tenant: int, ttl_seconds: int,
) -> None:
    async with db.transaction() as tx:
        if db.backend == "postgresql":
            await tx.execute("SET LOCAL lock_timeout = '5s'")
            await tx.execute("SET LOCAL statement_timeout = '10s'")
            await tx.execute("SELECT pg_advisory_xact_lock(?)", (0x42574154,))
            await tx.execute("SET LOCAL synchronous_commit = on")
        await tx.execute(
            "CREATE TABLE IF NOT EXISTS attachment_store_state ("
            "id TEXT PRIMARY KEY, version INTEGER NOT NULL, "
            "documents BIGINT NOT NULL DEFAULT 0 CHECK(documents >= 0), "
            "bytes BIGINT NOT NULL DEFAULT 0 CHECK(bytes >= 0), "
            "max_documents BIGINT NOT NULL, max_bytes BIGINT NOT NULL, "
            "max_per_tenant BIGINT NOT NULL, ttl_seconds BIGINT NOT NULL)"
        )
        limits = (max_documents, max_bytes, max_per_tenant, ttl_seconds)
        await tx.execute(
            "INSERT INTO attachment_store_state "
            "(id, version, max_documents, max_bytes, max_per_tenant, ttl_seconds) "
            "VALUES ('attachments', 0, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING", limits,
        )
        # First write precedes reads, avoiding SQLite deferred-lock upgrades.
        await tx.execute(
            "UPDATE attachment_store_state SET version = version WHERE id = 'attachments'"
        )
        row = await tx.fetch_one("SELECT * FROM attachment_store_state WHERE id = 'attachments'")
        if row is None or row["version"] not in (0, 1):
            raise ValueError("Unsupported attachment schema")
        if tuple(row[k] for k in ("max_documents", "max_bytes", "max_per_tenant", "ttl_seconds")) != limits:
            raise ValueError("Attachment limits must agree across replicas")
        if row["version"] == 0:
            for sql in POSTGRESQL_V1 if db.backend == "postgresql" else SQLITE_V1:
                await tx.execute(sql)
            await tx.execute(
                "UPDATE attachment_store_state SET version = 1 WHERE id = 'attachments'"
            )
