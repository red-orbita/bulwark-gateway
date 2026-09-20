"""Versioned, transactional telemetry schema (independent of admin migrations)."""

from src.storage.database import DatabaseEngine

SQLITE_V1 = (
    "CREATE TABLE telemetry_outbox_events ("
    "id TEXT PRIMARY KEY, tenant TEXT NOT NULL, payload TEXT NOT NULL, "
    "size_bytes INTEGER NOT NULL CHECK(size_bytes > 0), created_at REAL NOT NULL)",
    "CREATE TABLE telemetry_outbox_deliveries ("
    "event_id TEXT NOT NULL REFERENCES telemetry_outbox_events(id) ON DELETE CASCADE, "
    "destination TEXT NOT NULL, snapshot TEXT NOT NULL, "
    "lease_token TEXT NOT NULL DEFAULT '', lease_until REAL NOT NULL DEFAULT 0, "
    "available_at REAL NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0, "
    "PRIMARY KEY(event_id, destination))",
    "CREATE INDEX telemetry_outbox_ready ON telemetry_outbox_deliveries "
    "(destination, available_at, lease_until)",
)
POSTGRESQL_V1 = (
    "CREATE TABLE telemetry_outbox_events ("
    "id TEXT PRIMARY KEY, tenant TEXT NOT NULL, payload TEXT NOT NULL, "
    "size_bytes BIGINT NOT NULL CHECK(size_bytes > 0), created_at DOUBLE PRECISION NOT NULL)",
    "CREATE TABLE telemetry_outbox_deliveries ("
    "event_id TEXT NOT NULL REFERENCES telemetry_outbox_events(id) ON DELETE CASCADE, "
    "destination TEXT NOT NULL, snapshot TEXT NOT NULL, "
    "lease_token TEXT NOT NULL DEFAULT '', lease_until DOUBLE PRECISION NOT NULL DEFAULT 0, "
    "available_at DOUBLE PRECISION NOT NULL DEFAULT 0, attempts BIGINT NOT NULL DEFAULT 0, "
    "PRIMARY KEY(event_id, destination))",
    "CREATE INDEX telemetry_outbox_ready ON telemetry_outbox_deliveries "
    "(destination, available_at, lease_until)",
)


async def migrate_outbox(db: DatabaseEngine, max_events: int, max_bytes: int) -> None:
    async with db.transaction() as tx:
        if db.backend == "postgresql":
            # Transaction-scoped: acquire/release on the SAME pooled connection.
            await tx.execute("SELECT pg_advisory_xact_lock(?)", (0x42574F38,))
            await tx.execute("SET LOCAL synchronous_commit = on")
        await tx.execute(
            "CREATE TABLE IF NOT EXISTS telemetry_outbox_state ("
            "id TEXT PRIMARY KEY, version INTEGER NOT NULL, "
            "events BIGINT NOT NULL DEFAULT 0, bytes BIGINT NOT NULL DEFAULT 0, "
            "max_events BIGINT NOT NULL, max_bytes BIGINT NOT NULL, "
            "accepted BIGINT NOT NULL DEFAULT 0, rejected BIGINT NOT NULL DEFAULT 0, "
            "acked BIGINT NOT NULL DEFAULT 0, failures BIGINT NOT NULL DEFAULT 0, "
            "corrupt BIGINT NOT NULL DEFAULT 0)"
        )
        await tx.execute(
            "INSERT INTO telemetry_outbox_state (id, version, max_events, max_bytes) "
            "VALUES (?, 0, ?, ?) ON CONFLICT(id) DO NOTHING",
            ("outbox", max_events, max_bytes),
        )
        # Also the first write in SQLite, before any reads: no deferred-lock upgrade race.
        await tx.execute("UPDATE telemetry_outbox_state SET version = version WHERE id = ?", ("outbox",))
        row = await tx.fetch_one("SELECT * FROM telemetry_outbox_state WHERE id = ?", ("outbox",))
        if row is None or row["version"] not in (0, 1):
            raise RuntimeError("Unsupported telemetry outbox schema")
        if (row["max_events"], row["max_bytes"]) != (max_events, max_bytes):
            raise ValueError("Outbox capacity must agree across replicas")
        if row["version"] == 0:
            for statement in POSTGRESQL_V1 if db.backend == "postgresql" else SQLITE_V1:
                await tx.execute(statement)
            await tx.execute("UPDATE telemetry_outbox_state SET version = 1 WHERE id = ?", ("outbox",))
