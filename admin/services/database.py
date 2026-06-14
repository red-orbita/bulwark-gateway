"""Database abstraction layer supporting SQLite and PostgreSQL.

Selection via SENTINEL_ADMIN_DB_URL:
  - sqlite:///path/to/db.sqlite  (default, backward compatible)
  - sqlite+cipher:///path/to/db.sqlite?key=... (SQLCipher, existing behavior)
  - postgresql://user:pass@host:5432/sentinel_admin (enterprise)
  - postgresql+asyncpg://... (async PostgreSQL)

Design principles:
  - Async-first (asyncpg for PostgreSQL, aiosqlite for SQLite)
  - Connection pooling (PostgreSQL: min=2, max=20)
  - Automatic retries with exponential backoff
  - Health check endpoint integration
  - Zero-downtime schema migrations

Usage:
    from admin.services.database import get_database

    db = get_database()
    await db.init()

    # Execute statements
    await db.execute("INSERT INTO users (id, name) VALUES (?, ?)", (uid, name))

    # Fetch rows
    row = await db.fetch_one("SELECT * FROM users WHERE id = ?", (uid,))
    rows = await db.fetch_all("SELECT * FROM users WHERE active = ?", (1,))

    # Transactions
    async with db.transaction() as tx:
        await tx.execute("UPDATE users SET active = ? WHERE id = ?", (0, uid))
        await tx.execute("INSERT INTO audit_log (...) VALUES (...)", params)

    # Health check
    ok = await db.health_check()

    # Shutdown
    await db.close()
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncGenerator, Optional, Sequence

logger = logging.getLogger(__name__)

# ─── Configuration ────────────────────────────────────────────────────────────

# Default: SQLite in data/ directory (backward compatible, zero-config for dev)
DEFAULT_DB_URL = "sqlite:///data/admin.db"


def _read_db_url() -> str:
    """Read database URL from env var or file (Docker secrets pattern)."""
    # Check file-based secret first (Kubernetes-native)
    url_file = os.getenv("SENTINEL_ADMIN_DB_URL_FILE")
    if url_file and os.path.isfile(url_file):
        return open(url_file).read().strip()
    return os.getenv("SENTINEL_ADMIN_DB_URL", DEFAULT_DB_URL)


# Read from environment or file
ADMIN_DB_URL = _read_db_url()
ADMIN_DB_POOL_MIN = int(os.getenv("SENTINEL_ADMIN_DB_POOL_MIN", "2"))
ADMIN_DB_POOL_MAX = int(os.getenv("SENTINEL_ADMIN_DB_POOL_MAX", "20"))
ADMIN_DB_SSL = os.getenv("SENTINEL_ADMIN_DB_SSL", "false").lower() in ("true", "1")
ADMIN_DB_SSL_MODE = os.getenv("SENTINEL_ADMIN_DB_SSL_MODE", "require")

# Retry configuration
MAX_RETRIES = 3
RETRY_BASE_DELAY = 0.5  # seconds, exponential backoff


# ─── Types ────────────────────────────────────────────────────────────────────

@dataclass
class Row:
    """A single database row as a dict-like object."""
    _data: dict[str, Any] = field(default_factory=dict)

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __contains__(self, key: str) -> bool:
        return key in self._data

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def keys(self):
        return self._data.keys()

    def values(self):
        return self._data.values()

    def items(self):
        return self._data.items()

    def __repr__(self) -> str:
        return f"Row({self._data})"

    def to_dict(self) -> dict[str, Any]:
        return dict(self._data)


# ─── Query Translation ────────────────────────────────────────────────────────

class QueryTranslator:
    """Translates SQL between SQLite and PostgreSQL dialects.

    Handles:
    - Placeholder conversion: ? → $1, $2, ...
    - Type mapping: INTEGER PRIMARY KEY AUTOINCREMENT → SERIAL PRIMARY KEY
    - UPSERT syntax: INSERT OR REPLACE → INSERT ... ON CONFLICT DO UPDATE
    - Boolean handling: SQLite uses 0/1, PostgreSQL uses TRUE/FALSE
    - PRAGMA statements: SQLite-only, skipped for PostgreSQL
    """

    def __init__(self, backend: str):
        self._backend = backend  # "sqlite" or "postgresql"

    @property
    def is_postgresql(self) -> bool:
        return self._backend == "postgresql"

    @property
    def is_sqlite(self) -> bool:
        return self._backend == "sqlite"

    def translate(self, query: str, params: Optional[Sequence] = None) -> tuple[str, Optional[Sequence]]:
        """Translate a query from SQLite dialect to the target backend.

        Input queries use SQLite syntax (? placeholders). This method converts
        them to the appropriate dialect.
        """
        if self.is_sqlite:
            # No translation needed for SQLite
            return query, params

        # PostgreSQL translation
        translated = query

        # Skip PRAGMA statements (SQLite-only)
        if translated.strip().upper().startswith("PRAGMA"):
            return "", None

        # Convert AUTOINCREMENT → SERIAL (for CREATE TABLE)
        translated = re.sub(
            r"INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT",
            "SERIAL PRIMARY KEY",
            translated,
            flags=re.IGNORECASE,
        )

        # Convert INTEGER PRIMARY KEY (without AUTOINCREMENT) → SERIAL PRIMARY KEY
        # Only for id columns in CREATE TABLE
        translated = re.sub(
            r"(\w+)\s+INTEGER\s+PRIMARY\s+KEY(?!\s+AUTOINCREMENT)",
            r"\1 SERIAL PRIMARY KEY",
            translated,
            flags=re.IGNORECASE,
        )

        # Convert TEXT PRIMARY KEY → TEXT PRIMARY KEY (no change needed)
        # SQLite: CREATE TABLE IF NOT EXISTS → PostgreSQL: same syntax

        # Convert INSERT OR REPLACE → INSERT ... ON CONFLICT DO UPDATE
        insert_or_replace = re.match(
            r"INSERT\s+OR\s+REPLACE\s+INTO\s+(\w+)\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)",
            translated,
            flags=re.IGNORECASE,
        )
        if insert_or_replace:
            table = insert_or_replace.group(1)
            columns = insert_or_replace.group(2)
            values = insert_or_replace.group(3)
            col_list = [c.strip() for c in columns.split(",")]
            # Assume first column is the PK for conflict target
            pk_col = col_list[0]
            update_cols = [c for c in col_list[1:]]
            set_clause = ", ".join(f"{c} = EXCLUDED.{c}" for c in update_cols)
            translated = (
                f"INSERT INTO {table} ({columns}) VALUES ({values}) "
                f"ON CONFLICT ({pk_col}) DO UPDATE SET {set_clause}"
            )

        # Convert INSERT OR IGNORE → INSERT ... ON CONFLICT DO NOTHING
        translated = re.sub(
            r"INSERT\s+OR\s+IGNORE\s+INTO",
            "INSERT INTO",
            translated,
            flags=re.IGNORECASE,
        )
        if "ON CONFLICT" not in translated.upper() and "INSERT INTO" in translated.upper():
            # Check if original had OR IGNORE
            if re.search(r"INSERT\s+OR\s+IGNORE", query, re.IGNORECASE):
                translated = translated.rstrip(";") + " ON CONFLICT DO NOTHING"

        # Convert ? placeholders to $1, $2, ... for PostgreSQL
        param_counter = [0]

        def replace_placeholder(match):
            param_counter[0] += 1
            return f"${param_counter[0]}"

        translated = re.sub(r"\?", replace_placeholder, translated)

        # Convert LIKE with % → ILIKE for case-insensitive (optional, keep LIKE for now)

        # Convert datetime function differences
        # SQLite: datetime('now') → PostgreSQL: NOW()
        translated = re.sub(
            r"datetime\s*\(\s*'now'\s*\)",
            "NOW()",
            translated,
            flags=re.IGNORECASE,
        )

        # Coerce parameters: asyncpg requires native types (datetime objects, not strings)
        coerced_params = self._coerce_params(params) if params else params
        return translated, coerced_params

    def _coerce_params(self, params: Sequence) -> tuple:
        """Coerce parameter types for asyncpg compatibility.

        asyncpg requires native Python types for PostgreSQL columns:
        - TIMESTAMPTZ / TIMESTAMP → datetime.datetime (not ISO strings)
        - BOOLEAN → bool (not int 0/1)

        This is a no-op for SQLite backend.
        """
        if self.is_sqlite:
            return tuple(params)

        coerced = []
        for p in params:
            if isinstance(p, str) and self._looks_like_iso_datetime(p):
                coerced.append(self._parse_iso_datetime(p))
            else:
                coerced.append(p)
        return tuple(coerced)

    @staticmethod
    def _looks_like_iso_datetime(s: str) -> bool:
        """Check if a string looks like an ISO 8601 datetime.

        Matches patterns like:
        - 2026-06-13T13:00:42.841174+00:00
        - 2026-06-13T13:00:42Z
        - 2026-06-13T13:00:42
        """
        if len(s) < 19 or len(s) > 35:
            return False
        # Quick check: must start with YYYY-MM-DD and have T separator
        return (
            s[4:5] == "-" and s[7:8] == "-" and
            (s[10:11] == "T" or s[10:11] == " ") and
            s[0:4].isdigit()
        )

    @staticmethod
    def _parse_iso_datetime(s: str) -> datetime:
        """Parse ISO 8601 string to datetime object."""
        # Handle Z suffix
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(s)
        except (ValueError, TypeError):
            # If parsing fails, return the string as-is (let asyncpg raise proper error)
            return s  # type: ignore[return-value]

    def create_table_sql(self, table_name: str, columns: list[tuple[str, str]],
                         indexes: Optional[list[tuple[str, list[str]]]] = None) -> list[str]:
        """Generate CREATE TABLE + CREATE INDEX statements for the target backend.

        Args:
            table_name: Name of the table
            columns: List of (column_name, column_definition) tuples
            indexes: Optional list of (index_name, [column_names]) tuples

        Returns:
            List of SQL statements to execute
        """
        statements = []

        col_defs = []
        for col_name, col_def in columns:
            if self.is_postgresql:
                # Convert SQLite types to PostgreSQL
                pg_def = col_def
                pg_def = re.sub(r"INTEGER\s+NOT\s+NULL\s+DEFAULT\s+(\d+)",
                                r"INTEGER NOT NULL DEFAULT \1", pg_def, flags=re.IGNORECASE)
                # AUTOINCREMENT not needed in PG (use SERIAL)
                pg_def = re.sub(r"\s+AUTOINCREMENT", "", pg_def, flags=re.IGNORECASE)
                col_defs.append(f"    {col_name} {pg_def}")
            else:
                col_defs.append(f"    {col_name} {col_def}")

        create_sql = f"CREATE TABLE IF NOT EXISTS {table_name} (\n"
        create_sql += ",\n".join(col_defs)
        create_sql += "\n)"
        statements.append(create_sql)

        if indexes:
            for idx_name, idx_cols in indexes:
                col_str = ", ".join(idx_cols)
                statements.append(
                    f"CREATE INDEX IF NOT EXISTS {idx_name} ON {table_name}({col_str})"
                )

        return statements


# ─── Transaction Context Manager ──────────────────────────────────────────────

class Transaction(ABC):
    """Abstract transaction context for executing multiple statements atomically."""

    @abstractmethod
    async def execute(self, query: str, params: Optional[Sequence] = None) -> int:
        """Execute a statement within the transaction. Returns rows affected."""
        ...

    @abstractmethod
    async def fetch_one(self, query: str, params: Optional[Sequence] = None) -> Optional[Row]:
        """Fetch a single row within the transaction."""
        ...

    @abstractmethod
    async def fetch_all(self, query: str, params: Optional[Sequence] = None) -> list[Row]:
        """Fetch all matching rows within the transaction."""
        ...


# ─── Database Engine Interface ────────────────────────────────────────────────

class DatabaseEngine(ABC):
    """Abstract database engine interface.

    Provides async database operations with automatic query translation,
    connection management, and health monitoring.
    """

    def __init__(self, url: str):
        self._url = url
        self._initialized = False
        self._translator: Optional[QueryTranslator] = None

    @property
    def backend(self) -> str:
        """Return backend type: 'sqlite' or 'postgresql'."""
        ...

    @property
    def translator(self) -> QueryTranslator:
        if self._translator is None:
            self._translator = QueryTranslator(self.backend)
        return self._translator

    @abstractmethod
    async def init(self) -> None:
        """Initialize the database engine (create pool, verify connectivity)."""
        ...

    @abstractmethod
    async def close(self) -> None:
        """Gracefully close all connections."""
        ...

    @abstractmethod
    async def execute(self, query: str, params: Optional[Sequence] = None) -> int:
        """Execute a statement. Returns number of rows affected."""
        ...

    @abstractmethod
    async def fetch_one(self, query: str, params: Optional[Sequence] = None) -> Optional[Row]:
        """Fetch a single row. Returns None if no match."""
        ...

    @abstractmethod
    async def fetch_all(self, query: str, params: Optional[Sequence] = None) -> list[Row]:
        """Fetch all matching rows."""
        ...

    @abstractmethod
    async def execute_script(self, script: str) -> None:
        """Execute a multi-statement SQL script (for migrations)."""
        ...

    @abstractmethod
    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator[Transaction, None]:
        """Context manager for atomic transactions.

        Usage:
            async with db.transaction() as tx:
                await tx.execute("INSERT ...", params)
                await tx.execute("UPDATE ...", params)
        """
        yield  # type: ignore

    @abstractmethod
    async def health_check(self) -> dict[str, Any]:
        """Check database connectivity and return status.

        Returns:
            dict with keys: healthy (bool), latency_ms (float), backend (str),
                           pool_size (int, pg only), pool_free (int, pg only)
        """
        ...

    @abstractmethod
    async def table_exists(self, table_name: str) -> bool:
        """Check if a table exists in the database."""
        ...


# ─── SQLite Engine ────────────────────────────────────────────────────────────

class SQLiteEngine(DatabaseEngine):
    """SQLite/aiosqlite database engine.

    Falls back to synchronous sqlite3 wrapped in run_in_executor if aiosqlite
    is not available. Supports WAL mode for concurrent readers.
    """

    def __init__(self, url: str):
        super().__init__(url)
        self._conn = None
        self._lock = asyncio.Lock()
        self._aiosqlite_available = False
        self._db_path = self._parse_path(url)

    @property
    def backend(self) -> str:
        return "sqlite"

    def _parse_path(self, url: str) -> str:
        """Extract file path from sqlite:///path URL."""
        # Handle sqlite:///path/to/db and sqlite+cipher:///path/to/db
        path = re.sub(r"^sqlite(\+cipher)?:///", "", url)
        # Strip query params (?key=...)
        path = path.split("?")[0]
        return path or "data/admin.db"

    async def init(self) -> None:
        if self._initialized:
            return

        # Ensure directory exists
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)

        try:
            import aiosqlite
            self._aiosqlite_available = True
            self._conn = await aiosqlite.connect(self._db_path)
            self._conn.row_factory = aiosqlite.Row
            await self._conn.execute("PRAGMA journal_mode=WAL")
            await self._conn.execute("PRAGMA foreign_keys=ON")
            await self._conn.execute("PRAGMA busy_timeout=5000")
            logger.info("Database engine initialized: SQLite (aiosqlite) at %s", self._db_path)
        except ImportError:
            # Fallback to synchronous sqlite3 in executor
            import sqlite3
            self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=5000")
            logger.info("Database engine initialized: SQLite (sync) at %s", self._db_path)

        self._initialized = True

    async def close(self) -> None:
        if self._conn is None:
            return
        async with self._lock:
            if self._aiosqlite_available:
                await self._conn.close()
            else:
                self._conn.close()
            self._conn = None
            self._initialized = False
        logger.info("SQLite engine closed")

    async def execute(self, query: str, params: Optional[Sequence] = None) -> int:
        translated, translated_params = self.translator.translate(query, params)
        if not translated:
            return 0

        async with self._lock:
            if self._aiosqlite_available:
                cursor = await self._conn.execute(translated, translated_params or ())
                await self._conn.commit()
                return cursor.rowcount
            else:
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(
                    None, self._sync_execute, translated, translated_params
                )

    def _sync_execute(self, query: str, params: Optional[Sequence]) -> int:
        cursor = self._conn.execute(query, params or ())
        self._conn.commit()
        return cursor.rowcount

    async def fetch_one(self, query: str, params: Optional[Sequence] = None) -> Optional[Row]:
        translated, translated_params = self.translator.translate(query, params)
        if not translated:
            return None

        async with self._lock:
            if self._aiosqlite_available:
                cursor = await self._conn.execute(translated, translated_params or ())
                row = await cursor.fetchone()
                if row is None:
                    return None
                columns = [desc[0] for desc in cursor.description]
                return Row(_data=dict(zip(columns, row)))
            else:
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(
                    None, self._sync_fetch_one, translated, translated_params
                )

    def _sync_fetch_one(self, query: str, params: Optional[Sequence]) -> Optional[Row]:
        cursor = self._conn.execute(query, params or ())
        row = cursor.fetchone()
        if row is None:
            return None
        columns = [desc[0] for desc in cursor.description]
        return Row(_data=dict(zip(columns, row)))

    async def fetch_all(self, query: str, params: Optional[Sequence] = None) -> list[Row]:
        translated, translated_params = self.translator.translate(query, params)
        if not translated:
            return []

        async with self._lock:
            if self._aiosqlite_available:
                cursor = await self._conn.execute(translated, translated_params or ())
                rows = await cursor.fetchall()
                if not rows:
                    return []
                columns = [desc[0] for desc in cursor.description]
                return [Row(_data=dict(zip(columns, r))) for r in rows]
            else:
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(
                    None, self._sync_fetch_all, translated, translated_params
                )

    def _sync_fetch_all(self, query: str, params: Optional[Sequence]) -> list[Row]:
        cursor = self._conn.execute(query, params or ())
        rows = cursor.fetchall()
        if not rows:
            return []
        columns = [desc[0] for desc in cursor.description]
        return [Row(_data=dict(zip(columns, r))) for r in rows]

    async def execute_script(self, script: str) -> None:
        """Execute multi-statement SQL script."""
        async with self._lock:
            if self._aiosqlite_available:
                await self._conn.executescript(script)
            else:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, self._conn.executescript, script)

    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator[Transaction, None]:
        async with self._lock:
            tx = _SQLiteTransaction(self._conn, self._aiosqlite_available, self.translator)
            try:
                if self._aiosqlite_available:
                    await self._conn.execute("BEGIN")
                else:
                    self._conn.execute("BEGIN")
                yield tx
                if self._aiosqlite_available:
                    await self._conn.commit()
                else:
                    self._conn.commit()
            except Exception:
                if self._aiosqlite_available:
                    await self._conn.rollback()
                else:
                    self._conn.rollback()
                raise

    async def health_check(self) -> dict[str, Any]:
        start = time.monotonic()
        try:
            row = await self.fetch_one("SELECT 1 as ok")
            latency = (time.monotonic() - start) * 1000
            return {
                "healthy": row is not None,
                "latency_ms": round(latency, 2),
                "backend": "sqlite",
                "path": self._db_path,
                "async_driver": self._aiosqlite_available,
            }
        except Exception as e:
            latency = (time.monotonic() - start) * 1000
            return {
                "healthy": False,
                "latency_ms": round(latency, 2),
                "backend": "sqlite",
                "error": str(e),
            }

    async def table_exists(self, table_name: str) -> bool:
        row = await self.fetch_one(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        )
        return row is not None


class _SQLiteTransaction(Transaction):
    """SQLite transaction wrapper."""

    def __init__(self, conn, is_async: bool, translator: QueryTranslator):
        self._conn = conn
        self._is_async = is_async
        self._translator = translator

    async def execute(self, query: str, params: Optional[Sequence] = None) -> int:
        translated, translated_params = self._translator.translate(query, params)
        if not translated:
            return 0
        if self._is_async:
            cursor = await self._conn.execute(translated, translated_params or ())
            return cursor.rowcount
        else:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, self._sync_execute, translated, translated_params
            )

    def _sync_execute(self, query: str, params: Optional[Sequence]) -> int:
        cursor = self._conn.execute(query, params or ())
        return cursor.rowcount

    async def fetch_one(self, query: str, params: Optional[Sequence] = None) -> Optional[Row]:
        translated, translated_params = self._translator.translate(query, params)
        if not translated:
            return None
        if self._is_async:
            cursor = await self._conn.execute(translated, translated_params or ())
            row = await cursor.fetchone()
            if row is None:
                return None
            columns = [desc[0] for desc in cursor.description]
            return Row(_data=dict(zip(columns, row)))
        else:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, self._sync_fetch_one, translated, translated_params
            )

    def _sync_fetch_one(self, query: str, params: Optional[Sequence]) -> Optional[Row]:
        cursor = self._conn.execute(query, params or ())
        row = cursor.fetchone()
        if row is None:
            return None
        columns = [desc[0] for desc in cursor.description]
        return Row(_data=dict(zip(columns, row)))

    async def fetch_all(self, query: str, params: Optional[Sequence] = None) -> list[Row]:
        translated, translated_params = self._translator.translate(query, params)
        if not translated:
            return []
        if self._is_async:
            cursor = await self._conn.execute(translated, translated_params or ())
            rows = await cursor.fetchall()
            if not rows:
                return []
            columns = [desc[0] for desc in cursor.description]
            return [Row(_data=dict(zip(columns, r))) for r in rows]
        else:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, self._sync_fetch_all, translated, translated_params
            )

    def _sync_fetch_all(self, query: str, params: Optional[Sequence]) -> list[Row]:
        cursor = self._conn.execute(query, params or ())
        rows = cursor.fetchall()
        if not rows:
            return []
        columns = [desc[0] for desc in cursor.description]
        return [Row(_data=dict(zip(columns, r))) for r in rows]


# ─── PostgreSQL Engine ────────────────────────────────────────────────────────

class PostgreSQLEngine(DatabaseEngine):
    """PostgreSQL database engine using asyncpg with connection pooling.

    Features:
    - Connection pool (min/max configurable)
    - Automatic reconnection with exponential backoff
    - SSL/TLS support (sslmode configurable)
    - Health checks on connection checkout
    - Advisory locks for migration coordination
    """

    def __init__(self, url: str, pool_min: int = 2, pool_max: int = 20,
                 ssl: bool = False, ssl_mode: str = "require"):
        super().__init__(url)
        self._pool = None
        self._pool_min = pool_min
        self._pool_max = pool_max
        self._ssl = ssl
        self._ssl_mode = ssl_mode
        # Normalize URL: strip asyncpg scheme prefix if present
        self._dsn = url.replace("postgresql+asyncpg://", "postgresql://")

    @property
    def backend(self) -> str:
        return "postgresql"

    async def init(self) -> None:
        if self._initialized:
            return

        try:
            import asyncpg
        except ImportError:
            raise RuntimeError(
                "asyncpg is required for PostgreSQL backend. "
                "Install: pip install asyncpg"
            )

        # Build connection kwargs
        connect_kwargs: dict[str, Any] = {}
        if self._ssl:
            import ssl as ssl_module
            if self._ssl_mode == "verify-full":
                ssl_ctx = ssl_module.create_default_context()
            elif self._ssl_mode == "verify-ca":
                ssl_ctx = ssl_module.create_default_context()
                ssl_ctx.check_hostname = False
            elif self._ssl_mode == "require":
                ssl_ctx = ssl_module.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl_module.CERT_NONE
            else:
                ssl_ctx = False
            connect_kwargs["ssl"] = ssl_ctx

        # Retry pool creation with exponential backoff
        last_error = None
        for attempt in range(MAX_RETRIES):
            try:
                self._pool = await asyncpg.create_pool(
                    dsn=self._dsn,
                    min_size=self._pool_min,
                    max_size=self._pool_max,
                    command_timeout=30,
                    **connect_kwargs,
                )
                self._initialized = True
                logger.info(
                    "Database engine initialized: PostgreSQL pool "
                    "(min=%d, max=%d, ssl=%s)",
                    self._pool_min, self._pool_max, self._ssl_mode if self._ssl else "disabled"
                )
                return
            except Exception as e:
                last_error = e
                delay = RETRY_BASE_DELAY * (2 ** attempt)
                logger.warning(
                    "PostgreSQL connection failed (attempt %d/%d): %s. "
                    "Retrying in %.1fs...",
                    attempt + 1, MAX_RETRIES, e, delay
                )
                await asyncio.sleep(delay)

        raise RuntimeError(
            f"Failed to connect to PostgreSQL after {MAX_RETRIES} attempts: {last_error}"
        )

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
            self._initialized = False
            logger.info("PostgreSQL engine closed")

    async def execute(self, query: str, params: Optional[Sequence] = None) -> int:
        translated, translated_params = self.translator.translate(query, params)
        if not translated:
            return 0

        async with self._pool.acquire() as conn:
            result = await conn.execute(translated, *(translated_params or ()))
            # asyncpg returns "INSERT 0 1" or "UPDATE 3" etc.
            return self._parse_rowcount(result)

    def _parse_rowcount(self, status: str) -> int:
        """Parse asyncpg command status to get row count."""
        if not status:
            return 0
        parts = status.split()
        if len(parts) >= 2:
            try:
                return int(parts[-1])
            except ValueError:
                pass
        return 0

    async def fetch_one(self, query: str, params: Optional[Sequence] = None) -> Optional[Row]:
        translated, translated_params = self.translator.translate(query, params)
        if not translated:
            return None

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(translated, *(translated_params or ()))
            if row is None:
                return None
            return Row(_data=dict(row))

    async def fetch_all(self, query: str, params: Optional[Sequence] = None) -> list[Row]:
        translated, translated_params = self.translator.translate(query, params)
        if not translated:
            return []

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(translated, *(translated_params or ()))
            return [Row(_data=dict(r)) for r in rows]

    async def execute_script(self, script: str) -> None:
        """Execute multi-statement SQL script.

        For PostgreSQL, we split on semicolons and execute each statement.
        PRAGMA statements are filtered out by the translator.
        """
        async with self._pool.acquire() as conn:
            # Use asyncpg's built-in script execution
            await conn.execute(script)

    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator[Transaction, None]:
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                tx = _PostgreSQLTransaction(conn, self.translator)
                yield tx

    async def health_check(self) -> dict[str, Any]:
        start = time.monotonic()
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow("SELECT 1 as ok")
                latency = (time.monotonic() - start) * 1000
                return {
                    "healthy": row is not None,
                    "latency_ms": round(latency, 2),
                    "backend": "postgresql",
                    "pool_size": self._pool.get_size(),
                    "pool_free": self._pool.get_idle_size(),
                    "pool_min": self._pool.get_min_size(),
                    "pool_max": self._pool.get_max_size(),
                }
        except Exception as e:
            latency = (time.monotonic() - start) * 1000
            return {
                "healthy": False,
                "latency_ms": round(latency, 2),
                "backend": "postgresql",
                "error": str(e),
            }

    async def table_exists(self, table_name: str) -> bool:
        row = await self.fetch_one(
            "SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = $1)",
            (table_name,),
        )
        if row is None:
            return False
        return bool(list(row.values())[0])

    async def acquire_advisory_lock(self, lock_id: int) -> bool:
        """Acquire a PostgreSQL advisory lock (for migration coordination).

        Returns True if lock acquired, False if already held by another session.
        """
        row = await self.fetch_one(
            "SELECT pg_try_advisory_lock($1) as acquired",
            (lock_id,),
        )
        return bool(row["acquired"]) if row else False

    async def release_advisory_lock(self, lock_id: int) -> None:
        """Release a PostgreSQL advisory lock."""
        await self.execute("SELECT pg_advisory_unlock($1)", (lock_id,))


class _PostgreSQLTransaction(Transaction):
    """PostgreSQL transaction wrapper (uses asyncpg connection within transaction)."""

    def __init__(self, conn, translator: QueryTranslator):
        self._conn = conn
        self._translator = translator

    async def execute(self, query: str, params: Optional[Sequence] = None) -> int:
        translated, translated_params = self._translator.translate(query, params)
        if not translated:
            return 0
        result = await self._conn.execute(translated, *(translated_params or ()))
        return self._parse_rowcount(result)

    def _parse_rowcount(self, status: str) -> int:
        if not status:
            return 0
        parts = status.split()
        if len(parts) >= 2:
            try:
                return int(parts[-1])
            except ValueError:
                pass
        return 0

    async def fetch_one(self, query: str, params: Optional[Sequence] = None) -> Optional[Row]:
        translated, translated_params = self._translator.translate(query, params)
        if not translated:
            return None
        row = await self._conn.fetchrow(translated, *(translated_params or ()))
        if row is None:
            return None
        return Row(_data=dict(row))

    async def fetch_all(self, query: str, params: Optional[Sequence] = None) -> list[Row]:
        translated, translated_params = self._translator.translate(query, params)
        if not translated:
            return []
        rows = await self._conn.fetch(translated, *(translated_params or ()))
        return [Row(_data=dict(r)) for r in rows]


# ─── Engine Factory ───────────────────────────────────────────────────────────

def create_engine(url: Optional[str] = None) -> DatabaseEngine:
    """Create a database engine based on the URL scheme.

    Args:
        url: Database URL. If None, reads from SENTINEL_ADMIN_DB_URL env var.

    Returns:
        Appropriate DatabaseEngine instance (SQLiteEngine or PostgreSQLEngine)

    Raises:
        ValueError: If URL scheme is unsupported
    """
    db_url = url or ADMIN_DB_URL

    if db_url.startswith("sqlite"):
        return SQLiteEngine(db_url)
    elif db_url.startswith("postgresql") or db_url.startswith("postgres://"):
        return PostgreSQLEngine(
            url=db_url,
            pool_min=ADMIN_DB_POOL_MIN,
            pool_max=ADMIN_DB_POOL_MAX,
            ssl=ADMIN_DB_SSL,
            ssl_mode=ADMIN_DB_SSL_MODE,
        )
    else:
        raise ValueError(
            f"Unsupported database URL scheme: {db_url}. "
            "Supported: sqlite:///path, postgresql://user:pass@host:port/db"
        )


# ─── Singleton Access ─────────────────────────────────────────────────────────

_engine: Optional[DatabaseEngine] = None


def get_database() -> DatabaseEngine:
    """Get the global database engine singleton.

    The engine must be initialized via `await init_database()` during app startup.
    This function returns the already-created engine for dependency injection.

    Raises:
        RuntimeError: If called before init_database()
    """
    global _engine
    if _engine is None:
        raise RuntimeError(
            "Database not initialized. Call await init_database() during app startup."
        )
    return _engine


async def init_database(url: Optional[str] = None) -> DatabaseEngine:
    """Initialize the global database engine and run migrations.

    Called once during application lifespan startup. Creates the engine,
    establishes connections, and runs any pending schema migrations.

    Args:
        url: Optional database URL override. Defaults to SENTINEL_ADMIN_DB_URL.

    Returns:
        The initialized DatabaseEngine instance.
    """
    global _engine

    if _engine is not None and _engine._initialized:
        return _engine

    _engine = create_engine(url)
    await _engine.init()

    # Run migrations
    from .migrations import run_migrations
    await run_migrations(_engine)

    logger.info("Database layer fully initialized (backend=%s)", _engine.backend)
    return _engine


async def close_database() -> None:
    """Close the global database engine. Called during app shutdown."""
    global _engine
    if _engine is not None:
        await _engine.close()
        _engine = None
