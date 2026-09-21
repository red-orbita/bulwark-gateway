"""Async attachment storage with database-clock TTLs and fenced parsing leases."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import math
from collections.abc import Callable, Coroutine
from secrets import token_hex
from typing import Any, TypeVar

from src.storage.attachment_migrations import migrate_attachments
from src.storage.database import DatabaseEngine, Row, Transaction, create_engine

MAX_RAW_BYTES = 2 * 1024 * 1024
MAX_TEXT_BYTES = 32 * 1024
MAX_CLEANUP = 100
MAX_ATTEMPTS = 3
OPERATION_TIMEOUT = 15
TERMINAL_STATES = frozenset({"approved", "blocked", "review_required", "failed"})
PUBLIC_REASON_CODES = frozenset({
    "policy_changed", "unsupported_format", "extraction_unavailable", "no_text",
    "incomplete", "unsafe_document", "input_detection", "input_dlp", "processor_failed",
    "attempts_exhausted", "integrity_error", "approved",
})
_PUBLIC_REASONS = {json.dumps(code): code for code in PUBLIC_REASON_CODES}
T = TypeVar("T")


class StoreError(Exception):
    """Safe, stable error code. Never contains document or database details."""

    def __init__(self, code: str):
        self.code = code if code in {
            "not_found", "not_ready", "policy_changed", "integrity_error",
            "invalid_input", "too_large", "capacity", "busy", "unavailable",
            "configuration_error",
        } else "unavailable"
        self.retryable = self.code in {"busy", "unavailable"}
        super().__init__(self.code)


def _string(value: str, limit: int = 256, *, empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > limit or (not empty and not value):
        raise StoreError("invalid_input")
    # JSON framing avoids the shared PostgreSQL translator's datetime coercion.
    return json.dumps(value, ensure_ascii=True)


class AttachmentStore:
    """SQLite implementation with shared transactional SQL for PostgreSQL.

    One operation per instance; replicas serialize on a database state-row write.
    Use a dedicated engine, not a connection managed by another store.
    """

    def __init__(self, db: DatabaseEngine, max_documents: int = 100,
                 max_bytes: int = 32 * 1024 * 1024, max_per_tenant: int = 20,
                 ttl_seconds: int = 3600):
        limits = (max_documents, max_bytes, max_per_tenant, ttl_seconds)
        bounds = (1000000, 1024**4, 1000000, 604800)
        if any(type(v) is not int or not 1 <= v <= bound for v, bound in zip(limits, bounds, strict=True)):
            raise StoreError("configuration_error")
        self._db = db
        self._limits = limits
        self._lock = asyncio.Lock()
        self._ready = False
        self._closed = False

    async def _run(self, operation: Callable[[], Coroutine[Any, Any, T]], *, initializing: bool = False) -> T:
        if self._lock.locked():
            raise StoreError("busy")
        if not self._ready and not initializing:
            raise StoreError("not_ready")
        async with self._lock:
            async def bounded() -> T:
                try:
                    async with asyncio.timeout(OPERATION_TIMEOUT):
                        return await operation()
                except StoreError:
                    raise
                except Exception:
                    raise StoreError("unavailable") from None

            task = asyncio.create_task(bounded())
            try:
                return await asyncio.shield(task)
            except asyncio.CancelledError:
                # Keep the instance locked until the driver finishes/rolls back.
                # Cancellation cannot leave a still-committing worker unobserved.
                while not task.done():
                    try:
                        await asyncio.shield(task)
                    except asyncio.CancelledError:
                        continue
                    except Exception:
                        break
                if not task.cancelled():
                    task.exception()
                raise

    async def initialize(self) -> None:
        async def initialize() -> None:
            if self._closed:
                raise StoreError("not_ready")
            if self._ready:
                return
            await self._db.init()
            if self._db.backend == "sqlite":
                await self._db.execute("PRAGMA synchronous=FULL")
            try:
                await migrate_attachments(self._db, *self._limits)
            except ValueError:
                raise StoreError("configuration_error") from None
            self._ready = True
        await self._run(initialize, initializing=True)

    async def close(self) -> None:
        """Close the owned engine after callers drain operations; safe to repeat.

        A busy instance rejects shutdown rather than racing a transaction. Once
        shutdown starts, errors or cancellation cannot restore its readiness.
        """
        async def close() -> None:
            self._closed = True
            self._ready = False
            await self._db.close()
        await self._run(close, initializing=True)

    async def _state(self, tx: Transaction) -> float:
        if not self._ready:
            raise StoreError("not_ready")
        if self._db.backend == "postgresql":
            await tx.execute("SET LOCAL lock_timeout = '5s'")
            await tx.execute("SET LOCAL statement_timeout = '10s'")
            await tx.execute("SET LOCAL synchronous_commit = on")
        await tx.execute("UPDATE attachment_store_state SET version = version WHERE id = 'attachments'")
        if self._db.backend == "postgresql":
            row = await tx.fetch_one("SELECT EXTRACT(EPOCH FROM clock_timestamp())::double precision AS now")
        else:
            row = await tx.fetch_one("SELECT (julianday('now') - 2440587.5) * 86400.0 AS now")
        if row is None:
            raise StoreError("unavailable")
        return float(row["now"])

    @staticmethod
    def _public(row: Row) -> dict[str, Any]:
        return {
            "id": row["id"], "state": row["state"], "sha256": row["sha256"],
            "created_at": row["created_at"], "expires_at": row["expires_at"],
            "mime": json.loads(row["mime"]), "size_bytes": row["raw_size"],
            "policy_revision": json.loads(row["policy_revision"]),
            "text_sha256": row["text_sha256"],
            # Match encoded fixed codes only; arbitrary internal diagnostics and
            # malformed persisted values never become public error messages.
            "reason": _PUBLIC_REASONS.get(row["reason"], ""),
        }

    async def _remove(self, tx: Transaction, row: Row) -> None:
        await tx.execute("DELETE FROM attachment_documents WHERE id = ?", (row["id"],))
        await tx.execute(
            "UPDATE attachment_store_state SET documents = documents - 1, bytes = bytes - ? "
            "WHERE id = 'attachments'", (row["size_bytes"],),
        )

    async def _expire(self, tx: Transaction, now: float, limit: int) -> int:
        rows = await tx.fetch_all(
            "SELECT id, size_bytes FROM attachment_documents WHERE expires_at <= ? "
            "ORDER BY expires_at, id LIMIT ?", (now, limit),
        )
        for row in rows:
            await self._remove(tx, row)
        return len(rows)

    async def expire(self, *, limit: int = 100) -> int:
        if type(limit) is not int or not 1 <= limit <= MAX_CLEANUP:
            raise StoreError("invalid_input")

        async def expire() -> int:
            async with self._db.transaction() as tx:
                return await self._expire(tx, await self._state(tx), limit)
        return await self._run(expire)

    async def create(self, *, tenant: str, agent: str, owner: str, mime: str,
                     raw: bytes, policy_revision: str) -> dict[str, Any]:
        async def create() -> dict[str, Any]:
            identity = tuple(_string(v) for v in (tenant, agent, owner, mime, policy_revision))
            if not isinstance(raw, bytes) or not raw:
                raise StoreError("invalid_input")
            if len(raw) > MAX_RAW_BYTES:
                raise StoreError("too_large")
            encoded = base64.b64encode(raw).decode("ascii")
            # Account for encoded payload and bounded metadata, not just raw bytes.
            # Reserve terminal diagnostics too, so rejecting even a tiny upload
            # never needs additional capacity (JSON reason <= 3074 bytes).
            size = len(encoded) + sum(len(v) for v in identity) + 4096
            key = "att_" + token_hex(32)
            digest = hashlib.sha256(raw).hexdigest()
            # Commit bounded cleanup even if the following admission is denied.
            # Both transactions remain under the instance's single-operation lock.
            async with self._db.transaction() as tx:
                await self._expire(tx, await self._state(tx), MAX_CLEANUP)
            async with self._db.transaction() as tx:
                now = await self._state(tx)
                tenant_count = await tx.fetch_one(
                    "SELECT COUNT(*) AS count FROM attachment_documents WHERE tenant = ?", (identity[0],),
                )
                if tenant_count is None or tenant_count["count"] >= self._limits[2]:
                    raise StoreError("capacity")
                changed = await tx.execute(
                    "UPDATE attachment_store_state SET documents = documents + 1, bytes = bytes + ? "
                    "WHERE id = 'attachments' AND documents < max_documents AND bytes + ? <= max_bytes",
                    (size, size),
                )
                if not changed:
                    raise StoreError("capacity")
                await tx.execute(
                    "INSERT INTO attachment_documents "
                    "(id, tenant, agent, owner, mime, policy_revision, sha256, state, raw_base64, "
                    "raw_size, size_bytes, created_at, expires_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?)",
                    (key, *identity, digest, encoded, len(raw), size, now, now + self._limits[3]),
                )
                row = await tx.fetch_one(
                    "SELECT id, state, sha256, created_at, expires_at, mime, raw_size, "
                    "policy_revision, text_sha256, reason FROM attachment_documents WHERE id = ?", (key,),
                )
                if row is None:
                    raise StoreError("unavailable")
                return self._public(row)
        return await self._run(create)

    async def _scoped(self, tx: Transaction, id: str, tenant: str, agent: str, owner: str) -> Row | None:
        _string(id, 128)
        scope = tuple(_string(v) for v in (tenant, agent, owner))
        # Never fetch raw or extracted text for a public status/delete operation.
        return await tx.fetch_one(
            "SELECT id, state, sha256, created_at, expires_at, mime, raw_size, "
            "policy_revision, text_sha256, reason, size_bytes FROM attachment_documents "
            "WHERE id = ? AND tenant = ? AND agent = ? AND owner = ?", (id, *scope),
        )

    async def get(self, id: str, *, tenant: str, agent: str, owner: str) -> dict[str, Any] | None:
        async def get() -> dict[str, Any] | None:
            async with self._db.transaction() as tx:
                now = await self._state(tx)
                row = await self._scoped(tx, id, tenant, agent, owner)
                if row is None:
                    return None
                if row["expires_at"] <= now:
                    await self._remove(tx, row)
                    return None
                return self._public(row)
        return await self._run(get)

    async def delete(self, id: str, *, tenant: str, agent: str, owner: str) -> bool:
        async def delete() -> bool:
            async with self._db.transaction() as tx:
                now = await self._state(tx)
                row = await self._scoped(tx, id, tenant, agent, owner)
                if row is None:
                    return False
                await self._remove(tx, row)
                return row["expires_at"] > now
        return await self._run(delete)

    async def _terminal(self, tx: Transaction, row: Row, state: str, text_json: str | None,
                        text_sha256: str | None, reason: str) -> None:
        old_payload = 4 * ((row["raw_size"] + 2) // 3)
        delta = len(text_json or "") - old_payload
        if not await tx.execute(
            "UPDATE attachment_store_state SET bytes = bytes + ? "
            "WHERE id = 'attachments' AND bytes + ? <= max_bytes", (delta, delta),
        ):
            raise StoreError("capacity")
        await tx.execute(
            "UPDATE attachment_documents SET state = ?, raw_base64 = NULL, text_json = ?, "
            "text_sha256 = ?, reason = ?, size_bytes = size_bytes + ?, "
            "lease_token = '', lease_until = 0 WHERE id = ?",
            (state, text_json, text_sha256, reason, delta, row["id"]),
        )

    async def claim(self, *, lease_seconds: int = 120) -> dict[str, Any] | None:
        if (isinstance(lease_seconds, bool) or not isinstance(lease_seconds, (int, float))
                or not math.isfinite(lease_seconds) or not 1 <= lease_seconds <= 3600):
            raise StoreError("invalid_input")

        async def claim() -> dict[str, Any] | None:
            async with self._db.transaction() as tx:
                now = await self._state(tx)
                await self._expire(tx, now, MAX_CLEANUP)
                rows = await tx.fetch_all(
                    "SELECT id, raw_size, attempts FROM attachment_documents "
                    "WHERE expires_at > ? AND (state = 'queued' OR "
                    "(state = 'processing' AND lease_until <= ?)) "
                    "ORDER BY created_at, id LIMIT ?", (now, now, MAX_CLEANUP),
                )
                for row in rows:
                    if row["attempts"] >= MAX_ATTEMPTS:
                        await self._terminal(tx, row, "review_required", None, None, '"attempts_exhausted"')
                        continue
                    record = await tx.fetch_one(
                        "SELECT tenant, agent, owner, mime, policy_revision, sha256, raw_base64 "
                        "FROM attachment_documents WHERE id = ? AND length(raw_base64) <= ?",
                        (row["id"], 4 * ((MAX_RAW_BYTES + 2) // 3)),
                    )
                    try:
                        if record is None:
                            raise ValueError("missing")
                        raw = base64.b64decode(record["raw_base64"], validate=True)
                        if not 1 <= len(raw) <= MAX_RAW_BYTES or len(raw) != row["raw_size"] or not hmac.compare_digest(
                            hashlib.sha256(raw).hexdigest(), record["sha256"],
                        ):
                            raise ValueError("hash")
                        payload = {
                            k: json.loads(record[k])
                            for k in ("tenant", "agent", "owner", "mime", "policy_revision")
                        }
                    except (ValueError, TypeError):
                        await self._terminal(tx, row, "failed", None, None, '"integrity_error"')
                        continue
                    token = token_hex(32)
                    await tx.execute(
                        "UPDATE attachment_documents SET state = 'processing', lease_token = ?, "
                        "lease_until = ?, attempts = attempts + 1 WHERE id = ?",
                        (token, now + lease_seconds, row["id"]),
                    )
                    return {"id": row["id"], **payload, "raw": raw, "lease_token": token, "sha256": record["sha256"]}
                return None
        return await self._run(claim)

    async def finish(self, id: str, token: str, *, state: str, text: str | None = None,
                     reason: str = "") -> bool:
        async def finish() -> bool:
            _string(id, 128)
            _string(token, 128)
            if not isinstance(state, str) or state not in TERMINAL_STATES:
                raise StoreError("invalid_input")
            reason_json = _string(reason, empty=True)
            if text is not None and not isinstance(text, str):
                raise StoreError("invalid_input")
            if text is not None:
                if len(text) > MAX_TEXT_BYTES:
                    raise StoreError("too_large")
                try:
                    text_bytes = text.encode("utf-8")
                except UnicodeError:
                    raise StoreError("invalid_input") from None
                if len(text_bytes) > MAX_TEXT_BYTES:
                    raise StoreError("too_large")
            if state == "approved" and text is None:
                raise StoreError("invalid_input")
            text_json = json.dumps(text, ensure_ascii=True) if state == "approved" else None
            digest = (
                hashlib.sha256(text.encode("utf-8")).hexdigest()
                if state == "approved" and text is not None else None
            )
            async with self._db.transaction() as tx:
                now = await self._state(tx)
                row = await tx.fetch_one(
                    "SELECT id, raw_size, lease_token FROM attachment_documents "
                    "WHERE id = ? AND state = 'processing' AND lease_until > ? AND expires_at > ?",
                    (id, now, now),
                )
                if row is None or not hmac.compare_digest(row["lease_token"], token):
                    return False
                await self._terminal(tx, row, state, text_json, digest, reason_json)
                return True
        return await self._run(finish)

    async def resolve(self, id: str, *, tenant: str, agent: str, owner: str,
                      policy_revision: str) -> str:
        async def resolve() -> str:
            revision = _string(policy_revision)
            async with self._db.transaction() as tx:
                now = await self._state(tx)
                row = await self._scoped(tx, id, tenant, agent, owner)
                if row is None or row["expires_at"] <= now:
                    raise StoreError("not_found")
                if row["policy_revision"] != revision:
                    raise StoreError("policy_changed")
                if row["state"] != "approved":
                    raise StoreError("not_ready")
                result = await tx.fetch_one(
                    "SELECT text_json FROM attachment_documents WHERE id = ? AND length(text_json) <= ?",
                    (id, MAX_TEXT_BYTES * 6 + 2),
                )
                try:
                    text = json.loads(result["text_json"]) if result else None
                    if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_TEXT_BYTES:
                        raise ValueError("text")
                    if not hmac.compare_digest(hashlib.sha256(text.encode("utf-8")).hexdigest(), row["text_sha256"]):
                        raise ValueError("hash")
                except (ValueError, TypeError, UnicodeError):
                    raise StoreError("integrity_error") from None
                return text
        return await self._run(resolve)


class PostgreSQLAttachmentStore(AttachmentStore):
    """PostgreSQL variant; state-row locking supplies cross-replica serialization."""


def get_attachment_store(url: str, **limits: int) -> AttachmentStore:
    try:
        # The shared SQLite engine does not implement SQLCipher: accepting its
        # cipher scheme would silently strip the key and persist plaintext.
        if not isinstance(url, str) or not url.startswith((
            "sqlite:///", "postgresql://", "postgresql+asyncpg://", "postgres://",
        )):
            raise ValueError("unsupported")
        db = create_engine(url)
    except Exception:
        raise StoreError("configuration_error") from None
    cls = PostgreSQLAttachmentStore if db.backend == "postgresql" else AttachmentStore
    return cls(db, **limits)
