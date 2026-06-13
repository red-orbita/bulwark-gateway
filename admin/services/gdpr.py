"""GDPR Compliance Service — Pseudonymization, Data Export, Retention.

Implements:
- Art.17 (Right to Erasure) via irreversible HMAC-SHA256 pseudonymization
- Art.15 (Right of Access) via structured data export
- Art.30 (Records of Processing Activities) via data inventory
- Retention policy enforcement with cold storage archival

Security: All operations are audit-logged. Pseudonymization is ONE-WAY.
The HMAC salt is per-subject and stored in Redis or encrypted file.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import shutil
import sqlite3
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from .audit_logger import get_audit_logger, AUDIT_DB_PATH
from .redis_sync import get_redis_client

logger = logging.getLogger(__name__)

# ─── Configuration ────────────────────────────────────────────────────────────

GDPR_SALT_DIR = Path(os.getenv("SENTINEL_GDPR_SALT_DIR", "data/gdpr/salts"))
GDPR_ARCHIVE_DIR = Path(os.getenv("SENTINEL_GDPR_ARCHIVE_DIR", "data/gdpr/archive"))
GDPR_REQUESTS_DB = Path(os.getenv("SENTINEL_GDPR_REQUESTS_DB", "data/gdpr/requests.db"))

# Retention defaults (days)
RETENTION_SECURITY_EVENTS_DAYS = int(os.getenv("SENTINEL_RETENTION_SECURITY_DAYS", "90"))
RETENTION_AUDIT_DAYS = int(os.getenv("SENTINEL_RETENTION_AUDIT_DAYS", "365"))

# Redis keys for GDPR salt storage
REDIS_GDPR_SALT_PREFIX = "sentinel:gdpr:salt:"
REDIS_GDPR_REQUESTS_KEY = "sentinel:gdpr:requests"


# ─── Models ───────────────────────────────────────────────────────────────────

class PseudonymizeRequest(BaseModel):
    subject_id: str = Field(..., description="Data subject identifier (tenant_id, username, email, or IP)")
    confirmation: str = Field(..., description="Must be: 'I confirm this action affects N records'")
    reason: str = Field(default="GDPR Art.17 right to erasure", description="Legal basis for request")


class ExportRequest(BaseModel):
    subject_id: str = Field(..., description="Data subject identifier")
    include_security_events: bool = True
    include_audit_entries: bool = True
    include_rate_limit_history: bool = True


class RetentionStatus(BaseModel):
    security_events_retention_days: int
    audit_retention_days: int
    last_enforcement: Optional[str] = None
    records_archived: int = 0
    records_deleted: int = 0
    next_scheduled: Optional[str] = None


class GDPRRequestRecord(BaseModel):
    id: str
    request_type: str  # pseudonymize, export, retention_enforce
    subject_id: Optional[str] = None
    requested_by: str
    requested_at: str
    status: str  # pending, completed, failed
    records_affected: int = 0
    details: Optional[str] = None


class DataCategory(BaseModel):
    category: str
    description: str
    purpose: str
    legal_basis: str
    retention_period: str
    recipients: list[str]
    contains_pii: bool
    pseudonymizable: bool


# ─── GDPR Service ─────────────────────────────────────────────────────────────

class GDPRService:
    """GDPR compliance operations — pseudonymization, export, retention."""

    def __init__(self):
        self._lock = threading.Lock()
        self._requests_conn: Optional[sqlite3.Connection] = None
        # Ensure directories exist
        GDPR_SALT_DIR.mkdir(parents=True, exist_ok=True)
        GDPR_ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
        GDPR_REQUESTS_DB.parent.mkdir(parents=True, exist_ok=True)

    async def initialize(self) -> None:
        """Initialize GDPR requests database."""
        self._requests_conn = sqlite3.connect(str(GDPR_REQUESTS_DB), isolation_level=None)
        self._requests_conn.execute("PRAGMA journal_mode=WAL")
        self._requests_conn.execute("""
            CREATE TABLE IF NOT EXISTS gdpr_requests (
                id TEXT PRIMARY KEY,
                request_type TEXT NOT NULL,
                subject_id TEXT,
                requested_by TEXT NOT NULL,
                requested_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                records_affected INTEGER DEFAULT 0,
                details TEXT
            )
        """)
        self._requests_conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_gdpr_subject ON gdpr_requests(subject_id)
        """)
        self._requests_conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_gdpr_type ON gdpr_requests(request_type)
        """)

    # ─── Pseudonymization (Art.17) ────────────────────────────────────────

    async def pseudonymize_subject(
        self, subject_id: str, requested_by: str, ip_address: Optional[str] = None
    ) -> dict:
        """Replace all PII for a data subject with irreversible HMAC-SHA256 hashes.

        Process:
        1. Generate (or retrieve) a per-subject salt
        2. Find all audit entries containing the subject
        3. Replace identifiable fields with HMAC-SHA256(field + salt)
        4. Record the pseudonymization action in audit log
        5. The original data cannot be recovered (one-way)
        """
        request_id = str(uuid4())
        audit = get_audit_logger()

        # Get or create per-subject salt (one-way: even if salt is found,
        # the original data is hashed and cannot be reversed)
        salt = self._get_or_create_salt(subject_id)

        # Find affected records
        affected_count = await self._count_subject_records(subject_id)

        if affected_count == 0:
            # Record the request even if no records found
            await self._record_request(
                request_id, "pseudonymize", subject_id, requested_by,
                "completed", 0, "No records found for subject"
            )
            return {
                "request_id": request_id,
                "status": "completed",
                "records_affected": 0,
                "message": "No records found for this data subject",
            }

        # Perform pseudonymization
        pseudonymized_count = await self._apply_pseudonymization(subject_id, salt)

        # Record the GDPR request
        await self._record_request(
            request_id, "pseudonymize", subject_id, requested_by,
            "completed", pseudonymized_count,
            f"Pseudonymized {pseudonymized_count} records for subject"
        )

        # Meta-audit: log the pseudonymization action itself
        await audit.log(
            actor=requested_by,
            action="gdpr_pseudonymize",
            resource_type="data_subject",
            resource_id=self._hash_value(subject_id, salt),  # Store hashed ID
            result="success",
            details=json.dumps({
                "request_id": request_id,
                "records_affected": pseudonymized_count,
                "reason": "GDPR Art.17 right to erasure",
            }),
            ip_address=ip_address,
        )

        # Delete the salt after use — ensures no future correlation possible
        # (Even with the salt, HMAC is one-way, but defense-in-depth)
        self._delete_salt(subject_id)

        return {
            "request_id": request_id,
            "status": "completed",
            "records_affected": pseudonymized_count,
            "message": f"Successfully pseudonymized {pseudonymized_count} records",
            "irreversible": True,
        }

    # ─── Data Export (Art.15) ─────────────────────────────────────────────

    async def export_subject_data(
        self, subject_id: str, requested_by: str,
        include_security_events: bool = True,
        include_audit_entries: bool = True,
        include_rate_limit_history: bool = True,
        ip_address: Optional[str] = None,
    ) -> dict:
        """Export all data related to a subject in machine-readable JSON format.

        GDPR Art.15: Right of access — data subject can request all personal data.
        """
        request_id = str(uuid4())
        audit = get_audit_logger()
        export_data: dict = {
            "export_id": request_id,
            "subject_id": subject_id,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "exported_by": requested_by,
            "data_categories": [],
        }

        total_records = 0

        # 1. Audit entries
        if include_audit_entries:
            entries = await self._find_audit_entries(subject_id)
            export_data["audit_entries"] = [
                {
                    "id": e["id"],
                    "timestamp": e["timestamp"],
                    "action": e["action"],
                    "resource_type": e["resource_type"],
                    "resource_id": e["resource_id"],
                    "result": e["result"],
                    "ip_address": e["ip_address"],
                }
                for e in entries
            ]
            export_data["data_categories"].append("audit_log")
            total_records += len(entries)

        # 2. Security events (from Redis or recent blocks)
        if include_security_events:
            events = await self._find_security_events(subject_id)
            export_data["security_events"] = events
            export_data["data_categories"].append("security_events")
            total_records += len(events)

        # 3. Rate limit history
        if include_rate_limit_history:
            rate_history = await self._find_rate_limit_history(subject_id)
            export_data["rate_limit_history"] = rate_history
            export_data["data_categories"].append("rate_limit_history")
            total_records += len(rate_history)

        export_data["total_records"] = total_records

        # Record the export request
        await self._record_request(
            request_id, "export", subject_id, requested_by,
            "completed", total_records,
            f"Exported {total_records} records for subject"
        )

        # Audit log the export action
        await audit.log(
            actor=requested_by,
            action="gdpr_export",
            resource_type="data_subject",
            resource_id=subject_id,
            result="success",
            details=json.dumps({
                "request_id": request_id,
                "records_exported": total_records,
                "categories": export_data["data_categories"],
            }),
            ip_address=ip_address,
        )

        return export_data

    # ─── Retention Policy Enforcement ─────────────────────────────────────

    async def retention_policy_enforce(
        self, requested_by: str, ip_address: Optional[str] = None
    ) -> dict:
        """Enforce retention policy — archive then delete old records.

        Security events: default 90 days
        Audit entries: default 365 days (regulatory minimum)
        """
        request_id = str(uuid4())
        audit = get_audit_logger()
        now = datetime.now(timezone.utc)

        security_cutoff = now - timedelta(days=RETENTION_SECURITY_EVENTS_DAYS)
        audit_cutoff = now - timedelta(days=RETENTION_AUDIT_DAYS)

        archived_count = 0
        deleted_count = 0

        # Archive audit entries beyond retention period
        old_entries = await self._find_entries_before(audit_cutoff)
        if old_entries:
            archive_path = GDPR_ARCHIVE_DIR / f"audit_archive_{now.strftime('%Y%m%d_%H%M%S')}.json"
            archive_path.write_text(
                json.dumps(old_entries, indent=2, default=str),
                encoding="utf-8"
            )
            archived_count = len(old_entries)

            # Delete archived entries from main DB
            deleted_count = await self._delete_entries_before(audit_cutoff)

        # Record the enforcement
        await self._record_request(
            request_id, "retention_enforce", None, requested_by,
            "completed", archived_count + deleted_count,
            json.dumps({
                "security_cutoff": security_cutoff.isoformat(),
                "audit_cutoff": audit_cutoff.isoformat(),
                "archived": archived_count,
                "deleted": deleted_count,
            })
        )

        # Audit log
        await audit.log(
            actor=requested_by,
            action="gdpr_retention_enforce",
            resource_type="retention_policy",
            resource_id=request_id,
            result="success",
            details=json.dumps({
                "archived": archived_count,
                "deleted": deleted_count,
                "security_retention_days": RETENTION_SECURITY_EVENTS_DAYS,
                "audit_retention_days": RETENTION_AUDIT_DAYS,
            }),
            ip_address=ip_address,
        )

        # Update status in Redis
        self._update_retention_status(archived_count, deleted_count)

        return {
            "request_id": request_id,
            "status": "completed",
            "archived": archived_count,
            "deleted": deleted_count,
            "security_cutoff": security_cutoff.isoformat(),
            "audit_cutoff": audit_cutoff.isoformat(),
        }

    # ─── Data Inventory (Art.30) ──────────────────────────────────────────

    async def data_inventory(self) -> list[dict]:
        """Return structured list of all data categories processed (Art.30).

        Records of processing activities — required for organizations with
        more than 250 employees or processing sensitive data.
        """
        categories = [
            DataCategory(
                category="audit_log",
                description="Administrative action records (who did what, when)",
                purpose="Security monitoring, compliance, accountability",
                legal_basis="Legitimate interest (Art.6(1)(f)) — security of processing",
                retention_period=f"{RETENTION_AUDIT_DAYS} days",
                recipients=["Security team", "SIEM platform", "Compliance auditors"],
                contains_pii=True,
                pseudonymizable=True,
            ),
            DataCategory(
                category="security_events",
                description="Detected threats, blocked requests, guardrail triggers",
                purpose="Threat detection, incident response, security analytics",
                legal_basis="Legitimate interest (Art.6(1)(f)) — security of processing",
                retention_period=f"{RETENTION_SECURITY_EVENTS_DAYS} days",
                recipients=["Security team", "SIEM platform", "SOC analysts"],
                contains_pii=True,
                pseudonymizable=True,
            ),
            DataCategory(
                category="rate_limit_counters",
                description="Request frequency per tenant (sliding window)",
                purpose="Service protection, abuse prevention",
                legal_basis="Legitimate interest (Art.6(1)(f)) — availability of service",
                retention_period="Rolling window (60 seconds)",
                recipients=["Internal system only"],
                contains_pii=True,
                pseudonymizable=False,
            ),
            DataCategory(
                category="request_metadata",
                description="IP addresses, user agents, request timestamps",
                purpose="Authentication, abuse detection, forensics",
                legal_basis="Legitimate interest (Art.6(1)(f)) — security of processing",
                retention_period=f"{RETENTION_SECURITY_EVENTS_DAYS} days",
                recipients=["Security team", "SIEM platform"],
                contains_pii=True,
                pseudonymizable=True,
            ),
            DataCategory(
                category="authentication_data",
                description="Usernames, hashed passwords, session tokens, MFA secrets",
                purpose="Access control, identity verification",
                legal_basis="Contract performance (Art.6(1)(b)) — service delivery",
                retention_period="Account lifetime + 30 days",
                recipients=["Internal authentication system"],
                contains_pii=True,
                pseudonymizable=False,
            ),
            DataCategory(
                category="tenant_configuration",
                description="Tenant names, agent configurations, policy assignments",
                purpose="Multi-tenant service delivery, policy enforcement",
                legal_basis="Contract performance (Art.6(1)(b))",
                retention_period="Contract duration + 90 days",
                recipients=["Tenant administrators", "System operators"],
                contains_pii=False,
                pseudonymizable=False,
            ),
            DataCategory(
                category="gdpr_request_log",
                description="Records of GDPR requests (pseudonymization, export, deletion)",
                purpose="Compliance demonstration, accountability (Art.5(2))",
                legal_basis="Legal obligation (Art.6(1)(c)) — GDPR compliance record",
                retention_period="5 years (regulatory requirement)",
                recipients=["Data Protection Officer", "Compliance auditors"],
                contains_pii=True,
                pseudonymizable=False,
            ),
        ]
        return [c.model_dump() for c in categories]

    # ─── Request History ──────────────────────────────────────────────────

    async def get_requests(
        self, limit: int = 50, offset: int = 0, request_type: Optional[str] = None
    ) -> list[GDPRRequestRecord]:
        """Get GDPR request history (audit trail of all GDPR operations)."""
        if not self._requests_conn:
            return []

        conditions = []
        params: list = []
        if request_type:
            conditions.append("request_type = ?")
            params.append(request_type)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"SELECT * FROM gdpr_requests {where} ORDER BY requested_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        records = []
        with self._lock:
            rows = self._requests_conn.execute(sql, params).fetchall()
            for row in rows:
                records.append(GDPRRequestRecord(
                    id=row[0],
                    request_type=row[1],
                    subject_id=row[2],
                    requested_by=row[3],
                    requested_at=row[4],
                    status=row[5],
                    records_affected=row[6] or 0,
                    details=row[7],
                ))
        return records

    # ─── Retention Status ─────────────────────────────────────────────────

    async def get_retention_status(self) -> RetentionStatus:
        """Get current retention policy configuration and last enforcement status."""
        status = RetentionStatus(
            security_events_retention_days=RETENTION_SECURITY_EVENTS_DAYS,
            audit_retention_days=RETENTION_AUDIT_DAYS,
        )

        # Try to get last enforcement from Redis
        client = get_redis_client()
        if client:
            try:
                last_run = client.get("sentinel:gdpr:retention:last_run")
                if last_run:
                    status.last_enforcement = last_run
                archived = client.get("sentinel:gdpr:retention:archived")
                if archived:
                    status.records_archived = int(archived)
                deleted = client.get("sentinel:gdpr:retention:deleted")
                if deleted:
                    status.records_deleted = int(deleted)
            except Exception:
                pass

        return status

    # ─── Private Methods ──────────────────────────────────────────────────

    def _get_or_create_salt(self, subject_id: str) -> bytes:
        """Get existing salt or generate a new one for a subject.

        Storage priority: Redis > File system.
        Salt is 32 bytes of cryptographic randomness.
        """
        redis_key = f"{REDIS_GDPR_SALT_PREFIX}{hashlib.sha256(subject_id.encode()).hexdigest()}"

        # Try Redis first
        client = get_redis_client()
        if client:
            try:
                existing = client.get(redis_key)
                if existing:
                    return bytes.fromhex(existing)
                # Generate new salt
                salt = os.urandom(32)
                client.set(redis_key, salt.hex(), ex=86400)  # 24h TTL
                return salt
            except Exception:
                pass

        # Fallback: file-based salt storage
        salt_file = GDPR_SALT_DIR / f"{hashlib.sha256(subject_id.encode()).hexdigest()}.salt"
        if salt_file.exists():
            return bytes.fromhex(salt_file.read_text().strip())

        # Generate new salt
        salt = os.urandom(32)
        salt_file.write_text(salt.hex())
        return salt

    def _delete_salt(self, subject_id: str) -> None:
        """Delete salt after pseudonymization (defense-in-depth)."""
        key_hash = hashlib.sha256(subject_id.encode()).hexdigest()
        redis_key = f"{REDIS_GDPR_SALT_PREFIX}{key_hash}"

        client = get_redis_client()
        if client:
            try:
                client.delete(redis_key)
            except Exception:
                pass

        salt_file = GDPR_SALT_DIR / f"{key_hash}.salt"
        if salt_file.exists():
            salt_file.unlink()

    def _hash_value(self, value: str, salt: bytes) -> str:
        """Compute irreversible HMAC-SHA256 pseudonym for a value."""
        return hmac.new(salt, value.encode("utf-8"), hashlib.sha256).hexdigest()[:32]

    async def _count_subject_records(self, subject_id: str) -> int:
        """Count audit records that reference the subject."""
        audit = get_audit_logger()
        if not audit._conn:
            return 0

        with audit._lock:
            cursor = audit._conn.execute(
                """SELECT COUNT(*) FROM audit_log
                   WHERE actor = ? OR ip_address = ?
                   OR details LIKE ? OR resource_id LIKE ?""",
                (subject_id, subject_id, f"%{subject_id}%", f"%{subject_id}%")
            )
            return cursor.fetchone()[0]

    async def _apply_pseudonymization(self, subject_id: str, salt: bytes) -> int:
        """Replace PII fields with HMAC-SHA256 hashes in audit records."""
        audit = get_audit_logger()
        if not audit._conn:
            return 0

        pseudonym = self._hash_value(subject_id, salt)
        count = 0

        with audit._lock:
            # Find all affected rows
            rows = audit._conn.execute(
                """SELECT id, actor, ip_address, details, resource_id FROM audit_log
                   WHERE actor = ? OR ip_address = ?
                   OR details LIKE ? OR resource_id LIKE ?""",
                (subject_id, subject_id, f"%{subject_id}%", f"%{subject_id}%")
            ).fetchall()

            for row in rows:
                row_id, actor, ip_addr, details, resource_id = row
                new_actor = pseudonym if actor == subject_id else actor
                new_ip = self._hash_value(ip_addr, salt) if ip_addr == subject_id else ip_addr
                new_details = details.replace(subject_id, pseudonym) if details and subject_id in details else details
                new_resource_id = pseudonym if resource_id == subject_id else resource_id

                audit._conn.execute(
                    """UPDATE audit_log
                       SET actor = ?, ip_address = ?, details = ?, resource_id = ?
                       WHERE id = ?""",
                    (new_actor, new_ip, new_details, new_resource_id, row_id)
                )
                count += 1

        return count

    async def _find_audit_entries(self, subject_id: str) -> list[dict]:
        """Find all audit entries related to a subject."""
        audit = get_audit_logger()
        if not audit._conn:
            return []

        with audit._lock:
            rows = audit._conn.execute(
                """SELECT id, timestamp, actor, action, resource_type, resource_id,
                          result, ip_address, details
                   FROM audit_log
                   WHERE actor = ? OR ip_address = ?
                   OR details LIKE ? OR resource_id LIKE ?
                   ORDER BY timestamp DESC""",
                (subject_id, subject_id, f"%{subject_id}%", f"%{subject_id}%")
            ).fetchall()

        return [
            {
                "id": r[0], "timestamp": r[1], "actor": r[2],
                "action": r[3], "resource_type": r[4], "resource_id": r[5],
                "result": r[6], "ip_address": r[7], "details": r[8],
            }
            for r in rows
        ]

    async def _find_security_events(self, subject_id: str) -> list[dict]:
        """Find security events related to a subject (from Redis recent blocks)."""
        events = []
        client = get_redis_client()
        if not client:
            return events

        try:
            # Check recent blocks list
            recent = client.lrange("sentinel:recent_blocks", 0, -1)
            for item in (recent or []):
                try:
                    event = json.loads(item) if isinstance(item, str) else item
                    # Match on tenant_id, source IP, or any field containing subject
                    if self._event_matches_subject(event, subject_id):
                        events.append(event)
                except (json.JSONDecodeError, TypeError):
                    continue
        except Exception as e:
            logger.warning("Failed to query security events from Redis: %s", e)

        return events

    async def _find_rate_limit_history(self, subject_id: str) -> list[dict]:
        """Find rate limit records for a subject (tenant-based)."""
        history = []
        client = get_redis_client()
        if not client:
            return history

        try:
            # Rate limit keys are per-tenant
            key = f"sentinel:rate_limit:{subject_id}"
            members = client.zrangebyscore(key, "-inf", "+inf", withscores=True)
            for member, score in (members or []):
                history.append({
                    "timestamp": datetime.fromtimestamp(score, tz=timezone.utc).isoformat(),
                    "request_id": member,
                    "tenant_id": subject_id,
                })
        except Exception as e:
            logger.warning("Failed to query rate limit history: %s", e)

        return history

    def _event_matches_subject(self, event: dict, subject_id: str) -> bool:
        """Check if a security event references the given subject."""
        searchable_fields = ["tenant_id", "agent_id", "source_ip", "actor", "description"]
        for field in searchable_fields:
            value = event.get(field, "")
            if isinstance(value, str) and subject_id in value:
                return True
        # Check metadata dict
        metadata = event.get("metadata", {})
        if isinstance(metadata, dict):
            for v in metadata.values():
                if isinstance(v, str) and subject_id in v:
                    return True
        return False

    async def _find_entries_before(self, cutoff: datetime) -> list[dict]:
        """Find audit entries older than cutoff date."""
        audit = get_audit_logger()
        if not audit._conn:
            return []

        with audit._lock:
            rows = audit._conn.execute(
                "SELECT * FROM audit_log WHERE timestamp < ? ORDER BY timestamp",
                (cutoff.isoformat(),)
            ).fetchall()

        return [
            {
                "id": r[0], "timestamp": r[1], "actor": r[2], "action": r[3],
                "resource_type": r[4], "resource_id": r[5], "payload_hash": r[6],
                "result": r[7], "details": r[8], "ip_address": r[9],
                "rollback_ref": r[10],
            }
            for r in rows
        ]

    async def _delete_entries_before(self, cutoff: datetime) -> int:
        """Delete audit entries older than cutoff (after archival)."""
        audit = get_audit_logger()
        if not audit._conn:
            return 0

        with audit._lock:
            cursor = audit._conn.execute(
                "DELETE FROM audit_log WHERE timestamp < ?",
                (cutoff.isoformat(),)
            )
            return cursor.rowcount

    async def _record_request(
        self, request_id: str, request_type: str, subject_id: Optional[str],
        requested_by: str, status: str, records_affected: int, details: Optional[str] = None
    ) -> None:
        """Record a GDPR request in the requests database."""
        if not self._requests_conn:
            return

        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._requests_conn.execute(
                "INSERT INTO gdpr_requests VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (request_id, request_type, subject_id, requested_by,
                 now, status, records_affected, details)
            )

    def _update_retention_status(self, archived: int, deleted: int) -> None:
        """Update retention enforcement status in Redis."""
        client = get_redis_client()
        if not client:
            return

        try:
            now = datetime.now(timezone.utc).isoformat()
            client.set("sentinel:gdpr:retention:last_run", now)
            client.set("sentinel:gdpr:retention:archived", str(archived))
            client.set("sentinel:gdpr:retention:deleted", str(deleted))
        except Exception:
            pass

    async def close(self) -> None:
        """Close database connections."""
        with self._lock:
            if self._requests_conn:
                self._requests_conn.close()
                self._requests_conn = None


# ─── Singleton ────────────────────────────────────────────────────────────────

_service: Optional[GDPRService] = None


def get_gdpr_service() -> GDPRService:
    global _service
    if _service is None:
        _service = GDPRService()
    return _service
