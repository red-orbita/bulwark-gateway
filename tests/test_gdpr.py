"""Tests for GDPR service — pseudonymization, export, retention.

Coverage targets:
  - GDPRService initialization and request DB creation
  - Pseudonymization (Art.17): salt management, HMAC irreversibility, record update
  - Data export (Art.15): audit entries, security events, rate limit history
  - Retention enforcement: archive, encrypt, delete old entries
  - Data inventory (Art.30): complete category list
  - Request history (GDPR request log with pseudonymized subject_id)
  - Security: SQL LIKE wildcard escaping (L-12 fix)
  - Redis erasure (H-09 fix): rate limit keys, recent blocks
  - PostgreSQL backend selection (CRIT-A fix)
  - Edge cases: empty DB, nonexistent subject, concurrent salt creation
"""

import json
import os
import sqlite3
import tempfile
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

import pytest


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def gdpr_tmp_dirs(tmp_path, monkeypatch):
    """Override GDPR storage directories to use temp paths."""
    salt_dir = tmp_path / "gdpr_salts"
    archive_dir = tmp_path / "gdpr_archive"
    requests_db = tmp_path / "gdpr_requests.db"
    audit_db = tmp_path / "audit_log.db"

    monkeypatch.setattr("admin.services.gdpr.GDPR_SALT_DIR", salt_dir)
    monkeypatch.setattr("admin.services.gdpr.GDPR_ARCHIVE_DIR", archive_dir)
    monkeypatch.setattr("admin.services.gdpr.GDPR_REQUESTS_DB", requests_db)
    monkeypatch.setattr("admin.services.audit_logger.AUDIT_DB_PATH", str(audit_db))

    # Reset singleton so each test gets a fresh service
    monkeypatch.setattr("admin.services.gdpr._service", None)
    return {
        "salt_dir": salt_dir,
        "archive_dir": archive_dir,
        "requests_db": requests_db,
        "audit_db": audit_db,
    }


@pytest.fixture
async def audit_logger_with_data(gdpr_tmp_dirs):
    """Create a real audit logger with some test data."""
    from admin.services.audit_logger import AuditLogger

    audit = AuditLogger(db_path=str(gdpr_tmp_dirs["audit_db"]))
    await audit.initialize()

    # Insert test audit entries
    entries = [
        ("user-123", "login", "session", "sess-001", "success", "192.168.1.10",
         json.dumps({"tenant": "acme-corp"})),
        ("user-123", "update_policy", "policy", "pol-001", "success", "192.168.1.10",
         json.dumps({"tenant": "acme-corp", "user": "user-123"})),
        ("admin-456", "delete_user", "user", "user-123", "success", "10.0.0.1",
         json.dumps({"target": "user-123"})),
        ("other-user", "login", "session", "sess-999", "success", "172.16.0.5",
         json.dumps({"tenant": "other-corp"})),
    ]
    for actor, action, rtype, rid, result, ip, details in entries:
        await audit.log(
            actor=actor,
            action=action,
            resource_type=rtype,
            resource_id=rid,
            result=result,
            ip_address=ip,
            details=details,
        )
    return audit


@pytest.fixture
async def gdpr_service(gdpr_tmp_dirs, audit_logger_with_data):
    """Create an initialized GDPRService with test audit data."""
    from admin.services.gdpr import GDPRService

    service = GDPRService()
    await service.initialize()

    # Patch get_audit_logger to return our test instance
    with patch("admin.services.gdpr.get_audit_logger", return_value=audit_logger_with_data):
        yield service

    await service.close()


@pytest.fixture
def mock_redis():
    """Provide a mock Redis client."""
    client = MagicMock()
    client.get.return_value = None
    client.set.return_value = True
    client.keys.return_value = []
    client.lrange.return_value = []
    client.delete.return_value = 0
    client.lrem.return_value = 0
    client.sismember.return_value = False
    client.zrangebyscore.return_value = []
    return client


# ─── Initialization Tests ─────────────────────────────────────────────────────


class TestGDPRServiceInit:
    """Test GDPR service initialization."""

    @pytest.mark.asyncio
    async def test_initialize_creates_requests_table(self, gdpr_tmp_dirs):
        """Initialize should create gdpr_requests table with indexes."""
        from admin.services.gdpr import GDPRService

        service = GDPRService()
        await service.initialize()

        assert service._requests_conn is not None
        # Verify table exists
        cursor = service._requests_conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='gdpr_requests'"
        )
        assert cursor.fetchone() is not None

        # Verify indexes
        cursor = service._requests_conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_gdpr%'"
        )
        indexes = [row[0] for row in cursor.fetchall()]
        assert "idx_gdpr_subject" in indexes
        assert "idx_gdpr_type" in indexes

        await service.close()

    @pytest.mark.asyncio
    async def test_initialize_creates_directories(self, gdpr_tmp_dirs):
        """Initialize should create salt and archive directories."""
        from admin.services.gdpr import GDPRService, GDPR_SALT_DIR, GDPR_ARCHIVE_DIR

        service = GDPRService()
        await service.initialize()
        assert GDPR_SALT_DIR.exists()
        assert GDPR_ARCHIVE_DIR.exists()
        await service.close()

    @pytest.mark.asyncio
    async def test_close_nullifies_connection(self, gdpr_tmp_dirs):
        """Close should close the SQLite connection."""
        from admin.services.gdpr import GDPRService

        service = GDPRService()
        await service.initialize()
        assert service._requests_conn is not None
        await service.close()
        assert service._requests_conn is None


# ─── Pseudonymization Tests (Art.17) ─────────────────────────────────────────


class TestPseudonymization:
    """Test GDPR Art.17 Right to Erasure via pseudonymization."""

    @pytest.mark.asyncio
    async def test_pseudonymize_replaces_pii(self, gdpr_service, audit_logger_with_data):
        """Pseudonymization should replace all occurrences of subject_id."""
        with patch("admin.services.gdpr.get_audit_logger", return_value=audit_logger_with_data):
            with patch("admin.services.gdpr.get_redis_client", return_value=None):
                result = await gdpr_service.pseudonymize_subject(
                    subject_id="user-123",
                    requested_by="admin-dpo",
                    ip_address="10.0.0.1",
                )

        assert result["status"] == "completed"
        assert result["records_affected"] > 0
        assert result["irreversible"] is True

        # Verify original value no longer exists in audit log
        with audit_logger_with_data._lock:
            rows = audit_logger_with_data._conn.execute(
                "SELECT * FROM audit_log WHERE actor = ?", ("user-123",)
            ).fetchall()
            assert len(rows) == 0  # Should be pseudonymized

    @pytest.mark.asyncio
    async def test_pseudonymize_nonexistent_subject(self, gdpr_service, audit_logger_with_data):
        """Pseudonymizing a subject with no records returns 0 affected."""
        with patch("admin.services.gdpr.get_audit_logger", return_value=audit_logger_with_data):
            with patch("admin.services.gdpr.get_redis_client", return_value=None):
                result = await gdpr_service.pseudonymize_subject(
                    subject_id="nonexistent-user-xyz",
                    requested_by="admin-dpo",
                )

        assert result["status"] == "completed"
        assert result["records_affected"] == 0
        assert "No records found" in result["message"]

    @pytest.mark.asyncio
    async def test_pseudonymize_is_irreversible(self, gdpr_service, audit_logger_with_data, gdpr_tmp_dirs):
        """After pseudonymization, the salt is deleted — no recovery possible."""
        from admin.services.gdpr import GDPR_SALT_DIR
        import hashlib

        with patch("admin.services.gdpr.get_audit_logger", return_value=audit_logger_with_data):
            with patch("admin.services.gdpr.get_redis_client", return_value=None):
                await gdpr_service.pseudonymize_subject(
                    subject_id="user-123",
                    requested_by="admin-dpo",
                )

        # Salt file should be deleted after pseudonymization
        salt_hash = hashlib.sha256(b"user-123").hexdigest()
        salt_file = GDPR_SALT_DIR / f"{salt_hash}.salt"
        assert not salt_file.exists()

    @pytest.mark.asyncio
    async def test_pseudonymize_with_redis_erasure(self, gdpr_service, audit_logger_with_data, mock_redis):
        """Pseudonymization should also erase Redis keys containing subject."""
        mock_redis.keys.return_value = ["sentinel:ratelimit:user-123"]
        mock_redis.lrange.return_value = [
            json.dumps({"tenant": "user-123", "description": "blocked"}),
            json.dumps({"tenant": "other-user", "description": "blocked"}),
        ]

        with patch("admin.services.gdpr.get_audit_logger", return_value=audit_logger_with_data):
            with patch("admin.services.gdpr.get_redis_client", return_value=mock_redis):
                result = await gdpr_service.pseudonymize_subject(
                    subject_id="user-123",
                    requested_by="admin-dpo",
                )

        assert result["status"] == "completed"
        # Redis key deletion called
        mock_redis.delete.assert_called()
        # Matching entry removed from recent_blocks
        mock_redis.lrem.assert_called()


# ─── Salt Management Tests ────────────────────────────────────────────────────


class TestSaltManagement:
    """Test salt generation, storage, and deletion."""

    def test_salt_created_on_first_access(self, gdpr_service, gdpr_tmp_dirs):
        """First access to a subject's salt should generate and store it."""
        from admin.services.gdpr import GDPR_SALT_DIR
        import hashlib

        with patch("admin.services.gdpr.get_redis_client", return_value=None):
            salt = gdpr_service._get_or_create_salt("new-subject")

        assert isinstance(salt, bytes)
        assert len(salt) == 32

        # Should be persisted to file
        salt_hash = hashlib.sha256(b"new-subject").hexdigest()
        salt_file = GDPR_SALT_DIR / f"{salt_hash}.salt"
        assert salt_file.exists()

    def test_salt_reused_on_second_access(self, gdpr_service, gdpr_tmp_dirs):
        """Second access should return the same salt."""
        with patch("admin.services.gdpr.get_redis_client", return_value=None):
            salt1 = gdpr_service._get_or_create_salt("repeat-subject")
            salt2 = gdpr_service._get_or_create_salt("repeat-subject")

        assert salt1 == salt2

    def test_salt_deletion(self, gdpr_service, gdpr_tmp_dirs):
        """_delete_salt should remove both file and Redis key."""
        import hashlib
        from admin.services.gdpr import GDPR_SALT_DIR

        with patch("admin.services.gdpr.get_redis_client", return_value=None):
            gdpr_service._get_or_create_salt("delete-me")

        salt_hash = hashlib.sha256(b"delete-me").hexdigest()
        salt_file = GDPR_SALT_DIR / f"{salt_hash}.salt"
        assert salt_file.exists()

        with patch("admin.services.gdpr.get_redis_client", return_value=None):
            gdpr_service._delete_salt("delete-me")

        assert not salt_file.exists()

    def test_salt_redis_priority(self, gdpr_service, mock_redis):
        """Redis should be preferred over file for salt storage."""
        mock_redis.get.return_value = None
        mock_redis.set.return_value = True  # NX set succeeded

        with patch("admin.services.gdpr.get_redis_client", return_value=mock_redis):
            salt = gdpr_service._get_or_create_salt("redis-subject")

        assert isinstance(salt, bytes)
        assert len(salt) == 32
        mock_redis.set.assert_called_once()


# ─── Data Export Tests (Art.15) ───────────────────────────────────────────────


class TestDataExport:
    """Test GDPR Art.15 Right of Access via data export."""

    @pytest.mark.asyncio
    async def test_export_returns_audit_entries(self, gdpr_service, audit_logger_with_data):
        """Export should include audit entries for the subject."""
        with patch("admin.services.gdpr.get_audit_logger", return_value=audit_logger_with_data):
            with patch("admin.services.gdpr.get_redis_client", return_value=None):
                result = await gdpr_service.export_subject_data(
                    subject_id="user-123",
                    requested_by="admin-dpo",
                )

        assert "audit_entries" in result
        assert len(result["audit_entries"]) > 0
        assert "audit_log" in result["data_categories"]
        assert result["total_records"] > 0

    @pytest.mark.asyncio
    async def test_export_empty_subject(self, gdpr_service, audit_logger_with_data):
        """Export for unknown subject returns empty results."""
        with patch("admin.services.gdpr.get_audit_logger", return_value=audit_logger_with_data):
            with patch("admin.services.gdpr.get_redis_client", return_value=None):
                result = await gdpr_service.export_subject_data(
                    subject_id="nonexistent-user-abc",
                    requested_by="admin-dpo",
                )

        assert result["total_records"] == 0

    @pytest.mark.asyncio
    async def test_export_includes_security_events_from_redis(
        self, gdpr_service, audit_logger_with_data, mock_redis
    ):
        """Export should pull security events from Redis recent_blocks."""
        mock_redis.lrange.return_value = [
            json.dumps({"tenant_id": "user-123", "category": "prompt_injection", "description": "blocked"}),
            json.dumps({"tenant_id": "other-user", "category": "jailbreak", "description": "blocked"}),
        ]

        with patch("admin.services.gdpr.get_audit_logger", return_value=audit_logger_with_data):
            with patch("admin.services.gdpr.get_redis_client", return_value=mock_redis):
                result = await gdpr_service.export_subject_data(
                    subject_id="user-123",
                    requested_by="admin-dpo",
                    include_security_events=True,
                )

        assert "security_events" in result
        # Only the matching event should be included
        assert len(result["security_events"]) == 1

    @pytest.mark.asyncio
    async def test_export_selective_categories(self, gdpr_service, audit_logger_with_data):
        """Export should respect include/exclude flags."""
        with patch("admin.services.gdpr.get_audit_logger", return_value=audit_logger_with_data):
            with patch("admin.services.gdpr.get_redis_client", return_value=None):
                result = await gdpr_service.export_subject_data(
                    subject_id="user-123",
                    requested_by="admin-dpo",
                    include_audit_entries=True,
                    include_security_events=False,
                    include_rate_limit_history=False,
                )

        assert "audit_entries" in result
        assert "security_events" not in result
        assert "rate_limit_history" not in result


# ─── Retention Policy Tests ───────────────────────────────────────────────────


class TestRetentionPolicy:
    """Test GDPR retention policy enforcement."""

    @pytest.mark.asyncio
    async def test_retention_archives_old_entries(self, gdpr_service, audit_logger_with_data, gdpr_tmp_dirs):
        """Retention enforcement should archive entries older than cutoff."""
        from admin.services.gdpr import GDPR_ARCHIVE_DIR

        # Manually insert an old entry (with required payload_hash)
        old_ts = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
        with audit_logger_with_data._lock:
            audit_logger_with_data._conn.execute(
                "INSERT INTO audit_log (id, timestamp, actor, action, resource_type, resource_id, payload_hash, result) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("old-entry-001", old_ts, "old-user", "old-action", "test", "test-001", "sha256:placeholder", "success"),
            )

        with patch("admin.services.gdpr.get_audit_logger", return_value=audit_logger_with_data):
            with patch("admin.services.gdpr.get_redis_client", return_value=None):
                result = await gdpr_service.retention_policy_enforce(
                    requested_by="system-cron",
                )

        assert result["status"] == "completed"
        assert result["archived"] >= 1

        # Verify archive file created
        archive_files = list(GDPR_ARCHIVE_DIR.iterdir())
        assert len(archive_files) >= 1

    @pytest.mark.asyncio
    async def test_retention_no_old_entries(self, gdpr_service, audit_logger_with_data):
        """Retention enforcement with no old entries does nothing."""
        with patch("admin.services.gdpr.get_audit_logger", return_value=audit_logger_with_data):
            with patch("admin.services.gdpr.get_redis_client", return_value=None):
                result = await gdpr_service.retention_policy_enforce(
                    requested_by="system-cron",
                )

        # All test entries are fresh — nothing to archive
        assert result["archived"] == 0
        assert result["deleted"] == 0

    @pytest.mark.asyncio
    async def test_retention_status(self, gdpr_service):
        """get_retention_status should return configured values."""
        with patch("admin.services.gdpr.get_redis_client", return_value=None):
            status = await gdpr_service.get_retention_status()

        assert status.security_events_retention_days == 90
        assert status.audit_retention_days == 365


# ─── Data Inventory Tests (Art.30) ───────────────────────────────────────────


class TestDataInventory:
    """Test GDPR Art.30 data inventory."""

    @pytest.mark.asyncio
    async def test_inventory_returns_all_categories(self, gdpr_service):
        """Data inventory should list all processing categories."""
        inventory = await gdpr_service.data_inventory()

        assert len(inventory) == 7
        categories = [item["category"] for item in inventory]
        assert "audit_log" in categories
        assert "security_events" in categories
        assert "rate_limit_counters" in categories
        assert "request_metadata" in categories
        assert "authentication_data" in categories
        assert "tenant_configuration" in categories
        assert "gdpr_request_log" in categories

    @pytest.mark.asyncio
    async def test_inventory_has_required_fields(self, gdpr_service):
        """Each category must have all GDPR-required fields."""
        inventory = await gdpr_service.data_inventory()

        for item in inventory:
            assert "category" in item
            assert "description" in item
            assert "purpose" in item
            assert "legal_basis" in item
            assert "retention_period" in item
            assert "recipients" in item
            assert "contains_pii" in item
            assert "pseudonymizable" in item


# ─── Request History Tests ────────────────────────────────────────────────────


class TestRequestHistory:
    """Test GDPR request log."""

    @pytest.mark.asyncio
    async def test_requests_recorded_after_pseudonymize(self, gdpr_service, audit_logger_with_data):
        """A pseudonymization action should be recorded in GDPR request log."""
        with patch("admin.services.gdpr.get_audit_logger", return_value=audit_logger_with_data):
            with patch("admin.services.gdpr.get_redis_client", return_value=None):
                await gdpr_service.pseudonymize_subject(
                    subject_id="user-123",
                    requested_by="dpo-admin",
                )

        requests = await gdpr_service.get_requests(limit=10)
        assert len(requests) >= 1
        assert requests[0].request_type == "pseudonymize"
        assert requests[0].status == "completed"
        # subject_id should be pseudonymized in the log (H-08 fix)
        assert requests[0].subject_id != "user-123"

    @pytest.mark.asyncio
    async def test_requests_filter_by_type(self, gdpr_service, audit_logger_with_data):
        """Request history should be filterable by type."""
        with patch("admin.services.gdpr.get_audit_logger", return_value=audit_logger_with_data):
            with patch("admin.services.gdpr.get_redis_client", return_value=None):
                await gdpr_service.pseudonymize_subject("user-123", "admin")
                await gdpr_service.export_subject_data("user-123", "admin")

        export_requests = await gdpr_service.get_requests(request_type="export")
        assert all(r.request_type == "export" for r in export_requests)


# ─── Security Tests ───────────────────────────────────────────────────────────


class TestGDPRSecurity:
    """Security-specific GDPR tests."""

    @pytest.mark.asyncio
    async def test_sql_like_wildcard_escaped(self, gdpr_service, audit_logger_with_data):
        """Subject IDs with SQL wildcards (%, _) should be properly escaped (L-12 fix)."""
        with patch("admin.services.gdpr.get_audit_logger", return_value=audit_logger_with_data):
            with patch("admin.services.gdpr.get_redis_client", return_value=None):
                # This should NOT match all rows via SQL injection
                result = await gdpr_service.export_subject_data(
                    subject_id="%",  # SQL wildcard — should match nothing
                    requested_by="admin",
                )

        # "%" should not match everything — it should be escaped
        assert result["total_records"] == 0

    @pytest.mark.asyncio
    async def test_subject_id_with_underscore(self, gdpr_service, audit_logger_with_data):
        """Subject ID with _ wildcard should not match single-char positions."""
        with patch("admin.services.gdpr.get_audit_logger", return_value=audit_logger_with_data):
            with patch("admin.services.gdpr.get_redis_client", return_value=None):
                result = await gdpr_service.export_subject_data(
                    subject_id="user_123",  # _ is single-char wildcard in SQL
                    requested_by="admin",
                )

        # "user_123" should not match "user-123" (underscore escaped)
        assert result["total_records"] == 0

    def test_hash_value_is_deterministic(self, gdpr_service):
        """_hash_value should produce consistent output for same input."""
        salt = b"test-salt-32-bytes-exactly-here!"
        h1 = gdpr_service._hash_value("user@example.com", salt)
        h2 = gdpr_service._hash_value("user@example.com", salt)
        assert h1 == h2
        assert len(h1) == 32  # Truncated to 32 hex chars

    def test_hash_value_is_one_way(self, gdpr_service):
        """Different inputs should produce different hashes."""
        salt = b"test-salt-32-bytes-exactly-here!"
        h1 = gdpr_service._hash_value("user-a", salt)
        h2 = gdpr_service._hash_value("user-b", salt)
        assert h1 != h2

    @pytest.mark.asyncio
    async def test_redis_erasure_patterns(self, gdpr_service, audit_logger_with_data, mock_redis):
        """Redis erasure should scan correct key patterns (H-09 fix)."""
        mock_redis.keys.return_value = []
        mock_redis.lrange.return_value = []

        with patch("admin.services.gdpr.get_redis_client", return_value=mock_redis):
            await gdpr_service._erase_redis_subject_data("tenant-acme")

        # Verify correct patterns were scanned
        calls = [str(c) for c in mock_redis.keys.call_args_list]
        assert any("sentinel:ratelimit:*tenant-acme*" in c for c in calls)
        assert any("sentinel:quota:*tenant-acme*" in c for c in calls)
        assert any("sentinel:tenant:tenant-acme:*" in c for c in calls)


# ─── Factory Function Tests (CRIT-A fix) ─────────────────────────────────────


class TestFactoryFunction:
    """Test get_gdpr_service() backend selection."""

    def test_sqlite_selected_by_default(self, gdpr_tmp_dirs, monkeypatch):
        """Default (no PG URL) should use base GDPRService (SQLite)."""
        monkeypatch.setattr("admin.services.gdpr._service", None)
        monkeypatch.setattr("admin.services.database.ADMIN_DB_URL", "sqlite:///data/admin.db")

        from admin.services.gdpr import get_gdpr_service, GDPRService

        service = get_gdpr_service()
        assert type(service) is GDPRService

    def test_postgresql_selected_when_configured(self, gdpr_tmp_dirs, monkeypatch):
        """PostgreSQL URL should select PostgreSQLGDPRService."""
        monkeypatch.setattr("admin.services.gdpr._service", None)
        monkeypatch.setattr(
            "admin.services.database.ADMIN_DB_URL",
            "postgresql://user:pass@localhost/sentinel"
        )

        from admin.services.gdpr import get_gdpr_service, PostgreSQLGDPRService

        service = get_gdpr_service()
        assert isinstance(service, PostgreSQLGDPRService)

    def test_postgres_short_url_also_works(self, gdpr_tmp_dirs, monkeypatch):
        """postgres:// (short form) should also select PostgreSQL backend."""
        monkeypatch.setattr("admin.services.gdpr._service", None)
        monkeypatch.setattr(
            "admin.services.database.ADMIN_DB_URL",
            "postgres://user:pass@localhost/sentinel"
        )

        from admin.services.gdpr import get_gdpr_service, PostgreSQLGDPRService

        service = get_gdpr_service()
        assert isinstance(service, PostgreSQLGDPRService)


# ─── Edge Cases ───────────────────────────────────────────────────────────────


class TestEdgeCases:
    """Edge case and error handling tests."""

    @pytest.mark.asyncio
    async def test_get_requests_uninitialized(self, gdpr_tmp_dirs):
        """get_requests with no DB connection should return empty list."""
        from admin.services.gdpr import GDPRService

        service = GDPRService()
        # Don't initialize — _requests_conn is None
        result = await service.get_requests()
        assert result == []

    @pytest.mark.asyncio
    async def test_count_records_no_audit_conn(self, gdpr_service):
        """_count_subject_records with no audit DB should return 0."""
        mock_audit = MagicMock()
        mock_audit._conn = None

        with patch("admin.services.gdpr.get_audit_logger", return_value=mock_audit):
            count = await gdpr_service._count_subject_records("any-user")

        assert count == 0

    @pytest.mark.asyncio
    async def test_export_no_redis(self, gdpr_service, audit_logger_with_data):
        """Export should gracefully handle missing Redis for security events."""
        with patch("admin.services.gdpr.get_audit_logger", return_value=audit_logger_with_data):
            with patch("admin.services.gdpr.get_redis_client", return_value=None):
                result = await gdpr_service.export_subject_data(
                    subject_id="user-123",
                    requested_by="admin",
                    include_security_events=True,
                    include_rate_limit_history=True,
                )

        # Should complete without error, Redis-dependent sections return empty
        assert result["security_events"] == []
        assert result["rate_limit_history"] == []
