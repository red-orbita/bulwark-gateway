"""Tests for the admin per-tenant quota surface.

Covers:
  - TenantQuotaInfo / TenantQuotaUpdate models
  - TenantManager get/update/clear quota CRUD with YAML persistence
  - merge semantics (omitted fields unchanged; empty allowed_models = all)
  - persisted shape is parseable by the proxy's AgentRegistry
  - RBAC permission wiring
"""

from __future__ import annotations

import pytest
import yaml

from admin.models.tenants import TenantQuotaUpdate
from admin.services.tenant_manager import TenantManager


@pytest.fixture
def mgr(tmp_path):
    """A TenantManager backed by a temp agents.yaml with two tenants."""
    cfg = tmp_path / "agents.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "defaults": {"backend_url": "http://ollama:11434", "timeout": 120.0},
                "tenants": {
                    "acme-corp": {
                        "_meta": {"name": "Acme", "status": "active"},
                        "agents": {},
                    },
                    "globex": {
                        "_meta": {"name": "Globex", "status": "active"},
                        "agents": {},
                        "quotas": {
                            "max_concurrent_requests": 5,
                            "max_tokens_per_day": 100000,
                            "priority_weight": 2.0,
                        },
                    },
                },
            }
        )
    )
    return TenantManager(config_path=cfg)


class TestQuotaRead:
    def test_unconfigured_tenant_returns_defaults(self, mgr):
        info = mgr.get_tenant_quotas("acme-corp")
        assert info is not None
        assert info.configured is False
        assert info.max_concurrent_requests == 0
        assert info.max_tokens_per_day == 0
        assert info.priority_weight == 1.0
        assert info.allowed_models is None

    def test_configured_tenant_reads_values(self, mgr):
        info = mgr.get_tenant_quotas("globex")
        assert info.configured is True
        assert info.max_concurrent_requests == 5
        assert info.max_tokens_per_day == 100000
        assert info.priority_weight == 2.0

    def test_missing_tenant_returns_none(self, mgr):
        assert mgr.get_tenant_quotas("does-not-exist") is None


class TestQuotaUpdate:
    def test_create_quota_block(self, mgr):
        req = TenantQuotaUpdate(
            max_concurrent_requests=10,
            max_tokens_per_day=50000,
            allowed_models=["gpt-4o", "tinyllama"],
        )
        info = mgr.update_tenant_quotas("acme-corp", req)
        assert info.configured is True
        assert info.max_concurrent_requests == 10
        assert info.max_tokens_per_day == 50000
        assert info.allowed_models == ["gpt-4o", "tinyllama"]

        # Persisted to disk
        raw = yaml.safe_load(mgr._config_path.read_text())
        q = raw["tenants"]["acme-corp"]["quotas"]
        assert q["max_concurrent_requests"] == 10
        assert q["allowed_models"] == ["gpt-4o", "tinyllama"]

    def test_merge_leaves_omitted_fields(self, mgr):
        # globex starts with concurrency=5, tokens=100000, weight=2.0
        req = TenantQuotaUpdate(max_tokens_per_day=200000)
        info = mgr.update_tenant_quotas("globex", req)
        assert info.max_tokens_per_day == 200000
        assert info.max_concurrent_requests == 5  # unchanged
        assert info.priority_weight == 2.0  # unchanged

    def test_empty_allowed_models_clears_to_all(self, mgr):
        mgr.update_tenant_quotas("globex", TenantQuotaUpdate(allowed_models=["gpt-4o"]))
        assert mgr.get_tenant_quotas("globex").allowed_models == ["gpt-4o"]
        # Empty list = revert to all models (None)
        info = mgr.update_tenant_quotas("globex", TenantQuotaUpdate(allowed_models=[]))
        assert info.allowed_models is None
        raw = yaml.safe_load(mgr._config_path.read_text())
        assert "allowed_models" not in raw["tenants"]["globex"]["quotas"]

    def test_update_missing_tenant_returns_none(self, mgr):
        assert mgr.update_tenant_quotas("ghost", TenantQuotaUpdate(max_tokens_per_day=1)) is None


class TestQuotaClear:
    def test_clear_removes_block(self, mgr):
        assert mgr.clear_tenant_quotas("globex") is True
        info = mgr.get_tenant_quotas("globex")
        assert info.configured is False
        raw = yaml.safe_load(mgr._config_path.read_text())
        assert "quotas" not in raw["tenants"]["globex"]

    def test_clear_unconfigured_is_false(self, mgr):
        assert mgr.clear_tenant_quotas("acme-corp") is False

    def test_clear_missing_tenant_is_false(self, mgr):
        assert mgr.clear_tenant_quotas("ghost") is False


class TestProxyCompatibility:
    """The shape we persist must be parseable by the proxy quota parser."""

    def test_persisted_shape_parses_into_tenant_quota_config(self, mgr):
        from src.middleware.quotas import TenantQuotaConfig

        mgr.update_tenant_quotas(
            "acme-corp",
            TenantQuotaUpdate(
                max_concurrent_requests=3,
                max_tokens_per_day=1000,
                max_request_size_bytes=4096,
                allowed_models=["tinyllama"],
                priority_weight=1.5,
            ),
        )
        raw = yaml.safe_load(mgr._config_path.read_text())
        q = raw["tenants"]["acme-corp"]["quotas"]
        # Mirror AgentRegistry.load() construction
        cfg = TenantQuotaConfig(
            max_concurrent_requests=q.get("max_concurrent_requests", 0),
            max_tokens_per_day=q.get("max_tokens_per_day", 0),
            max_request_size_bytes=q.get("max_request_size_bytes", 0),
            allowed_models=q.get("allowed_models"),
            priority_weight=q.get("priority_weight", 1.0),
            rate_limit_rpm=q.get("rate_limit_rpm", 0),
        )
        assert cfg.max_concurrent_requests == 3
        assert cfg.max_tokens_per_day == 1000
        assert cfg.max_request_size_bytes == 4096
        assert cfg.allowed_models == ["tinyllama"]
        assert cfg.priority_weight == 1.5

    def test_quotas_sibling_of_agents_not_under_meta(self, mgr):
        mgr.update_tenant_quotas("acme-corp", TenantQuotaUpdate(max_tokens_per_day=5))
        raw = yaml.safe_load(mgr._config_path.read_text())
        tenant = raw["tenants"]["acme-corp"]
        assert "quotas" in tenant
        assert "quotas" not in tenant.get("_meta", {})


class TestRbacWiring:
    def test_permissions_assigned(self):
        from admin.models.auth import ROLE_PERMISSIONS, UserRole

        assert "quotas:read" in ROLE_PERMISSIONS[UserRole.ADMIN]
        assert "quotas:write" in ROLE_PERMISSIONS[UserRole.ADMIN]
        assert "quotas:write" in ROLE_PERMISSIONS[UserRole.SECURITY]
        # Auditors/viewers read-only
        assert "quotas:read" in ROLE_PERMISSIONS[UserRole.AUDITOR]
        assert "quotas:write" not in ROLE_PERMISSIONS[UserRole.AUDITOR]
        assert "quotas:read" in ROLE_PERMISSIONS[UserRole.VIEWER]
        assert "quotas:write" not in ROLE_PERMISSIONS[UserRole.VIEWER]
