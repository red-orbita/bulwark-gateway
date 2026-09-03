"""Tests for declarative service-account seeding (Phase 3.2d).

Covers both halves of the startup-seeding path against a real migrated SQLite
database (migration v10+):

* :meth:`ServiceAccountStore.seed_from_spec` — provisioning from an
  OPERATOR-SUPPLIED key (hashed at rest, verifiable, idempotent by key hash),
  and its input validation (key shape + grantable-permission whitelist); and
* :func:`seed_service_accounts` — the best-effort startup driver that reads the
  ``BULWARK_SERVICE_ACCOUNTS_SEED[_FILE]`` spec, skips bad entries, and never
  raises.
"""

from __future__ import annotations

import hashlib

import pytest

# A well-formed operator-supplied seed key: bwk_sa_ + 48 lowercase-hex chars.
_GOOD_KEY = "bwk_sa_" + "a1b2c3d4" * 6
_GOOD_KEY_2 = "bwk_sa_" + "0f1e2d3c" * 6


# ─── shared fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
async def engine(tmp_path):
    """A migrated throwaway SQLite engine shared by the store fixtures."""
    from admin.services.database import create_engine
    from admin.services.migrations import run_migrations

    eng = create_engine(f"sqlite:///{tmp_path / 'svc_seed_test.db'}")
    await eng.init()
    await run_migrations(eng)
    try:
        yield eng
    finally:
        await eng.close()


@pytest.fixture
async def store(engine, monkeypatch):
    from admin.services import service_account_store as mod
    from admin.services.service_account_store import ServiceAccountStore

    monkeypatch.setattr(mod, "get_database", lambda: engine)
    return ServiceAccountStore()


# ═══════════════════════════════════════════════════════════════════════════
# ServiceAccountStore.seed_from_spec
# ═══════════════════════════════════════════════════════════════════════════


class TestSeedFromSpec:
    async def test_seeds_operator_key_hashed_at_rest(self, store, engine):
        account_id = await store.seed_from_spec(
            name="shuffle-soar",
            permissions=["investigation:write", "automation:respond"],
            raw_key=_GOOD_KEY,
        )
        assert account_id is not None
        assert account_id.startswith("sa_")

        # The raw key is never persisted — only its SHA-256.
        row = await engine.fetch_one(
            "SELECT key_hash, key_prefix, created_by FROM service_account "
            "WHERE account_id = ?",
            [account_id],
        )
        assert row["key_hash"] == hashlib.sha256(_GOOD_KEY.encode()).hexdigest()
        assert row["key_prefix"] == _GOOD_KEY[:15]
        assert row["created_by"] == "startup-seed"

    async def test_seeded_key_verifies(self, store):
        await store.seed_from_spec(
            name="playbook",
            permissions=["investigation:write"],
            raw_key=_GOOD_KEY,
        )
        account = await store.verify(_GOOD_KEY)
        assert account is not None
        assert account["name"] == "playbook"
        assert account["permissions"] == ["investigation:write"]

    async def test_idempotent_by_key_hash(self, store):
        first = await store.seed_from_spec(
            name="soar",
            permissions=["investigation:write"],
            raw_key=_GOOD_KEY,
        )
        # Re-seeding the SAME key is a no-op (returns None), no duplicate row.
        second = await store.seed_from_spec(
            name="soar-renamed",
            permissions=["automation:respond"],
            raw_key=_GOOD_KEY,
        )
        assert first is not None
        assert second is None
        accounts = await store.list_accounts()
        assert len(accounts) == 1
        # The original account is untouched.
        assert accounts[0]["name"] == "soar"

    async def test_rejects_weak_key_shape(self, store):
        for bad in ["", "not-a-key", "bwk_sa_short", "bwk_sa_" + "A" * 40]:
            with pytest.raises(ValueError):
                await store.seed_from_spec(
                    name="x", permissions=["investigation:write"], raw_key=bad
                )

    async def test_rejects_non_grantable_permission(self, store):
        with pytest.raises(ValueError):
            await store.seed_from_spec(
                name="x",
                permissions=["automation:manage"],  # deliberately not grantable
                raw_key=_GOOD_KEY,
            )

    async def test_rejects_empty_name(self, store):
        with pytest.raises(ValueError):
            await store.seed_from_spec(
                name="   ", permissions=["investigation:write"], raw_key=_GOOD_KEY
            )

    async def test_persists_rate_limit_and_expiry(self, store):
        account_id = await store.seed_from_spec(
            name="capped",
            permissions=["investigation:write"],
            raw_key=_GOOD_KEY,
            rate_limit_rpm=30,
            expires_at="2999-01-01T00:00:00+00:00",
        )
        account = await store.get(account_id)
        assert account["rate_limit_rpm"] == 30
        assert account["expires_at"] == "2999-01-01T00:00:00+00:00"


# ═══════════════════════════════════════════════════════════════════════════
# seed_service_accounts (startup driver)
# ═══════════════════════════════════════════════════════════════════════════


class TestSeedDriver:
    async def test_no_spec_is_noop(self, store, monkeypatch):
        from admin.services import service_account_seed as seed_mod

        monkeypatch.delenv("BULWARK_SERVICE_ACCOUNTS_SEED", raising=False)
        monkeypatch.delenv("BULWARK_SERVICE_ACCOUNTS_SEED_FILE", raising=False)
        created = await seed_mod.seed_service_accounts()
        assert created == 0

    async def test_seeds_from_env_spec(self, store, monkeypatch):
        import json

        from admin.services import service_account_seed as seed_mod

        spec = json.dumps([
            {
                "name": "shuffle",
                "permissions": ["investigation:write", "automation:respond"],
                "key": _GOOD_KEY,
                "rate_limit_rpm": 60,
            },
            {
                "name": "n8n",
                "permissions": ["investigation:write"],
                "key": _GOOD_KEY_2,
            },
        ])
        monkeypatch.setenv("BULWARK_SERVICE_ACCOUNTS_SEED", spec)
        created = await seed_mod.seed_service_accounts()
        assert created == 2

        # Idempotent: a second run creates nothing new.
        again = await seed_mod.seed_service_accounts()
        assert again == 0

        accounts = await store.list_accounts()
        assert {a["name"] for a in accounts} == {"shuffle", "n8n"}

    async def test_skips_bad_entries_but_seeds_good(self, store, monkeypatch):
        import json

        from admin.services import service_account_seed as seed_mod

        spec = json.dumps([
            {"name": "good", "permissions": ["investigation:write"], "key": _GOOD_KEY},
            {"name": "bad-key", "permissions": ["investigation:write"], "key": "nope"},
            {"name": "bad-perm", "permissions": ["automation:manage"], "key": _GOOD_KEY_2},
            "not-a-dict",
        ])
        monkeypatch.setenv("BULWARK_SERVICE_ACCOUNTS_SEED", spec)
        created = await seed_mod.seed_service_accounts()
        assert created == 1
        accounts = await store.list_accounts()
        assert [a["name"] for a in accounts] == ["good"]

    async def test_invalid_json_is_noop(self, store, monkeypatch):
        from admin.services import service_account_seed as seed_mod

        monkeypatch.setenv("BULWARK_SERVICE_ACCOUNTS_SEED", "{not valid json")
        created = await seed_mod.seed_service_accounts()
        assert created == 0

    async def test_non_array_spec_is_noop(self, store, monkeypatch):
        from admin.services import service_account_seed as seed_mod

        monkeypatch.setenv("BULWARK_SERVICE_ACCOUNTS_SEED", '{"name": "x"}')
        created = await seed_mod.seed_service_accounts()
        assert created == 0

    async def test_reads_from_file_variant(self, store, monkeypatch, tmp_path):
        import json

        from admin.services import service_account_seed as seed_mod

        spec_file = tmp_path / "sa_seed.json"
        spec_file.write_text(json.dumps([
            {"name": "from-file", "permissions": ["investigation:write"], "key": _GOOD_KEY},
        ]))
        monkeypatch.delenv("BULWARK_SERVICE_ACCOUNTS_SEED", raising=False)
        monkeypatch.setenv("BULWARK_SERVICE_ACCOUNTS_SEED_FILE", str(spec_file))
        created = await seed_mod.seed_service_accounts()
        assert created == 1
        accounts = await store.list_accounts()
        assert accounts[0]["name"] == "from-file"
