"""Cross-backend store parity — real stores exercised on SQLite *and* live PG.

``tests/test_postgres_parity.py`` proves the low-level engine (placeholder
translation, upsert rewrite, ``23505`` classification, transactions) behaves on
asyncpg. This module goes one level up: it drives an actual admin store
(:class:`CaseStore` + :class:`ObservableStore`) end-to-end against *both*
backends and asserts the store's public contract is backend-agnostic.

Every test runs twice via the parametrized ``store_engine`` fixture:

* ``sqlite``   — a throwaway migrated SQLite file (always runs);
* ``postgresql`` — a real migrated PostgreSQL, skipped unless
  ``BULWARK_TEST_POSTGRES_URL`` is set (CI provisions one).

This is the harness that catches genuine dialect divergences in *store* code —
e.g. a ``TIMESTAMPTZ`` column handing back a ``datetime`` on PostgreSQL where
SQLite (a ``TEXT`` column) hands back an ISO string. Such a mismatch would let a
store's JSON contract silently differ between backends; asserting parity here
locks it down.
"""

from __future__ import annotations

import pytest

from tests.conftest import postgres_test_url

pytestmark = pytest.mark.asyncio


@pytest.fixture(params=["sqlite", "postgresql"])
async def store_engine(request, tmp_path):
    """A migrated engine for each backend. The ``postgresql`` leg skips cleanly
    unless a throwaway PostgreSQL DSN is provided."""
    from admin.services.database import PostgreSQLEngine, create_engine
    from admin.services.migrations import run_migrations

    if request.param == "sqlite":
        eng = create_engine(f"sqlite:///{tmp_path / 'store_parity.db'}")
        await eng.init()
        await run_migrations(eng)
        try:
            yield eng
        finally:
            await eng.close()
        return

    # PostgreSQL leg
    url = postgres_test_url()
    if not url:
        pytest.skip("BULWARK_TEST_POSTGRES_URL not set — live PostgreSQL leg skipped")
    try:
        import asyncpg  # noqa: F401  (availability probe)
    except ImportError:
        pytest.skip("asyncpg not installed — install the `postgres` extra")

    eng = PostgreSQLEngine(url)
    await eng.init()
    await eng.execute_script("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
    await run_migrations(eng)
    try:
        yield eng
    finally:
        await eng.close()


@pytest.fixture
async def case_store(store_engine, monkeypatch):
    from admin.services import investigation_case_store as store_mod
    from admin.services.investigation_case_store import CaseStore

    monkeypatch.setattr(store_mod, "get_database", lambda: store_engine)
    return CaseStore()


@pytest.fixture
async def observable_store(store_engine, monkeypatch):
    from admin.services import investigation_observable_store as store_mod
    from admin.services.investigation_observable_store import ObservableStore

    monkeypatch.setattr(store_mod, "get_database", lambda: store_engine)
    return ObservableStore()


async def test_case_create_roundtrip_is_backend_agnostic(case_store):
    """A created case reads back identically regardless of backend, and its
    ISO-8601 timestamp columns are plain strings on both (not a datetime on PG)."""
    case = await case_store.create_case(
        title="Parity probe", actor="tester", severity="high", tenant="acme",
    )
    fetched = await case_store.get(case["case_id"])
    assert fetched is not None
    assert fetched["title"] == "Parity probe"
    assert fetched["severity"] == "high"
    assert fetched["status"] == "open"
    # The store's public contract is ISO strings. On PostgreSQL these columns are
    # TIMESTAMPTZ, so asyncpg would hand back datetime objects unless the store
    # normalizes them — assert the string contract holds on BOTH backends.
    assert isinstance(fetched["created_at"], str)
    assert isinstance(fetched["updated_at"], str)


async def test_observable_add_roundtrip_is_backend_agnostic(case_store, observable_store):
    """Add → get → list round-trips a real observable identically on both
    backends, including JSON tags, the is_ioc INTEGER→bool flag, and the
    TIMESTAMPTZ/TEXT first_seen/last_seen columns."""
    case = await case_store.create_case(title="Obs case", actor="tester")
    obs = await observable_store.add(
        case_id=case["case_id"],
        observable_type="domain",
        value="Evil.Example.COM",
        actor="tester",
        is_ioc=True,
        tags=["c2", "phishing"],
    )
    assert obs["is_ioc"] is True
    assert obs["type"] == "domain"
    # normalise_value lowercases the domain — same on both backends.
    assert obs["value"] == "evil.example.com"
    assert obs["tags"] == ["c2", "phishing"]
    assert isinstance(obs["first_seen"], str)
    assert isinstance(obs["last_seen"], str)

    listed = await observable_store.list_for_case(case["case_id"])
    assert len(listed) == 1
    assert listed[0]["observable_id"] == obs["observable_id"]
    assert listed[0]["is_ioc"] is True
    assert isinstance(listed[0]["first_seen"], str)


async def test_observable_add_is_idempotent_per_case_type_value(case_store, observable_store):
    """Re-adding the same (case, type, value) refreshes rather than duplicating —
    the race-safe upsert path must behave the same on SQLite and PostgreSQL."""
    case = await case_store.create_case(title="Dedup case", actor="tester")
    first = await observable_store.add(
        case_id=case["case_id"], observable_type="ip", value="10.0.0.9", actor="a",
    )
    second = await observable_store.add(
        case_id=case["case_id"], observable_type="ip", value="10.0.0.9", actor="b",
        is_ioc=True,
    )
    assert first["observable_id"] == second["observable_id"]
    assert second["is_ioc"] is True

    listed = await observable_store.list_for_case(case["case_id"])
    assert len(listed) == 1
