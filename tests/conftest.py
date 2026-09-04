"""Shared pytest fixtures and test configuration."""

import os

# Ensure debug mode for tests (allows insecure JWT secret)
os.environ.setdefault("ADMIN_DEBUG", "true")

import pytest


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Remove force_password_change flag from seeded users so tests can authenticate."""
    from admin.services.user_store import get_user_store

    store = get_user_store()
    store._conn.execute("UPDATE users SET force_password_change = 0")
    store._conn.commit()


# ─── Live PostgreSQL backend-parity harness ──────────────────────────────────
#
# The admin store is dual-backend (SQLite + PostgreSQL via
# admin/services/database.py), but historically only the SQLite path and the
# *string-level* QueryTranslator were exercised in tests — no test ever opened a
# real PostgreSQL connection. The `pg_engine` fixture closes that gap without
# disturbing the default SQLite-only local/CI run: it skips unless
# BULWARK_TEST_POSTGRES_URL points at a throwaway PostgreSQL (CI provisions one
# in a dedicated job).

POSTGRES_URL_ENV = "BULWARK_TEST_POSTGRES_URL"


def postgres_test_url() -> str | None:
    """Return the throwaway-PostgreSQL DSN for parity tests, or None if unset."""
    return os.environ.get(POSTGRES_URL_ENV) or None


@pytest.fixture
async def pg_engine():
    """A migrated, per-test-isolated live PostgreSQL engine for parity tests.

    Skips unless ``BULWARK_TEST_POSTGRES_URL`` is set (local SQLite dev is
    unaffected). The ``public`` schema is dropped + recreated per test so each
    test starts from a clean, fully migrated schema — mirroring the throwaway
    SQLite ``engine`` fixtures used elsewhere.
    """
    url = postgres_test_url()
    if not url:
        pytest.skip(f"{POSTGRES_URL_ENV} not set — live PostgreSQL parity test skipped")

    try:
        import asyncpg  # noqa: F401  (availability probe)
    except ImportError:
        pytest.skip("asyncpg not installed — install the `postgres` extra to run parity tests")

    from admin.services.database import PostgreSQLEngine
    from admin.services.migrations import run_migrations

    eng = PostgreSQLEngine(url)
    await eng.init()
    # Clean slate: a fresh schema per test keeps them isolated and forces the
    # full migration chain to run against an empty database every time.
    await eng.execute_script("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
    await run_migrations(eng)
    try:
        yield eng
    finally:
        await eng.close()
