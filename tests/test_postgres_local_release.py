"""Run the exact CI release contracts on a uniquely owned local TLS database.

Opt-in only: BULWARK_DB_REVIEW_LIVE=1. No operator database URL is consumed.
"""

import pytest

from admin.services.migrations import run_migrations
from tests.test_postgres_release_contract import (  # noqa: F401
    test_attachment_migrations_scope_and_reclaimed_lease_fencing,
    test_bootstrap_v14_preserves_operator_password_and_rotates_explicit_secret,
    test_invalid_timestamp_rolls_back_without_corrupting_text,
    test_outbox_migrations_scope_fanout_and_ack_fencing,
    test_task_due_dates_match_sqlite_and_preserve_timestamp_looking_text,
    test_timestamp_codecs_preserve_text_and_real_timestamp_columns,
)
from tests.test_storage_database_live import local_pg as local_pg


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Never initialize the operator's user database."""


@pytest.fixture
async def pg_engine(local_pg):
    factory, _ = local_pg
    engine = factory()
    try:
        await engine.init()
        # This fixture is backed ONLY by local_pg's generated container/credential.
        await engine.execute_script("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        await run_migrations(engine)
        yield engine
    finally:
        await engine.close()
