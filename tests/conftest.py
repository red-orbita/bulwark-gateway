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
