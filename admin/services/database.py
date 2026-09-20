"""Compatibility exports and admin lifecycle for the shared database engines."""

from src.storage import database as _database
from src.storage.database import *  # noqa: F403 - preserve the shipped import API

_engine: _database.DatabaseEngine | None = None


def __getattr__(name: str):
    return getattr(_database, name)


def create_engine(url: str | None = None) -> _database.DatabaseEngine:  # type: ignore[no-redef]
    return _database.create_engine(url or ADMIN_DB_URL)  # noqa: F405


def get_database() -> _database.DatabaseEngine:
    if _engine is None:
        raise RuntimeError("Database not initialized. Call await init_database() during app startup.")
    return _engine


async def init_database(url: str | None = None) -> _database.DatabaseEngine:
    global _engine
    if _engine is not None and _engine._initialized:
        return _engine
    _engine = create_engine(url)
    await _engine.init()
    from .migrations import run_migrations
    await run_migrations(_engine)
    return _engine


async def close_database() -> None:
    global _engine
    if _engine is not None:
        await _engine.close()
        _engine = None
