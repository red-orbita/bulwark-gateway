"""Tests for QueryTranslator — SQLite→PostgreSQL dialect translation.

Focus: the LIKE → ILIKE conversion (WS8). Queries are authored in the SQLite
dialect, where LIKE is case-insensitive for ASCII by default; PostgreSQL LIKE is
case-sensitive, so a verbatim translation silently drops rows. ILIKE restores
the case-insensitive contract the query authors rely on.
"""

from __future__ import annotations

from admin.services.database import QueryTranslator


def _pg(query: str, params=None):
    return QueryTranslator("postgresql").translate(query, params)


# ─── LIKE → ILIKE (case-insensitive parity with SQLite) ──────────────────────


def test_like_becomes_ilike_on_postgres():
    translated, _ = _pg("SELECT * FROM tenants WHERE name LIKE ?", ["%acme%"])
    assert "ILIKE" in translated
    assert "LIKE" in translated  # ILIKE contains LIKE — sanity only
    # No bare (non-I) LIKE operator remains.
    assert " LIKE " not in f" {translated} "


def test_like_conversion_is_case_insensitive_in_source():
    translated, _ = _pg("SELECT * FROM t WHERE col like ?", ["%x%"])
    assert "ILIKE" in translated
    assert " like " not in translated.lower().replace("ilike", "")


def test_not_like_becomes_not_ilike():
    translated, _ = _pg("SELECT * FROM t WHERE col NOT LIKE ?", ["%x%"])
    assert "NOT ILIKE" in translated


def test_like_conversion_is_idempotent_on_existing_ilike():
    """An already-ILIKE query must not become 'IILIKE'."""
    translated, _ = _pg("SELECT * FROM t WHERE col ILIKE ?", ["%x%"])
    assert "ILIKE" in translated
    assert "IILIKE" not in translated


def test_like_conversion_leaves_identifiers_untouched():
    """Column names embedding 'like' must not be rewritten."""
    translated, _ = _pg(
        "SELECT like_count, dislike FROM posts WHERE like_count > ?", [5]
    )
    assert "like_count" in translated
    assert "dislike" in translated
    assert "Ilike_count" not in translated
    assert "disIlike" not in translated


# ─── SQLite backend leaves LIKE untouched (no translation) ───────────────────


def test_sqlite_backend_keeps_like_verbatim():
    """SQLite LIKE is already case-insensitive; the translator is a no-op there."""
    query = "SELECT * FROM t WHERE col LIKE ?"
    translated, params = QueryTranslator("sqlite").translate(query, ["%x%"])
    assert translated == query  # untouched
    assert "ILIKE" not in translated
    assert params == ["%x%"]


# ─── LIKE conversion coexists with placeholder translation ───────────────────


def test_like_and_placeholder_conversion_together():
    translated, _ = _pg(
        "SELECT * FROM audit_log WHERE actor LIKE ? AND action LIKE ?",
        ["%admin%", "%delete%"],
    )
    # Placeholders converted to $1/$2 AND both operators are ILIKE.
    assert "$1" in translated and "$2" in translated
    assert translated.count("ILIKE") == 2
