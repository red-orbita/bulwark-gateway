"""Small shared helpers for outbound connectors (kept dependency-free)."""

from __future__ import annotations

from datetime import datetime, timezone


def iso_now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()
