"""Shared bounded-time policy for vulnerability DB metadata and scan timestamps."""

from datetime import datetime, timedelta, timezone


def validate_database_metadata(metadata, now=None):
    """Require current vendor data; downloading an old database is not freshness."""
    now = now or datetime.now(timezone.utc)
    try:
        if not isinstance(metadata, dict) or type(metadata.get("Version")) is not int or metadata["Version"] != 2:
            raise ValueError("Invalid metadata")
        updated, downloaded, next_update = [datetime.fromisoformat(metadata[field].replace("Z", "+00:00"))
                                            for field in ("UpdatedAt", "DownloadedAt", "NextUpdate")]
        if any(value.tzinfo is None for value in (updated, downloaded, next_update)):
            raise ValueError("Missing timezone")
        if (not now - timedelta(hours=24) <= updated <= now + timedelta(minutes=5)
                or not updated - timedelta(minutes=5) <= downloaded <= now + timedelta(minutes=5)
                or next_update <= now or next_update <= updated):
            raise ValueError("Stale metadata")
    except (KeyError, AttributeError, TypeError, ValueError, OverflowError):
        raise ValueError("Vulnerability database is stale or metadata is invalid; refresh before scanning") from None


def validate_scan_freshness(scan, metadata, *, current):
    """Historic verification checks scan-time validity; signing/deploy also check now."""
    try:
        created = datetime.fromisoformat(scan["CreatedAt"].replace("Z", "+00:00"))
        downloaded = datetime.fromisoformat(metadata["DownloadedAt"].replace("Z", "+00:00"))
        if created.tzinfo is None or downloaded.tzinfo is None or created < downloaded - timedelta(minutes=5):
            raise ValueError("Scan predates database download")
        validate_database_metadata(metadata, created)
        if current:
            now = datetime.now(timezone.utc)
            if not now - timedelta(hours=24) <= created <= now + timedelta(minutes=5):
                raise ValueError("Scan is stale")
            validate_database_metadata(metadata, now)
    except (KeyError, AttributeError, TypeError, ValueError, OverflowError):
        raise ValueError("Scan/database freshness validation failed") from None
