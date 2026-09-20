"""Separate historic artifact authenticity from current deployment authorization."""

import importlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


def test_historic_scan_verifies_but_cannot_authorize_new_deployment(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    policy = importlib.import_module("release_scan_policy")
    then = datetime.now(timezone.utc) - timedelta(days=5)
    metadata = {"Version": 2, "UpdatedAt": (then - timedelta(hours=1)).isoformat(),
                "DownloadedAt": then.isoformat(), "NextUpdate": (then + timedelta(hours=12)).isoformat()}
    scan = {"CreatedAt": then.isoformat()}
    policy.validate_scan_freshness(scan, metadata, current=False)
    with pytest.raises(ValueError, match="freshness"):
        policy.validate_scan_freshness(scan, metadata, current=True)


@pytest.mark.parametrize("timestamp", [None, 42, "2026-09-19T12:00:00", "invalid"])
def test_scan_timestamp_must_be_explicit_and_valid(monkeypatch, timestamp):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    policy = importlib.import_module("release_scan_policy")
    now = datetime.now(timezone.utc)
    metadata = {"Version": 2, "UpdatedAt": now.isoformat(), "DownloadedAt": now.isoformat(),
                "NextUpdate": (now + timedelta(hours=12)).isoformat()}
    with pytest.raises(ValueError, match="freshness"):
        policy.validate_scan_freshness({"CreatedAt": timestamp}, metadata, current=True)
