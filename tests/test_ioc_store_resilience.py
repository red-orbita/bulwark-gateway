"""Regression tests for admin IOCStore resilience to corrupt persistence files.

A truncated/corrupt ``iocs.json`` (e.g. an interrupted feed write) previously
raised ``json.JSONDecodeError`` inside ``IOCStore._load()``, which propagated
through ``get_ioc_store()`` and bricked the entire IOC admin page
("Couldn't load indicators / The IOC store didn't respond").
"""

import json
from pathlib import Path

from admin.services.ioc_store import IOCStore


def _paths(tmp_path: Path) -> tuple[Path, Path]:
    return tmp_path / "iocs.json", tmp_path / "feed_state.json"


def test_valid_ioc_file_loads(tmp_path):
    ioc_path, feed_path = _paths(tmp_path)
    ioc_path.write_text(json.dumps({"domains": ["evil.example"], "ips": ["1.2.3.4"]}))

    store = IOCStore(ioc_path=ioc_path, feed_state_path=feed_path)
    entries, total = store.list()

    assert total == 2
    values = {e.value for e in entries}
    assert values == {"evil.example", "1.2.3.4"}


def test_corrupt_ioc_file_does_not_crash(tmp_path):
    ioc_path, feed_path = _paths(tmp_path)
    # Truncated JSON — unterminated string, mirrors the real production corruption.
    ioc_path.write_text('{"domains": ["evil.example", "truncated-here')

    # Must NOT raise.
    store = IOCStore(ioc_path=ioc_path, feed_state_path=feed_path)
    entries, total = store.list()

    assert total == 0
    assert entries == []


def test_corrupt_ioc_file_is_quarantined(tmp_path):
    ioc_path, feed_path = _paths(tmp_path)
    ioc_path.write_text('{"domains": [not valid json')

    IOCStore(ioc_path=ioc_path, feed_state_path=feed_path)

    # Original corrupt file moved aside so it can be inspected, not silently lost.
    assert not ioc_path.exists()
    quarantined = list(tmp_path.glob("iocs.json.corrupt-*"))
    assert len(quarantined) == 1
    assert "not valid json" in quarantined[0].read_text()


def test_store_usable_after_corruption_recovery(tmp_path):
    ioc_path, feed_path = _paths(tmp_path)
    ioc_path.write_text("}{ broken")

    store = IOCStore(ioc_path=ioc_path, feed_state_path=feed_path)

    from admin.models.iocs import IOCCreate, IOCType

    created = store.create(IOCCreate(type=IOCType.DOMAIN, value="added-after-recovery.example"))
    assert created.value == "added-after-recovery.example"

    # A fresh valid file was written back and reloads cleanly.
    reloaded = IOCStore(ioc_path=ioc_path, feed_state_path=feed_path)
    _, total = reloaded.list()
    assert total == 1


def test_corrupt_feed_state_does_not_crash(tmp_path):
    ioc_path, feed_path = _paths(tmp_path)
    ioc_path.write_text(json.dumps({"domains": ["evil.example"]}))
    feed_path.write_text('{"threatfox": {truncated')

    store = IOCStore(ioc_path=ioc_path, feed_state_path=feed_path)
    _, total = store.list()

    assert total == 1
    assert not feed_path.exists()
    assert len(list(tmp_path.glob("feed_state.json.corrupt-*"))) == 1


def test_non_object_json_is_treated_as_corrupt(tmp_path):
    ioc_path, feed_path = _paths(tmp_path)
    ioc_path.write_text("[1, 2, 3]")  # valid JSON, wrong shape

    store = IOCStore(ioc_path=ioc_path, feed_state_path=feed_path)
    _, total = store.list()

    assert total == 0
    assert len(list(tmp_path.glob("iocs.json.corrupt-*"))) == 1
