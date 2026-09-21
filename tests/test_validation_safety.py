"""Offline validation admission tests; no services, images or host changes."""

from collections import namedtuple
from pathlib import Path

import pytest

from scripts import validation_safety as safety


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Do not initialize the unrelated admin database."""


@pytest.fixture
def root(tmp_path, monkeypatch):
    (tmp_path / "shared").mkdir()
    original = Path.read_text
    monkeypatch.setattr(Path, "read_text", lambda path, *a, **k:
                        "MemAvailable: 8388608 kB\n" if str(path) == "/proc/meminfo" else original(path, *a, **k))
    usage = namedtuple("Usage", "total used free")
    monkeypatch.setattr(safety.shutil, "disk_usage", lambda path: usage(20 * 1024**3, 0, 20 * 1024**3))
    return tmp_path


def test_exclusive_slot_and_release(root):
    with safety.validation_slot(root):
        with pytest.raises(RuntimeError, match="another_validation"):
            with safety.validation_slot(root):
                pytest.fail("Concurrent workload admitted")
    with safety.validation_slot(root):
        assert (root / "shared/.validation.lock").stat().st_mode & 0o777 == 0o600


def test_exception_releases_slot(root):
    with pytest.raises(ValueError):
        with safety.validation_slot(root):
            raise ValueError("synthetic interruption")
    with safety.validation_slot(root):
        pass


def test_memory_failure_prevents_work_and_releases_lock(root, monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(Path, "read_text", lambda *a, **k: "MemAvailable: 1024 kB\n")
        with pytest.raises(RuntimeError, match="memory_reserve"):
            with safety.validation_slot(root):
                pytest.fail("Low memory admitted")
    with safety.validation_slot(root):
        pass


def test_disk_failure_prevents_work(root, monkeypatch):
    usage = namedtuple("Usage", "free")
    monkeypatch.setattr(safety.shutil, "disk_usage", lambda path: usage(1024))
    with pytest.raises(RuntimeError, match="disk_reserve"):
        with safety.validation_slot(root):
            pytest.fail("Low disk admitted")


def test_symlink_lock_rejected(root):
    target = root / "unrelated"
    target.write_text("preserve")
    (root / "shared/.validation.lock").symlink_to(target)
    with pytest.raises(OSError):
        with safety.validation_slot(root):
            pytest.fail("Unsafe lock admitted")
    assert target.read_text() == "preserve"


def test_all_cli_runners_use_same_guard():
    root = Path(__file__).resolve().parents[1]
    for name in ("validation-live-stores.py", "validation-live-siem.py", "validation-load.py",
                 "validation-storage-sandbox.py", "chatbot-e2e-lab.py"):
        text = (root / "scripts" / name).read_text()
        assert "with validation_slot(ROOT):" in text
        assert "return _main()" in text


def test_images_include_license_and_context_excludes_models():
    root = Path(__file__).resolve().parents[1]
    for name in ("Dockerfile", "docker/Dockerfile.admin"):
        assert "COPY LICENSE LICENSING.md /app/" in (root / name).read_text()
    rules = (root / ".dockerignore").read_text().splitlines()
    assert "models/" in rules and "!LICENSING.md" in rules
    assert "!src/evaluation/data/NOTICE" in rules
