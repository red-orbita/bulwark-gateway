"""Offline build supply-chain contracts; no package download or operator data."""

import hashlib
import io
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from docker import fetch_runtime

ROOT = Path(__file__).parents[1]


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """No admin database."""


def test_snapshot_and_full_closure_are_pinned():
    index = ROOT / "docker/wolfi-APKINDEX.tar.gz"
    assert hashlib.sha256(index.read_bytes()).hexdigest() == fetch_runtime.INDEX_SHA256
    lines = [line for line in (ROOT / "docker/wolfi-runtime.lock").read_text().splitlines() if not line.startswith("#")]
    assert len(lines) == 30
    assert all(re.fullmatch(r"[a-f0-9]{64}  [a-z0-9.+_-]+\.apk", line) for line in lines)
    assert len(set(lines)) == len(lines)
    assert any("python-3.14-base-3.14.8_" in line for line in lines)
    assert not any("busybox" in line or "apk-tools" in line for line in lines)


@pytest.mark.parametrize("filename", ["Dockerfile", "docker/Dockerfile.admin", "docker/Dockerfile.candidate-tests"])
def test_same_signed_offline_root_is_used_everywhere(filename):
    source = (ROOT / filename).read_text()
    assert "FROM scratch" in source
    assert "COPY --from=runtime-root /rootfs/ /" in source
    assert "--network=none" in source and "--no-network" in source
    assert "--no-scripts" in source and "--repositories-file /dev/null" in source
    assert "--allow-untrusted" not in source
    assert "docker/wolfi-runtime.lock docker/wolfi-APKINDEX.tar.gz" in source
    assert "USER 65532:65532" in source


@pytest.fixture
def download(tmp_path, monkeypatch):
    lock = tmp_path / "runtime.lock"
    index = b"synthetic signed index"
    (tmp_path / "wolfi-APKINDEX.tar.gz").write_bytes(index)
    monkeypatch.setattr(fetch_runtime, "INDEX_SHA256", hashlib.sha256(index).hexdigest())
    data = b"synthetic package"
    lock.write_text(hashlib.sha256(data).hexdigest() + "  python-3.14-3.14.8-r0.apk\n")
    calls = []

    class Response(io.BytesIO):
        status = 200
        headers = {}

    def open_package(url, timeout):
        calls.append((url, timeout))
        return Response(data)

    monkeypatch.setattr(fetch_runtime.urllib.request, "build_opener",
                        lambda *args: SimpleNamespace(open=open_package))
    return SimpleNamespace(lock=lock, destination=tmp_path / "apks", calls=calls, data=data, response=Response)


def test_download_hash_and_exact_specs(download):
    d = download
    fetch_runtime.fetch(d.lock, d.destination)
    assert (d.destination / "python-3.14-3.14.8-r0.apk").read_bytes() == d.data
    assert (d.destination / "packages.txt").read_text() == "python-3.14=3.14.8-r0\n"
    assert d.calls == [(fetch_runtime.REPOSITORY + "python-3.14-3.14.8-r0.apk", 30)]


@pytest.mark.parametrize("fault", ["hash", "index", "duplicate", "traversal", "no_version", "size", "total", "status", "encoding"])
def test_fetch_fails_closed(download, monkeypatch, fault):
    d = download
    if fault == "hash":
        d.lock.write_text("0" * 64 + "  python-3.14-3.14.8-r0.apk\n")
    elif fault == "index":
        d.lock.with_name("wolfi-APKINDEX.tar.gz").write_bytes(b"tampered")
    elif fault == "duplicate":
        d.lock.write_text(d.lock.read_text() * 2)
    elif fault == "traversal":
        d.lock.write_text("0" * 64 + "  ../package.apk\n")
    elif fault == "no_version":
        d.lock.write_text("0" * 64 + "  package.apk\n")
    elif fault == "size":
        monkeypatch.setattr(fetch_runtime, "MAX_APK_BYTES", 1)
    elif fault == "total":
        monkeypatch.setattr(fetch_runtime, "MAX_TOTAL_BYTES", 1)
    elif fault == "status":
        d.response.status = 302
    elif fault == "encoding":
        d.response.headers = {"Content-Encoding": "gzip"}
    with pytest.raises(ValueError):
        fetch_runtime.fetch(d.lock, d.destination)


def test_redirect_refused():
    with pytest.raises(ValueError, match="redirects"):
        fetch_runtime.NoRedirect().redirect_request(None, None, 302, "", {}, "https://elsewhere.invalid")


@pytest.mark.parametrize("fault", [None, "extra", "version", "missing", "empty"])
def test_installed_os_inventory_must_equal_lock(tmp_path, monkeypatch, fault):
    from docker import verify_runtime

    (tmp_path / "wolfi-runtime.lock").write_text("0" * 64 + "  python-3.14-base-3.14.8-r0.apk\n")
    data = "P:python-3.14-base\nV:3.14.8-r0\n"
    if fault == "extra":
        data += "\nP:unreviewed\nV:1-r0\n"
    elif fault == "version":
        data = data.replace("3.14.8-r0", "3.15.0-r0")
    elif fault == "missing":
        data = ""
    elif fault == "empty":
        (tmp_path / "wolfi-runtime.lock").write_text("# no packages\n")
    original = Path.read_text
    monkeypatch.setattr(Path, "read_text", lambda self, *a, **kw: data if str(self) == "/lib/apk/db/installed"
                        else original(self, *a, **kw))
    if fault:
        with pytest.raises(ValueError, match="closure"):
            verify_runtime.verify_os_packages(tmp_path)
    else:
        assert verify_runtime.verify_os_packages(tmp_path) == 1
