"""Tests for scripts/download-models.py — provisioning + integrity plumbing.

Focus: the fastText language-ID download path (B-short / closes former L3) and
the security-relevant guarantees of the generic HTTPS downloader. Network is
never touched; the HTTP layer is monkeypatched.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

# The script has a hyphen in its name, so import it via importlib rather than a
# normal `import`.
_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "download-models.py"


@pytest.fixture(scope="module")
def dl():
    spec = importlib.util.spec_from_file_location("bulwark_download_models", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# download_url — HTTPS enforcement (security control)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://dl.fbaipublicfiles.com/x.ftz",  # plain HTTP
        "ftp://example.com/x.ftz",
        "file:///etc/passwd",
        "HtTp://sneaky.example/x",  # case-insensitivity
        "",
    ],
)
def test_download_url_refuses_non_https(dl, tmp_path, url):
    dest = tmp_path / "out.bin"
    assert dl.download_url(url, dest) is False
    assert not dest.exists()  # nothing written on refusal


def test_download_url_streams_and_publishes_on_success(dl, tmp_path, monkeypatch):
    """A successful HTTPS fetch writes the body to dest atomically."""
    import contextlib
    import io
    import urllib.request

    payload = b"fake-fasttext-model-bytes" * 10

    class _FakeResp(io.BytesIO):
        status = 200

    @contextlib.contextmanager
    def _fake_urlopen(url, timeout=0):  # noqa: ARG001
        yield _FakeResp(payload)

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)

    dest = tmp_path / "sub" / "lid.176.ftz"
    assert dl.download_url("https://dl.fbaipublicfiles.com/x.ftz", dest) is True
    assert dest.read_bytes() == payload


def test_download_url_returns_false_on_http_error(dl, tmp_path, monkeypatch):
    import contextlib
    import io
    import urllib.request

    class _FakeResp(io.BytesIO):
        status = 404

    @contextlib.contextmanager
    def _fake_urlopen(url, timeout=0):  # noqa: ARG001
        yield _FakeResp(b"nope")

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)

    dest = tmp_path / "out.ftz"
    assert dl.download_url("https://example.com/x", dest) is False
    assert not dest.exists()


# ---------------------------------------------------------------------------
# download_fasttext — wiring: correct URL, dest path, and manifest key
# ---------------------------------------------------------------------------


def test_download_fasttext_targets_official_url_and_pins_hash(dl, tmp_path, monkeypatch):
    captured: dict = {}

    def _fake_download_url(url, dest):
        captured["url"] = url
        captured["dest"] = dest
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"model")
        return True

    # Redirect the manifest to a temp file so we don't touch the repo's.
    manifest = tmp_path / "manifest.json"
    monkeypatch.setattr(dl, "download_url", _fake_download_url)
    monkeypatch.setattr(dl, "_MANIFEST_PATH", manifest)

    model_dir = tmp_path / "models"
    assert dl.download_fasttext(model_dir) is True

    # Downloaded from the canonical Facebook AI source, to <model_dir>/lid.176.ftz
    assert captured["url"] == dl._FASTTEXT_LID_URL
    assert captured["url"].startswith("https://")
    assert captured["dest"] == model_dir / "lid.176.ftz"

    # Hash recorded under the manifest key the model_manager expects (relative path)
    recorded = json.loads(manifest.read_text())
    assert "lid.176.ftz" in recorded
    assert len(recorded["lid.176.ftz"]) == 64  # sha256 hexdigest


def test_download_fasttext_propagates_download_failure(dl, tmp_path, monkeypatch):
    monkeypatch.setattr(dl, "download_url", lambda url, dest: False)
    monkeypatch.setattr(dl, "_MANIFEST_PATH", tmp_path / "manifest.json")
    assert dl.download_fasttext(tmp_path / "models") is False


# ---------------------------------------------------------------------------
# update_manifest — the TOFU / pinning trust anchor (re-used for lid.176.ftz)
# ---------------------------------------------------------------------------


def test_update_manifest_detects_tampering(dl, tmp_path, monkeypatch):
    manifest = tmp_path / "manifest.json"
    monkeypatch.setattr(dl, "_MANIFEST_PATH", manifest)

    f = tmp_path / "lid.176.ftz"
    f.write_bytes(b"trusted-bytes")

    # First download bootstraps the pin.
    assert dl.update_manifest(f, "lid.176.ftz") is True
    pinned = json.loads(manifest.read_text())["lid.176.ftz"]

    # Same bytes → integrity OK.
    assert dl.update_manifest(f, "lid.176.ftz") is True

    # Tampered bytes under a pinned key → refuse (fail-closed).
    f.write_bytes(b"malicious-swap")
    assert dl.update_manifest(f, "lid.176.ftz") is False
    # Manifest must NOT have been overwritten with the bad hash.
    assert json.loads(manifest.read_text())["lid.176.ftz"] == pinned


# ---------------------------------------------------------------------------
# verify_models — offline integrity audit (--verify), stdlib only, fail-closed
# ---------------------------------------------------------------------------


def _pin(dl, manifest: Path, model_dir: Path, key: str, data: bytes) -> None:
    """Write a model file under model_dir and pin its hash in the manifest."""
    target = model_dir / key
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    existing: dict = json.loads(manifest.read_text()) if manifest.exists() else {}
    existing[key] = dl._sha256(target)
    manifest.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n")


def test_verify_models_passes_when_all_hashes_match(dl, tmp_path, monkeypatch):
    manifest = tmp_path / "manifest.json"
    monkeypatch.setattr(dl, "_MANIFEST_PATH", manifest)
    model_dir = tmp_path / "models"

    _pin(dl, manifest, model_dir, "injection-classifier/model.onnx", b"onnx-bytes")
    _pin(dl, manifest, model_dir, "lid.176.ftz", b"fasttext-bytes")

    assert dl.verify_models(model_dir) is True


def test_verify_models_fails_on_hash_mismatch(dl, tmp_path, monkeypatch):
    manifest = tmp_path / "manifest.json"
    monkeypatch.setattr(dl, "_MANIFEST_PATH", manifest)
    model_dir = tmp_path / "models"

    _pin(dl, manifest, model_dir, "lid.176.ftz", b"trusted")
    # Swap the on-disk bytes without updating the manifest → tamper.
    (model_dir / "lid.176.ftz").write_bytes(b"swapped-bytes")

    assert dl.verify_models(model_dir) is False


def test_verify_models_fails_on_missing_file(dl, tmp_path, monkeypatch):
    manifest = tmp_path / "manifest.json"
    monkeypatch.setattr(dl, "_MANIFEST_PATH", manifest)
    model_dir = tmp_path / "models"

    _pin(dl, manifest, model_dir, "toxicity/model.onnx", b"present")
    # Pin a second entry but never write the file.
    m = json.loads(manifest.read_text())
    m["nli-classifier/model.onnx"] = "deadbeef" * 8
    manifest.write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")

    assert dl.verify_models(model_dir) is False


def test_verify_models_fails_when_manifest_absent(dl, tmp_path, monkeypatch):
    monkeypatch.setattr(dl, "_MANIFEST_PATH", tmp_path / "nope.json")
    assert dl.verify_models(tmp_path / "models") is False


def test_verify_models_fails_on_empty_manifest(dl, tmp_path, monkeypatch):
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}\n")
    monkeypatch.setattr(dl, "_MANIFEST_PATH", manifest)
    assert dl.verify_models(tmp_path / "models") is False

