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


# ---------------------------------------------------------------------------
# _pin_model_files — pins every load-bearing file, not just the ONNX weights
# ---------------------------------------------------------------------------


def test_pin_model_files_pins_all_load_bearing_files(dl, tmp_path, monkeypatch):
    manifest = tmp_path / "manifest.json"
    monkeypatch.setattr(dl, "_MANIFEST_PATH", manifest)
    dest = tmp_path / "models" / "injection-classifier"
    dest.mkdir(parents=True)
    (dest / "model.onnx").write_bytes(b"weights")
    (dest / "tokenizer.json").write_bytes(b"tok")
    (dest / "config.json").write_bytes(b"cfg")

    assert dl._pin_model_files(dest, "injection-classifier") is True

    recorded = json.loads(manifest.read_text())
    # Not just the weights — the tokenizer and config are pinned too, so a
    # poisoned tokenizer / reordered config is tamper-evident at load time.
    assert "injection-classifier/model.onnx" in recorded
    assert "injection-classifier/tokenizer.json" in recorded
    assert "injection-classifier/config.json" in recorded


def test_pin_model_files_skips_absent_config(dl, tmp_path, monkeypatch):
    manifest = tmp_path / "manifest.json"
    monkeypatch.setattr(dl, "_MANIFEST_PATH", manifest)
    dest = tmp_path / "models" / "some-model"
    dest.mkdir(parents=True)
    (dest / "model.onnx").write_bytes(b"weights")
    (dest / "tokenizer.json").write_bytes(b"tok")
    # No config.json on disk.

    assert dl._pin_model_files(dest, "some-model") is True

    recorded = json.loads(manifest.read_text())
    assert "some-model/model.onnx" in recorded
    assert "some-model/tokenizer.json" in recorded
    assert "some-model/config.json" not in recorded


def test_verify_models_skips_metadata_keys(dl, tmp_path, monkeypatch):
    """A ``_comment`` (or any ``_``-prefixed) meta key documents the manifest and
    must NOT be treated as a model file to hash — otherwise --verify always fails
    on the real repo manifest."""
    manifest = tmp_path / "manifest.json"
    monkeypatch.setattr(dl, "_MANIFEST_PATH", manifest)
    model_dir = tmp_path / "models"

    _pin(dl, manifest, model_dir, "toxicity/model.onnx", b"present")
    # Inject a metadata key alongside the real file entry.
    m = json.loads(manifest.read_text())
    m["_comment"] = "this is documentation, not a file"
    manifest.write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")

    # Verification passes: the meta key is ignored, the real file matches.
    assert dl.verify_models(model_dir) is True


# ---------------------------------------------------------------------------
# _scan_artifact_safety — supply-chain gate that runs BEFORE a hash is pinned
# ---------------------------------------------------------------------------


def _malicious_pickle() -> bytes:
    """Pickle bytes with an os.system __reduce__ gadget (serialize-only).

    ``pickle.dumps`` never executes the gadget — only unpickling would. The
    resulting bytes carry a REDUCE opcode wired to an os.system global import,
    i.e. the BWK-ART-PICKLE-RCE signature the artifact scanner detects
    statically (without deserializing).
    """
    import os
    import pickle

    class _Evil:
        def __reduce__(self):
            return (os.system, ("echo pwned",))

    return pickle.dumps(_Evil())


def test_scan_artifact_safety_blocks_malicious_pickle(dl, tmp_path):
    """A downloaded artifact carrying an RCE gadget is refused before pinning."""
    evil = tmp_path / "model.onnx"  # disguised as ONNX weights
    evil.write_bytes(_malicious_pickle())
    assert dl._scan_artifact_safety(evil) is False


def test_scan_artifact_safety_passes_benign_json(dl, tmp_path):
    """A legitimate JSON aux file (tokenizer/config) has no code surface → allowed."""
    tok = tmp_path / "tokenizer.json"
    tok.write_bytes(b'{"model": {"type": "BPE"}, "vocab": {}}')
    assert dl._scan_artifact_safety(tok) is True


def test_scan_artifact_safety_degrades_open_on_scan_error(dl, tmp_path, monkeypatch):
    """A scanner error must NOT block provisioning (hash pin stays primary gate)."""
    import src.scanners.artifacts.model_artifact_scanner as scanner

    def _boom(path, source=""):
        raise RuntimeError("scanner exploded")

    monkeypatch.setattr(scanner, "analyze_file", _boom)
    f = tmp_path / "model.onnx"
    f.write_bytes(b"whatever")
    assert dl._scan_artifact_safety(f) is True


def test_pin_model_files_refuses_malicious_artifact(dl, tmp_path, monkeypatch):
    """_pin_model_files rejects (and never pins) a model with a poisoned weight file."""
    manifest = tmp_path / "manifest.json"
    monkeypatch.setattr(dl, "_MANIFEST_PATH", manifest)
    dest = tmp_path / "models" / "injection-classifier"
    dest.mkdir(parents=True)
    dest.joinpath("model.onnx").write_bytes(_malicious_pickle())  # RCE gadget
    dest.joinpath("tokenizer.json").write_bytes(b"tok")

    assert dl._pin_model_files(dest, "injection-classifier") is False
    # Nothing was pinned — the scan blocks before update_manifest ever writes it,
    # so a malicious artifact never enters the trust anchor.
    assert not manifest.exists()


def test_download_fasttext_refuses_malicious_payload(dl, tmp_path, monkeypatch):
    """download_fasttext rejects a poisoned .ftz before pinning its hash."""
    def _fake_download_url(url, dest):
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(_malicious_pickle())  # upstream served an RCE gadget
        return True

    manifest = tmp_path / "manifest.json"
    monkeypatch.setattr(dl, "download_url", _fake_download_url)
    monkeypatch.setattr(dl, "_MANIFEST_PATH", manifest)

    assert dl.download_fasttext(tmp_path / "models") is False
    # The poisoned artifact was never recorded as trusted (scan blocks pre-pin).
    assert not manifest.exists()


# ---------------------------------------------------------------------------
# Committed manifest completeness — every model pins ALL load-bearing files
# ---------------------------------------------------------------------------


def test_committed_manifest_pins_aux_files_for_every_model():
    """The repo's config/model_manifest.json must pin tokenizer.json and
    config.json for every ONNX model directory it references, not just the
    weights. A model whose tokenizer/config is unpinned is unverifiable and would
    fail closed at load — or, worse, silently trusted if the gate were weaker."""
    manifest_path = (
        Path(__file__).resolve().parent.parent / "config" / "model_manifest.json"
    )
    manifest = json.loads(manifest_path.read_text())

    # Model subdirs are keys shaped "<subdir>/model.onnx" (fasttext is a bare file).
    subdirs = {
        key.split("/", 1)[0]
        for key in manifest
        if not key.startswith("_") and key.endswith("/model.onnx")
    }
    assert subdirs, "expected at least one ONNX model in the manifest"

    for subdir in subdirs:
        assert f"{subdir}/tokenizer.json" in manifest, (
            f"{subdir}: tokenizer.json not pinned (poisoned-tokenizer bypass risk)"
        )
        assert f"{subdir}/config.json" in manifest, (
            f"{subdir}: config.json not pinned (label-inversion risk)"
        )


