"""Offline release authenticity tests with ephemeral keys; no production signing."""

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@pytest.fixture
def verifier(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    name = "bulwark_release_verifier_test"
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / "scripts/verify-release.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    yield module
    sys.modules.pop(name, None)


@pytest.fixture
def release(tmp_path, verifier):
    private = Ed25519PrivateKey.generate()
    artifact = tmp_path / "package.tar"
    artifact.write_bytes(b"safe inert fixture")
    payload = {"schema_version": 1, "revision": "a" * 40, "artifacts": [{
        "name": artifact.name, "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "size": artifact.stat().st_size,
    }]}
    manifest, signature, public = tmp_path / "release.json", tmp_path / "release.sig", tmp_path / "trusted.pub"
    def sign(data):
        raw = json.dumps(data).encode()
        manifest.write_bytes(raw)
        signature.write_text(private.sign(verifier.DOMAIN + raw).hex())
    sign(payload)
    public.write_text(private.public_key().public_bytes_raw().hex())
    return artifact, payload, manifest, signature, public, sign


def test_valid_release_is_verified_without_execution(tmp_path, verifier, release):
    _, _, manifest, signature, public, _ = release
    result = verifier.verify_release(manifest, signature, public, tmp_path, "a" * 40)
    assert result["verified"] and result["artifacts"] == 1


@pytest.mark.parametrize("fault", ["artifact", "manifest", "key", "revision", "symlink", "missing"])
def test_tampered_or_wrong_release_rejected(tmp_path, verifier, release, fault):
    artifact, _, manifest, signature, public, _ = release
    revision = "a" * 40
    if fault == "artifact":
        artifact.write_bytes(b"tampered artifact!")
    elif fault == "manifest":
        manifest.write_bytes(manifest.read_bytes() + b" ")
    elif fault == "key":
        public.write_text(Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex())
    elif fault == "revision":
        revision = "b" * 40
    elif fault == "missing":
        artifact.unlink()
    else:
        real = tmp_path / "elsewhere"
        artifact.rename(real)
        artifact.symlink_to(real)
    with pytest.raises((OSError, ValueError, InvalidSignature)):
        verifier.verify_release(manifest, signature, public, tmp_path, revision)


@pytest.mark.parametrize("fault", ["traversal", "duplicate", "oversize", "extra", "negative", "wrong_version"])
def test_signed_invalid_manifest_rejected(tmp_path, verifier, release, fault):
    _, payload, manifest, signature, public, sign = release
    if fault == "traversal":
        payload["artifacts"][0]["name"] = "../outside"
    elif fault == "duplicate":
        payload["artifacts"] *= 2
    elif fault == "oversize":
        payload["artifacts"][0]["size"] = verifier.MAX_ARTIFACT_BYTES + 1
    elif fault == "negative":
        payload["artifacts"][0]["size"] = -1
    elif fault == "wrong_version":
        payload["schema_version"] = 2
    else:
        payload["run"] = "untrusted executable"
    sign(payload)
    with pytest.raises(ValueError):
        verifier.verify_release(manifest, signature, public, tmp_path, "a" * 40)


@pytest.mark.parametrize("fault", ["wrong_domain", "duplicate_key", "aggregate", "count", "directory", "fifo"])
def test_verification_boundaries(tmp_path, verifier, release, fault):
    artifact, payload, manifest, signature, public, sign = release
    if fault in ("wrong_domain", "duplicate_key"):
        private = Ed25519PrivateKey.generate()
        public.write_text(private.public_key().public_bytes_raw().hex())
        raw = manifest.read_bytes()
        if fault == "duplicate_key":
            raw = raw.replace(b'{"schema_version": 1,', b'{"schema_version": 1, "schema_version": 1,')
        manifest.write_bytes(raw)
        signature.write_text(private.sign((b"other-domain" if fault == "wrong_domain" else verifier.DOMAIN) + raw).hex())
    elif fault in ("aggregate", "count"):
        count = 5 if fault == "aggregate" else 129
        payload["artifacts"] = [{"name": f"part-{i}", "sha256": "a" * 64,
                                 "size": verifier.MAX_ARTIFACT_BYTES if fault == "aggregate" else 0} for i in range(count)]
        sign(payload)
    else:
        artifact.unlink()
        if fault == "directory":
            artifact.mkdir()
        else:
            import os
            os.mkfifo(artifact)
    with pytest.raises((OSError, ValueError, InvalidSignature)):
        verifier.verify_release(manifest, signature, public, tmp_path, "a" * 40)


def test_offline_manifest_cannot_authorize_image_deployment(tmp_path, verifier, release):
    _, _, manifest, signature, public, _ = release
    images = verifier.Images(proxy="ghcr.io/example/proxy@sha256:" + "a" * 64,
                             admin="ghcr.io/example/admin@sha256:" + "b" * 64)
    with pytest.raises(ValueError, match="images do not match"):
        verifier.verify_release(manifest, signature, public, tmp_path, "a" * 40, images)


@pytest.mark.parametrize("fault", ["short_revision", "bad_key_hex", "bad_signature_hex", "large_manifest", "key_fifo"])
def test_verification_rejects_invalid_inputs(tmp_path, verifier, release, fault):
    import os
    _, _, manifest, signature, public, _ = release
    revision = "a" * 40
    if fault == "short_revision":
        revision = "a" * 8
    elif fault == "bad_key_hex":
        public.write_text("z" * 64)
    elif fault == "bad_signature_hex":
        signature.write_text("z" * 128)
    elif fault == "large_manifest":
        manifest.write_bytes(b" " * (verifier.MAX_MANIFEST_BYTES + 1))
    else:
        public.unlink()
        os.mkfifo(public)
    with pytest.raises(ValueError):
        verifier.verify_release(manifest, signature, public, tmp_path, revision)
