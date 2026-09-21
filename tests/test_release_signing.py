"""Round-trip release tests use only ephemeral keys and inert synthetic reports."""

import importlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@pytest.fixture
def signer(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    return importlib.import_module("sign-release")


@pytest.fixture
def candidate(tmp_path, monkeypatch, signer):
    # Model a CI checkout distinct from runner secrets even when pytest's base
    # directory itself lives inside the developer workspace.
    checkout = tmp_path / "checkout" / "scripts"
    checkout.mkdir(parents=True)
    monkeypatch.setattr(signer, "__file__", str(checkout / "sign-release.py"))
    private = Ed25519PrivateKey.generate()
    key = tmp_path / "key"
    key.write_text(private.private_bytes_raw().hex())
    key.chmod(0o600)
    public = tmp_path / "trusted.pub"
    public.write_text(private.public_key().public_bytes_raw().hex())
    monkeypatch.setenv("BULWARK_RELEASE_SIGNING_KEY_FILE", str(key))
    scans = tmp_path / "scans"
    scans.mkdir()
    images = signer.verifier.Images(
        proxy="ghcr.io/example/proxy@sha256:" + "a" * 64,
        admin="ghcr.io/example/admin@sha256:" + "b" * 64,
    )
    for role, image in images.model_dump().items():
        now = datetime.now(timezone.utc)
        (scans / f"{role}-database.json").write_text(json.dumps({
            "Version": 2, "UpdatedAt": (now - timedelta(hours=1)).isoformat(),
            "DownloadedAt": now.isoformat(), "NextUpdate": (now + timedelta(hours=12)).isoformat()}))
        purls = ["pkg:deb/debian/libc6@2.41?arch=amd64", "pkg:pypi/fastapi@0.115.0"]
        (scans / f"{role}-scan.json").write_text(json.dumps({
            "SchemaVersion": 2, "ArtifactName": image, "ArtifactType": "container_image",
            "CreatedAt": now.isoformat(),
            "Metadata": {"ImageID": "sha256:" + "d" * 64, "OS": {"Family": "debian"}},
            "Results": [{"Class": "os-pkgs", "Type": "debian", "Vulnerabilities": [],
                         "Packages": [{"Identifier": {"PURL": purls[0]}}]},
                        {"Class": "lang-pkgs", "Type": "python-pkg", "Vulnerabilities": [],
                         "Packages": [{"Identifier": {"PURL": purls[1]}}]}],
        }))
        (scans / f"{role}.cdx.json").write_text(json.dumps({
            "bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
            "metadata": {"component": {"type": "container", "name": image, "bom-ref": "root",
                         "properties": [{"name": "aquasecurity:trivy:ImageID", "value": "sha256:" + "d" * 64}]}},
            "components": [{"type": "library", "name": purl, "version": "1", "purl": purl,
                            "bom-ref": purl} for purl in purls],
        }))
    return dict(revision="c" * 40, proxy_image=images.proxy, admin_image=images.admin,
                artifact_dir=scans, public_key_path=public, output_dir=tmp_path / "signed")


def verify(signer, candidate, **kwargs):
    return signer.verifier.verify_release(
        candidate["output_dir"] / "release.json", candidate["output_dir"] / "release.sig",
        candidate["public_key_path"], candidate["artifact_dir"], candidate["revision"],
        **kwargs,
    )


def test_sign_verify_build_digests(signer, candidate):
    assert signer.sign_release(**candidate)["signed"]
    images = signer.verifier.Images(proxy=candidate["proxy_image"], admin=candidate["admin_image"])
    result = verify(signer, candidate, expected_images=images)
    assert result["images"] == images.model_dump()
    assert result["artifacts"] == 6


def test_low_medium_findings_allowed(signer, candidate):
    path = candidate["artifact_dir"] / "admin-scan.json"
    report = json.loads(path.read_text())
    report["Results"][0]["Vulnerabilities"] = [{"Severity": value} for value in ("LOW", "MEDIUM")]
    path.write_text(json.dumps(report))
    signer.sign_release(**candidate)
    assert verify(signer, candidate)["verified"]


@pytest.mark.parametrize("fault", [
    "HIGH", "CRITICAL", "UNKNOWN", "missing_severity", "null_results", "empty_results",
    "missing_results", "wrong_digest", "wrong_type", "null_vulns", "symlink", "missing",
    "oversized", "duplicate_key", "bad_json", "bad_result", "bad_class", "null_vuln", "list",
    "missing_os", "missing_python", "wrong_language",
])
def test_refuse_bad_or_vulnerable_scans_before_reading_key(signer, candidate, monkeypatch, fault):
    path = candidate["artifact_dir"] / "proxy-scan.json"
    report = json.loads(path.read_text())
    if fault in ("HIGH", "CRITICAL", "UNKNOWN", "missing_severity"):
        report["Results"][0]["Vulnerabilities"] = [{} if fault == "missing_severity" else {"Severity": fault}]
    elif fault == "null_results":
        report["Results"] = None
    elif fault == "empty_results":
        report["Results"] = []
    elif fault == "missing_results":
        del report["Results"]
    elif fault == "wrong_digest":
        report["ArtifactName"] = candidate["admin_image"]
    elif fault == "wrong_type":
        report["ArtifactType"] = "filesystem"
    elif fault == "null_vulns":
        report["Results"][0]["Vulnerabilities"] = None
    elif fault == "missing_os":
        report["Results"] = report["Results"][1:]
    elif fault == "missing_python":
        report["Results"] = report["Results"][:1]
    elif fault == "wrong_language":
        report["Results"][1]["Type"] = "npm"
    elif fault == "bad_result":
        report["Results"] = [None]
    elif fault == "bad_class":
        report["Results"][0]["Class"] = "secret"
    elif fault == "null_vuln":
        report["Results"][0]["Vulnerabilities"] = [None]
    elif fault == "list":
        report = []
    path.write_text(json.dumps(report))
    if fault == "symlink":
        path.unlink()
        path.symlink_to(candidate["artifact_dir"] / "admin-scan.json")
    elif fault == "missing":
        path.unlink()
    elif fault == "oversized":
        monkeypatch.setattr(signer.verifier, "MAX_REPORT_BYTES", 1)
    elif fault == "duplicate_key":
        path.write_text('{"SchemaVersion": 2, "SchemaVersion": 2}')
    elif fault == "bad_json":
        path.write_text("not JSON")
    monkeypatch.delenv("BULWARK_RELEASE_SIGNING_KEY_FILE")
    with pytest.raises((ValueError, OSError)):
        signer.sign_release(**candidate)
    assert not candidate["output_dir"].exists()


@pytest.mark.parametrize("fault", ["absent", "encoding", "permissions", "mismatch", "symlink", "inside_artifacts", "inside_output", "inside_checkout"])
def test_private_key_fail_closed(signer, candidate, monkeypatch, fault):
    key = Path(os.environ["BULWARK_RELEASE_SIGNING_KEY_FILE"])
    if fault == "absent":
        monkeypatch.delenv("BULWARK_RELEASE_SIGNING_KEY_FILE")
    elif fault == "encoding":
        key.write_text("not-a-key")
    elif fault == "permissions":
        key.chmod(0o644)
    elif fault == "mismatch":
        candidate["public_key_path"].write_text(Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex())
    elif fault == "symlink":
        link = key.with_name("linked-key")
        link.symlink_to(key)
        monkeypatch.setenv("BULWARK_RELEASE_SIGNING_KEY_FILE", str(link))
    else:
        directory = (Path(signer.__file__).parents[1] if fault == "inside_checkout" else
                     candidate["artifact_dir"] if fault == "inside_artifacts" else candidate["output_dir"])
        directory.mkdir(exist_ok=True)
        moved = directory / "key"
        key.rename(moved)
        monkeypatch.setenv("BULWARK_RELEASE_SIGNING_KEY_FILE", str(moved))
    with pytest.raises((OSError, ValueError, KeyError)):
        signer.sign_release(**candidate)
    assert not (candidate["output_dir"] / "release.sig").exists()


@pytest.mark.parametrize("image", ["proxy:latest", "ghcr.io/proxy@sha256:abc", "https://user:pass@host/proxy", "\nmalicious", "gһcr.io/proxy@sha256:" + "a" * 64])
def test_reject_tags_credentials_and_adversarial_refs(signer, candidate, image):
    candidate["proxy_image"] = image
    with pytest.raises(ValueError):
        signer.sign_release(**candidate)


def test_reject_wrong_revision_and_existing_output(signer, candidate):
    with pytest.raises(ValueError):
        signer.sign_release(**dict(candidate, revision="short"))
    signer.sign_release(**candidate)
    with pytest.raises(FileExistsError):
        signer.sign_release(**candidate)


@pytest.mark.parametrize("fault", ["scan", "signature", "expected_digest", "signed_digest", "missing_scan", "vulnerable"])
def test_deploy_rechecks_signed_scans_and_expected_digests(signer, candidate, fault):
    signer.sign_release(**candidate)
    kwargs = {}
    if fault == "scan":
        (candidate["artifact_dir"] / "proxy-scan.json").write_text("tampered")
    elif fault == "signature":
        (candidate["output_dir"] / "release.sig").write_text("0" * 128)
    elif fault == "expected_digest":
        kwargs["expected_images"] = signer.verifier.Images(proxy=candidate["admin_image"], admin=candidate["proxy_image"])
    else:
        import hashlib
        manifest_path = candidate["output_dir"] / "release.json"
        manifest = json.loads(manifest_path.read_bytes())
        if fault == "signed_digest":
            manifest["images"]["proxy"] = candidate["admin_image"]
        elif fault == "missing_scan":
            manifest["artifacts"] = [a for a in manifest["artifacts"] if a["name"] != "admin-scan.json"]
        else:
            scan = candidate["artifact_dir"] / "proxy-scan.json"
            report = json.loads(scan.read_bytes())
            report["Results"][0]["Vulnerabilities"] = [{"Severity": "CRITICAL"}]
            scan.write_text(json.dumps(report))
            manifest["artifacts"][0].update(sha256=hashlib.sha256(scan.read_bytes()).hexdigest(), size=scan.stat().st_size)
        raw = json.dumps(manifest).encode()
        manifest_path.write_bytes(raw)
        private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(Path(os.environ["BULWARK_RELEASE_SIGNING_KEY_FILE"]).read_text()))
        (candidate["output_dir"] / "release.sig").write_text(private.sign(signer.verifier.DOMAIN + raw).hex())
    with pytest.raises((ValueError, InvalidSignature)):
        verify(signer, candidate, **kwargs)


def test_cli_helm_values_only_after_verification(signer, candidate, monkeypatch, capsys):
    signer.sign_release(**candidate)
    output = candidate["output_dir"] / "verified.json"
    args = ["verify-release.py", "--manifest", str(candidate["output_dir"] / "release.json"),
            "--signature", str(candidate["output_dir"] / "release.sig"),
            "--public-key", str(candidate["public_key_path"]), "--artifacts", str(candidate["artifact_dir"]),
            "--expected-revision", candidate["revision"], "--expected-proxy-image", candidate["proxy_image"],
            "--expected-admin-image", candidate["admin_image"], "--helm-values", str(output)]
    monkeypatch.setattr(sys, "argv", args)
    assert signer.verifier.main() == 0
    values = json.loads(output.read_text())
    assert values["proxy"]["image"] == {"repository": "ghcr.io/example/proxy", "digest": "sha256:" + "a" * 64}
    assert signer.verifier.main() == 1  # refuses overwrite
    output.unlink()
    (candidate["output_dir"] / "release.sig").write_text("invalid")
    assert signer.verifier.main() == 1
    assert not output.exists()
    assert "Release verification failed" in capsys.readouterr().err


def test_sign_cli_errors_do_not_leak_key(signer, candidate, monkeypatch, capsys):
    args = ["sign-release.py", "--revision", candidate["revision"],
            "--proxy-image", candidate["proxy_image"], "--admin-image", candidate["admin_image"],
            "--public-key", str(candidate["public_key_path"]), "--artifacts", str(candidate["artifact_dir"]),
            "--output", str(candidate["output_dir"])]
    monkeypatch.setattr(sys, "argv", args)
    assert signer.main() == 0
    assert json.loads(capsys.readouterr().out)["signed"]
    assert signer.main() == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "Release signing failed\n"
    assert Path(os.environ["BULWARK_RELEASE_SIGNING_KEY_FILE"]).read_text() not in captured.err


@pytest.mark.parametrize("fault", [
    "missing", "symlink", "format", "version", "bool_version", "root", "identity", "config_id",
    "duplicate_identity", "empty", "missing_python", "extra_package", "duplicate_ref",
    "missing_purl", "null_component", "duplicate_json", "packages", "scan_id", "oversized", "schema_extra",
])
def test_sbom_rejected_before_signing_key(signer, candidate, monkeypatch, fault):
    path = candidate["artifact_dir"] / "proxy.cdx.json"
    bom = json.loads(path.read_bytes())
    if fault == "format":
        bom["bomFormat"] = "SPDX"
    elif fault == "schema_extra":
        bom["unrecognized"] = True
    elif fault == "version":
        bom["specVersion"] = "1.6"
    elif fault == "bool_version":
        bom["version"] = True
    elif fault == "root":
        bom["metadata"] = None
    elif fault == "identity":
        bom["metadata"]["component"]["name"] = candidate["admin_image"]
    elif fault == "config_id":
        bom["metadata"]["component"]["properties"][0]["value"] = "sha256:" + "e" * 64
    elif fault == "duplicate_identity":
        bom["metadata"]["component"]["properties"] *= 2
    elif fault == "empty":
        bom["components"] = []
    elif fault == "missing_python":
        bom["components"].pop()
    elif fault == "extra_package":
        bom["components"][0]["purl"] += "-different"
    elif fault == "duplicate_ref":
        bom["components"][0]["bom-ref"] = "root"
    elif fault == "missing_purl":
        del bom["components"][0]["purl"]
    elif fault == "null_component":
        bom["components"] = [None]
    elif fault in ("packages", "scan_id"):
        scan_path = candidate["artifact_dir"] / "proxy-scan.json"
        scan = json.loads(scan_path.read_bytes())
        if fault == "packages":
            del scan["Results"][0]["Packages"]
        else:
            scan["Metadata"]["ImageID"] = "not-a-digest"
        scan_path.write_text(json.dumps(scan))
    path.write_text(json.dumps(bom))
    if fault == "missing":
        path.unlink()
    elif fault == "symlink":
        path.unlink()
        path.symlink_to(candidate["artifact_dir"] / "admin.cdx.json")
    elif fault == "duplicate_json":
        path.write_text('{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}')
    elif fault == "oversized":
        path.write_bytes(b" " * (signer.verifier.MAX_REPORT_BYTES + 1))
    monkeypatch.delenv("BULWARK_RELEASE_SIGNING_KEY_FILE")
    with pytest.raises((ValueError, OSError)):
        signer.sign_release(**candidate)
    assert not candidate["output_dir"].exists()


@pytest.mark.parametrize("fault", ["tampered", "missing", "signed_wrong_inventory", "signed_wrong_identity", "signed_bad_schema"])
def test_verifier_independently_requires_signed_sbom(signer, candidate, fault):
    import hashlib

    signer.sign_release(**candidate)
    path = candidate["artifact_dir"] / "proxy.cdx.json"
    manifest_path = candidate["output_dir"] / "release.json"
    manifest = json.loads(manifest_path.read_bytes())
    if fault == "tampered":
        path.write_text("tampered")
    elif fault == "missing":
        manifest["artifacts"] = [a for a in manifest["artifacts"] if a["name"] != path.name]
    else:
        bom = json.loads(path.read_bytes())
        if fault == "signed_wrong_identity":
            bom["metadata"]["component"]["name"] = candidate["admin_image"]
        elif fault == "signed_bad_schema":
            bom["unrecognized"] = True
        else:
            bom["components"].pop()
        path.write_text(json.dumps(bom))
        next(a for a in manifest["artifacts"] if a["name"] == path.name).update(
            sha256=hashlib.sha256(path.read_bytes()).hexdigest(), size=path.stat().st_size)
    raw = json.dumps(manifest).encode()
    manifest_path.write_bytes(raw)
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(Path(os.environ["BULWARK_RELEASE_SIGNING_KEY_FILE"]).read_text()))
    (candidate["output_dir"] / "release.sig").write_text(private.sign(signer.verifier.DOMAIN + raw).hex())
    with pytest.raises(ValueError):
        verify(signer, candidate)


def test_signed_evidence_order_does_not_change_verification(signer, candidate):
    signer.sign_release(**candidate)
    path = candidate["output_dir"] / "release.json"
    manifest = json.loads(path.read_bytes())
    manifest["artifacts"].reverse()
    raw = json.dumps(manifest).encode()
    path.write_bytes(raw)
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(Path(os.environ["BULWARK_RELEASE_SIGNING_KEY_FILE"]).read_text()))
    (candidate["output_dir"] / "release.sig").write_text(private.sign(signer.verifier.DOMAIN + raw).hex())
    assert verify(signer, candidate)["verified"]


@pytest.mark.parametrize("fault", [None, "unknown_os", "wrong_namespace", "wrong_type", "missing_os"])
def test_wolfi_profile_is_bound_to_scan_distribution(signer, candidate, fault):
    for role in ("proxy", "admin"):
        scan_path = candidate["artifact_dir"] / f"{role}-scan.json"
        bom_path = candidate["artifact_dir"] / f"{role}.cdx.json"
        scan = json.loads(scan_path.read_text().replace("pkg:deb/debian/", "pkg:apk/wolfi/"))
        bom = json.loads(bom_path.read_text().replace("pkg:deb/debian/", "pkg:apk/wolfi/"))
        scan["Metadata"]["OS"]["Family"] = "wolfi"
        scan["Results"][0]["Type"] = "wolfi"
        if fault == "unknown_os":
            scan["Metadata"]["OS"]["Family"] = "unknown"
        elif fault == "wrong_namespace":
            scan["Results"][0]["Packages"][0]["Identifier"]["PURL"] = "pkg:apk/alpine/libc@1"
            bom["components"][0]["purl"] = "pkg:apk/alpine/libc@1"
        elif fault == "wrong_type":
            scan["Results"][0]["Type"] = "debian"
        elif fault == "missing_os":
            del scan["Metadata"]["OS"]
        scan_path.write_text(json.dumps(scan))
        bom_path.write_text(json.dumps(bom))
    if fault:
        with pytest.raises(ValueError):
            signer.sign_release(**candidate)
    else:
        signer.sign_release(**candidate)
        assert verify(signer, candidate)["verified"]


@pytest.mark.parametrize("fault", ["missing", "stale_db", "future_scan", "scan_before_db", "duplicate", "symlink"])
def test_freshness_rejected_before_key_access(signer, candidate, monkeypatch, fault):
    path = candidate["artifact_dir"] / "proxy-database.json"
    metadata = json.loads(path.read_bytes())
    if fault == "missing":
        path.unlink()
    elif fault == "symlink":
        path.unlink()
        path.symlink_to(candidate["artifact_dir"] / "admin-database.json")
    elif fault == "duplicate":
        path.write_text('{"Version":2,"Version":2}')
    elif fault == "stale_db":
        metadata["UpdatedAt"] = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
        path.write_text(json.dumps(metadata))
    else:
        scan_path = candidate["artifact_dir"] / "proxy-scan.json"
        scan = json.loads(scan_path.read_bytes())
        delta = timedelta(days=1) if fault == "future_scan" else -timedelta(hours=2)
        scan["CreatedAt"] = (datetime.now(timezone.utc) + delta).isoformat()
        scan_path.write_text(json.dumps(scan))
    monkeypatch.delenv("BULWARK_RELEASE_SIGNING_KEY_FILE")
    with pytest.raises((ValueError, OSError)):
        signer.sign_release(**candidate)
    assert not candidate["output_dir"].exists()


def test_signed_database_bytes_cannot_be_replaced(signer, candidate):
    signer.sign_release(**candidate)
    (candidate["artifact_dir"] / "proxy-database.json").write_text('{}')
    with pytest.raises(ValueError):
        verify(signer, candidate)


def test_expired_signed_release_is_historical_only(signer, candidate):
    import hashlib

    signer.sign_release(**candidate)
    manifest_path = candidate["output_dir"] / "release.json"
    manifest = json.loads(manifest_path.read_bytes())
    then = datetime.now(timezone.utc) - timedelta(days=3)
    for role in ("admin", "proxy"):
        for suffix in ("-scan.json", "-database.json"):
            path = candidate["artifact_dir"] / (role + suffix)
            document = json.loads(path.read_bytes())
            if suffix == "-scan.json":
                document["CreatedAt"] = then.isoformat()
            else:
                document.update(UpdatedAt=(then - timedelta(hours=1)).isoformat(),
                                DownloadedAt=then.isoformat(), NextUpdate=(then + timedelta(hours=12)).isoformat())
            raw = json.dumps(document).encode()
            path.write_bytes(raw)
            next(a for a in manifest["artifacts"] if a["name"] == path.name).update(
                sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
    raw = json.dumps(manifest).encode()
    manifest_path.write_bytes(raw)
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(
        Path(os.environ["BULWARK_RELEASE_SIGNING_KEY_FILE"]).read_text()))
    (candidate["output_dir"] / "release.sig").write_text(private.sign(signer.verifier.DOMAIN + raw).hex())
    assert verify(signer, candidate)["verified"]
    images = signer.verifier.Images(proxy=candidate["proxy_image"], admin=candidate["admin_image"])
    with pytest.raises(ValueError, match="freshness"):
        verify(signer, candidate, expected_images=images)
