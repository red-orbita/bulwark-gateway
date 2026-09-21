"""Candidate containment and immutable scan evidence, not production approval."""

import importlib
import json
import os
from contextlib import contextmanager
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]


def test_canonical_builds_share_the_validated_candidate_profile():
    assert not (ROOT / "docker/Dockerfile.runtime-candidate").exists()
    for filename in ("Dockerfile", "docker/Dockerfile.admin"):
        candidate = (ROOT / filename).read_text()
        assert "--python-version 3.14" in candidate
        assert "--only-binary=:all: --require-hashes" in candidate
        assert 'org.bulwark.release.profile="python314-amd64-rc"' in candidate
        assert "afe19d0e00ec069cad58d69310ba53bbc038a686e279646a47c6549df20d323f" in candidate


@pytest.mark.parametrize("image", ["latest", "image:tag", "sha256:abc", "--privileged"])
def test_probe_refuses_mutable_or_invalid_images(monkeypatch, image):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    probe = importlib.import_module("validation-runtime-cves")
    monkeypatch.setattr(probe.sys if hasattr(probe, "sys") else __import__("sys"), "argv",
                        ["probe", "--image", image])
    with pytest.raises(SystemExit):
        probe.main()


def test_probe_is_serialized_and_does_not_mount_operator_files(monkeypatch, tmp_path):
    import subprocess
    import sys

    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    probe = importlib.import_module("validation-runtime-cves")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "shared").mkdir()
    monkeypatch.setattr(probe, "__file__", str(tmp_path / "scripts/probe.py"))
    image = "sha256:" + "a" * 64
    monkeypatch.setattr(sys, "argv", ["probe", "--image", image])
    active = False

    @contextmanager
    def slot(root):
        nonlocal active
        assert root == tmp_path
        active = True
        yield
        active = False

    def run(command, **kwargs):
        assert active
        for flag in ("--pull=never", "--network=none", "--read-only", "--user=65532:65532",
                     "--cap-drop=ALL", "--memory=256m", "--cpus=1", "--pids-limit=32"):
            assert flag in command
        assert not any("mount" in arg for arg in command[:-1])
        assert kwargs["check"] and kwargs["timeout"] == 45
        return subprocess.CompletedProcess(command, 0, stdout=b'{"python":"3.14"}')

    monkeypatch.setattr(probe, "validation_slot", slot)
    monkeypatch.setattr(probe.subprocess, "run", run)
    probe.main()
    reports = list((tmp_path / "shared").glob("*/report.json"))
    assert len(reports) == 1 and not active
    assert json.loads(reports[0].read_text())["vex_authorized"] is False


@pytest.mark.skipif(os.environ.get("BULWARK_CVE_CANDIDATE_LIVE") != "1", reason="Requires local candidate scans")
@pytest.mark.parametrize("role", ["admin", "proxy"])
def test_real_candidate_scan_has_os_python_and_no_release_severity(role, monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    verifier = importlib.import_module("verify-release")
    path = ROOT / f"shared/recovery-release-check/{role}-cve-fresh-scan.json"
    raw = verifier.read_regular(path, verifier.MAX_REPORT_BYTES)
    report = json.loads(raw)
    assert report["ArtifactName"] == f"/evidence/{role}-cve-candidate.tar"
    assert report["Metadata"]["OS"]["Family"] == "wolfi"
    # Intentionally not expected_images: tar-based scans cannot authorize deployment.
    verifier.validate_scan(raw, report["ArtifactName"])
    assert not [v for result in report["Results"] for v in result.get("Vulnerabilities", [])]
