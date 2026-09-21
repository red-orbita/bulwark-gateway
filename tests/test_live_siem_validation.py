"""Offline safety checks; no Docker launch and no operator database fixtures."""

import importlib.util
import json
import ssl
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Override the root fixture so no operator users database is touched."""


@pytest.fixture
def runner():
    path = Path(__file__).parents[1] / "scripts/validation-live-siem.py"
    spec = importlib.util.spec_from_file_location("live_siem_validation", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_private_certificates_and_no_overwrite(runner, tmp_path):
    from cryptography import x509

    runner.certificates(tmp_path, "172.28.0.2")
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in tmp_path.iterdir())
    cert = x509.load_pem_x509_certificate((tmp_path / "server.pem").read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["localhost"]
    assert [str(ip) for ip in san.get_values_for_type(x509.IPAddress)] == ["172.28.0.2"]
    assert (tmp_path / "ca.pem").read_bytes() != (tmp_path / "wrong-ca.pem").read_bytes()
    with pytest.raises(FileExistsError):
        runner.private_file(tmp_path / "server.key", "overwrite")


def test_tls_negative_evidence_does_not_accept_network_outages(runner):
    assert runner.certificate_rejection(ssl.SSLCertVerificationError("rejected"))
    assert not runner.certificate_rejection(ConnectionRefusedError("refused"))
    assert not runner.certificate_rejection(TimeoutError("timeout"))


def test_safe_command_error(runner, monkeypatch):
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
        a, 1, "", "snapshot error PRIVATE_CREDENTIAL"))
    with pytest.raises(runner.LabError, match="^docker_snapshot_error$"):
        runner.command("docker", "create")


def test_storage_reserve_prevents_creation(runner, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(runner, "command", lambda *a: calls.append(a) or "/var/lib/docker")
    monkeypatch.setattr(runner.shutil, "disk_usage", lambda p: SimpleNamespace(free=runner.RESERVE - 1))
    lab = runner.Lab(tmp_path)
    with pytest.raises(runner.LabError, match="storage_reserve_threatened"):
        lab.create()
    assert not lab.created and not lab.network
    assert all("create" not in call for call in calls)


def test_memory_reserve_prevents_creation(runner, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(runner, "command", lambda *a: calls.append(a) or "/var/lib/docker")
    monkeypatch.setattr(runner.shutil, "disk_usage", lambda p: SimpleNamespace(free=20 * 1024**3))
    monkeypatch.setattr(runner.Path, "read_text", lambda p: "MemAvailable: 1000000 kB\n")
    lab = runner.Lab(tmp_path)
    with pytest.raises(runner.LabError, match="insufficient_memory_headroom"):
        lab.create()
    assert not lab.created and not lab.network
    assert all("create" not in call for call in calls)


def test_create_uses_only_owned_cached_hardened_collector(runner, tmp_path, monkeypatch):
    lab = runner.Lab(tmp_path / "bulwark-live-siem-test")
    lab.directory.mkdir()
    monkeypatch.setattr(lab, "resources", lambda *a, **k: None)
    monkeypatch.setattr(runner.os, "getuid", lambda: 1000)
    monkeypatch.setattr(runner.os, "getgid", lambda: 1000)
    calls = []

    def command(*args):
        calls.append(args)
        if args[:3] == ("docker", "image", "inspect"):
            return runner.IMAGE
        if args[:3] == ("docker", "network", "inspect") and "--format" not in args:
            return json.dumps([{"IPAM": {"Config": [{"Subnet": "172.28.0.0/16"}]}}])
        if args[:2] == ("docker", "inspect"):
            return json.dumps([{"NetworkSettings": {"Networks": {lab.name: {"IPAddress": "172.28.0.2"}}},
                                "HostConfig": {"Memory": runner.MEMORY_LIMIT, "MemorySwap": runner.MEMORY_LIMIT,
                                               "ReadonlyRootfs": True}}])
        return lab.name

    monkeypatch.setattr(runner, "command", command)
    assert lab.create() == "172.28.0.2"
    create = next(call for call in calls if call[:2] == ("docker", "create"))
    assert "--pull=never" in create and runner.IMAGE in create
    assert "--read-only" in create and "--cap-drop=ALL" in create
    assert "1000:1000" in create and "--memory=1536m" in create
    password = (lab.directory / "config/password").read_text()
    assert all(password not in arg for call in calls for arg in call)
    assert all(arg.startswith("type=bind,") for i, arg in enumerate(create) if i and create[i - 1] == "--mount")
    assert all(call[-1] == lab.container for call in calls if call[:2] == ("docker", "start"))
    config = (lab.directory / "config/elasticsearch.yml").read_text()
    assert "xpack.security.enabled: true" in config
    assert "xpack.security.http.ssl.enabled: true" in config
    assert "xpack.security.transport.ssl.enabled: true" in config
    assert "0.0.0.0" in config  # Only reachable through the private internal bridge.


def test_partial_create_is_tracked_for_cleanup(runner, tmp_path, monkeypatch):
    lab = runner.Lab(tmp_path / "bulwark-live-siem-test")
    lab.directory.mkdir()
    monkeypatch.setattr(lab, "resources", lambda *a, **k: None)
    monkeypatch.setattr(runner.os, "getuid", lambda: 1000)

    def command(*args):
        if args[:2] == ("docker", "create"):
            raise runner.LabError("docker_snapshot_error")
        return runner.IMAGE

    monkeypatch.setattr(runner, "command", command)
    with pytest.raises(runner.LabError, match="docker_snapshot_error"):
        lab.create()
    assert lab.created and lab.network


def test_cleanup_refuses_foreign_owner(runner, tmp_path, monkeypatch):
    lab = runner.Lab(tmp_path / "bulwark-live-siem-test")
    lab.created = True
    calls = []
    monkeypatch.setattr(runner, "command", lambda *a: calls.append(a) or "foreign")
    lab.cleanup()
    assert all("rm" not in call for call in calls)
    assert lab.report["cleanup"][0]["status"] == "ownership_label_mismatch"


def test_cleanup_removes_only_owned_resources_and_credentials(runner, tmp_path, monkeypatch):
    directory = tmp_path / "bulwark-live-siem-test"
    directory.mkdir()
    (directory / "config").mkdir()
    runner.private_file(directory / "config/password", "synthetic")
    unrelated = tmp_path / "existing-wazuh"
    unrelated.mkdir()
    lab = runner.Lab(directory)
    lab.created = lab.network = True
    calls = []
    monkeypatch.setattr(runner, "command", lambda *a: calls.append(a) or lab.name)
    lab.cleanup()
    assert [call for call in calls if "rm" in call] == [
        ("docker", "container", "rm", "--force", lab.container), ("docker", "network", "rm", lab.name)]
    assert not (directory / "config").exists()
    assert unrelated.exists()


def test_no_pull_build_external_endpoint_or_insecure_tls_switch(runner):
    source = Path(runner.__file__).read_text()
    assert '"--pull=never"' in source and '"--internal"' in source
    assert '"--memory=1536m"' in source and '"--memory-swap=1536m"' in source
    assert "-Xms512m -Xmx512m" in source
    assert '"--read-only"' in source and '"--cap-drop=ALL"' in source
    assert 'add_argument("--run"' in source and 'add_argument("--url"' not in source
    assert "verify_ssl=False" not in source and "CERT_NONE" not in source
    assert '"docker", "pull"' not in source and '"docker", "build"' not in source
    assert "HttpRestTransport(HttpTransportConfig(" in source
    assert "TelemetryExporter(queue=queue" in source
    assert '"_source": False' in source
