"""Offline runner safety tests. Never invoke the root live-PG fixture."""

import importlib.util
import json
import socket
import ssl
import subprocess
import threading
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Override root fixture: never open or mutate the operator users database."""


@pytest.fixture
def runner():
    path = Path(__file__).parents[1] / "scripts/validation-live-stores.py"
    spec = importlib.util.spec_from_file_location("live_stores_validation", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_private_files_and_certificate_names(runner, tmp_path):
    from cryptography import x509

    runner.certificates(tmp_path)
    for path in tmp_path.iterdir():
        assert path.stat().st_mode & 0o777 == 0o600
    cert = x509.load_pem_x509_certificate((tmp_path / "server.pem").read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["localhost"]
    assert san.get_values_for_type(x509.IPAddress) == []
    assert cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    assert (tmp_path / "ca.pem").read_bytes() != (tmp_path / "wrong-ca.pem").read_bytes()
    with pytest.raises(FileExistsError):
        runner.private_file(tmp_path / "server.key", "must not overwrite")


def test_memory_pressure_restores_limit_and_only_deletes_owned_keys(runner):
    from unittest.mock import Mock

    import redis

    client = Mock()
    client.config_get.side_effect = [{"maxmemory": "67108864"}, {"maxmemory-policy": "noeviction"}]
    client.info.side_effect = [{"evicted_keys": 0}, {"used_memory": 1000000}, {"evicted_keys": 0}]
    client.set.side_effect = [redis.exceptions.OutOfMemoryError("synthetic"), True]
    client.sismember.return_value = True
    checks = []
    class Lab:
        def check(self, name, condition):
            assert condition
            checks.append(name)
    runner.redis_memory_retention_checks(Lab(), client)
    assert client.config_set.call_args.args == ("maxmemory", 67108864)
    assert "memory_pressure_keeps_revocation" in checks
    assert all(key.startswith("validation-pressure:") for call in client.delete.call_args_list for key in call.args)


def test_certificate_rejections_are_not_connectivity_errors(runner):
    assert runner.certificate_rejection(ssl.SSLCertVerificationError("certificate rejected"))
    assert not runner.certificate_rejection(ConnectionRefusedError("refused"))
    assert not runner.certificate_rejection(TimeoutError("timeout"))


def test_docker_errors_are_sanitized(runner, monkeypatch):
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
        a, 1, "", "failed to prepare snapshot: parent snapshot missing SYNTHETIC_SECRET"))
    with pytest.raises(runner.LabError, match="^docker_parent_snapshot_missing$"):
        runner.command("docker", "create")


def test_disk_reserve_prevents_resources(runner, tmp_path, monkeypatch):
    from collections import namedtuple

    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(runner.shutil, "disk_usage", lambda p: usage(10, 9, runner.RESERVE - 1))
    monkeypatch.setattr(runner, "command", lambda *a: pytest.fail("Docker must not be contacted"))
    lab = runner.Lab(tmp_path)
    with pytest.raises(runner.LabError, match="disk_reserve_threatened"):
        lab.preflight()
    assert not lab.containers


def test_cleanup_refuses_foreign_label(runner, tmp_path, monkeypatch):
    lab = runner.Lab(tmp_path / "bulwark-validation-test")
    lab.containers.append(lab.name + "-postgres")
    calls = []

    def command(*args):
        calls.append(args)
        return "some-other-owner"

    monkeypatch.setattr(runner, "command", command)
    lab.cleanup()
    assert all("rm" not in call for call in calls)
    assert lab.report["cleanup"][0]["status"] == "ownership_label_mismatch"


def test_cleanup_removes_only_explicit_owned_resources(runner, tmp_path, monkeypatch):
    lab = runner.Lab(tmp_path / "bulwark-validation-test")
    lab.containers.append(lab.name + "-redis")
    lab.network_created = True
    calls = []

    def command(*args):
        calls.append(args)
        return lab.name if "inspect" in args else ""

    monkeypatch.setattr(runner, "command", command)
    lab.cleanup()
    removals = [args for args in calls if "rm" in args]
    assert removals == [("docker", "container", "rm", "--force", lab.name + "-redis"),
                        ("docker", "network", "rm", lab.name)]


@pytest.mark.parametrize("kind", ["postgres", "redis"])
def test_create_is_pinned_loopback_nonroot_and_bind_only(runner, tmp_path, monkeypatch, kind):
    lab = runner.Lab(tmp_path / "bulwark-validation-test")
    lab.directory.mkdir()
    calls = []
    monkeypatch.setattr(lab, "disk", lambda stage: None)
    monkeypatch.setattr(runner.os, "getuid", lambda: 1000)
    monkeypatch.setattr(runner.os, "getgid", lambda: 1000)

    def command(*args):
        calls.append(args)
        return lab.name if "inspect" in args else ""

    monkeypatch.setattr(runner, "command", command)
    lab.create(kind)
    create = calls[0]
    assert "--pull=never" in create and runner.IMAGES[kind] in create
    assert "--read-only" in create and "--cap-drop=ALL" in create
    assert "1000:1000" in create
    assert create[create.index("-p") + 1].startswith("127.0.0.1::")
    assert not any("SYNTHETIC_SECRET" in arg for arg in create)
    password = (lab.directory / kind / "password").read_text()
    assert all(password not in arg for arg in create)
    assert all(arg.startswith("type=bind,") for i, arg in enumerate(create) if i and create[i - 1] == "--mount")


def test_no_schema_drop_or_external_endpoint_switch(runner):
    source = Path(runner.__file__).read_text()
    assert "DROP SCHEMA" not in source
    assert "BULWARK_TEST_POSTGRES_URL" not in source
    assert 'add_argument("--run"' in source
    assert 'add_argument("--url"' not in source
    assert "auth._revocation_redis =" not in source
    assert "auth._revocation_redis_init =" not in source
    assert "auth._auth_cache.clear()" not in source
    assert "auth._revoked_cache.clear()" not in source


def test_partial_create_failure_is_tracked_for_cleanup(runner, tmp_path, monkeypatch):
    lab = runner.Lab(tmp_path / "bulwark-validation-test")
    lab.directory.mkdir()
    monkeypatch.setattr(lab, "disk", lambda stage: None)
    monkeypatch.setattr(runner.os, "getuid", lambda: 1000)
    monkeypatch.setattr(runner.os, "getgid", lambda: 1000)

    def fail(*args):
        raise runner.LabError("docker_snapshot_error")

    monkeypatch.setattr(runner, "command", fail)
    with pytest.raises(runner.LabError, match="docker_snapshot_error"):
        lab.create("redis")
    assert lab.containers == [lab.name + "-redis"]


def test_internal_network_loopback_relay_and_shutdown(runner, tmp_path, monkeypatch):
    lab = runner.Lab(tmp_path / "bulwark-validation-test")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)
    port = listener.getsockname()[1]

    def echo_once():
        with listener:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(5)
                connection.sendall(connection.recv(64))

    server = threading.Thread(target=echo_once, daemon=True)
    server.start()

    def command(*args):
        if "port" in args:
            raise runner.LabError("command_failed")
        if args[-1] == "{{json .NetworkSettings.Ports}}":
            return '{}'
        if args[-1] == "{{json .NetworkSettings.Networks}}":
            return json.dumps({lab.name: {"IPAddress": "127.0.0.1"}})
        return lab.name

    monkeypatch.setattr(runner, "command", command)
    try:
        forwarded = lab.port(lab.name + "-redis", port)
        with socket.create_connection(("127.0.0.1", forwarded), timeout=5) as client:
            client.sendall(b"opaque-synthetic-TLS-bytes")
            assert client.recv(64) == b"opaque-synthetic-TLS-bytes"
    finally:
        lab.cleanup()
        server.join(timeout=5)
    assert not server.is_alive()
    assert all(not thread.is_alive() for _, thread in lab.relays)
    assert all(item["status"] == "removed" for item in lab.report["cleanup"])


def test_stream_lease_literals_match_current_proxy_without_import(runner):
    import ast

    source = (runner.ROOT / "src/routes/proxy.py").read_bytes()
    values = runner.stream_lease_literals(source)
    assignments = {target.id: node.value.value for node in ast.parse(source).body
                   if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
                   for target in node.targets if isinstance(target, ast.Name)}
    assert values == {key: assignments[key] for key in values}
    assert "redis.call('TIME')" in values["_STREAM_LEASE_ACQUIRE"]
    assert "ZREM" in values["_STREAM_LEASE_RELEASE"]
    assert "{stream-leases}" in values["_STREAM_LEASE_GLOBAL"]
    assert values["_STREAM_LEASE_GLOBAL"] != values["_STREAM_LEASE_TENANT"] + ":global"


@pytest.mark.parametrize("change", ["missing", "dynamic", "duplicate"])
def test_stream_lease_extraction_fails_closed_on_contract_drift(runner, change):
    source = (runner.ROOT / "src/routes/proxy.py").read_text()
    if change == "missing":
        source = source.replace("_STREAM_LEASE_RELEASE =", "_REMOVED_RELEASE =")
    elif change == "dynamic":
        source += '\n_STREAM_LEASE_RELEASE = dangerous_side_effect()\n'
    else:
        source += '\n_STREAM_LEASE_RELEASE = "different"\n'
    with pytest.raises(runner.LabError, match="stream_lease_source_contract_changed"):
        runner.stream_lease_literals(source.encode())


def test_redis_only_preflight_never_requires_postgres(runner, tmp_path, monkeypatch):
    from types import SimpleNamespace

    lab = runner.Lab(tmp_path / "bulwark-validation-test", stores=("redis",))
    commands, imports = [], []
    monkeypatch.setattr(lab, "disk", lambda stage: None)

    def command(*args):
        commands.append(args)
        if "info" in args:
            return "/var/lib/docker"
        if "image" in args:
            return runner.IMAGES["redis"]
        return ""

    def imported(name):
        imports.append(name)
        return SimpleNamespace(__version__="test")

    monkeypatch.setattr(runner, "command", command)
    monkeypatch.setattr(runner.importlib, "import_module", imported)
    lab.preflight()
    assert list(lab.report["images"]) == ["redis"]
    assert imports == ["redis", "cryptography"]
    assert not any(runner.IMAGES["postgres"] in call for call in commands)


async def test_lua_error_is_not_reported_as_success(runner, tmp_path, monkeypatch):
    from unittest.mock import AsyncMock

    import redis.asyncio

    client = AsyncMock()
    client.exists.return_value = 0
    client.eval.side_effect = redis.exceptions.ResponseError("synthetic Lua error")
    monkeypatch.setattr(redis.asyncio, "from_url", lambda *a, **k: client)
    lab = runner.Lab(tmp_path / "bulwark-validation-test", stores=("redis",))
    with pytest.raises(redis.exceptions.ResponseError):
        await runner.redis_stream_lease_checks(lab, "rediss://unused.invalid")
    assert [check["name"] for check in lab.report["checks"]] == ["stream_lease_fresh_namespace"]
    client.aclose.assert_awaited_once()
