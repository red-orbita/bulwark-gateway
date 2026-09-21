"""Offline safety/crypto tests; never use operator databases or live PG fixtures."""

import importlib.util
import json
import subprocess
from collections import namedtuple
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Override the root fixture that otherwise opens the operator user store."""


@pytest.fixture
def runner():
    path = Path(__file__).parents[1] / "scripts/validation-storage-sandbox.py"
    spec = importlib.util.spec_from_file_location("storage_sandbox_validation", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_private_artifact_cannot_overwrite_or_follow_link(runner, tmp_path):
    original = tmp_path / "original"
    runner.private_file(original, b"synthetic")
    assert original.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        runner.private_file(original, b"changed")
    link = tmp_path / "link"
    link.symlink_to(original)
    with pytest.raises(FileExistsError):
        runner.private_file(link, b"changed")
    assert original.read_bytes() == b"synthetic"


def test_bounded_read_rejects_large_artifact(runner, tmp_path):
    path = tmp_path / "large"
    path.write_bytes(b"12345")
    with pytest.raises(runner.ValidationError, match="artifact_size_limit"):
        runner.bounded_read(path, 4)
    assert runner.bounded_read(path, 5) == b"12345"


def test_device_evidence_follows_only_actual_backing_chain(runner):
    devices = [{"type": "disk", "maj:min": "8:0", "children": [
        {"type": "part", "maj:min": "8:1", "fstype": "ext4"},
        {"type": "part", "maj:min": "8:2", "fstype": "crypto_LUKS", "children": [
            {"type": "crypt", "maj:min": "253:0", "fstype": "ext4"}]}]}]
    plain = runner.backing_chain(devices, "8:1")
    assert not any(d["type"] == "crypt" for d in plain[0])
    encrypted = runner.backing_chain(devices, "253:0")
    assert any(d["type"] == "crypt" for d in encrypted[0])
    assert runner.backing_chain(devices, "0:99") == []


def test_resource_reserve_blocks_before_work(runner, monkeypatch):
    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(runner.shutil, "disk_usage", lambda p: usage(10, 9, runner.RESERVE - 1))
    with pytest.raises(runner.ValidationError, match="disk_reserve_threatened"):
        runner.resources()


def test_metadata_failure_does_not_leak_stderr(runner, monkeypatch):
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **kw: subprocess.CompletedProcess(
        a, 1, "", "SYNTHETIC_PRIVATE_DIAGNOSTIC"))
    with pytest.raises(runner.ValidationError, match="^metadata_command_failed$"):
        runner.command("findmnt")


@pytest.mark.parametrize("change", ["ciphertext", "nonce", "wrong_key", "aad", "truncate"])
def test_authenticated_backup_rejects_changes(runner, change):
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = AESGCM.generate_key(bit_length=256)
    nonce = b"0" * 12
    plain = json.dumps({name: "c3ludGhldGlj" for name in runner.DATABASES}).encode()
    artifact = nonce + AESGCM(key).encrypt(nonce, plain, runner.AAD if change != "aad" else b"wrong-context")
    if change == "ciphertext":
        artifact = artifact[:-1] + bytes([artifact[-1] ^ 1])
    elif change == "nonce":
        artifact = b"1" + artifact[1:]
    elif change == "wrong_key":
        key = AESGCM.generate_key(bit_length=256)
    elif change == "truncate":
        artifact = artifact[:-1]
    with pytest.raises(InvalidTag):
        runner.decrypt_backup(key, artifact)


def test_authenticated_bundle_rejects_unexpected_restore_paths(runner):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = AESGCM.generate_key(bit_length=256)
    nonce = b"0" * 12
    artifact = nonce + AESGCM(key).encrypt(nonce, b'{"../escape":"eA=="}', runner.AAD)
    with pytest.raises(runner.ValidationError, match="backup_scope_invalid"):
        runner.decrypt_backup(key, artifact)


async def test_real_abstraction_backup_restore_hash_and_scope(runner, tmp_path):
    temporary = tmp_path / "scratch"
    temporary.mkdir()
    result = await runner.backup_checks(tmp_path, temporary)
    assert result["status"] == "pass"
    assert result["restored_approved_attachments"] == result["restored_pending_events"] == 1
    assert result["attachment_tenant_agent_owner_revision_fenced"]
    assert result["outbox_scope_revision_ack_fenced"] and result["source_unchanged"]
    assert not result["source_application_encryption"]
    assert len(result["tamper"]) == 4
    assert "SQLite format 3" not in (tmp_path / "backup.aes256gcm").read_bytes().decode(errors="ignore")


def test_missing_native_tools_are_blocked_not_mocked_pass(runner, tmp_path, monkeypatch):
    monkeypatch.setattr(runner.os, "access", lambda *a: False)
    result = runner.sandbox_checks(tmp_path)
    assert result["status"] == "blocked" and result["code"] == "native_tools_missing"
    assert not list(tmp_path.iterdir())


def test_runner_has_no_host_remediation_or_external_dsn(runner):
    source = Path(runner.__file__).read_text()
    for forbidden in ("cryptsetup", "chmod(", "chown(", "DROP SCHEMA", "import sqlite3", "shell=True",
                      'command("mount"', 'command("docker", "run"', 'command("docker", "pull"'):
        assert forbidden not in source
    assert 'parser.add_argument("--run"' in source
    assert 'parser.add_argument("--url"' not in source
