#!/usr/bin/env python3
"""Opt-in synthetic backup and native sandbox validation, never host remediation."""

from __future__ import annotations

import argparse
import asyncio
import base64
import errno
import hashlib
import json
import logging
import os
import resource
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
AUTHORIZED_ROOT = Path("/media/rokitoh/DATOS2/CODE/bulwark-security-coverage")
RESERVE = 5 * 1024**3
DISK_BUDGET = 128 * 1024**2
MAX_DB = 4 * 1024**2
MAX_BACKUP = 12 * 1024**2
AAD = b"bulwark-synthetic-sqlite-backup-v1"
DATABASES = ("attachments.sqlite", "outbox.sqlite")
SOURCE_FILES = (
    "src/storage/database.py", "src/storage/attachment_migrations.py",
    "src/storage/outbox_migrations.py", "src/attachments/store.py",
    "src/telemetry/shared_outbox.py", "src/guardrails/document_extraction.py",
    "src/guardrails/docx_extraction.py", "tests/test_document_extraction.py",
    "tests/test_docx_extraction.py", "scripts/validation-storage-sandbox.py",
    "tests/test_storage_sandbox_validation.py",
)


class ValidationError(Exception):
    """Fixed diagnostic codes only; no raw exceptions in evidence."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ValidationError(code)


def private_file(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def bounded_read(path: Path, limit: int) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "artifact_size_limit")
    return data


def command(*args: str) -> str:
    # Metadata commands only, fixed columns, no mount options/UUIDs/credentials.
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=10, check=False,  # noqa: S603
                                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/nonexistent"})
    except (OSError, subprocess.TimeoutExpired):
        raise ValidationError("metadata_command_unavailable") from None
    require(result.returncode == 0, "metadata_command_failed")
    require(len(result.stdout) <= 1024**2, "metadata_size_limit")
    return result.stdout


def resources() -> dict:
    free = {name: shutil.disk_usage(path).free for name, path in (
        ("root", Path("/")), ("workspace", ROOT / "shared"),
        ("docker_default", Path("/var/lib/docker")), ("containerd", Path("/var/lib/containerd")),
    ) if path.exists()}
    memory = dict(line.split(":", 1) for line in bounded_read(Path("/proc/meminfo"), 65536).decode().splitlines())
    available = int(memory["MemAvailable"].split()[0]) * 1024
    require(min(free.values()) >= RESERVE + DISK_BUDGET, "disk_reserve_threatened")
    require(available >= 2 * 1024**3, "memory_headroom_insufficient")
    return {"free_bytes": free, "memory_available_bytes": available}


def backing_chain(devices: list[dict], identity: str, ancestors: tuple = ()) -> list[list[dict]]:
    matches = []
    for device in devices:
        chain = (*ancestors, {key: device.get(key) for key in ("type", "fstype", "maj:min")})
        if device.get("maj:min") == identity:
            matches.append(list(chain))
        matches.extend(backing_chain(device.get("children", []), identity, chain))
    return matches


def storage_assessment() -> dict:
    devices = json.loads(command("lsblk", "--json", "--tree", "--output", "TYPE,FSTYPE,MAJ:MIN"))["blockdevices"]
    paths = {"source_and_backup_workspace": ROOT / "shared", "host_root": Path("/"),
             "containerd_default": Path("/var/lib/containerd")}
    docker_code = None
    try:
        docker_root = command("docker", "--host", "unix:///var/run/docker.sock",
                              "info", "--format", "{{.DockerRootDir}}").strip()
        require(docker_root.startswith("/") and Path(docker_root).is_dir(), "docker_root_unavailable")
        paths["actual_docker_root"] = Path(docker_root)
    except ValidationError as exc:
        docker_code = str(exc)
    observations = {}
    for name, path in paths.items():
        mount = json.loads(command("findmnt", "--json", "--target", str(path),
                                   "--output", "FSTYPE,MAJ:MIN"))["filesystems"][0]
        chains = backing_chain(devices, mount["maj:min"])
        visible = bool(chains) and all(any(d["type"] == "crypt" for d in chain) for chain in chains)
        observations[name] = {"filesystem": mount["fstype"], "backing_chains": chains,
                              "visible_block_encryption": visible,
                              "free_bytes": shutil.disk_usage(path).free}
        require(observations[name]["free_bytes"] >= RESERVE + DISK_BUDGET, "disk_reserve_threatened")
    return {"status": "blocked", "code": "source_pvc_encryption_not_attested",
            "observations": observations, "docker_metadata_blocker": docker_code,
            "scope": "read_only_host_metadata_not_fscrypt_hardware_or_pvc_attestation"}


def decrypt_backup(key: bytes, artifact: bytes) -> dict[str, bytes]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    require(28 <= len(artifact) <= MAX_BACKUP, "backup_size_limit")
    # Authentication completes before JSON parsing or any restore file creation.
    plain = AESGCM(key).decrypt(artifact[:12], artifact[12:], AAD)
    bundle = json.loads(plain)
    require(isinstance(bundle, dict) and set(bundle) == set(DATABASES), "backup_scope_invalid")
    restored = {name: base64.b64decode(bundle[name], validate=True) for name in DATABASES}
    require(all(0 < len(data) <= MAX_DB for data in restored.values()), "database_size_limit")
    return restored


async def backup_checks(directory: Path, temporary: Path) -> dict:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from src.attachments.store import AttachmentStore, StoreError
    from src.storage.database import SQLiteEngine
    from src.telemetry.schema import BulwarkFields, SecurityTelemetryEvent, TenantFields
    from src.telemetry.shared_outbox import DestinationSnapshot, SharedOutbox

    source, restore = temporary / "source", temporary / "restore"
    source.mkdir(mode=0o700)
    restore.mkdir(mode=0o700)
    scope = {"tenant": "synthetic-tenant-a", "agent": "synthetic-agent", "owner": "synthetic-owner"}
    text = "Approved synthetic attachment, no customer data."
    raw = b"Synthetic upload only."
    destination = DestinationSnapshot(destination_id="local-no-transport", revision="a" * 64,
                                      tenant_scope=(scope["tenant"],))
    event = SecurityTelemetryEvent(bulwark=BulwarkFields(verdict="block"),
                                   tenant=TenantFields(id=scope["tenant"]))
    event_bytes = event.model_dump_json(by_alias=True, exclude_none=True).encode()
    engines = [SQLiteEngine("sqlite:///" + str(source / name)) for name in DATABASES]
    store = AttachmentStore(engines[0])
    outbox = SharedOutbox(engines[1], max_events=10, max_bytes=1024**2)
    try:
        await store.initialize()
        await outbox.initialize()
        document = await store.create(**scope, mime="text/plain", raw=raw, policy_revision="revision-a")
        lease = await store.claim()
        require(lease is not None, "attachment_claim_failed")
        require(await store.finish(document["id"], lease["lease_token"], state="approved", text=text),
                "attachment_approval_failed")
        require(await outbox.enqueue(event, (destination,)), "outbox_enqueue_failed")
        for engine in engines:
            checkpoint = await engine.fetch_one("PRAGMA wal_checkpoint(TRUNCATE)")
            require(checkpoint is not None and list(checkpoint.values())[0] == 0, "checkpoint_busy")
    finally:
        for engine in engines:
            await engine.close()
    # This is an offline backup of exclusively owned, closed stores, not a live file copy.
    originals = {name: await asyncio.to_thread(bounded_read, source / name, MAX_DB) for name in DATABASES}
    require(all(data.startswith(b"SQLite format 3\x00") for data in originals.values()),
            "source_sqlite_format_unexpected")
    payload = json.dumps({name: base64.b64encode(data).decode("ascii") for name, data in originals.items()},
                         sort_keys=True).encode()
    key, nonce = AESGCM.generate_key(bit_length=256), secrets.token_bytes(12)
    artifact = nonce + AESGCM(key).encrypt(nonce, payload, AAD)
    require(len(artifact) <= MAX_BACKUP, "backup_size_limit")
    await asyncio.to_thread(private_file, directory / "backup.aes256gcm", artifact)
    await asyncio.to_thread(private_file, directory / "backup.key", key)
    tamper_results = {}
    for name, candidate, candidate_key in (
        ("ciphertext", artifact[:-1] + bytes([artifact[-1] ^ 1]), key),
        ("nonce", bytes([artifact[0] ^ 1]) + artifact[1:], key),
        ("truncated", artifact[:-1], key),
        ("wrong_key", artifact, AESGCM.generate_key(bit_length=256)),
    ):
        try:
            decrypt_backup(candidate_key, candidate)
        except InvalidTag:
            tamper_results[name] = "rejected_invalid_tag"
        else:
            raise ValidationError("tamper_not_rejected")
    require(not list(restore.iterdir()), "unauthenticated_restore_written")
    # Re-read persisted artifacts, rather than only testing in-memory round trips.
    recovered = await asyncio.to_thread(decrypt_backup,
                                        bounded_read(directory / "backup.key", 32),
                                        bounded_read(directory / "backup.aes256gcm", MAX_BACKUP))
    hashes = {}
    for name in DATABASES:
        require(recovered[name] == originals[name], "restore_byte_mismatch")
        hashes[name] = hashlib.sha256(recovered[name]).hexdigest()
        await asyncio.to_thread(private_file, restore / name, recovered[name])
    restored_engines = [SQLiteEngine("sqlite:///" + str(restore / name)) for name in DATABASES]
    restored_store = AttachmentStore(restored_engines[0])
    restored_outbox = SharedOutbox(restored_engines[1], max_events=10, max_bytes=1024**2)
    try:
        await restored_store.initialize()
        await restored_outbox.initialize()
        for engine in restored_engines:
            integrity = await engine.fetch_one("PRAGMA integrity_check")
            require(integrity is not None and list(integrity.values()) == ["ok"], "restore_integrity_failed")
        public = await restored_store.get(document["id"], **scope)
        resolved = await restored_store.resolve(document["id"], **scope, policy_revision="revision-a")
        text_hash = hashlib.sha256(resolved.encode()).hexdigest()
        require(public is not None and public["state"] == "approved" and
                public["sha256"] == hashlib.sha256(raw).hexdigest() and
                public["text_sha256"] == text_hash == hashlib.sha256(text.encode()).hexdigest(),
                "attachment_hash_mismatch")
        for field in scope:
            foreign = {**scope, field: "synthetic-foreign"}
            require(await restored_store.get(document["id"], **foreign) is None, "attachment_scope_leak")
            try:
                await restored_store.resolve(document["id"], **foreign, policy_revision="revision-a")
            except StoreError as exc:
                require(exc.code == "not_found", "attachment_scope_wrong_error")
            else:
                raise ValidationError("attachment_resolve_scope_leak")
        try:
            await restored_store.resolve(document["id"], **scope, policy_revision="revision-b")
        except StoreError as exc:
            require(exc.code == "policy_changed", "revision_wrong_error")
        else:
            raise ValidationError("revision_not_fenced")
        for foreign in (destination.model_copy(update={"tenant_scope": ("synthetic-tenant-b",)}),
                        destination.model_copy(update={"revision": "b" * 64})):
            require(await restored_outbox.claim(foreign) == [], "outbox_scope_leak")
        leases = await restored_outbox.claim(destination)
        require(len(leases) == 1 and leases[0].tenant == scope["tenant"], "outbox_restore_count_or_scope")
        restored_event = leases[0].event.model_dump_json(by_alias=True, exclude_none=True).encode()
        require(restored_event == event_bytes, "outbox_payload_mismatch")
        forged = leases[0].model_copy(update={"tenant": "synthetic-tenant-b"})
        require(await restored_outbox.finish([forged], success=True) == 0, "outbox_ack_scope_leak")
        require(await restored_outbox.finish(leases, success=True) == 1, "outbox_restore_ack_failed")
    finally:
        for engine in restored_engines:
            await engine.close()
    for name in DATABASES:
        require(await asyncio.to_thread(bounded_read, source / name, MAX_DB) == originals[name],
                "source_changed_by_restore")
    return {"status": "pass", "algorithm": "AES-256-GCM", "artifact_bytes": len(artifact),
            "artifact_sha256": hashlib.sha256(artifact).hexdigest(), "database_sha256": hashes,
            "attachment_text_sha256": text_hash, "outbox_payload_sha256": hashlib.sha256(event_bytes).hexdigest(),
            "tamper": tamper_results, "restored_approved_attachments": 1, "restored_pending_events": 1,
            "attachment_tenant_agent_owner_revision_fenced": True, "outbox_scope_revision_ack_fenced": True,
            "source_unchanged": True, "source_application_encryption": False,
            "key_custody": "local_demo_key_colocated_not_production_key_management"}


# Replaces only exec in the trusted worker, in this runner process. The real
# extraction launcher supplies all namespaces, mounts, environment and limits.
PROBE = r'''
import errno, json, socket
from pathlib import Path
spec = json.loads(Path('/work/probe.json').read_text())
result = {'netns_distinct': os.readlink('/proc/self/ns/net') != spec['netns'],
          'pidns_distinct': os.readlink('/proc/self/ns/pid') != spec['pidns'],
          'sensitive_paths_absent': all(not Path(p).exists() for p in
              ('/home', '/media', '/root', '/run/secrets', '/var/run/docker.sock', '/etc/passwd')),
          'isolated_interpreter': sys.flags.isolated == 1 and sys.executable == '/usr/bin/python3',
          'environment_allowlisted': set(os.environ) <= {'PATH', 'HOME', 'TMPDIR', 'LC_ALL',
              'OMP_THREAD_LIMIT', 'OMP_NUM_THREADS', 'OPENBLAS_NUM_THREADS', 'FONTCONFIG_FILE',
              'PWD', 'LC_CTYPE'}}
try:
    fd = os.open('/usr/bin/python3', os.O_WRONLY)
except OSError as exc:
    result['runtime_write_errno'] = exc.errno
else:
    os.close(fd)
    result['runtime_write_errno'] = 0
for mode, flags in [('read', os.O_RDONLY), ('write', os.O_WRONLY)]:
    try:
        fd = os.open(spec['sentinel'], flags)
    except OSError as exc:
        result['host_' + mode + '_errno'] = exc.errno
    else:
        os.close(fd)
        result['host_' + mode + '_errno'] = 0
with socket.socket() as sock:
    sock.settimeout(0.5)
    result['host_loopback_connect_errno'] = sock.connect_ex(('127.0.0.1', spec['port']))
with open('/proc/net/route') as f:
    result['no_ipv4_default_route'] = all(line.split()[1] != '00000000' for line in f.readlines()[1:])
with open('/proc/net/dev') as f:
    result['only_loopback_interface'] = all(line.split(':')[0].strip() == 'lo' for line in f.readlines()[2:])
with open('/proc/self/mountinfo') as f:
    mounts = [line.split() for line in f]
result['runtime_mounts_readonly'] = all(any(row[4] == p and 'ro' in row[5].split(',') for row in mounts)
    for p in ('/usr', '/lib', '/lib64'))
allowed = {'/', '/usr', '/lib', '/lib64', '/proc', '/dev', '/tmp', '/work', '/etc/ld.so.cache'}
result['mount_targets_allowlisted'] = all(row[4] in allowed or row[4].startswith(('/proc/', '/dev/')) for row in mounts)
with open('/work/writable-control', 'xb') as f:
    f.write(b'synthetic')
result['work_writable'] = True
print(json.dumps(result))
'''


def sandbox_checks(temporary: Path) -> dict:
    from src.guardrails import document_extraction as de

    available = {name: os.access(binary, os.X_OK) for name, binary in
                 {**de._BINARIES, "bwrap": de._BWRAP, "python": "/usr/bin/python3"}.items()}
    if not all(available.values()):
        return {"status": "blocked", "code": "native_tools_missing", "available": available}
    work = temporary / "sandbox-work"
    work.mkdir(mode=0o700)
    sentinel = temporary / "host-sentinel"
    private_file(sentinel, b"synthetic host sentinel")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        port = listener.getsockname()[1]
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            pass
        private_file(work / "probe.json", json.dumps({"port": port, "sentinel": str(sentinel),
                     "netns": os.readlink("/proc/self/ns/net"), "pidns": os.readlink("/proc/self/ns/pid")}).encode())
        launch = de.subprocess.Popen
        mounts_checked = []

        def checked_launch(args: list[str], **kwargs):
            require(args[0] == de._BWRAP and "--unshare-all" in args and "--share-net" not in args,
                    "sandbox_launch_not_isolated")
            bindings = [(args[i], args[i + 1], args[i + 2]) for i in range(len(args))
                        if args[i] in {"--bind", "--ro-bind"}]
            expected = [("--ro-bind", p, p) for p in ("/usr", "/lib", "/lib64")]
            expected.append(("--bind", str(work), "/work"))
            if Path("/etc/ld.so.cache").is_file():
                expected.append(("--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache"))
            require(bindings == expected, "sandbox_unexpected_bind_mount")
            mounts_checked.append(True)
            return launch(args, **kwargs)

        try:
            with patch.object(de.subprocess, "Popen", checked_launch):
                # Unmodified native binary first; probe is not proof of extraction by itself.
                de._run("tesseract", ["--list-langs"], work, threading.Event(), time.monotonic() + 10)
                worker = de._WORKER.replace("os.execve(binary, sys.argv[2:], dict(os.environ))", PROBE)
                require(worker != de._WORKER, "worker_instrumentation_mismatch")
                with patch.object(de, "_WORKER", worker):
                    result = json.loads(de._run("tesseract", [], work, threading.Event(), time.monotonic() + 10))
        except de.ExtractionError as exc:
            diagnostic = (bounded_read(work / "stderr", 65536).decode(errors="replace")
                          if (work / "stderr").is_file() else "")
            code = "native_" + exc.reason
            if "No permissions to create" in diagnostic or "Operation not permitted" in diagnostic:
                code = "user_namespace_or_lsm_denied"
            return {"status": "blocked", "code": code, "available": available,
                    "raw_diagnostics_retained": False, "unsandboxed_fallback": False}
    expected_true = ("netns_distinct", "pidns_distinct", "sensitive_paths_absent", "isolated_interpreter",
                     "environment_allowlisted", "no_ipv4_default_route", "only_loopback_interface",
                     "runtime_mounts_readonly", "mount_targets_allowlisted", "work_writable")
    if not all(result.get(k) is True for k in expected_true):
        return {"status": "fail", "code": "native_isolation_probe_failed", "probe": result,
                "bind_allowlist_checked_launches": len(mounts_checked)}
    # DAC may reject a non-root write before the VFS returns EROFS. The independent
    # mountinfo check above is mandatory; EACCES alone is not read-only evidence.
    require(result["runtime_write_errno"] in {errno.EROFS, errno.EACCES}, "runtime_write_not_denied")
    require(result["host_read_errno"] == result["host_write_errno"] == errno.ENOENT, "host_path_exposed")
    require(result["host_loopback_connect_errno"] in {errno.ECONNREFUSED, errno.ENETUNREACH},
            "host_loopback_reachable_or_ambiguous")
    require(bounded_read(sentinel, 128) == b"synthetic host sentinel", "host_sentinel_changed")
    return {"status": "pass", "probe": result, "bind_allowlist_checked_launches": len(mounts_checked),
            "host_loopback_positive_control": True, "host_sentinel_unchanged": True,
            "unsandboxed_fallback": False}


def extraction_tests(directory: Path, native: bool) -> dict:
    # Tests override the root autouse fixture that otherwise mutates users.db.
    import pytest

    class Results:
        def __init__(self):
            self.counts = {"passed": 0, "failed": 0, "skipped": 0}

        def pytest_runtest_logreport(self, report):
            if report.when == "call" or report.outcome != "passed":
                self.counts[report.outcome] += 1

    os.environ["BULWARK_TEST_DOCUMENT_TOOLS"] = "1" if native else "0"
    results = Results()
    # Console redirected to a bounded disposable file; only aggregate outcomes retained.
    with tempfile.TemporaryFile(dir=directory) as output:
        saved = os.dup(1), os.dup(2)
        try:
            sys.stdout.flush()
            sys.stderr.flush()
            os.dup2(output.fileno(), 1)
            os.dup2(output.fileno(), 2)
            code = pytest.main(["tests/test_storage_sandbox_validation.py", "tests/test_document_extraction.py",
                                "tests/test_docx_extraction.py", "-q", "--tb=no", "-o", "addopts=",
                                "-p", "pytest_asyncio.plugin", "-p", "no:cacheprovider",
                                "--basetemp=" + str(directory / "pytest-tmp")], plugins=[results])
            sys.stdout.flush()
            sys.stderr.flush()
        finally:
            for target, fd in zip((1, 2), saved, strict=True):
                os.dup2(fd, target)
                os.close(fd)
    return {"status": "pass" if code == 0 else "fail", "exit_code": int(code), **results.counts,
            "native_enabled": native, "native_skips_are_not_passes": True}


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="authorize bounded local synthetic validation")
    args = parser.parse_args()
    if not args.run or ROOT != AUTHORIZED_ROOT or Path.cwd().resolve() != ROOT:
        parser.error("explicit --run from the authorized checkout required")
    if os.getuid() == 0 or not (ROOT / "shared").is_dir() or (ROOT / "shared").is_symlink():
        parser.error("nonroot runner and existing nonsymlink shared directory required")
    command("git", "check-ignore", "-q", "shared/storage-sandbox-probe")
    # Process-only configuration: never inherit operator endpoints or secret paths.
    os.environ.clear()
    os.environ.update(PATH="/usr/bin:/bin", LC_ALL="C", PYTHONDONTWRITEBYTECODE="1",
                      PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", OPENBLAS_NUM_THREADS="1", OMP_NUM_THREADS="1")
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(ROOT))
    logging.disable(logging.CRITICAL)
    os.umask(0o077)
    for kind, limit in ((resource.RLIMIT_FSIZE, 32 * 1024**2),
                        (resource.RLIMIT_CORE, 0), (resource.RLIMIT_CPU, 180)):
        resource.setrlimit(kind, (limit, limit))
    before = resources()
    directory = Path(tempfile.mkdtemp(prefix="storage-sandbox-", dir=ROOT / "shared"))
    report = {"schema_version": 1, "started_at": datetime.now(timezone.utc).isoformat(),
              "resources": {"before": before}, "checks": {}, "status": "running"}

    def interrupted(signum: int, frame: object) -> None:
        raise ValidationError("interrupted")

    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGALRM, interrupted)
    signal.alarm(240)
    try:
        report["source_sha256"] = {p: hashlib.sha256(bounded_read(ROOT / p, MAX_DB)).hexdigest() for p in SOURCE_FILES}
        report["checks"]["storage"] = storage_assessment()
        # Go's Docker CLI reserves a large virtual arena even for metadata. Apply
        # the Python/native workload address-space bound only after that command.
        resource.setrlimit(resource.RLIMIT_AS, (1536 * 1024**2, 1536 * 1024**2))
        with tempfile.TemporaryDirectory(prefix="scratch-", dir=directory) as name:
            temporary = Path(name)
            for key, operation in (
                ("backup", lambda: asyncio.run(asyncio.wait_for(backup_checks(directory, temporary), 45))),
                ("sandbox", lambda: sandbox_checks(temporary)),
            ):
                report["resources"]["before_" + key] = resources()
                try:
                    report["checks"][key] = operation()
                except Exception as exc:
                    report["checks"][key] = {
                        "status": "blocked" if isinstance(exc, ValidationError) else "fail",
                        "code": str(exc) if isinstance(exc, ValidationError) else type(exc).__name__,
                    }
                    if isinstance(exc, ValidationError) and str(exc) == "interrupted":
                        raise
            report["resources"]["before_tests"] = resources()
            report["checks"]["extraction_regressions"] = extraction_tests(
                temporary, report["checks"].get("sandbox", {}).get("status") == "pass")
        report["scratch_removed"] = not Path(name).exists()
        report["artifact_permissions_private"] = (
            directory.stat().st_mode & 0o777 == 0o700 and all(
                (directory / p).stat().st_mode & 0o777 == 0o600
                for p in ("backup.aes256gcm", "backup.key")))
        report["python_peak_rss_bytes"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
        report["largest_child_peak_rss_bytes"] = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * 1024
        report["source_unchanged_during_run"] = all(
            hashlib.sha256(bounded_read(ROOT / p, MAX_DB)).hexdigest() == digest
            for p, digest in report["source_sha256"].items())
    except Exception as exc:
        report["checks"]["execution"] = {"status": "blocked", "code": str(exc) if isinstance(exc, ValidationError)
                                         else type(exc).__name__}
    finally:
        signal.alarm(0)
        try:
            report["resources"]["after_cleanup"] = resources()
        except Exception:
            report["checks"]["final_resources"] = {"status": "blocked", "code": "final_resource_check_failed"}
        report["status"] = "blocked"  # Local metadata cannot attest production source/PVC encryption.
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        private_file(directory / "report.json", (json.dumps(report, indent=2) + "\n").encode())
    print(json.dumps({"status": report["status"], "report": str((directory / "report.json").relative_to(ROOT))}))
    return 1


def main() -> int:
    sys.path.insert(0, str(ROOT))
    from scripts.validation_safety import validation_slot
    with validation_slot(ROOT):
        return _main()


if __name__ == "__main__":
    raise SystemExit(main())
