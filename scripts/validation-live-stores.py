#!/usr/bin/env python3
"""Opt-in, cached-image-only local store characterization. No external DSNs."""

from __future__ import annotations

import argparse
import ast
import asyncio
import hashlib
import importlib
import json
import logging
import os
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
AUTHORIZED_ROOT = Path("/media/rokitoh/DATOS2/CODE/bulwark-security-coverage")
RESERVE = 5 * 1024**3
LABEL = "bulwark.validation.owner"
IMAGES = {
    "postgres": "sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685",
    "redis": "sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99",
}


class LabError(Exception):
    """Only fixed, non-secret diagnostic codes cross the reporting boundary."""


def command(*args: str, timeout: int = 60) -> str:
    try:
        # All callers supply fixed executables and generated lab arguments, never a shell.
        result = subprocess.run(  # noqa: S603
            args, capture_output=True, text=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        raise LabError("command_timeout") from None
    except OSError:
        raise LabError("command_unavailable") from None
    if result.returncode:
        diagnostic = result.stderr.lower()
        for needle, code in (
            ("parent snapshot", "docker_parent_snapshot_missing"),
            ("snapshot", "docker_snapshot_error"),
            ("permission denied", "permission_denied"),
            ("cannot connect to the docker daemon", "docker_unavailable"),
            ("no such container", "container_absent"),
            ("no such network", "network_absent"),
            ("no such image", "cached_image_missing"),
            ("no space left", "storage_exhausted"),
            ("apparmor", "docker_apparmor_error"),
            ("iptables", "docker_iptables_error"),
            ("runc", "docker_oci_runtime_error"),
            ("failed to create task", "docker_task_creation_failed"),
            ("failed to mount", "docker_mount_failed"),
        ):
            if needle in diagnostic:
                raise LabError(code) from None
        raise LabError("command_failed") from None
    if args[:2] == ("docker", "logs"):
        return (result.stdout + result.stderr).strip()
    return result.stdout.strip()


def private_file(path: Path, content: str | bytes) -> None:
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(content.encode() if isinstance(content, str) else content)


def certificates(directory: Path) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.now(timezone.utc)
    for name in ("ca", "wrong-ca"):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "local-validation-" + name)])
        ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
              .public_key(key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
              .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
              .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                             critical=True).sign(key, hashes.SHA256()))
        private_file(directory / (name + ".pem"), ca.public_bytes(serialization.Encoding.PEM))
        if name == "ca":
            server_key = ec.generate_private_key(ec.SECP256R1())
            server = (x509.CertificateBuilder()
                      .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
                      .issuer_name(subject).public_key(server_key.public_key())
                      .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                      .not_valid_after(now + timedelta(days=1))
                      .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                      .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
                                     critical=False)
                      .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
                                     critical=False)
                      .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
                      .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                                     critical=False).sign(key, hashes.SHA256()))
            private_file(directory / "server.pem", server.public_bytes(serialization.Encoding.PEM))
            private_file(directory / "server.key", server_key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))


def certificate_rejection(exc: BaseException) -> bool:
    """Connectivity failures must never count as certificate rejection evidence."""
    for _ in range(8):
        if isinstance(exc, ssl.SSLCertVerificationError):
            return True
        if "CERTIFICATE_VERIFY_FAILED" in str(exc):
            return True
        next_exc = exc.__cause__ or exc.__context__
        if next_exc is None:
            break
        exc = next_exc
    return False


class Lab:
    def __init__(self, directory: Path, stores: tuple[str, ...] = ("postgres", "redis")):
        self.directory = directory
        self.name = directory.name
        self.stores = stores
        self.containers: list[str] = []
        self.network_created = False
        self.relays: list[tuple[asyncio.AbstractEventLoop, threading.Thread]] = []
        self.report: dict = {"schema_version": 1, "lab": self.name, "checks": [], "disk": [],
                             "images": {kind: IMAGES[kind] for kind in stores},
                             "stores": stores, "cleanup": [], "status": "running"}

    def check(self, name: str, condition: bool, **details: object) -> None:
        self.report["checks"].append({"name": name, "status": "pass" if condition else "fail", **details})
        if not condition:
            raise LabError("check_failed:" + name)

    def disk(self, stage: str) -> None:
        readings = {}
        for path in ("/var/lib/docker", "/var/lib/containerd", str(ROOT)):
            readings[path] = shutil.disk_usage(path).free
        self.report["disk"].append({"stage": stage, "free_bytes": readings})
        if min(readings.values()) < RESERVE:
            raise LabError("disk_reserve_threatened")

    def preflight(self) -> None:
        self.disk("before")
        if command("docker", "info", "--format", "{{.DockerRootDir}}") != "/var/lib/docker":
            raise LabError("unexpected_docker_storage_root")
        for name in self.stores:
            image = IMAGES[name]
            actual = command("docker", "image", "inspect", image, "--format", "{{.Id}}")
            self.check(name + "_cached_id", actual == image)
        for module in (("asyncpg",) if "postgres" in self.stores else ()) + ("redis", "cryptography"):
            imported = importlib.import_module(module)
            self.report.setdefault("dependencies", {})[module] = imported.__version__
        self.report["source_sha256"] = {
            path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
            for path in ("src/storage/database.py", "src/storage/attachment_migrations.py",
                         "src/storage/outbox_migrations.py", "src/attachments/store.py",
                         "src/telemetry/shared_outbox.py", "src/middleware/auth.py", "src/routes/proxy.py")
        }
        command("docker", "network", "create", "--internal", "--label", f"{LABEL}={self.name}", self.name)
        self.network_created = True

    def create(self, kind: str) -> str:
        self.disk("before_" + kind)
        name = self.name + "-" + kind
        data = self.directory / (kind + "-data")
        data.mkdir(mode=0o700)
        config = self.directory / kind
        config.mkdir(mode=0o700)
        certificates(config)
        private_file(config / "password", secrets.token_hex(32))
        uid, gid = os.getuid(), os.getgid()
        if uid == 0:
            raise LabError("runner_must_be_nonroot")
        base = ["docker", "create", "--pull=never", "--name", name, "--label", f"{LABEL}={self.name}",
                "--network", self.name, "--user", f"{uid}:{gid}", "--read-only", "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true", "--memory=384m", "--cpus=1", "--pids-limit=128",
                "--log-driver=local", "--log-opt=max-size=1m", "--log-opt=max-file=2",
                "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m",  # noqa: S108 - private container tmpfs
                "--mount", f"type=bind,src={config},dst=/lab,readonly"]
        if kind == "postgres":
            private_file(config / "passwd", f"root:x:0:0:root:/root:/bin/sh\n"
                         f"postgres:x:{uid}:{gid}:postgres:/tmp:/bin/sh\n")
            private_file(config / "pg_hba.conf", "local all all trust\nhostssl all all 0.0.0.0/0 scram-sha-256\n"
                         "hostssl all all ::/0 scram-sha-256\nhostnossl all all 0.0.0.0/0 reject\n")
            base += ["--mount", f"type=bind,src={config / 'passwd'},dst=/etc/passwd,readonly",
                     "--mount", f"type=bind,src={data},dst=/var/lib/postgresql/data",
                     "--tmpfs", f"/var/run/postgresql:rw,nosuid,size=8m,uid={uid},gid={gid}",
                     "-p", "127.0.0.1::5432", "-e", "POSTGRES_USER=validator",
                     "-e", "POSTGRES_DB=validation", "-e", "POSTGRES_PASSWORD_FILE=/lab/password",
                     IMAGES[kind], "postgres", "-c", "ssl=on", "-c", "ssl_min_protocol_version=TLSv1.2",
                     "-c", "ssl_cert_file=/lab/server.pem", "-c", "ssl_key_file=/lab/server.key",
                     "-c", "hba_file=/lab/pg_hba.conf", "-c", "shared_buffers=32MB", "-c", "max_connections=20"]
        else:
            password = (config / "password").read_text()
            private_file(config / "redis.conf", "bind 0.0.0.0\nport 0\ntls-port 6379\n"
                         "tls-cert-file /lab/server.pem\ntls-key-file /lab/server.key\n"
                         "tls-ca-cert-file /lab/ca.pem\ntls-auth-clients no\n"
                         'tls-protocols "TLSv1.2 TLSv1.3"\n'
                         f"requirepass {password}\ndir /data\nappendonly yes\nappendfsync always\n"
                         "maxmemory 64mb\nmaxmemory-policy noeviction\n")
            base += ["--mount", f"type=bind,src={data},dst=/data", "-p", "127.0.0.1::6379",
                     IMAGES[kind], "redis-server", "/lab/redis.conf"]
        # Track before create: failed creates can leave an owned container behind.
        self.containers.append(name)
        command(*base)
        self.owned("container", name)
        try:
            command("docker", "start", name)
        except LabError:
            # State.Error is daemon startup metadata, not application logs. Persist
            # bounded diagnostics after stripping all generated credentials/paths.
            error = command("docker", "container", "inspect", name, "--format", "{{.State.Error}}")
            error = error.replace((config / "password").read_text(), "[REDACTED]")
            error = error.replace(str(self.directory), "[LAB]")
            error = re.sub(r"[a-f0-9]{64}", "[ID]", error)
            self.report.setdefault("startup_diagnostics", {})[kind] = error[:1200]
            raise
        self.disk("started_" + kind)
        return name

    def owned(self, resource: str, name: str) -> None:
        if not name.startswith(self.name) or not self.name.startswith("bulwark-validation-"):
            raise LabError("ownership_name_mismatch")
        label = command("docker", resource, "inspect", name, "--format",
                        '{{index .Labels "' + LABEL + '"}}' if resource == "network" else
                        '{{index .Config.Labels "' + LABEL + '"}}')
        if label != self.name:
            raise LabError("ownership_label_mismatch")

    def control(self, action: str, name: str) -> None:
        if action not in {"stop", "start", "restart"}:
            raise LabError("invalid_container_action")
        self.owned("container", name)
        command("docker", action, *(["--time", "10"] if action != "start" else []), name)
        self.disk(action)

    def port(self, name: str, port: int) -> int:
        try:
            binding = command("docker", "port", name, str(port) + "/tcp")
        except LabError:
            self.report.setdefault("network_diagnostics", {})[name] = json.loads(command(
                "docker", "container", "inspect", name, "--format", "{{json .NetworkSettings.Ports}}"))
            self.owned("container", name)
            networks = json.loads(command("docker", "container", "inspect", name, "--format",
                                          "{{json .NetworkSettings.Networks}}"))
            if set(networks) != {self.name}:
                raise LabError("unexpected_container_networks") from None
            address = networks[self.name]["IPAddress"]
            # No egress-capable network: Docker 29 internal bridges suppress port
            # publication. Relay opaque bytes from loopback to this owned IP only.
            socket.inet_pton(socket.AF_INET, address)
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(16)
            listener.setblocking(False)
            assigned = listener.getsockname()[1]
            loop = asyncio.new_event_loop()
            ready = threading.Event()

            async def serve() -> None:
                active = 0

                async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                    nonlocal active
                    if active >= 16:
                        writer.close()
                        return
                    active += 1
                    upstream = None
                    try:
                        async with asyncio.timeout(180):
                            remote, upstream = await asyncio.wait_for(asyncio.open_connection(address, port), 3)

                            async def copy(source: asyncio.StreamReader, target: asyncio.StreamWriter) -> None:
                                while chunk := await source.read(65536):
                                    target.write(chunk)
                                    await target.drain()

                            tasks = [asyncio.create_task(copy(reader, upstream)),
                                     asyncio.create_task(copy(remote, writer))]
                            try:
                                await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                            finally:
                                for task in tasks:
                                    task.cancel()
                                await asyncio.gather(*tasks, return_exceptions=True)
                    except (OSError, TimeoutError):
                        # Expected while a store stops or restarts; no data is logged.
                        writer.close()
                    finally:
                        writer.close()
                        if upstream:
                            upstream.close()
                        active -= 1

                server = await asyncio.start_server(relay, sock=listener, limit=65536)
                ready.set()
                try:
                    await server.serve_forever()
                finally:
                    server.close()
                    await server.wait_closed()

            def run() -> None:
                asyncio.set_event_loop(loop)
                loop.create_task(serve())
                try:
                    loop.run_forever()
                finally:
                    tasks = asyncio.all_tasks(loop)
                    for task in tasks:
                        task.cancel()
                    loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
                    loop.close()
                    listener.close()

            thread = threading.Thread(target=run, daemon=True, name=self.name + "-relay")
            self.relays.append((loop, thread))
            thread.start()
            if not ready.wait(5):
                raise LabError("loopback_relay_start_failed") from None
            self.report.setdefault("loopback_relays", []).append({"container": name, "port": assigned})
            return assigned
        host, number = binding.rsplit(":", 1)
        if host != "127.0.0.1" or not 1 <= int(number) <= 65535:
            raise LabError("non_loopback_binding")
        return int(number)

    def cleanup(self) -> None:
        for loop, thread in self.relays:
            loop.call_soon_threadsafe(loop.stop)
            thread.join(timeout=5)
            self.report["cleanup"].append({"resource": thread.name,
                                          "status": "removed" if not thread.is_alive() else "relay_stop_failed"})
        resources = [("container", name) for name in reversed(self.containers)]
        if self.network_created:
            resources.append(("network", self.name))
        for resource, name in resources:
            try:
                self.owned(resource, name)
                command("docker", resource, "rm", *(["--force"] if resource == "container" else []), name)
                self.report["cleanup"].append({"resource": name, "status": "removed"})
            except LabError as exc:
                self.report["cleanup"].append({"resource": name, "status": str(exc)})


async def postgres_checks(lab: Lab, name: str) -> None:
    from src.attachments.store import PostgreSQLAttachmentStore, StoreError
    from src.storage.database import PostgreSQLEngine
    from src.telemetry.schema import BulwarkFields, SecurityTelemetryEvent, TenantFields
    from src.telemetry.shared_outbox import DestinationSnapshot, PostgreSQLSharedOutbox

    directory = lab.directory / "postgres"
    password = (directory / "password").read_text()
    port = lab.port(name, 5432)
    os.environ["SSL_CERT_FILE"] = str(directory / "ca.pem")

    def engine(host: str = "localhost") -> PostgreSQLEngine:
        return PostgreSQLEngine(f"postgresql://validator:{password}@{host}:{port}/validation",
                                pool_min=1, pool_max=2, ssl=True, ssl_mode="verify-full")

    db = engine()
    out_db = engine()
    store = PostgreSQLAttachmentStore(db)
    outbox = PostgreSQLSharedOutbox(out_db, max_events=10, max_bytes=1024**2)
    try:
        for attempt in range(10):
            try:
                await db.init()
                break
            except RuntimeError:
                if attempt == 9:
                    try:
                        await asyncio.to_thread(db.sync_fetch_one, "SELECT 1")
                    except Exception as exc:
                        lab.report["postgres_connection_diagnostic"] = str(exc).replace(password, "[REDACTED]")[:800]
                    raise LabError("postgres_not_ready") from None
                await asyncio.sleep(1)
        row = await db.fetch_one("SELECT ssl, version FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
        lab.check("postgres_verified_tls", bool(row and row["ssl"]), protocol=row["version"])
        # Direct abstraction path preserves the certificate exception, unlike pool retries.
        for case, host, ca in (("wrong_ca", "localhost", "wrong-ca.pem"),
                               ("wrong_hostname", "127.0.0.1", "ca.pem")):
            os.environ["SSL_CERT_FILE"] = str(directory / ca)
            probe = engine(host)
            rejected = False
            try:
                await asyncio.to_thread(probe.sync_fetch_one, "SELECT 1")
            except Exception as exc:
                rejected = certificate_rejection(exc)
            lab.check("postgres_" + case + "_rejected", rejected)
        os.environ["SSL_CERT_FILE"] = str(directory / "ca.pem")
        await store.initialize()
        await outbox.initialize()
        row = await db.fetch_one("SELECT version FROM attachment_store_state WHERE id = 'attachments'")
        lab.check("postgres_migrations", row["version"] == (await outbox.status())["version"] == 1)
        scope = {"tenant": "tenant-a", "agent": "agent-a", "owner": "synthetic-owner"}
        document = await store.create(**scope, mime="text/plain", raw=b"synthetic document",
                                      policy_revision="revision-a")
        lab.check("attachment_created", document["state"] == "queued")
        old = await store.claim(lease_seconds=1)
        await asyncio.sleep(1.1)
        current = await store.claim()
        lab.check("attachment_stale_fenced", old is not None and current is not None and
                  not await store.finish(document["id"], old["lease_token"], state="approved", text="stale"))
        lab.check("attachment_finished", await store.finish(document["id"], current["lease_token"],
                                                            state="approved", text="sanitized text"))
        lab.check("attachment_cross_tenant_hidden", await store.get(document["id"], **{
            **scope, "tenant": "tenant-b"}) is None)
        try:
            await store.resolve(document["id"], **scope, policy_revision="revision-b")
        except StoreError as exc:
            lab.check("attachment_policy_revision_rejected", exc.code == "policy_changed")
        else:
            lab.check("attachment_policy_revision_rejected", False)
        before = await db.fetch_one("SELECT documents, bytes FROM attachment_store_state WHERE id = 'attachments'")
        try:
            async with db.transaction() as tx:
                await tx.execute("UPDATE attachment_store_state SET documents = documents + 1 WHERE id = 'attachments'")
                await tx.execute("UPDATE attachment_documents SET state = ? WHERE id = ?", ("invalid", document["id"]))
        except Exception as exc:
            lab.check("attachment_transaction_constraint", getattr(exc, "sqlstate", None) == "23514")
        else:
            lab.check("attachment_transaction_constraint", False)
        after = await db.fetch_one("SELECT documents, bytes FROM attachment_store_state WHERE id = 'attachments'")
        lab.check("attachment_transaction_rollback", before.to_dict() == after.to_dict())
        destination = DestinationSnapshot(destination_id="local-evidence", revision="a" * 64,
                                          tenant_scope=("tenant-a",))
        event = SecurityTelemetryEvent(bulwark=BulwarkFields(verdict="block"), tenant=TenantFields(id="tenant-a"))
        lab.check("outbox_enqueued", await outbox.enqueue(event, (destination,)))
        before_out = await outbox.status()
        try:
            async with out_db.transaction() as tx:
                await tx.execute("UPDATE telemetry_outbox_state SET events = events + 1 WHERE id = 'outbox'")
                await tx.execute("INSERT INTO telemetry_outbox_deliveries (event_id, destination, snapshot) "
                                 "VALUES (?, ?, ?)", ("missing-event", "rollback-test", "{}"))
        except Exception as exc:
            lab.check("outbox_transaction_constraint", getattr(exc, "sqlstate", None) == "23503")
        else:
            lab.check("outbox_transaction_constraint", False)
        lab.check("outbox_transaction_rollback", before_out == await outbox.status())
        old_leases = await outbox.claim(destination, lease_seconds=1)
        lab.check("outbox_claimed", len(old_leases) == 1)
        await db.close()
        await out_db.close()
        await asyncio.to_thread(lab.control, "restart", name)
        await db.init()
        await out_db.init()
        # New store objects rerun versioned migrations against persisted state.
        store = PostgreSQLAttachmentStore(db)
        outbox = PostgreSQLSharedOutbox(out_db, max_events=10, max_bytes=1024**2)
        await store.initialize()
        await outbox.initialize()
        lab.check("attachment_resolved_after_restart", await store.resolve(
            document["id"], **scope, policy_revision="revision-a") == "sanitized text")
        await asyncio.sleep(1.1)
        leases = await outbox.claim(destination)
        lab.check("outbox_reclaimed_after_restart", len(leases) == 1 and leases[0].attempts == 2 and
                  leases[0].event.event.id == event.event.id)
        lab.check("outbox_stale_ack_fenced", await outbox.finish(old_leases, success=True) == 0)
        lab.check("outbox_stale_failure_fenced", await outbox.finish(old_leases, success=False) == 0)
        forged = leases[0].model_copy(update={"tenant": "tenant-b"})
        lab.check("outbox_cross_tenant_ack_fenced", await outbox.finish([forged], success=True) == 0)
        lab.check("outbox_finished", await outbox.finish(leases, success=True) == 1)
        await db.close()
        await out_db.close()
        await asyncio.to_thread(lab.control, "restart", name)
        await out_db.init()
        status = await outbox.status()
        lab.check("outbox_ack_persisted_after_restart",
                  status["events"] == status["bytes"] == 0 and status["acked"] == 1)
    finally:
        await db.close()
        await out_db.close()


def stream_lease_literals(source: bytes) -> dict[str, str | int]:
    """Read exact current literals without importing proxy startup dependencies."""
    expected = {
        "_STREAM_LEASE_ACQUIRE": str, "_STREAM_LEASE_RELEASE": str,
        "_STREAM_LEASE_GLOBAL": str, "_STREAM_LEASE_TENANT": str,
        "_MAX_STREAM_DURATION_SECONDS": int, "_STREAM_LEASE_MARGIN_SECONDS": int,
    }
    values = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in expected:
                    if target.id in values or not isinstance(node.value, ast.Constant):
                        raise LabError("stream_lease_source_contract_changed")
                    value = ast.literal_eval(node.value)
                    if type(value) is not expected[target.id]:
                        raise LabError("stream_lease_source_contract_changed")
                    values[target.id] = value
    if values.keys() != expected.keys():
        raise LabError("stream_lease_source_contract_changed")
    return values


async def redis_stream_lease_checks(lab: Lab, url: str) -> None:
    import redis.asyncio as redis
    from redis.backoff import NoBackoff
    from redis.retry import Retry

    source = (ROOT / "src/routes/proxy.py").read_bytes()
    literals = stream_lease_literals(source)
    acquire, release = literals["_STREAM_LEASE_ACQUIRE"], literals["_STREAM_LEASE_RELEASE"]
    global_key = literals["_STREAM_LEASE_GLOBAL"]
    tenant_prefix = literals["_STREAM_LEASE_TENANT"]
    production_ttl = literals["_MAX_STREAM_DURATION_SECONDS"] + literals["_STREAM_LEASE_MARGIN_SECONDS"]
    lab.report["stream_lease_source"] = {
        "path": "src/routes/proxy.py", "sha256": hashlib.sha256(source).hexdigest(),
        "acquire_sha256": hashlib.sha256(acquire.encode()).hexdigest(),
        "release_sha256": hashlib.sha256(release.encode()).hexdigest(),
        "production_lease_seconds": production_ttl, "concurrent_clients": 8,
    }
    # Exact production keys are safe only because the runner owns this entire
    # fresh Redis instance. Never accept an operator-provided URL here.
    tenant_keys = [tenant_prefix + ":" + tenant for tenant in ("global", "lab-a", "lab-b", "lab-c")]
    keys = [global_key, *tenant_keys]
    client = redis.from_url(url, decode_responses=True, socket_timeout=1, socket_connect_timeout=1,
                            max_connections=8, retry=Retry(NoBackoff(), 0))
    try:
        lab.check("stream_lease_fresh_namespace", await client.exists(*keys) == 0)
        for case in ("tenant", "global"):
            ready = asyncio.Event()
            assignments = [tenant_keys[0]] * 8 if case == "tenant" else [tenant_keys[i % 4] for i in range(8)]
            tokens = [secrets.token_hex(16) for _ in range(8)]
            global_limit = 6 if case == "tenant" else 3
            tenant_limit = 2 if case == "tenant" else 3

            async def admit(key: str, token: str, ready=ready,
                            global_limit=global_limit, tenant_limit=tenant_limit) -> int:
                await ready.wait()
                return await client.eval(acquire, 2, key, global_key, token, tenant_limit, global_limit, production_ttl)

            tasks = [asyncio.create_task(admit(key, token)) for key, token in zip(assignments, tokens, strict=True)]
            ready.set()
            try:
                results = await asyncio.wait_for(asyncio.gather(*tasks), 10)
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 2)
            admitted = {token for token, result in zip(tokens, results, strict=True) if result == 200}
            expected_count, refused = (2, 429) if case == "tenant" else (3, 503)
            lab.check("stream_lease_concurrent_" + case + "_bound",
                      results.count(200) == expected_count and results.count(refused) == 8 - expected_count,
                      admissions=results.count(200), rejections=results.count(refused), rejection_code=refused)
            lab.check("stream_lease_" + case + "_global_members",
                      set(await client.zrange(global_key, 0, -1)) == admitted)
            for key in set(assignments):
                expected = {token for assigned, token, result in zip(assignments, tokens, results, strict=True)
                            if assigned == key and result == 200}
                actual = set(await client.zrange(key, 0, -1))
                lab.check("stream_lease_" + case + "_tenant_members",
                          actual == expected and len(actual) <= tenant_limit)
            for key in keys:
                kind = await client.type(key)
                ttl = await client.pttl(key)
                lab.check("stream_lease_" + case + "_finite_ttl",
                          (kind == "none" and ttl == -2) or (kind == "zset" and 0 < ttl <= production_ttl * 1000))
            # Denied tokens and unknown tokens must not decrement somebody else's reservation.
            for key, token, result in zip(assignments, tokens, results, strict=True):
                if result != 200:
                    await client.eval(release, 2, key, global_key, token)
            await client.eval(release, 2, tenant_keys[0], global_key, "never-admitted")
            lab.check("stream_lease_" + case + "_rejected_release_noop",
                      set(await client.zrange(global_key, 0, -1)) == admitted)
            for key, token, result in zip(assignments, tokens, results, strict=True):
                if result == 200:
                    before = set(await client.zrange(global_key, 0, -1))
                    tenant_before = set(await client.zrange(key, 0, -1))
                    lab.check("stream_lease_release_lua_accepted", await client.eval(
                        release, 2, key, global_key, token) == 1)
                    await client.eval(release, 2, key, global_key, token)
                    lab.check("stream_lease_exact_token_removal",
                              set(await client.zrange(global_key, 0, -1)) == before - {token} and
                              set(await client.zrange(key, 0, -1)) == tenant_before - {token})
            lab.check("stream_lease_" + case + "_released_keys_absent", await client.exists(*keys) == 0)

        key = tenant_keys[0]
        old, keeper, current = [secrets.token_hex(16) for _ in range(3)]
        lab.check("stream_lease_short_old_admitted",
                  await client.eval(acquire, 2, key, global_key, old, 2, 2, 1) == 200)
        lab.check("stream_lease_keeper_admitted",
                  await client.eval(acquire, 2, key, global_key, keeper, 2, 2, 3) == 200)
        await asyncio.sleep(1.1)
        # The keeper keeps both keys alive; admission must prune the expired
        # member by Redis TIME, rather than relying only on whole-key expiry.
        lab.check("stream_lease_expired_score_reclaimed", await client.eval(
            acquire, 2, key, global_key, current, 2, 2, 3) == 200)
        before = await client.zrange(global_key, 0, -1, withscores=True)
        lab.check("stream_lease_reclaimed_members", {token for token, score in before} == {keeper, current})
        await client.eval(release, 2, key, global_key, old)
        lab.check("stream_lease_expired_token_cannot_remove_current",
                  await client.zrange(global_key, 0, -1, withscores=True) == before and
                  await client.zrange(key, 0, -1, withscores=True) == before)
        lab.check("stream_lease_reclaim_keeps_finite_ttl",
                  0 < await client.pttl(key) <= 3000 and 0 < await client.pttl(global_key) <= 3000)
        deadline = asyncio.get_running_loop().time() + 5
        while await client.exists(*keys) and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.1)
        lab.check("stream_lease_abandoned_keys_expire", await client.exists(*keys) == 0)
        await client.eval(release, 2, key, global_key, old)
        lab.check("stream_lease_late_release_no_immortal_keys",
                  await client.pttl(key) == -2 and await client.pttl(global_key) == -2)
        lab.check("stream_lease_legacy_counters_absent", await client.exists(
            "bulwark:streams:global", "bulwark:streams:tenant:global") == 0)
        lab.check("stream_lease_source_unchanged_during_checks",
                  hashlib.sha256((ROOT / "src/routes/proxy.py").read_bytes()).hexdigest() ==
                  lab.report["stream_lease_source"]["sha256"])
    finally:
        await client.aclose()


def redis_checks(lab: Lab, name: str) -> None:
    import redis

    directory = lab.directory / "redis"
    password = (directory / "password").read_text()
    port = lab.port(name, 6379)

    def url(host: str = "localhost", ca: str = "ca.pem") -> str:
        query = urlencode({"ssl_ca_certs": str(directory / ca), "ssl_cert_reqs": "required",
                           "ssl_check_hostname": "true", "socket_connect_timeout": "1"})
        return f"rediss://:{password}@{host}:{port}/0?{query}"

    client = redis.from_url(url(), socket_timeout=1, decode_responses=True)
    try:
        for attempt in range(30):
            try:
                if client.ping():
                    break
            except redis.ConnectionError as exc:
                if attempt == 29:
                    lab.report["redis_connection_diagnostic"] = str(exc).replace(password, "[REDACTED]")[:800]
                    raise LabError("redis_not_ready") from None
                time.sleep(0.2)
        lab.check("redis_verified_tls", client.ping())
        for case, host, ca in (("wrong_ca", "localhost", "wrong-ca.pem"),
                               ("wrong_hostname", "127.0.0.1", "ca.pem")):
            probe = redis.from_url(url(host, ca), socket_timeout=1)
            rejected = False
            try:
                probe.ping()
            except Exception as exc:
                rejected = certificate_rejection(exc)
            finally:
                probe.close()
            lab.check("redis_" + case + "_rejected", rejected)
        asyncio.run(asyncio.wait_for(redis_stream_lease_checks(lab, url()), 30))
        # Fresh runner process, real helper and its real TTLCache instances.
        os.environ["BULWARK_REDIS_URL"] = url().replace(f":{password}@", "")
        os.environ["BULWARK_REDIS_PASSWORD_FILE"] = str(directory / "password")
        os.environ["BULWARK_AUTH_CACHE_TTL"] = "2.0"
        os.environ["BULWARK_REVOKED_CACHE_TTL"] = "60.0"
        private_file(directory / "jwt-secret", secrets.token_hex(32))
        os.environ["BULWARK_JWT_SECRET_FILE"] = str(directory / "jwt-secret")
        from src.config import _build_settings
        from src.middleware import auth

        configured = _build_settings()
        auth.settings.redis_url = configured.redis_url
        auth.settings.redis_password = configured.redis_password
        auth.settings.redis_tls_insecure = configured.redis_tls_insecure
        # First ever helper call happens with Redis stopped. Recovery must happen
        # solely through repeated public helper calls, never global resets.
        lab.control("stop", name)
        lab.check("revocation_cold_outage_fail_closed", auth._is_token_revoked("synthetic-cold"))
        lab.control("start", name)
        deadline = time.monotonic() + 12
        recovered = False
        while time.monotonic() < deadline:
            if not auth._is_token_revoked("synthetic-cold"):
                recovered = True
                break
            time.sleep(0.1)
        lab.check("revocation_cold_start_recovery", recovered, manual_global_reset=False)
        lab.check("revocation_clean_allowed", not auth._is_token_revoked("synthetic-revoke"))
        lab.check("revocation_second_clean_allowed", not auth._is_token_revoked("synthetic-clean"))
        client.sadd("bulwark:revoked_tokens", "synthetic-revoke")
        client.sadd("bulwark:revoked_tokens", "synthetic-persisted")
        cached = not auth._is_token_revoked("synthetic-revoke")
        lab.check("revocation_positive_cache_window", cached, ttl_seconds=auth._auth_cache.ttl)
        time.sleep(auth._auth_cache.ttl + 0.1)
        lab.check("revocation_detected_after_ttl", auth._is_token_revoked("synthetic-revoke"))
        lab.check("revocation_clean_before_outage", not auth._is_token_revoked("synthetic-clean"))
        lab.control("stop", name)
        lab.check("revocation_negative_cache_during_outage", auth._is_token_revoked("synthetic-revoke"))
        lab.check("revocation_unknown_outage_fail_closed", auth._is_token_revoked("synthetic-unknown"))
        time.sleep(auth._auth_cache.ttl + 0.1)
        lab.check("revocation_expired_positive_fail_closed", auth._is_token_revoked("synthetic-clean"))
        lab.control("start", name)
        for attempt in range(30):
            try:
                if client.ping():
                    break
            except redis.ConnectionError:
                if attempt == 29:
                    raise LabError("redis_restart_not_ready") from None
                time.sleep(0.2)
        lab.check("redis_revocation_persisted", bool(client.sismember("bulwark:revoked_tokens", "synthetic-revoke")))
        deadline = time.monotonic() + 12
        recovered = False
        while time.monotonic() < deadline:
            if not auth._is_token_revoked("synthetic-clean"):
                recovered = True
                break
            time.sleep(0.1)
        lab.check("revocation_established_client_recovery", recovered, manual_global_reset=False)
        lab.check("revocation_persisted_without_cache", auth._is_token_revoked("synthetic-persisted"))
        redis_memory_retention_checks(lab, client)
    finally:
        client.close()
        auth_module = sys.modules.get("src.middleware.auth")
        if auth_module and auth_module._revocation_redis:
            auth_module._revocation_redis.close()


def redis_memory_retention_checks(lab, client):
    """Only the generated lab DB: bounded saturation, never the user's Redis."""
    import redis

    original = int(client.config_get("maxmemory")["maxmemory"])
    lab.check("security_state_noeviction", client.config_get("maxmemory-policy")["maxmemory-policy"] == "noeviction")
    prefix = "validation-pressure:" + secrets.token_hex(8)
    keys = [f"{prefix}:{index}" for index in range(64)]
    before = int(client.info("stats")["evicted_keys"])
    failed = False
    try:
        used = int(client.info("memory")["used_memory"])
        client.config_set("maxmemory", used + 1024 * 1024)
        for key in keys:
            try:
                client.set(key, b"x" * 65536)
            except redis.exceptions.OutOfMemoryError:
                failed = True
                break
        lab.check("memory_pressure_rejects_new_writes", failed)
        lab.check("memory_pressure_keeps_revocation", bool(
            client.sismember("bulwark:revoked_tokens", "synthetic-revoke")))
        lab.check("memory_pressure_no_evicted_keys", int(client.info("stats")["evicted_keys"]) == before)
    finally:
        client.config_set("maxmemory", original)
        client.delete(*keys)
    lab.check("memory_pressure_write_recovery", client.set(keys[0], "recovered"))
    client.delete(keys[0])


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="authorize this isolated local run")
    parser.add_argument("--redis-only", action="store_true", help="skip PostgreSQL provisioning and checks")
    args = parser.parse_args()
    if not args.run:
        parser.error("explicit --run required; no external endpoints are accepted")
    if ROOT != AUTHORIZED_ROOT or Path.cwd().resolve() != ROOT:
        parser.error("run only from the authorized checkout")
    if not (ROOT / "shared").is_dir():
        parser.error("shared parent directory must already exist")
    command("git", "check-ignore", "-q", "shared/bulwark-validation-probe")
    os.umask(0o077)
    directory = Path(tempfile.mkdtemp(prefix="bulwark-validation-", dir=ROOT / "shared"))
    lab = Lab(directory, stores=("redis",) if args.redis_only else ("postgres", "redis"))
    sys.path.insert(0, str(ROOT))
    # Do not inherit any operator endpoint, secret file, auth mode or PG service.
    for key in tuple(os.environ):
        if key.startswith(("BULWARK_", "ADMIN_", "PG")) or key in {"SSL_CERT_FILE", "SSL_CERT_DIR"}:
            os.environ.pop(key)
    logging.disable(logging.CRITICAL)

    def interrupted(signum: int, frame: object) -> None:
        raise LabError("interrupted")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        lab.preflight()
        for kind in lab.stores:
            try:
                name = lab.create(kind)
                if kind == "postgres":
                    asyncio.run(asyncio.wait_for(postgres_checks(lab, name), timeout=180))
                else:
                    redis_checks(lab, name)
            except Exception as exc:
                lab.report["checks"].append({"name": kind + "_execution", "status": "blocked",
                                             "code": str(exc) if isinstance(exc, LabError) else type(exc).__name__})
                try:
                    owned_name = lab.name + "-" + kind
                    lab.owned("container", owned_name)
                    logs = command("docker", "logs", "--tail", "20", owned_name)
                    logs = logs.replace((directory / kind / "password").read_text(), "[REDACTED]")
                    lab.report.setdefault("store_diagnostics", {})[kind] = logs[-4000:]
                except LabError:
                    lab.report.setdefault("store_diagnostics", {})[kind] = "diagnostics_unavailable"
                if isinstance(exc, LabError) and str(exc) in {"disk_reserve_threatened", "interrupted"}:
                    break
    except Exception as exc:
        lab.report["checks"].append({"name": "preflight", "status": "blocked",
                                     "code": str(exc) if isinstance(exc, LabError) else type(exc).__name__})
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        lab.cleanup()
        try:
            lab.disk("after_cleanup")
        except Exception as exc:
            lab.report["checks"].append({"name": "final_disk", "status": "fail",
                                         "code": str(exc) if isinstance(exc, LabError) else type(exc).__name__})
        failures = any(check["status"] in {"fail", "blocked"} for check in lab.report["checks"])
        failures |= any(item["status"] not in {"removed", "container_absent"} for item in lab.report["cleanup"])
        lab.report["status"] = "blocked_or_failed" if failures else "completed"
        private_file(directory / "report.json", json.dumps(lab.report, indent=2) + "\n")
    print(json.dumps({"status": lab.report["status"], "report": str(directory / "report.json")}))
    return int(failures)


def main() -> int:
    sys.path.insert(0, str(ROOT))
    from scripts.validation_safety import validation_slot
    with validation_slot(ROOT):
        return _main()


if __name__ == "__main__":
    raise SystemExit(main())
