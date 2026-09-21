#!/usr/bin/env python3
"""Explicitly authorized, offline-image Elastic backend validation, not SIEM UI certification."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import secrets
import shutil
import signal
import ssl
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUTHORIZED_ROOT = Path("/media/rokitoh/DATOS2/CODE/bulwark-security-coverage")
IMAGE = "sha256:a06b03a2db8db2be43d3c3851e7bcebdd4fff79f4db08c7da6bad7a8776d3e15"
LABEL = "bulwark.validation.live-siem"
RESERVE = 5 * 1024**3
MEMORY_LIMIT = 1536 * 1024**2
INDEX = "bulwark-live-validation"


class LabError(Exception):
    """Fixed safe codes only; never report command output or HTTP bodies."""


def command(*args: str) -> str:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=60, check=False)  # noqa: S603
    except (OSError, subprocess.TimeoutExpired):
        raise LabError("command_unavailable_or_timeout") from None
    if result.returncode:
        for needle, code in (("no such container", "container_absent"), ("no such network", "network_absent"),
                             ("snapshot", "docker_snapshot_error"), ("no such image", "cached_image_missing")):
            if needle in result.stderr.lower():
                raise LabError(code)
        raise LabError("command_failed")
    if args[:2] == ("docker", "logs"):
        return (result.stdout + result.stderr).strip()
    return result.stdout.strip()


def private_file(path: Path, content: str | bytes) -> None:
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(content.encode() if isinstance(content, str) else content)


def certificates(directory: Path, address: str) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.now(timezone.utc)
    for name in ("ca", "wrong-ca"):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "isolated-validation-" + name)])
        ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
              .public_key(key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
              .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
              .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
              .sign(key, hashes.SHA256()))
        private_file(directory / (name + ".pem"), ca.public_bytes(serialization.Encoding.PEM))
        if name == "wrong-ca":
            continue
        server_key = ec.generate_private_key(ec.SECP256R1())
        server = (x509.CertificateBuilder()
                  .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
                  .issuer_name(subject).public_key(server_key.public_key())
                  .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                  .not_valid_after(now + timedelta(days=1))
                  .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                  .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), False)
                  .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
                  .add_extension(x509.SubjectAlternativeName([
                      x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address(address))]), False)
                  .add_extension(x509.ExtendedKeyUsage([
                      ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), False)
                  .sign(key, hashes.SHA256()))
        private_file(directory / "server.pem", server.public_bytes(serialization.Encoding.PEM))
        private_file(directory / "server.key", server_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def certificate_rejection(exc: BaseException) -> bool:
    for _ in range(8):
        if isinstance(exc, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in str(exc):
            return True
        cause = exc.__cause__ or exc.__context__
        if cause is None:
            break
        exc = cause
    return False


class Lab:
    def __init__(self, directory: Path):
        self.directory = directory
        self.name = directory.name
        self.container = self.name + "-elastic"
        self.created = False
        self.network = False
        self.report: dict = {"schema_version": 1, "scope": "Elastic backend only; no SIEM UI certification",
                             "lab": self.name, "image": IMAGE, "checks": [], "resources": [], "cleanup": []}

    def check(self, name: str, condition: bool, **details: object) -> None:
        self.report["checks"].append({"name": name, "status": "pass" if condition else "fail", **details})
        if not condition:
            raise LabError("check_failed:" + name)

    def resources(self, stage: str, *, launching: bool = False) -> None:
        docker_root = command("docker", "info", "--format", "{{.DockerRootDir}}")
        paths = {"/", docker_root, "/var/lib/containerd", str(ROOT)}
        free = {path: shutil.disk_usage(path).free for path in sorted(paths)}
        memory = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
        available = int(memory["MemAvailable"].split()[0]) * 1024
        self.report["resources"].append({"stage": stage, "free_bytes": free, "available_memory": available})
        if min(free.values()) < RESERVE + (1024**3 if launching else 0):
            raise LabError("storage_reserve_threatened")
        if launching and available < MEMORY_LIMIT + 2 * 1024**3:
            raise LabError("insufficient_memory_headroom")

    def owned(self, kind: str) -> None:
        if not self.name.startswith("bulwark-live-siem-"):
            raise LabError("ownership_name_mismatch")
        field = ".Config.Labels" if kind == "container" else ".Labels"
        name = self.container if kind == "container" else self.name
        label = command("docker", kind, "inspect", name, "--format", '{{index ' + field + ' "' + LABEL + '"}}')
        if label != self.name:
            raise LabError("ownership_label_mismatch")

    def control(self, action: str) -> None:
        if action not in {"start", "stop", "restart"}:
            raise LabError("invalid_action")
        self.owned("container")
        self.resources("before_" + action, launching=action != "stop")
        command("docker", action, *(["--time", "10"] if action != "start" else []), self.container)

    def create(self) -> str:
        import bcrypt

        self.resources("preflight", launching=True)
        self.check("cached_image", command("docker", "image", "inspect", IMAGE, "--format", "{{.Id}}") == IMAGE)
        if os.getuid() == 0:
            raise LabError("nonroot_runner_required")
        for path in ("config", "data"):
            (self.directory / path).mkdir(mode=0o700)
        config = self.directory / "config"
        password = secrets.token_hex(32)
        private_file(config / "password", password)
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()
        private_file(config / "users", "validator:" + password_hash + "\n")
        private_file(config / "users_roles", "validation:validator\n")
        private_file(config / "roles.yml", 'validation:\n  cluster: ["monitor"]\n  indices:\n'
                     f'    - names: ["{INDEX}"]\n      privileges: ["manage", "read", "write"]\n')
        self.network = True
        command("docker", "network", "create", "--internal", "--label", f"{LABEL}={self.name}", self.name)
        self.created = True
        command("docker", "create", "--pull=never", "--name", self.container, "--label", f"{LABEL}={self.name}",
                "--network", self.name, "--user", f"{os.getuid()}:{os.getgid()}", "--read-only", "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true", "--memory=1536m", "--memory-swap=1536m", "--cpus=1",
                "--pids-limit=256", "--log-driver=local", "--log-opt=max-size=1m", "--log-opt=max-file=2",
                "--tmpfs", "/tmp:rw,nosuid,size=128m",  # noqa: S108 - isolated container tmpfs
                "--tmpfs", f"/usr/share/elasticsearch/logs:rw,nosuid,size=32m,uid={os.getuid()},gid={os.getgid()}",
                "--mount", f"type=bind,src={config},dst=/lab,readonly",
                "--mount", f"type=bind,src={self.directory / 'data'},dst=/usr/share/elasticsearch/data",
                "-e", "ES_PATH_CONF=/lab", "-e", "ES_JAVA_OPTS=-Xms512m -Xmx512m",
                "--entrypoint", "/bin/tini", IMAGE, "--", "/bin/bash", "-c",
                "cp -a /lab /tmp/config && export ES_PATH_CONF=/tmp/config && "
                "exec /usr/share/elasticsearch/bin/elasticsearch")
        self.owned("container")
        # Copy only public distribution defaults out of our stopped container.
        for filename in ("jvm.options", "log4j2.properties"):
            command("docker", "cp", self.container + ":/usr/share/elasticsearch/config/" + filename,
                    str(config / filename))
        # Allocate the owned endpoint before cert creation without starting any process.
        # Docker assigns the address on start, so choose a free address in this fresh bridge.
        network = json.loads(command("docker", "network", "inspect", self.name))[0]
        subnet = ipaddress.ip_network(network["IPAM"]["Config"][0]["Subnet"])
        address = str(subnet.network_address + 2)
        command("docker", "network", "disconnect", self.name, self.container)
        command("docker", "network", "connect", "--ip", address, self.name, self.container)
        certificates(config, address)
        private_file(config / "elasticsearch.yml", "cluster.name: isolated-validation\nnode.name: collector\n"
                     "discovery.type: single-node\nnetwork.host: 0.0.0.0\n"
                     "path.data: /usr/share/elasticsearch/data\npath.logs: /tmp\n"
                     "node.store.allow_mmap: false\nxpack.security.enabled: true\n"
                     "xpack.security.authc.realms.file.local.order: 0\n"
                     "xpack.security.http.ssl.enabled: true\nxpack.security.http.ssl.key: server.key\n"
                     "xpack.security.http.ssl.certificate: server.pem\n"
                     "xpack.security.http.ssl.supported_protocols: [TLSv1.2, TLSv1.3]\n"
                     "xpack.security.transport.ssl.enabled: true\nxpack.security.transport.ssl.key: server.key\n"
                     "xpack.security.transport.ssl.certificate: server.pem\n"
                     "xpack.security.transport.ssl.certificate_authorities: [ca.pem]\n"
                     "xpack.security.transport.ssl.verification_mode: certificate\n"
                     "xpack.ml.enabled: false\nxpack.watcher.enabled: false\n"
                     "ingest.geoip.downloader.enabled: false\n")
        self.control("start")
        actual = json.loads(command("docker", "inspect", self.container))[0]
        self.check("isolated_network", set(actual["NetworkSettings"]["Networks"]) == {self.name}
                   and actual["NetworkSettings"]["Networks"][self.name]["IPAddress"] == address)
        self.check("resource_limits", actual["HostConfig"]["Memory"] == MEMORY_LIMIT
                   and actual["HostConfig"]["MemorySwap"] == MEMORY_LIMIT
                   and actual["HostConfig"]["ReadonlyRootfs"])
        return address

    def cleanup(self) -> None:
        for kind, created, name in (("container", self.created, self.container), ("network", self.network, self.name)):
            if not created:
                continue
            try:
                self.owned(kind)
                command("docker", kind, "rm", *(["--force"] if kind == "container" else []), name)
                status = "removed"
            except LabError as exc:
                status = str(exc)
            self.report["cleanup"].append({"resource": kind, "status": status})
        # Never remove source or another lab, and retain files if container ownership is uncertain.
        if all(item["status"] in {"removed", "container_absent", "network_absent"}
               for item in self.report["cleanup"]):
            for name in ("config", "data"):
                path = self.directory / name
                if path.exists():
                    shutil.rmtree(path)
            for path in self.directory.glob("outbox.db*"):
                path.unlink()
            self.report["cleanup"].append({"resource": "credentials_and_data", "status": "removed"})

    def diagnostics(self) -> None:
        self.owned("container")
        state = json.loads(command("docker", "inspect", self.container, "--format", "{{json .State}}"))
        self.report["collector_state"] = {key: state[key] for key in ("Running", "ExitCode", "OOMKilled")}
        # Only known diagnostic flags cross the evidence boundary, never log text.
        logs = command("docker", "logs", "--tail", "100", self.container).lower()
        needles = ("started", "exception", "read-only file system", "accessdeniedexception",
                   "failed to load ssl", "failed to load plugin", "bootstrap checks failed",
                   "unable to load", "fatal", "authentication", "security is enabled",
                   "logs/gc.log", "invalid -xlog", "could not create the java virtual machine",
                   "jvm.options.d", "permission denied", "could not find or load main class",
                   "elasticsearch.keystore", "keystore.tmp", "users_roles", "server.key",
                   "nosuchfileexception", "bootstrap", "config")
        self.report["collector_log_flags"] = {needle: needle in logs for needle in needles}


async def validate(lab: Lab, address: str) -> None:
    import httpx

    from src.telemetry.exporter import TelemetryExporter
    from src.telemetry.queue import TelemetryQueue
    from src.telemetry.schema import BulwarkFields, SecurityTelemetryEvent, TenantFields
    from src.telemetry.transports.http_rest import HttpAuthMethod, HttpRestTransport, HttpTransportConfig

    config = lab.directory / "config"
    password = (config / "password").read_text()
    base = f"https://{address}:9200"
    context = ssl.create_default_context(cafile=str(config / "ca.pem"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    def transport(ca: str = "ca.pem", credential: str = password) -> HttpRestTransport:
        return HttpRestTransport(HttpTransportConfig(
            url=base + f"/{INDEX}/_bulk?refresh=wait_for", format="elastic_bulk", auth_method=HttpAuthMethod.BASIC,
            username="validator", password=credential, tls_ca=str(config / ca), verify_ssl=True, timeout_seconds=3))

    async with httpx.AsyncClient(verify=context, auth=("validator", password), timeout=3,
                                trust_env=False, follow_redirects=False) as client:
        async def ready() -> None:
            deadline = time.monotonic() + 100
            while time.monotonic() < deadline:
                await asyncio.to_thread(lab.resources, "readiness")
                running = await asyncio.to_thread(command, "docker", "inspect", lab.container,
                                                  "--format", "{{.State.Running}}")
                if running != "true":
                    raise LabError("collector_exited_before_ready")
                try:
                    response = await client.get(base + "/_cluster/health")
                    if response.status_code == 200 and response.json().get("status") in {"yellow", "green"}:
                        return
                except httpx.TransportError as exc:
                    lab.report["last_readiness_error"] = type(exc).__name__
                    lab.report["readiness_certificate_rejection"] = certificate_rejection(exc)
                    await asyncio.sleep(1)
                    continue
                lab.report["last_readiness_http_status"] = response.status_code
                await asyncio.sleep(1)
            raise LabError("authenticated_tls_readiness_timeout")

        async def ids() -> list[str]:
            response = await client.post(base + f"/{INDEX}/_search", json={
                "size": 10, "_source": False, "query": {"match_all": {}}})
            lab.check("id_query_http_ok", response.status_code == 200, http_status=response.status_code)
            return sorted(hit["_id"] for hit in response.json()["hits"]["hits"])

        await ready()
        lab.check("authenticated_tls_ready", True)
        lab.check("unauthenticated_rejected", (await client.get(base + "/", auth=None)).status_code == 401)
        # Same live server, deliberately wrong identity; refusal/timeouts do not count as TLS rejection.
        for name, ca, hostname in (("wrong_ca", "wrong-ca.pem", address),
                                   ("wrong_hostname", "ca.pem", "not-this-collector.invalid")):
            rejected = False
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection(
                    address, 9200, ssl=ssl.create_default_context(cafile=str(config / ca)),
                    server_hostname=hostname), 3)
                writer.close()
                await writer.wait_closed()
            except (OSError, TimeoutError) as exc:
                rejected = certificate_rejection(exc)
            lab.check(name + "_certificate_rejected", rejected)

        # A loopback-only ephemeral diagnostic TLS connection, without a public Docker port.
        # The actual transport below uses the owned bridge IP, respecting its SSRF guard.
        active: set[asyncio.Task] = set()

        async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            task = asyncio.current_task()
            if len(active) >= 4:
                writer.close()
                return
            active.add(task)
            upstream = None
            try:
                async with asyncio.timeout(5):
                    remote, upstream = await asyncio.open_connection(address, 9200)

                    async def copy(source: asyncio.StreamReader, target: asyncio.StreamWriter) -> None:
                        while chunk := await source.read(16384):
                            target.write(chunk)
                            await target.drain()

                    async with asyncio.TaskGroup() as group:
                        group.create_task(copy(reader, upstream))
                        group.create_task(copy(remote, writer))
            except (OSError, TimeoutError, ExceptionGroup):
                logging.debug("diagnostic_relay_closed")
            finally:
                writer.close()
                if upstream:
                    upstream.close()
                active.discard(task)

        server = await asyncio.start_server(relay, "127.0.0.1", 0, limit=16384)
        try:
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.wait_for(asyncio.open_connection(
                "127.0.0.1", port, ssl=context, server_hostname="localhost"), 3)
            lab.check("loopback_ephemeral_tls", True, port=port,
                      protocol=writer.get_extra_info("ssl_object").version())
            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()
            for task in tuple(active):
                task.cancel()
            if active:
                await asyncio.wait_for(asyncio.gather(*tuple(active), return_exceptions=True), 6)

        response = await client.put(base + "/" + INDEX, json={
            "settings": {"number_of_shards": 1, "number_of_replicas": 0}})
        lab.check("single_shard_no_replicas", response.status_code == 200)
        events = [SecurityTelemetryEvent(bulwark=BulwarkFields(verdict="block"),
                                        tenant=TenantFields(id="synthetic-validation")) for _ in range(2)]
        lab.check("transport_wrong_ca_rejected", not await transport("wrong-ca.pem").send_batch(events[:1]))
        lab.check("transport_wrong_password_rejected", not await transport(credential=secrets.token_hex(32))
                  .send_batch(events[:1]))
        lab.check("negative_probes_not_indexed", await ids() == [])
        lab.check("real_elastic_bulk_ack", await transport().send_batch(events[:1]))
        expected = [events[0].event.id]
        lab.check("indexed_event_id", await ids() == expected, event_ids=expected)
        await asyncio.to_thread(lab.control, "restart")
        await ready()
        lab.check("collector_restart_persistence", await ids() == expected, event_ids=expected)
        await asyncio.to_thread(lab.control, "stop")
        queue = TelemetryQueue(max_size=10, disk_path=str(lab.directory / "outbox.db"), durable=True, shared=False)
        exporter = TelemetryExporter(queue=queue, batch_size=1, flush_interval=0.5)
        exporter.add_transport(transport())
        try:
            lab.check("durable_event_accepted_during_outage", await queue.enqueue(events[1]))
            await exporter.start()
            deadline = time.monotonic() + 10
            while exporter.stats["delivery_retries"] == 0 and time.monotonic() < deadline:
                await asyncio.sleep(0.2)
            lab.check("outage_retry_retains_event", exporter.stats["delivery_retries"] > 0 and queue.disk_depth == 1,
                      retries=exporter.stats["delivery_retries"], disk_depth=queue.disk_depth)
            await asyncio.to_thread(lab.control, "start")
            await ready()
            deadline = time.monotonic() + 65
            while queue.disk_depth and time.monotonic() < deadline:
                await asyncio.to_thread(lab.resources, "recovery")
                await asyncio.sleep(1)
            expected = sorted(event.event.id for event in events)
            lab.check("exporter_recovers_and_acknowledges", queue.disk_depth == 0 and await ids() == expected,
                      event_ids=expected, retries=exporter.stats["delivery_retries"],
                      errors=exporter.stats["export_errors"])
            lab.check("stable_id_resend_ack", await transport().send_batch(events))
            lab.check("stable_id_resend_document_count", await ids() == expected, count=len(expected))
        finally:
            await exporter.stop()


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="authorize one isolated cached-image run")
    args = parser.parse_args()
    if not args.run or ROOT != AUTHORIZED_ROOT or Path.cwd().resolve() != ROOT:
        parser.error("explicit --run from the authorized checkout required")
    if not (ROOT / "shared").is_dir():
        parser.error("existing shared parent required")
    command("git", "check-ignore", "-q", "shared/bulwark-live-siem-probe")
    os.umask(0o077)
    directory = Path(tempfile.mkdtemp(prefix="bulwark-live-siem-", dir=ROOT / "shared"))
    lab = Lab(directory)
    sys.path.insert(0, str(ROOT))
    for key in tuple(os.environ):
        if key.startswith(("BULWARK_", "ADMIN_", "PG")) or key in {"SSL_CERT_FILE", "SSL_CERT_DIR"}:
            os.environ.pop(key)
    os.environ.update(BULWARK_TELEMETRY_ENABLED="true", BULWARK_SIEM_SSRF_ALLOW_PRIVATE="true",
                      BULWARK_SIEM_STATS_FILE=str(directory / "stats.json"),
                      BULWARK_TELEMETRY_DB_MAX_EVENTS="10", BULWARK_TELEMETRY_DB_MAX_SIZE=str(1024**2))
    logging.disable(logging.CRITICAL)

    def interrupted(signum: int, frame: object) -> None:
        raise LabError("interrupted")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        lab.report["source_sha256"] = {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in (
            "src/telemetry/schema.py", "src/telemetry/transports/http_rest.py", "src/telemetry/queue.py",
            "src/telemetry/exporter.py", "scripts/validation-live-siem.py")}
        address = lab.create()
        asyncio.run(asyncio.wait_for(validate(lab, address), 360))
        lab.report["status"] = "completed"
    except Exception as exc:
        lab.report["status"] = "blocked_or_failed"
        lab.report["failure"] = str(exc) if isinstance(exc, LabError) else type(exc).__name__
        if lab.created:
            try:
                lab.diagnostics()
            except LabError:
                lab.report["diagnostics"] = "unavailable"
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        try:
            lab.cleanup()
            lab.resources("after_cleanup")
        except Exception as exc:
            lab.report["cleanup"].append({"resource": "cleanup", "status": type(exc).__name__})
        if any(item["status"] not in {"removed", "container_absent", "network_absent"}
               for item in lab.report["cleanup"]):
            lab.report["status"] = "blocked_or_failed"
        private_file(directory / "report.json", json.dumps(lab.report, indent=2) + "\n")
    print(json.dumps({"status": lab.report["status"], "report": str(directory / "report.json")}))
    return int(lab.report["status"] != "completed")


def main() -> int:
    sys.path.insert(0, str(ROOT))
    from scripts.validation_safety import validation_slot
    with validation_slot(ROOT):
        return _main()


if __name__ == "__main__":
    raise SystemExit(main())
