"""Candidate PostgreSQL parity or Redis TLS/JWT checks on one owned disposable store."""

import argparse
import asyncio
import hashlib
import importlib
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode


def validate_result(result: object, store: str) -> None:
    """A zero exit code alone must never imply that all checks executed."""
    required = ({"migrations_idempotent", "text_timestamp_parity", "direct_connection", "transaction_rollback",
                 "reopen", "attachment_scope_policy_and_leases", "outbox_scope_and_ack_fencing"}
                if store == "postgres" else {"jwt_accepted_before_revocation", "revoked_jwt_rejected"})
    if (not isinstance(result, dict) or not isinstance(result.get("python"), str)
            or not result["python"].startswith("3.14.")
            or result.get("production_approved") is not False
            or result.get("tls_rejected") != ["wrong_ca", "wrong_hostname"]
            or any(result.get(key) is not True for key in required)):
        raise ValueError("candidate_store_result_incomplete")


async def worker() -> dict:
    sys.path.insert(0, "/app")
    from admin.services.migrations import run_migrations
    from src.storage.database import PostgreSQLEngine

    password = Path("/probe-secrets/password").read_text()
    os.environ["SSL_CERT_FILE"] = "/probe-secrets/ca.pem"
    db = PostgreSQLEngine(f"postgresql://validator:{password}@localhost:5432/validation",
                          pool_min=1, pool_max=2, ssl=True, ssl_mode="verify-full")
    try:
        for attempt in range(15):
            try:
                await db.init()
                break
            except RuntimeError:
                if attempt == 14:
                    raise
                await asyncio.sleep(1)
        await run_migrations(db)
        await run_migrations(db)
        await db.execute("CREATE TABLE candidate_parity (label TEXT, instant TIMESTAMPTZ)")
        await db.execute("INSERT INTO candidate_parity VALUES (?, ?)",
                         ("2026-09-17T10:00:00Z", "2026-09-17T12:00:00+02:00"))
        row = await db.fetch_one("SELECT label, instant FROM candidate_parity")
        expected_instant = datetime(2026, 9, 17, 10, tzinfo=timezone.utc)
        actual_instant = datetime.fromisoformat(str(row["instant"])) if row else None
        if not row or row["label"] != "2026-09-17T10:00:00Z" or actual_instant != expected_instant:
            raise RuntimeError("timestamp_or_text_parity_failed")
        direct = await asyncio.to_thread(db.sync_fetch_one, "SELECT label FROM candidate_parity")
        if direct is None or direct["label"] != "2026-09-17T10:00:00Z":
            raise RuntimeError("direct_connection_parity_failed")
        try:
            async with db.transaction() as transaction:
                await transaction.execute("INSERT INTO candidate_parity VALUES (?, ?)",
                                          ("rollback-marker", "2026-09-17T10:00:00Z"))
                raise ValueError("synthetic transaction rollback")
        except ValueError:
            if await db.fetch_one("SELECT label FROM candidate_parity WHERE label = ?", ("rollback-marker",)):
                raise RuntimeError("transaction_rollback_failed") from None
        from src.attachments.store import PostgreSQLAttachmentStore, StoreError
        from src.telemetry.schema import BulwarkFields, SecurityTelemetryEvent, TenantFields
        from src.telemetry.shared_outbox import DestinationSnapshot, get_shared_outbox

        attachments = PostgreSQLAttachmentStore(db)
        await attachments.initialize()
        scope = {"tenant": "candidate", "agent": "agent", "owner": "owner"}
        doc = await attachments.create(**scope, mime="text/plain", raw=b"public fixture", policy_revision="revision")
        for field in scope:
            wrong_scope = {**scope, field: "other"}
            if await attachments.get(doc["id"], **wrong_scope) is not None:
                raise RuntimeError("attachment_scope_leak")
            if await attachments.delete(doc["id"], **wrong_scope):
                raise RuntimeError("attachment_scope_delete")
        lease = await attachments.claim()
        if lease is None or lease["id"] != doc["id"]:
            raise RuntimeError("attachment_claim_failed")
        if await attachments.finish(doc["id"], "stale-token", state="approved", text="wrong"):
            raise RuntimeError("attachment_stale_lease_accepted")
        if not await attachments.finish(doc["id"], lease["lease_token"], state="approved", text="public fixture"):
            raise RuntimeError("attachment_finish_failed")
        if await attachments.resolve(doc["id"], **scope, policy_revision="revision") != "public fixture":
            raise RuntimeError("attachment_resolve_failed")
        try:
            await attachments.resolve(doc["id"], **scope, policy_revision="changed")
        except StoreError as exc:
            if exc.code != "policy_changed":
                raise
        else:
            raise RuntimeError("attachment_policy_change_ignored")
        if not await attachments.delete(doc["id"], **scope):
            raise RuntimeError("attachment_delete_failed")

        outbox = get_shared_outbox(db=db)
        await outbox.initialize()
        destination = DestinationSnapshot(destination_id="candidate", tenant_scope=("candidate",),
                                          revision=hashlib.sha256(b"candidate").hexdigest())
        event = SecurityTelemetryEvent(bulwark=BulwarkFields(verdict="block"), tenant=TenantFields(id="candidate"))
        if await outbox.enqueue(event.model_copy(update={"tenant": TenantFields(id="other")}), (destination,)):
            raise RuntimeError("outbox_tenant_scope_bypass")
        if not await outbox.enqueue(event, (destination,)):
            raise RuntimeError("outbox_enqueue_failed")
        deliveries = await outbox.claim(destination)
        if len(deliveries) != 1:
            raise RuntimeError("outbox_claim_failed")
        stale = deliveries[0].model_copy(update={"token": "stale-token"})
        if await outbox.finish([stale], success=True) != 0:
            raise RuntimeError("outbox_stale_ack_accepted")
        if await outbox.finish(deliveries, success=True) != 1 or (await outbox.status())["events"] != 0:
            raise RuntimeError("outbox_ack_failed")
    finally:
        await db.close()
    reopened = PostgreSQLEngine(f"postgresql://validator:{password}@localhost:5432/validation",
                                pool_min=1, pool_max=2, ssl=True, ssl_mode="verify-full")
    try:
        await reopened.init()
        if not await reopened.fetch_one("SELECT label FROM candidate_parity"):
            raise RuntimeError("reopen_failed")
    finally:
        await reopened.close()
    rejected = []
    for label, host, ca in (("wrong_ca", "localhost", "wrong-ca.pem"),
                            ("wrong_hostname", "127.0.0.1", "ca.pem")):
        os.environ["SSL_CERT_FILE"] = "/probe-secrets/" + ca
        probe = PostgreSQLEngine(f"postgresql://validator:{password}@{host}:5432/validation",
                                 pool_min=1, pool_max=1, ssl=True, ssl_mode="verify-full")
        try:
            await probe.init()
        except RuntimeError as exc:
            # The DB adapter deliberately sanitizes driver errors. Validate the
            # TLS failure independently, not by accepting any connection failure.
            import ssl
            context = ssl.create_default_context(cafile="/probe-secrets/" + ca)
            try:
                _, writer = await asyncio.open_connection(host, 5432)
                writer.close()
                await writer.wait_closed()
            except OSError:
                raise RuntimeError("negative_probe_endpoint_unreachable") from exc
            import asyncpg
            try:
                connection = await asyncpg.connect(host=host, port=5432, user="validator", password=password,
                                                   database="validation", ssl=context, timeout=5)
            except ssl.SSLCertVerificationError:
                rejected.append(label)
            else:
                await connection.close()
                raise RuntimeError("tls_negative_probe_accepted")
        else:
            raise RuntimeError("invalid_tls_configuration_accepted")
        finally:
            await probe.close()
    return {"python": sys.version.split()[0], "migrations_idempotent": True, "text_timestamp_parity": True,
            "direct_connection": True, "transaction_rollback": True, "reopen": True,
            "attachment_scope_policy_and_leases": True, "outbox_scope_and_ack_fencing": True,
            "tls_rejected": rejected, "production_approved": False}


async def redis_worker() -> dict:
    sys.path.insert(0, "/app")

    import httpx
    import jwt
    import redis
    from fastapi import FastAPI

    password = Path("/probe-secrets/password").read_text()

    def url(host="localhost", ca="ca.pem"):
        query = urlencode({"ssl_ca_certs": "/probe-secrets/" + ca,
                           "ssl_check_hostname": "true"})
        return f"rediss://{host}:6379/0?{query}"

    client = redis.from_url(url(), password=password, socket_timeout=2, socket_connect_timeout=2)
    try:
        for attempt in range(15):
            try:
                await asyncio.to_thread(client.ping)
                break
            except redis.ConnectionError:
                if attempt == 14:
                    raise
                await asyncio.sleep(1)
        rejected = []
        for label, host, ca in (("wrong_ca", "localhost", "wrong-ca.pem"),
                                ("wrong_hostname", "127.0.0.1", "ca.pem")):
            probe = redis.from_url(url(host, ca), password=password, socket_timeout=2, socket_connect_timeout=2)
            try:
                await asyncio.to_thread(probe.ping)
            except redis.ConnectionError as exc:
                if "CERTIFICATE_VERIFY_FAILED" not in str(exc):
                    raise RuntimeError("unrelated_redis_connection_failure") from None
                rejected.append(label)
            else:
                raise RuntimeError("invalid_redis_certificate_accepted")
            finally:
                probe.close()
        secret = secrets.token_hex(32)
        os.environ.update({"BULWARK_REDIS_URL": url(),
                           "BULWARK_REDIS_PASSWORD_FILE": "/probe-secrets/password",
                           "BULWARK_JWT_SECRET": secret, "BULWARK_AUTH_CACHE_TTL": "0.1"})
        from src.middleware.auth import AuthMiddleware

        app = FastAPI()
        app.add_middleware(AuthMiddleware)

        @app.get("/v1/probe")
        async def endpoint():
            return {"authenticated": True}

        jti = secrets.token_hex(16)
        token = jwt.encode({"sub": "candidate", "tenant_id": "candidate", "agent_id": "test",
                            "jti": jti, "exp": int(time.time()) + 60,
                            "aud": "bulwark-proxy", "iss": "bulwark-gateway"}, secret, algorithm="HS256")
        headers = {"Authorization": "Bearer " + token}
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as http:
            response = await http.get("/v1/probe", headers=headers)
            if response.status_code != 200 or response.json() != {"authenticated": True}:
                raise RuntimeError("valid_jwt_rejected")
            await asyncio.to_thread(client.sadd, "bulwark:revoked_tokens", jti)
            await asyncio.sleep(0.2)
            if (await http.get("/v1/probe", headers=headers)).status_code != 401:
                raise RuntimeError("revoked_jwt_accepted")
            if (await http.get("/v1/probe")).status_code != 401:
                raise RuntimeError("missing_jwt_accepted")
        return {"python": sys.version.split()[0], "tls_rejected": rejected,
                "jwt_accepted_before_revocation": True, "revoked_jwt_rejected": True,
                "production_approved": False, "http_transport": "ASGI"}
    finally:
        client.close()


def main() -> None:
    if sys.argv[1:] in (["--worker"], ["--worker", "redis"]):
        signal.alarm(100)  # Bound shutdown/native driver threads as well as asyncio work.
        try:
            operation = redis_worker if sys.argv[1:] == ["--worker", "redis"] else worker
            print(json.dumps(asyncio.run(asyncio.wait_for(operation(), 90))))
        except Exception as exc:
            frames = []
            trace = exc.__traceback__
            while trace:
                if trace.tb_frame.f_code.co_filename == __file__:
                    frames.append(trace.tb_lineno)
                trace = trace.tb_next
            print(json.dumps({"error_type": type(exc).__name__, "probe_lines": frames}), file=sys.stderr)
            raise SystemExit("candidate_postgres_validation_failed:" + type(exc).__name__) from None
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--store", choices=("postgres", "redis"), default="postgres")
    args = parser.parse_args()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image):
        parser.error("Require immutable cached candidate ID")
    root = Path(__file__).resolve().parents[1]
    from validation_safety import validation_slot
    runner = importlib.import_module("validation-live-stores")
    with validation_slot(root):
        directory = Path(tempfile.mkdtemp(prefix="bulwark-validation-cp314-", dir=root / "shared"))
        lab = runner.Lab(directory, stores=(args.store,))
        lab.report["status"] = "failed"
        lab.report["runner_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        try:
            lab.preflight()
            name = lab.create(args.store)
            client = directory / "client"
            client.mkdir(mode=0o700)
            for filename in ("password", "ca.pem", "wrong-ca.pem"):
                runner.private_file(client / filename, (directory / args.store / filename).read_bytes())
            client_name = lab.name + "-client"
            # Track before create so a timeout or failed start is cleaned up too.
            lab.containers.append(client_name)
            result = subprocess.run(  # noqa: S603
                ["docker", "run", "--name", client_name, "--label", f"{runner.LABEL}={lab.name}",  # noqa: S607
                 "--pull=never", "--read-only", "--network=container:" + name,
                 f"--user={os.getuid()}:{os.getgid()}", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                 "--memory=384m", "--memory-swap=384m", "--cpus=1", "--pids-limit=48",
                 "--mount", f"type=bind,src={client},dst=/probe-secrets,readonly",
                 "--mount", f"type=bind,src={Path(__file__).resolve()},dst=/probe.py,readonly",
                 "--entrypoint=python3", args.image, "/probe.py", "--worker",
                 *(["redis"] if args.store == "redis" else [])],
                capture_output=True, check=False, timeout=110)
            if result.returncode:
                marker = re.search(rb"candidate_postgres_validation_failed:([A-Za-z]+)", result.stderr)
                lab.report["client_error_type"] = marker[1].decode() if marker else "worker_start_failure"
                for line in result.stderr.splitlines():
                    if line.startswith(b'{"error_type":'):
                        lab.report["client_diagnostic"] = json.loads(line)
                raise RuntimeError("candidate_postgres_validation_failed")
            lab.report["candidate"] = args.image
            client_result = json.loads(result.stdout)
            validate_result(client_result, args.store)
            lab.report["client_result"] = client_result
            lab.report["status"] = "passed"
        finally:
            lab.cleanup()
            if any(item["status"] != "removed" for item in lab.report["cleanup"]):
                lab.report["status"] = "cleanup_failed"
            runner.private_file(directory / "report.json", json.dumps(lab.report, indent=2))
            print(str(directory.relative_to(root) / "report.json"))
        if lab.report["status"] != "passed":
            raise RuntimeError("candidate_store_cleanup_failed")


if __name__ == "__main__":
    main()
