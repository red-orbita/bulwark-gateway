"""Recover the explicitly named local admin after mixed source/image imports.

No production approval: preserve the old container and encrypted rollback backup.
The backup key is local, not a KMS. Never print environment or raw container logs.
"""

import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
NAME = "bulwark-gateway-admin-1"
CANDIDATE = "sha256:c22b32e6e91da27ffa089f93e1da494df70e4b56078582da79abd0074b416b88"
HELPER = "sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285"
LIMIT = 64 * 1024**2
DOMAIN = b"bulwark-local-admin-backup-v1"


def docker(*args, data=None, timeout=90):
    result = subprocess.run(["docker", *args], input=data, capture_output=True, timeout=timeout, check=False)  # noqa: S603,S607
    if result.returncode:
        markers = re.findall(rb"(PermissionError|FileNotFoundError|MemoryError|ValueError|SyntaxError):", result.stderr)
        raise RuntimeError("docker_operation_failed:" + args[0] + ":" +
                           (markers[-1].decode() if markers else "unclassified"))
    return result.stdout


def inspect(name):
    return json.loads(docker("inspect", name))[0]


def request(client, method, path, body=None):
    result = client.request(method, "http://docker/v1.53" + path, json=body)
    if result.status_code not in (200, 201, 204, 304):
        raise RuntimeError("docker_api_failed:" + str(result.status_code))
    return result.json() if result.content else None


def coherent_config(original, *, clones=None, isolated=False):
    config = {key: original["Config"][key] for key in (
        "Env", "Entrypoint", "Cmd", "WorkingDir", "User", "ExposedPorts", "Healthcheck", "Labels",
    ) if key in original["Config"]}
    config["Image"] = CANDIDATE
    config["Labels"] = {**config.get("Labels", {}), "org.bulwark.recovery": "local-candidate-not-production"}
    host = {key: original["HostConfig"][key] for key in (
        "ReadonlyRootfs", "CapDrop", "SecurityOpt", "Tmpfs", "ShmSize", "Memory", "MemorySwap",
        "NanoCpus", "PidsLimit", "PortBindings", "RestartPolicy", "ExtraHosts", "NetworkMode",
    ) if key in original["HostConfig"]}
    mounts = []
    for mount in original["Mounts"]:
        target = mount["Destination"]
        if target in {"/app/admin", "/app/src"} or target.startswith(("/app/admin/", "/app/src/")):
            continue
        source = mount["Name"] if mount["Type"] == "volume" else mount["Source"]
        if mount["Type"] == "volume" and clones is not None:
            source = clones[source]
        mounts.append({"Type": mount["Type"], "Source": source, "Target": target, "ReadOnly": not mount["RW"]})
    host["Mounts"] = mounts
    if isolated:
        host.update(NetworkMode="none", PortBindings={}, RestartPolicy={"Name": "no"},
                    Memory=512 * 1024**2, MemorySwap=512 * 1024**2, NanoCpus=1000000000, PidsLimit=128)
        overrides = {"BULWARK_REDIS_URL": "", "BULWARK_INTEGRATION_RECONCILE_POLL_ENABLED": "false",
                     "BULWARK_SIGHTING_FEEDBACK_ENABLED": "false"}
        config["Env"] = [entry for entry in config["Env"] if entry.split("=", 1)[0] not in overrides]
        config["Env"] += [f"{key}={value}" for key, value in overrides.items()]
    config["HostConfig"] = host
    if not isolated:
        config["NetworkingConfig"] = {"EndpointsConfig": {
            name: {"Aliases": [alias for alias in values.get("Aliases", []) or []
                               if alias != original["Id"][:12]]}
            for name, values in original["NetworkSettings"]["Networks"].items()
        }}
    return config


def health(name, timeout=90):
    for _ in range(timeout // 2):
        result = subprocess.run(["docker", "exec", name, "python3", "-c",  # noqa: S603,S607
            "import urllib.request; "
            "r=urllib.request.urlopen('http://127.0.0.1:8090/admin/health',timeout=2); assert r.status==200"],
            capture_output=True, timeout=5, check=False)
        if result.returncode == 0:
            return True
        time.sleep(2)
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repair", action="store_true", required=True)
    parser.parse_args()
    from scripts.validation_safety import validation_slot
    with validation_slot(ROOT):
        os.umask(0o077)
        directory = Path(tempfile.mkdtemp(prefix="admin-recovery-", dir=ROOT / "shared"))
        report = {"status": "started", "candidate": CANDIDATE, "production_approved": False, "cleanup": []}
        original = inspect(NAME)
        before_id = original["Id"]
        if original["State"].get("Running") and not original["State"].get("Restarting"):
            raise RuntimeError("refuse_to_replace_running_admin_without_diagnosis")
        volumes = [m for m in original["Mounts"] if m["Type"] == "volume"]
        if len(volumes) != 6 or any(not m["Name"].startswith("bulwark-gateway_") for m in volumes):
            raise RuntimeError("unexpected_volume_set")
        suffix = directory.name.removeprefix("admin-recovery-")
        test_name = "bulwark-recovery-check-" + suffix
        rollback = NAME + "-rollback-" + suffix
        clones = {}
        stopped = renamed = replacement = False
        try:
            docker("stop", "--time", "10", NAME)
            stopped = True
            # Read only original mounts. Bound the archive at producer and consumer.
            source = r'''import io,os,sys,tarfile
roots = ["/app/data","/app/reports","/app/config/policies",
         "/app/shared/enrichment","/app/shared/notifications","/app/shared/siem"]
out=io.BytesIO(); total=0; count=0
with tarfile.open(fileobj=out,mode="w") as archive:
 for root in roots:
  for parent,dirs,files in os.walk(root):
   for name in sorted(dirs+files):
    path=os.path.join(parent,name)
    if os.path.islink(path): raise ValueError("symlink")
   for name in sorted(files):
    path=os.path.join(parent,name); size=os.stat(path).st_size; total+=size; count+=1
    if total>33554432 or count>4096: raise ValueError("backup_limit")
    archive.add(path,arcname=path.lstrip("/"),recursive=False)
 if len(out.getvalue())>67108864: raise ValueError("archive_limit")
sys.stdout.buffer.write(out.getvalue())'''
            raw = docker("run", "--rm", "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL",
                         "--user=65532:65532",
                         "--security-opt=no-new-privileges", "--memory=192m", "--memory-swap=192m", "--cpus=0.5",
                         "--volumes-from", NAME + ":ro", "--entrypoint=python3", HELPER, "-c", source)
            if len(raw) > LIMIT:
                raise RuntimeError("backup_too_large")
            key, nonce = AESGCM.generate_key(bit_length=256), secrets.token_bytes(12)
            payload = json.dumps({"config": original, "archive_hex": raw.hex()}).encode()
            encrypted = nonce + AESGCM(key).encrypt(nonce, payload, DOMAIN)
            (directory / "backup.key").write_bytes(key)
            (directory / "backup.aesgcm").write_bytes(encrypted)
            persisted = (directory / "backup.aesgcm").read_bytes()
            if AESGCM(key).decrypt(persisted[:12], persisted[12:], DOMAIN) != payload:
                raise RuntimeError("backup_verification_failed")
            report.update(backup_verified=True, archive_bytes=len(raw), archive_sha256=hashlib.sha256(raw).hexdigest())
            for mount in volumes:
                name = "bulwark-recovery-" + suffix + "-" + str(len(clones))
                docker("volume", "create", "--label", "org.bulwark.recovery=" + suffix, name)
                clones[mount["Name"]] = name
            mounts = [part for m in volumes for part in (
                "--mount", f"type=volume,src={clones[m['Name']]},dst={m['Destination']}")]
            restore = r'''import io,sys,tarfile,os
data=sys.stdin.buffer.read(67108865)
if len(data)>67108864: raise ValueError("limit")
with tarfile.open(fileobj=io.BytesIO(data)) as archive:
 for item in archive:
  if not item.isfile() or ".." in item.name.split("/") or not item.name.startswith("app/"): raise ValueError("unsafe")
  target="/"+item.name; os.makedirs(os.path.dirname(target),exist_ok=True)
  with archive.extractfile(item) as reader, open(target,"xb") as writer: writer.write(reader.read())
  os.chmod(target,item.mode); os.chown(target,item.uid,item.gid)
 for root in ("/app/data","/app/reports","/app/config/policies",
              "/app/shared/enrichment","/app/shared/notifications","/app/shared/siem"):
  os.chown(root,65532,65532)
  for parent,dirs,files in os.walk(root):
   for name in dirs: os.chown(os.path.join(parent,name),65532,65532)
'''
            docker("run", "--rm", "-i", "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL",
                   "--cap-add=CHOWN", "--security-opt=no-new-privileges", "--memory=192m", "--memory-swap=192m",
                   "--cpus=0.5", *mounts, "--entrypoint=python3", HELPER, "-c", restore, data=raw)
            with httpx.Client(transport=httpx.HTTPTransport(uds="/var/run/docker.sock"), timeout=90) as client:
                request(client, "POST", "/containers/create?name=" + test_name,
                        coherent_config(original, clones=clones, isolated=True))
                request(client, "POST", f"/containers/{test_name}/start")
                report["clone_startup_passed"] = health(test_name)
                if not report["clone_startup_passed"]:
                    output = subprocess.run(["docker", "logs", "--tail", "100", test_name],  # noqa: S603,S607
                                            capture_output=True, timeout=15, check=False)
                    logs = (output.stdout + output.stderr).decode(errors="replace")
                    report["clone_error_markers"] = re.findall(
                        r"(PermissionError|ModuleNotFoundError|OperationalError|DatabaseError|ValueError|FileNotFoundError):",
                        logs,
                    )
                    report["clone_trace_locations"] = re.findall(
                        r'File "(/app/[A-Za-z0-9_./-]+\.py)", line ([0-9]+)', logs)
                    raise RuntimeError("candidate_clone_health_failed")
                docker("rm", "-f", test_name)
                if inspect(NAME)["Id"] != before_id:
                    raise RuntimeError("original_container_changed")
                request(client, "POST", f"/containers/{NAME}/rename?name={rollback}")
                renamed = True
                # Promote the tested copies; never run new migrations on original
                # volumes, so rollback remains a container switch, not data surgery.
                request(client, "POST", "/containers/create?name=" + NAME, coherent_config(original, clones=clones))
                replacement = True
                request(client, "POST", f"/containers/{NAME}/start")
                report["recovered_health"] = health(NAME)
                if not report["recovered_health"]:
                    raise RuntimeError("replacement_health_failed")
            report.update(status="local_admin_recovered", rollback_container=rollback,
                          source_mounts_removed=True, original_volumes_preserved=True, active_volume_copies=clones)
        except Exception as exc:
            report.update(status="failed", error_code=type(exc).__name__ + ":" + str(exc)[:120])
            if replacement:
                docker("rm", "-f", NAME)
            if renamed:
                docker("rename", rollback, NAME)
            if stopped:
                docker("start", NAME)
            raise
        finally:
            subprocess.run(["docker", "rm", "-f", test_name], capture_output=True, timeout=30)  # noqa: S603,S607
            for name in clones.values():
                if report["status"] == "local_admin_recovered":
                    report["cleanup"].append({"volume": name, "retained_for_active_service": True})
                    continue
                result = subprocess.run(["docker", "volume", "rm", name], capture_output=True, timeout=30)  # noqa: S603,S607
                report["cleanup"].append({"volume": name, "removed": result.returncode == 0})
            (directory / "report.json").write_text(json.dumps(report, indent=2))
            print(json.dumps({"status": report["status"], "report": str(directory / "report.json")}))


if __name__ == "__main__":
    main()
