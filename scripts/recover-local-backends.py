"""Recover stopped local Redis/proxy using preserved originals and copied data.

Requires successful admin recovery. Does not start or modify Wazuh or Minikube.
"""

import argparse
import importlib.util
import json
import os
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
spec = importlib.util.spec_from_file_location("admin_recovery", ROOT / "scripts/recover-local-admin.py")
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)
PROXY_IMAGE = "sha256:97692c7b780f1a8787077af58eb0adf02980ca072b553e600a3e00abc7d9a632"
LEGACY = "/home/rokitoh/CODE/sentinel-gateway/"
CURRENT = ROOT.parent / "sentinel-gateway"


def fixed_config(original, copies, image):
    config = recovery.coherent_config(original, clones=copies)
    config["Image"] = image
    for mount in config["HostConfig"]["Mounts"]:
        if mount["Type"] == "bind" and mount["Source"].startswith(LEGACY):
            source = CURRENT / mount["Source"][len(LEGACY):]
            if not source.exists():
                raise RuntimeError("missing_relocated_bind")
            mount["Source"] = str(source)
    # Distroless supplies python3, not the old Compose python healthcheck alias.
    if image == PROXY_IMAGE:
        config["Healthcheck"]["Test"] = ["CMD", "python3", "-c",
            "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=2)"]
        # Offline/model-free recovery: no automatic downloads during startup.
        disabled = {"BULWARK_ENRICHMENT_ENABLED": "false", "BULWARK_ML_ENABLED": "false",
                    "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1"}
        config["Env"] = [value for value in config["Env"] if value.split("=", 1)[0] not in disabled]
        config["Env"] += [f"{key}={value}" for key, value in disabled.items()]
    return config


def copy_volume(source, destination):
    script = r'''import os,shutil
total=count=0
for parent,dirs,files in os.walk('/source'):
 for name in dirs+files:
  if os.path.islink(os.path.join(parent,name)): raise ValueError('symlink')
 for name in files:
  total+=os.stat(os.path.join(parent,name)).st_size; count+=1
if total>67108864 or count>4096: raise ValueError('copy_limit')
shutil.copytree('/source','/target',dirs_exist_ok=True,copy_function=shutil.copy2)
for parent,dirs,files in os.walk('/source'):
 target='/target'+parent[len('/source'):]
 st=os.stat(parent); os.chmod(target,st.st_mode&0o777); os.chown(target,st.st_uid,st.st_gid)
 for name in files:
  st=os.stat(os.path.join(parent,name)); os.chown(os.path.join(target,name),st.st_uid,st.st_gid)
print(total)'''
    return int(recovery.docker("run", "--rm", "--pull=never", "--network=none", "--read-only",
        "--cap-drop=ALL", "--cap-add=CHOWN", "--security-opt=no-new-privileges", "--memory=192m",
        "--memory-swap=192m", "--cpus=0.5", "--mount", f"type=volume,src={source},dst=/source,readonly",
        "--mount", f"type=volume,src={destination},dst=/target", "--entrypoint=python3", recovery.HELPER,
        "-c", script))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repair", action="store_true", required=True)
    parser.add_argument("--admin-report", type=Path, required=True)
    args = parser.parse_args()
    from scripts.validation_safety import validation_slot
    with validation_slot(ROOT):
        admin = json.loads(args.admin_report.read_text())
        if admin["status"] != "local_admin_recovered":
            raise RuntimeError("admin_not_recovered")
        copies = dict(admin["active_volume_copies"])
        os.umask(0o077)
        directory = Path(tempfile.mkdtemp(prefix="backend-recovery-", dir=ROOT / "shared"))
        suffix = directory.name.removeprefix("backend-recovery-")
        originals = {role: recovery.inspect(f"bulwark-gateway-{role}-1") for role in ("redis", "proxy")}
        if any(item["State"]["Running"] for item in originals.values()):
            raise RuntimeError("refuse_to_replace_running_backend")
        key, nonce = AESGCM.generate_key(bit_length=256), secrets.token_bytes(12)
        raw = json.dumps(originals).encode()
        sealed = nonce + AESGCM(key).encrypt(nonce, raw, b"bulwark-backend-config-v1")
        (directory / "config.key").write_bytes(key)
        (directory / "config.aesgcm").write_bytes(sealed)
        if AESGCM(key).decrypt(sealed[:12], sealed[12:], b"bulwark-backend-config-v1") != raw:
            raise RuntimeError("backup_failed")
        report = {"status": "started", "production_approved": False, "services": {}, "copies": {}}
        activated = []
        try:
            with httpx.Client(transport=httpx.HTTPTransport(uds="/var/run/docker.sock"), timeout=90) as client:
                for role, original in originals.items():
                    for mount in original["Mounts"]:
                        if mount["Type"] == "volume" and mount["Name"] not in copies:
                            name = f"bulwark-backend-recovery-{suffix}-{len(copies)}"
                            recovery.docker("volume", "create", "--label", "org.bulwark.recovery=" + suffix, name)
                            copied = copy_volume(mount["Name"], name)
                            copies[mount["Name"]] = name
                            report["copies"][mount["Name"]] = {"copy": name, "bytes": copied}
                    name = f"bulwark-gateway-{role}-1"
                    rollback = name + "-rollback-" + suffix
                    config = fixed_config(original, copies, original["Image"] if role == "redis" else PROXY_IMAGE)
                    recovery.request(client, "POST", f"/containers/{name}/rename?name={rollback}")
                    activated.append((name, rollback))
                    recovery.request(client, "POST", "/containers/create?name=" + name, config)
                    recovery.request(client, "POST", f"/containers/{name}/start")
                    ok = False
                    for _ in range(45):
                        state = recovery.inspect(name)["State"]
                        if state.get("Health", {}).get("Status") == "healthy":
                            ok = True
                            break
                        time.sleep(2)
                    if not ok:
                        raise RuntimeError(role + "_health_failed")
                    report["services"][role] = {"healthy": True, "rollback_container": rollback,
                                               "image": config["Image"]}
            report["status"] = "local_backends_recovered"
        except Exception as exc:
            report.update(status="failed", code=type(exc).__name__ + ":" + str(exc)[:100])
            for name, rollback in reversed(activated):
                subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30)  # noqa: S603,S607
                recovery.docker("rename", rollback, name)
            raise
        finally:
            (directory / "report.json").write_text(json.dumps(report, indent=2))
            print(json.dumps({"status": report["status"], "report": str(directory / "report.json")}))


if __name__ == "__main__":
    main()
