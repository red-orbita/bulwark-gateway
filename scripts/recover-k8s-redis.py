"""Prepare an encrypted backup and isolated AOF diagnosis; never truncate original.

This command pauses the explicitly named broken Redis Deployment. It leaves the
original PVC intact and resumes the original replica count after preparation.
Promoting a repaired copy requires a separately reviewed action.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
NS = "bulwark-gateway"
REDIS_IMAGE = "redis@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99"
PYTHON_IMAGE = "python@sha256:a39549e211a16149edf74e5fdc9ef03a6767e46cd987c5048b6659b6c9904c94"
LIMIT = 256 * 1024**2


def kubectl(*args, data=None, timeout=90, check=True):
    result = subprocess.run(  # noqa: S603,S607
        ["kubectl", "--context=minikube", "--request-timeout=20s", *args], input=data,  # noqa: S607
        capture_output=True, timeout=timeout, check=False,
    )
    if check and result.returncode:
        raise RuntimeError("kubernetes_operation_failed:" + args[0])
    return result


def create(obj):
    kubectl("create", "-f", "-", data=json.dumps(obj).encode())


def helper(name, claim, *, original=False):
    mounts = [{"name": "copy", "mountPath": "/copy"}]
    volumes = [{"name": "copy", "persistentVolumeClaim": {"claimName": claim}}]
    if original:
        mounts.append({"name": "original", "mountPath": "/original", "readOnly": True})
        volumes.append({"name": "original", "persistentVolumeClaim": {"claimName": "redis-data", "readOnly": True}})
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": NS,
            "labels": {"bulwark.validation": "redis-recovery"}}, "spec": {
        "automountServiceAccountToken": False, "restartPolicy": "Never", "activeDeadlineSeconds": 600,
        "terminationGracePeriodSeconds": 5,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 999, "runAsGroup": 999,
                            "fsGroup": 999, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "helper", "image": PYTHON_IMAGE if original else REDIS_IMAGE,
            "imagePullPolicy": "Never", "command": ["python3", "-c", "import time; time.sleep(590)"] if original
            else ["sh", "-c", "sleep 590"],
            "resources": {"requests": {"memory": "32Mi", "cpu": "10m"},
                          "limits": {"memory": "128Mi", "cpu": "250m"}},
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}}, "volumeMounts": mounts}],
        "volumes": volumes,
    }}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", action="store_true", required=True)
    parser.parse_args()
    from scripts.validation_safety import validation_slot
    with validation_slot(ROOT):
        os.umask(0o077)
        directory = Path(tempfile.mkdtemp(prefix="k8s-redis-recovery-", dir=ROOT / "shared"))
        suffix = directory.name.removeprefix("k8s-redis-recovery-").replace("_", "-")
        pod, checker, claim = "redis-copy-" + suffix, "redis-check-" + suffix, "redis-recovered-" + suffix
        deployment = json.loads(kubectl("get", "deployment", "redis", "-n", NS, "-o", "json").stdout)
        replicas = deployment["spec"].get("replicas", 1)
        report = {"status": "preparing", "original_pvc": "redis-data", "copy_pvc": claim,
                  "namespace": NS, "original_replicas": replicas, "original_untouched": True}
        paused = False
        try:
            if replicas != 1 or deployment["status"].get("readyReplicas", 0):
                raise RuntimeError("expected_single_unready_redis")
            kubectl("scale", "deployment/redis", "-n", NS, "--replicas=0")
            paused = True
            kubectl("wait", "--for=delete", "pod", "-l", "app.kubernetes.io/name=redis", "-n", NS, "--timeout=90s")
            create({"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {
                "name": claim, "namespace": NS, "labels": {"bulwark.validation": "redis-recovery"}},
                "spec": {"accessModes": ["ReadWriteOnce"], "storageClassName": "standard",
                         "resources": {"requests": {"storage": "1Gi"}}}})
            create(helper(pod, claim, original=True))
            kubectl("wait", "--for=condition=Ready", "pod/" + pod, "-n", NS, "--timeout=60s")
            source = r'''import os,json,hashlib,shutil
from pathlib import Path
root=Path('/original'); out=Path('/copy'); items=[]; total=0
for parent,dirs,files in os.walk(root):
 for name in dirs+files:
  p=Path(parent)/name
  if p.is_symlink(): raise ValueError('symlink')
 for name in files:
  p=Path(parent)/name; total+=p.stat().st_size; items.append(p)
  if total>201326592 or len(items)>4096: raise ValueError('backup_limit')
manifest={}
for p in sorted(items):
 relative=p.relative_to(root); dst=out/relative; dst.parent.mkdir(parents=True,exist_ok=True)
 shutil.copyfile(p,dst)
 def digest(path):
  h=hashlib.sha256()
  with path.open('rb') as f:
   while chunk:=f.read(1048576): h.update(chunk)
  return h.hexdigest()
 a=digest(p); b=digest(dst)
 if a!=b: raise ValueError('copy_mismatch')
 manifest[str(relative)]={'bytes':p.stat().st_size,'sha256':a}
print(json.dumps({'files':manifest,'total_bytes':total}))'''
            copied = kubectl("exec", "-n", NS, pod, "--", "python3", "-c", source, timeout=150)
            report["copy"] = json.loads(copied.stdout)
            backup_code = ("import sys,tarfile\n"
                           "with tarfile.open(fileobj=sys.stdout.buffer,mode='w|') as t:\n"
                           " t.add('/copy',arcname='redis')")
            # A temp private file bounds parent RAM; subprocess output is capped by
            # the checked source total plus tar overhead. Do not print its contents.
            archive = directory / "redis-backup.tar"
            with archive.open("xb") as output:
                result = subprocess.run(["kubectl", "--context=minikube", "--request-timeout=20s",  # noqa: S603,S607
                    "exec", "-n", NS, pod, "--", "python3", "-c", backup_code],
                    stdout=output, stderr=subprocess.PIPE, timeout=120, check=False)
            if result.returncode or archive.stat().st_size > LIMIT:
                raise RuntimeError("backup_export_failed")
            key, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
            raw = archive.read_bytes()
            sealed = nonce + AESGCM(key).encrypt(nonce, raw, b"bulwark-redis-aof-backup-v1")
            (directory / "backup.key").write_bytes(key)
            (directory / "backup.aesgcm").write_bytes(sealed)
            persisted = (directory / "backup.aesgcm").read_bytes()
            if AESGCM(key).decrypt(persisted[:12], persisted[12:], b"bulwark-redis-aof-backup-v1") != raw:
                raise RuntimeError("backup_verification_failed")
            archive.unlink()
            report["encrypted_backup_verified"] = True
            report["backup_sha256"] = hashlib.sha256(sealed).hexdigest()
            (directory / "deployment.json").write_text(json.dumps(deployment))
            manifests = [name for name in report["copy"]["files"] if name.endswith(".manifest")]
            if (len(manifests) != 1 or not re.fullmatch(r"[A-Za-z0-9_./-]+", manifests[0])
                    or ".." in manifests[0].split("/")):
                raise RuntimeError("ambiguous_aof_manifest")
            report["aof_manifest"] = manifests[0]
            kubectl("delete", "pod", pod, "-n", NS, "--wait=true", "--timeout=30s")
            create(helper(checker, claim))
            kubectl("wait", "--for=condition=Ready", "pod/" + checker, "-n", NS, "--timeout=60s")
            checked = kubectl("exec", "-n", NS, checker, "--", "redis-check-aof", "/copy/" + manifests[0],
                              check=False, timeout=150)
            text = (checked.stdout + checked.stderr).decode(errors="replace")
            (directory / "check-private.log").write_text(text)
            report["check_exit_code"] = checked.returncode
            report["aof_metrics"] = re.findall(r"(?:size|ok_up_to|ok_up_to_line|diff|line|offset)=\d+", text)
            report["status"] = "copy_valid" if checked.returncode == 0 else "repair_authorization_required"
        except Exception as exc:
            report.update(status="preparation_failed", error=type(exc).__name__ + ":" + str(exc)[:100])
            raise
        finally:
            for name in (pod, checker):
                kubectl("delete", "pod", name, "-n", NS, "--ignore-not-found",
                        "--wait=true", "--timeout=30s", check=False)
            if paused:
                kubectl("scale", "deployment/redis", "-n", NS, "--replicas=" + str(replicas))
                report["original_replicas_restored"] = True
            (directory / "report.json").write_text(json.dumps(report, indent=2))
            print(json.dumps({key: value for key, value in report.items() if key != "copy"}, indent=2))
            print("Evidence: " + str(directory / "report.json"))


if __name__ == "__main__":
    main()
