"""Probe actual NetworkPolicy enforcement in an owned, bounded namespace.

No CNI installation, existing workload changes, image downloads or host mutation.
Exit nonzero if deny-all does not block traffic. Cluster context is explicit.
"""

import argparse
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
IMAGE = "python@sha256:a39549e211a16149edf74e5fdc9ef03a6767e46cd987c5048b6659b6c9904c94"


def command(*args, data=None):
    result = subprocess.run(["kubectl", "--context=minikube", "--request-timeout=15s", *args],  # noqa: S603,S607
                            input=data, text=True, capture_output=True, timeout=90, check=False)
    if result.returncode:
        raise RuntimeError("kubernetes_operation_failed:" + args[0])
    return result.stdout


def pod(name, namespace, program):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": namespace,
            "labels": {"app": name}}, "spec": {
                "automountServiceAccountToken": False, "restartPolicy": "Never",
                "activeDeadlineSeconds": 300,
                "terminationGracePeriodSeconds": 5,
                "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
                                    "seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [{"name": name, "image": IMAGE, "imagePullPolicy": "Never",
                    "command": ["python3", "-B", "-c", program],
                    "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                        "capabilities": {"drop": ["ALL"]}},
                    "resources": {"requests": {"memory": "24Mi", "cpu": "10m"},
                                  "limits": {"memory": "64Mi", "cpu": "100m"}}}],
            }}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", required=True)
    parser.parse_args()
    from scripts.validation_safety import validation_slot
    with validation_slot(ROOT):
        os.umask(0o077)
        directory = Path(tempfile.mkdtemp(prefix="k8s-network-", dir=ROOT / "shared"))
        namespace = "bulwark-validation-" + directory.name.removeprefix("k8s-network-").replace("_", "-")
        report = {"namespace": namespace, "context": "minikube", "image": IMAGE, "status": "running"}
        created = False
        owner = secrets.token_hex(12)
        try:
            created = True  # Intent precedes create; reconcile lost acknowledgements.
            command("create", "-f", "-", data=json.dumps({"apiVersion": "v1", "kind": "Namespace",
                "metadata": {"name": namespace, "labels": {"bulwark.validation": "network-policy",
                    "bulwark.validation-run": owner,
                    "pod-security.kubernetes.io/enforce": "restricted"}}}))
            server = "from http.server import HTTPServer,BaseHTTPRequestHandler\n" \
                     "class H(BaseHTTPRequestHandler):\n" \
                     " def do_GET(self): self.send_response(200); self.end_headers(); self.wfile.write(b'probe')\n" \
                     " def log_message(self,*args): pass\n" \
                     "HTTPServer(('0.0.0.0',8080),H).serve_forever()"
            for name, program in (("server", server), ("client", "import time; time.sleep(290)")):
                command("create", "-f", "-", data=json.dumps(pod(name, namespace, program)))
            command("wait", "-n", namespace, "--for=condition=Ready", "pod", "--all", "--timeout=60s")
            ip = command("get", "pod", "server", "-n", namespace, "-o", "jsonpath={.status.podIP}").strip()
            def probe():
                program = ("import urllib.request\ntry:\n"
                           f" r=urllib.request.urlopen('http://{ip}:8080',timeout=2); print(r.status)\n"
                           "except Exception: print('blocked')")
                return command("exec", "-n", namespace, "client", "--", "python3", "-c", program).strip()
            baseline = []
            for _ in range(8):
                baseline.append(probe())
                if baseline[-1] == "200":
                    break
                time.sleep(1)
            report["baseline_attempts"] = baseline
            report["baseline_connected"] = baseline[-1] == "200"
            if not report["baseline_connected"]:
                raise RuntimeError("baseline_unavailable")
            report["directions"] = {}
            # Never combine directions: ingress-only enforcement must not mask
            # a broken egress implementation (or vice versa).
            for direction in ("Ingress", "Egress"):
                result = {}
                deny, allow = directional_policies(namespace, direction)
                command("create", "-f", "-", data=json.dumps(deny))
                outcomes = []
                for _ in range(5):
                    time.sleep(2)
                    outcomes.append(probe())
                result["after_deny"] = outcomes
                result["deny_enforced"] = all(value == "blocked" for value in outcomes[-3:])
                command("create", "-f", "-", data=json.dumps(allow))
                command("label", "pod", "client", "-n", namespace, "probe-access=allowed")
                for _ in range(5):
                    time.sleep(1)
                    result["selected_client_connected"] = probe() == "200"
                    if result["selected_client_connected"]:
                        break
                command("label", "pod", "client", "-n", namespace, "probe-access-")
                unselected = []
                for _ in range(5):
                    time.sleep(2)
                    unselected.append(probe())
                result["after_label_removed"] = unselected
                result["unselected_client_blocked"] = all(value == "blocked" for value in unselected[-3:])
                command("delete", "networkpolicy", "deny-probe", allow["metadata"]["name"], "-n", namespace)
                for _ in range(5):
                    time.sleep(1)
                    result["reconnected_after_removal"] = probe() == "200"
                    if result["reconnected_after_removal"]:
                        break
                report["directions"][direction] = result
            report["status"] = ("passed" if all(
                result[key] for result in report["directions"].values()
                for key in ("deny_enforced", "selected_client_connected", "unselected_client_blocked",
                            "reconnected_after_removal")) else "blocked_network_policy_not_enforced")
        except Exception as exc:
            report.update(status="blocked", error=type(exc).__name__)
        finally:
            try:
                if created:
                    current = command("get", "namespace", namespace, "--ignore-not-found", "-o", "json")
                    if current.strip():
                        resource = json.loads(current)
                        if resource["metadata"].get("labels", {}).get("bulwark.validation-run") != owner:
                            raise RuntimeError("namespace_ownership_changed")
                        command("delete", "--raw", "/api/v1/namespaces/" + namespace, "-f", "-", data=json.dumps({
                            "apiVersion": "v1", "kind": "DeleteOptions",
                            "preconditions": {"uid": resource["metadata"]["uid"]}}))
                        command("wait", "--for=delete", "namespace/" + namespace, "--timeout=60s")
                    report["namespace_removed"] = True
            except Exception:
                report.update(status="blocked_cleanup_failed", namespace_removed=False)
            finally:
                (directory / "report.json").write_text(json.dumps(report, indent=2))
                print(json.dumps({**report, "report": str(directory / "report.json")}))
        return int(report["status"] != "passed")


def selective_policies(namespace):
    """Paired ingress/egress exceptions with no arbitrary namespace access."""
    metadata = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy"}
    ports = [{"port": 8080, "protocol": "TCP"}]
    client = {"matchLabels": {"app": "client", "probe-access": "allowed"}}
    server = {"matchLabels": {"app": "server"}}
    return (
        {**metadata, "metadata": {"name": "server-allow", "namespace": namespace},
         "spec": {"podSelector": server, "policyTypes": ["Ingress"],
                  "ingress": [{"from": [{"podSelector": client}], "ports": ports}]}},
        {**metadata, "metadata": {"name": "client-allow", "namespace": namespace},
         "spec": {"podSelector": client, "policyTypes": ["Egress"],
                  "egress": [{"to": [{"podSelector": server}], "ports": ports}]}},
    )


def directional_policies(namespace, direction):
    if direction not in ("Ingress", "Egress"):
        raise ValueError("Unsupported direction")
    role = "server" if direction == "Ingress" else "client"
    deny = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "deny-probe", "namespace": namespace},
            "spec": {"podSelector": {"matchLabels": {"app": role}},
                     "policyTypes": [direction], direction.lower(): []}}
    return deny, selective_policies(namespace)[0 if direction == "Ingress" else 1]


if __name__ == "__main__":
    raise SystemExit(main())
