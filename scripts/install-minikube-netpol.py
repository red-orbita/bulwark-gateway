"""Operator-authorized, single-node NetworkPolicy intervention with rollback.

Infrastructure exception: root + NET_ADMIN + hostNetwork inside Minikube only.
No CNI/IPAM/kube-proxy replacement, no physical-host firewall commands.
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
NAME = "bulwark-netpol-controller"
IMAGE = "cloudnativelabs/kube-router@sha256:64da9a538d29e13780e256ce3897a52932a68657793bef009063bbeb2762146a"
APP = "bulwark-gateway"
SIEM = "bulwark-siem"
OWNER_LABEL = "bulwark.intervention-run"


def run(args, *, obj=None, timeout=60, check=True):
    result = subprocess.run(args, input=json.dumps(obj).encode() if obj is not None else None,  # noqa: S603
                            capture_output=True, timeout=timeout, check=False)
    if check and result.returncode:
        raise RuntimeError("operation_failed:" + args[0])
    return result


def kube(*args, **kwargs):
    return run(["kubectl", "--context=minikube", "--request-timeout=20s", *args], **kwargs)


def delete_owned(obj, owner):
    """Reconcile uncertain creates; delete by UID, never a replacement resource."""
    metadata = obj["metadata"]
    scope = ["-n", metadata["namespace"]] if metadata.get("namespace") else []
    def fetch():
        raw = kube("get", obj["kind"], metadata["name"], *scope, "--ignore-not-found", "-o", "json").stdout
        return json.loads(raw) if raw.strip() else None
    actual = fetch()
    if actual is None:
        return
    if actual["metadata"].get("labels", {}).get(OWNER_LABEL) != owner:
        raise RuntimeError("resource_ownership_changed")
    uid = actual["metadata"]["uid"]
    resources = {"Deployment": "deployments", "ServiceAccount": "serviceaccounts",
                 "ClusterRole": "clusterroles", "ClusterRoleBinding": "clusterrolebindings",
                 "NetworkPolicy": "networkpolicies"}
    api = "/api/v1" if obj["apiVersion"] == "v1" else "/apis/" + obj["apiVersion"]
    if scope:
        api += "/namespaces/" + metadata["namespace"]
    api += "/" + resources[obj["kind"]] + "/" + metadata["name"]
    kube("delete", "--raw", api, "-f", "-", obj={"apiVersion": "v1", "kind": "DeleteOptions",
         "preconditions": {"uid": uid}, "propagationPolicy": "Foreground"})
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        current = fetch()
        if current is None:
            return
        if current["metadata"]["uid"] != uid:
            raise RuntimeError("resource_replaced_during_cleanup")
        time.sleep(1)
    raise RuntimeError("owned_resource_deletion_timeout")


def restore_monitoring(monitoring):
    failures = []
    for kind, name, replicas in monitoring:
        try:
            kube("scale", kind + "/" + name, "-n", APP, "--replicas=" + str(replicas))
            kube("rollout", "status", kind + "/" + name, "-n", APP, "--timeout=90s", timeout=110)
            obj = json.loads(kube("get", kind, name, "-n", APP, "-o", "json").stdout)
            if obj["spec"].get("replicas") != replicas or obj.get("status", {}).get("readyReplicas", 0) != replicas:
                raise RuntimeError("monitoring_replica_mismatch")
        except Exception:
            failures.append({"kind": kind, "name": name, "error": "monitoring_restore_failed"})
    return failures


def rollback(intended, owner):
    failures = []
    controllers = [obj for obj in intended if obj["kind"] == "Deployment"]
    for obj in controllers:
        try:
            delete_owned(obj, owner)
            remaining = json.loads(kube("get", "pods", "-n", "kube-system", "-l",
                                  OWNER_LABEL + "=" + owner, "-o", "json").stdout)["items"]
            if remaining:
                raise RuntimeError("controller_pods_remain")
        except Exception:
            # Do not remove policy/RBAC/firewall while reconciliation may be active.
            return [{"stage": "stop_controller", "error": "controller_stop_unconfirmed"}]
    if controllers:
        try:
            remove_owned_firewall()
        except Exception:
            return [{"stage": "firewall_cleanup", "error": "firewall_cleanup_incomplete"}]
    for obj in reversed(intended):
        if obj["kind"] == "Deployment":
            continue
        try:
            delete_owned(obj, owner)
        except Exception:
            failures.append({"stage": "resource_cleanup", "name": obj["metadata"]["name"], "error": "delete_failed"})
    return failures


def peer(role, namespace=None):
    result = {"podSelector": {"matchLabels": {"app.kubernetes.io/name": role}}}
    if namespace:
        result["namespaceSelector"] = {"matchLabels": {"kubernetes.io/metadata.name": namespace}}
    return result


def policy(name, namespace, role, *, ingress=None, egress=None):
    spec = {"podSelector": peer(role)["podSelector"], "policyTypes": []}
    for direction, rules in (("Ingress", ingress), ("Egress", egress)):
        if rules is not None:
            spec["policyTypes"].append(direction)
            spec[direction.lower()] = rules
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": NAME + "-" + name, "namespace": namespace,
                         "labels": {"bulwark.intervention": NAME}}, "spec": spec}


def flow(direction, peers, port, protocol="TCP"):
    return {direction: peers, "ports": [{"port": port, "protocol": protocol}]}


def connectivity_policies():
    """Add only missing observed role/namespace routes; retain existing policies."""
    return [
        policy("proxy", APP, "proxy", ingress=[flow("from", [peer("admin"), peer("prometheus")], 8080)],
               egress=[flow("to", [peer("mock-llm")], 11434)]),
        policy("admin", APP, "admin", egress=[flow("to", [peer("proxy")], 8080),
               flow("to", [peer("wazuh", SIEM)], 55000), flow("to", [peer("prometheus")], 9090)]),
        policy("database", APP, "postgresql", ingress=[flow("from", [peer("admin")], 5432)]),
        policy("backend", APP, "mock-llm", ingress=[flow("from", [peer("proxy")], 11434)]),
        policy("prometheus", APP, "prometheus", ingress=[flow("from", [peer("admin")], 9090)]),
        policy("wazuh", SIEM, "wazuh", ingress=[flow("from", [peer("admin", APP)], 55000),
               flow("from", [{"ipBlock": {"cidr": "192.168.49.10/32"}}], 55000)]),
    ]


def controller_objects():
    metadata = {"name": NAME, "namespace": "kube-system", "labels": {"bulwark.intervention": NAME}}
    cluster_metadata = {"name": NAME, "labels": {"bulwark.intervention": NAME}}
    return [
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": metadata},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": cluster_metadata,
         "rules": [
             {"apiGroups": [""], "resources": ["pods", "nodes", "namespaces", "services", "endpoints"],
              "verbs": ["get", "list", "watch"]},
             {"apiGroups": ["networking.k8s.io"], "resources": ["networkpolicies"], "verbs": ["get", "list", "watch"]},
             {"apiGroups": ["discovery.k8s.io"], "resources": ["endpointslices"], "verbs": ["get", "list", "watch"]},
         ]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": cluster_metadata,
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": NAME},
         "subjects": [{"kind": "ServiceAccount", "name": NAME, "namespace": "kube-system"}]},
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": metadata, "spec": {
            "replicas": 1, "strategy": {"type": "Recreate"}, "selector": {"matchLabels": {"app": NAME}},
            "template": {"metadata": {"labels": {"app": NAME}}, "spec": {
                "serviceAccountName": NAME, "hostNetwork": True, "dnsPolicy": "ClusterFirstWithHostNet",
                "nodeSelector": {"kubernetes.io/hostname": "minikube"}, "terminationGracePeriodSeconds": 15,
                "containers": [{"name": "controller", "image": IMAGE, "imagePullPolicy": "Never",
                    "args": ["--run-router=false", "--run-firewall=true", "--run-service-proxy=false",
                             "--run-loadbalancer=false", "--enable-cni=false", "--hostname-override=minikube",
                             "--enable-ipv6=false", "--netpol-default-deny=false", "--iptables-sync-period=5s",
                             "--health-addr=127.0.0.1", "--health-port=20244"],
                    "securityContext": {"runAsUser": 0, "allowPrivilegeEscalation": False,
                                        "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"],
                                        "add": ["NET_ADMIN", "NET_RAW"]}, "seccompProfile": {"type": "RuntimeDefault"}},
                    "resources": {"requests": {"cpu": "50m", "memory": "64Mi"},
                                  "limits": {"cpu": "500m", "memory": "192Mi"}},
                    "volumeMounts": [{"name": "lock", "mountPath": "/run/xtables.lock"},
                                     {"name": "tmp", "mountPath": "/tmp"}],  # noqa: S108 -- pod-owned tmpfs
                    "startupProbe": {"httpGet": {"host": "127.0.0.1", "path": "/healthz", "port": 20244},
                                     "periodSeconds": 5, "failureThreshold": 24},
                    "readinessProbe": {"httpGet": {"host": "127.0.0.1", "path": "/healthz", "port": 20244},
                                       "periodSeconds": 5, "timeoutSeconds": 2},
                    "livenessProbe": {"httpGet": {"host": "127.0.0.1", "path": "/healthz", "port": 20244},
                                      "periodSeconds": 10, "timeoutSeconds": 2, "failureThreshold": 6},
                }],
                "volumes": [{"name": "lock", "hostPath": {"path": "/run/xtables.lock", "type": "FileOrCreate"}},
                            {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}}],
            }},
        }},
    ]


def check_connections():
    checks = []
    for source, destinations in (("admin", [("redis", 6379), ("postgresql", 5432), ("proxy", 8080),
                                            ("wazuh.bulwark-siem.svc.cluster.local", 55000)]),
                                 ("proxy", [("redis", 6379), ("mock-llm", 11434),
                                            ("wazuh.bulwark-siem.svc.cluster.local", 5514)])):
        program = ("import socket,json\nresults=[]\n"
                   f"for host,port in {destinations!r}:\n"
                   " try:\n  s=socket.create_connection((host,port),2); s.close(); results.append(True)\n"
                   " except Exception: results.append(False)\nprint(json.dumps(results))")
        result = kube("exec", "-n", APP, "deployment/" + source, "-c", source, "--", "python3", "-c", program)
        results = json.loads(result.stdout)
        checks.extend({"source": source, "destination": host, "port": port, "connected": ok}
                      for (host, port), ok in zip(destinations, results, strict=True))
    return checks


def remove_owned_firewall():
    """Stop reconciliation first. Remove only our unique, preflight-absent chains.

    No full-table restore: preserve concurrent kube-proxy/Docker changes. All
    commands execute inside Minikube's network namespace, never the host's.
    """
    program = r'''import shlex,subprocess
def run(*args): return subprocess.check_output(args,text=True)
prefixes=('KUBE-ROUTER-','KUBE-POD-FW-','KUBE-NWPLCY-')
for binary in ('iptables','ip6tables'):
 rules=[shlex.split(line) for line in run(binary,'-S').splitlines()]
 chains={r[1] for r in rules if r[0]=='-N' and r[1].startswith(prefixes)}
 for r in rules:
  if r[0]=='-A' and r[1] not in chains and any(r[i] in ('-j','-g') and r[i+1] in chains for i in range(len(r)-1)):
   subprocess.check_call([binary,'-w','5','-D',*r[1:]])
 for chain in chains: subprocess.check_call([binary,'-w','5','-F',chain])
 for chain in chains: subprocess.check_call([binary,'-w','5','-X',chain])
'''
    run(["docker", "exec", "minikube", "python3", "-c", program])
    # Node-local Docker hosts this helper; --network=host refers to the Minikube
    # node, NOT the physical workstation. No routing/IPVS cleanup is performed.
    cleanup_sets = (
        "set -eu; names=$(ipset list -name); for name in $names; do "
        "case \"$name\" in KUBE-SRC-*|KUBE-DST-*) ipset destroy \"$name\";; esac; done"
    )
    run(["docker", "exec", "minikube", "docker", "run", "--rm", "--pull=never",
         "--network=host", "--read-only", "--cap-drop=ALL", "--cap-add=NET_ADMIN",
         "--security-opt=no-new-privileges", "--memory=64m", "--memory-swap=64m", "--cpus=0.5",
         "--entrypoint=/bin/sh", IMAGE, "-c", cleanup_sets])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply-authorized", action="store_true", required=True)
    parser.parse_args()
    from scripts.validation_safety import validation_slot
    with validation_slot(ROOT):
        os.umask(0o077)
        directory = Path(tempfile.mkdtemp(prefix="netpol-intervention-", dir=ROOT / "shared"))
        report = {"status": "preparing", "image": IMAGE, "node": "minikube", "production_approved": False}
        created = []
        monitoring = []
        owner = secrets.token_hex(12)
        report["owner"] = owner
        try:
            for table in ("iptables", "ip6tables"):
                rules = run(["docker", "exec", "minikube", table + "-save"]).stdout
                if any(prefix in rules for prefix in (b"KUBE-ROUTER-", b"KUBE-POD-FW-", b"KUBE-NWPLCY-")):
                    raise RuntimeError("existing_controller_rules_refuse_ownership")
                (directory / (table + "-before.txt")).write_bytes(rules)
            ipsets = run(["docker", "exec", "minikube", "docker", "run", "--rm", "--pull=never",
                          "--network=host", "--read-only", "--cap-drop=ALL", "--cap-add=NET_ADMIN",
                          "--security-opt=no-new-privileges", "--memory=64m", "--memory-swap=64m",
                          "--cpus=0.5", "--entrypoint=ipset", IMAGE, "list", "-name"]).stdout
            (directory / "ipsets-before.txt").write_bytes(ipsets)
            if any(line.startswith((b"KUBE-SRC-", b"KUBE-DST-", b"kube-router-local-pods"))
                   for line in ipsets.splitlines()):
                raise RuntimeError("existing_controller_ipsets_refuse_ownership")
            policies = kube("get", "networkpolicy", "-A", "-o", "json").stdout
            (directory / "policies-before.json").write_bytes(policies)
            report["connections_before"] = check_connections()
            if not all(item["connected"] for item in report["connections_before"]):
                raise RuntimeError("baseline_connectivity_failed")
            for kind, name in (("deployment", "grafana"), ("statefulset", "prometheus")):
                obj = json.loads(kube("get", kind, name, "-n", APP, "-o", "json").stdout)
                replicas = obj["spec"].get("replicas", 1)
                monitoring.append((kind, name, replicas))
                (directory / "monitoring-before.json").write_text(json.dumps(monitoring))
                kube("scale", kind + "/" + name, "-n", APP, "--replicas=0")
            time.sleep(10)
            objects = connectivity_policies() + controller_objects()
            for obj in objects:
                obj["metadata"].setdefault("labels", {})[OWNER_LABEL] = owner
                if obj["kind"] == "Deployment":
                    obj["spec"]["template"]["metadata"]["labels"][OWNER_LABEL] = owner
            (directory / "applied-manifests.json").write_text(json.dumps(objects, indent=2))
            for obj in objects:
                created.append(obj)
                (directory / "creation-intent.json").write_text(json.dumps(created))
                kube("create", "-f", "-", obj=obj)
            kube("rollout", "status", "deployment/" + NAME, "-n", "kube-system", "--timeout=120s", timeout=150)
            time.sleep(8)
            report["connections_after"] = check_connections()
            if not all(item["connected"] for item in report["connections_after"]):
                raise RuntimeError("retained_connectivity_regression")
            # Probe runs after releasing the shared admission lock.
            report["status"] = "controller_running_pending_enforcement_probe"
        except BaseException as exc:
            report.update(status="rollback_incomplete", error=type(exc).__name__)
            report["rollback_errors"] = rollback(created, owner)
            if not report["rollback_errors"]:
                report["status"] = "rolled_back"
            raise
        finally:
            report["monitoring_replicas"] = monitoring
            try:
                report["monitoring_restore_errors"] = restore_monitoring(monitoring)
                if report["monitoring_restore_errors"]:
                    report["status"] = "monitoring_restore_incomplete"
            finally:
                (directory / "report.json").write_text(json.dumps(report, indent=2))
                print(json.dumps({"status": report["status"], "report": str(directory / "report.json")}))
        return int(report["status"] != "controller_running_pending_enforcement_probe")


if __name__ == "__main__":
    raise SystemExit(main())
