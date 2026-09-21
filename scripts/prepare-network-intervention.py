"""Read-only Minikube intervention inventory; never installs a network controller.

Only non-secret resource projections are persisted. A passing inventory is not
permission to mutate the cluster or proof that NetworkPolicy is enforced.
"""

import argparse
import ipaddress
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def capture(args):
    result = subprocess.run(args, capture_output=True, timeout=30, check=False)  # noqa: S603
    if result.returncode or len(result.stdout) > 8 * 1024**2:
        raise RuntimeError("inventory_unavailable")
    return json.loads(result.stdout)


def assess(nodes, pods, container):
    """Reject unproven range/capacity assumptions rather than recommending rollout."""
    issues = []
    node_ranges = {}
    for node in nodes:
        name = node["metadata"]["name"]
        cidrs = node.get("spec", {}).get("podCIDRs", [])
        node_ranges[name] = [ipaddress.ip_network(cidr, strict=True) for cidr in cidrs]
        if not cidrs:
            issues.append({"code": "node_pod_cidr_missing", "node": name})
    outside = []
    for pod in pods:
        spec, status = pod.get("spec", {}), pod.get("status", {})
        if spec.get("hostNetwork") or status.get("phase") in {"Succeeded", "Failed"}:
            continue
        ips = status.get("podIPs", []) or ([{"ip": status["podIP"]}] if status.get("podIP") else [])
        for entry in ips:
            ip = ipaddress.ip_address(entry["ip"])
            if not any(ip in network for network in node_ranges.get(spec.get("nodeName"), [])):
                outside.append({"namespace": pod["metadata"]["namespace"], "pod": pod["metadata"]["name"]})
                break
    if outside:
        issues.append({"code": "pods_outside_declared_node_cidr", "pods": outside})
    limit = container.get("HostConfig", {}).get("Memory", 0)
    if not isinstance(limit, int) or limit <= 0:
        issues.append({"code": "node_container_memory_limit_unproven"})
        limit = 0
    for node in nodes:
        allocated = node.get("status", {}).get("allocatable", {}).get("memory", "")
        if allocated.endswith("Ki") and allocated[:-2].isdigit():
            if limit and int(allocated[:-2]) * 1024 > limit:
                issues.append({"code": "scheduler_memory_exceeds_container_limit", "node": node["metadata"]["name"],
                               "container_limit_bytes": limit, "advertised_bytes": int(allocated[:-2]) * 1024})
        else:
            issues.append({"code": "node_allocatable_memory_unparsed", "node": node["metadata"]["name"]})
    return {"status": "blocked" if issues else "inventory_consistent_not_approved", "issues": issues,
            "controller_install_authorized": False, "live_enforcement_proven": False}


def project(kind, obj):
    """Exclude annotations, ConfigMaps, Secrets and workload environment values."""
    metadata = obj["metadata"]
    clean = {"apiVersion": obj["apiVersion"], "kind": kind, "metadata": {
        key: metadata[key] for key in ("name", "namespace", "uid", "resourceVersion", "labels") if key in metadata}}
    if kind == "NetworkPolicy":
        clean["spec"] = obj["spec"]
    elif kind == "Node":
        clean.update(spec={"podCIDRs": obj.get("spec", {}).get("podCIDRs", [])},
                     status={"allocatable": obj.get("status", {}).get("allocatable", {})})
    elif kind == "Pod":
        spec = obj.get("spec", {})
        clean["spec"] = {key: spec[key] for key in ("nodeName", "hostNetwork") if key in spec}
        clean["status"] = {key: obj.get("status", {})[key] for key in ("podIP", "podIPs", "phase")
                           if key in obj.get("status", {})}
    return clean


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inspect", action="store_true", required=True)
    parser.parse_args()
    from scripts.validation_safety import validation_slot
    with validation_slot(ROOT):
        os.umask(0o077)
        directory = Path(tempfile.mkdtemp(prefix="network-preflight-", dir=ROOT / "shared"))
        inventory = {}
        for resource, kind in (("nodes", "Node"), ("pods", "Pod"), ("networkpolicies", "NetworkPolicy")):
            data = capture(["kubectl", "--context=minikube", "--request-timeout=15s",
                            "get", resource, "-A", "-o", "json"])
            inventory[resource] = [project(kind, item) for item in data["items"]]
        # Ask Docker only for the single cgroup limit, not the full environment.
        limit = capture(["docker", "inspect", "minikube", "--format", "{{json .HostConfig.Memory}}"])
        report = assess(inventory["nodes"], inventory["pods"], {"HostConfig": {"Memory": limit}})
        report.update(context="minikube", snapshot_scope="nonsecret_projections_not_etcd_or_volume_backup")
        (directory / "inventory.json").write_text(json.dumps(inventory, indent=2))
        (directory / "report.json").write_text(json.dumps(report, indent=2))
        print(json.dumps({"status": report["status"], "blockers": [i["code"] for i in report["issues"]],
                          "report": str(directory / "report.json")}))
        return int(report["status"] == "blocked")


if __name__ == "__main__":
    raise SystemExit(main())
