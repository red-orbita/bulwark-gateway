"""Pure preflight safety tests; no cluster access."""

import importlib.util
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """No application persistence needed."""


@pytest.fixture
def module():
    path = Path(__file__).parents[1] / "scripts/prepare-network-intervention.py"
    spec = importlib.util.spec_from_file_location("network_preflight", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def node(cidrs=None):
    return {"metadata": {"name": "node"}, "spec": {"podCIDRs": cidrs or ["10.244.0.0/24"]},
            "status": {"allocatable": {"memory": "16777216Ki"}}}


def pod(ip, **spec):
    return {"metadata": {"name": "pod", "namespace": "test"}, "spec": {"nodeName": "node", **spec},
            "status": {"podIP": ip, "phase": "Running"}}


def test_real_mismatch_blocks_controller_assumptions(module):
    report = module.assess([node()], [pod("10.244.3.10")], {"HostConfig": {"Memory": 3 * 1024**3}})
    assert report["status"] == "blocked"
    assert {i["code"] for i in report["issues"]} == {
        "pods_outside_declared_node_cidr", "scheduler_memory_exceeds_container_limit"}
    assert not report["controller_install_authorized"]


def test_consistent_inventory_never_implies_enforcement(module):
    report = module.assess([node()], [pod("10.244.0.10")], {"HostConfig": {"Memory": 16 * 1024**3}})
    assert report["status"] == "inventory_consistent_not_approved"
    assert not report["live_enforcement_proven"]


def test_host_network_and_terminal_pods_not_cidr_failures(module):
    terminal = pod("192.168.1.2")
    terminal["status"]["phase"] = "Succeeded"
    report = module.assess([node()], [pod("192.168.1.1", hostNetwork=True), terminal],
                           {"HostConfig": {"Memory": 16 * 1024**3}})
    assert not report["issues"]


def test_projection_excludes_env_and_last_applied_annotations(module):
    original = pod("10.244.0.2")
    original.update(apiVersion="v1")
    original["metadata"]["annotations"] = {"last-applied": "SYNTHETIC_SECRET"}
    original["spec"]["containers"] = [{"env": [{"value": "SYNTHETIC_SECRET"}]}]
    assert "SYNTHETIC_SECRET" not in str(module.project("Pod", original))


@pytest.mark.parametrize("memory", [0, None, "3072Mi"])
def test_unproven_container_limit_blocks(module, memory):
    report = module.assess([node()], [], {"HostConfig": {"Memory": memory}})
    assert any(i["code"] == "node_container_memory_limit_unproven" for i in report["issues"])
