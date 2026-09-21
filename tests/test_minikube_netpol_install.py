"""Offline checks of the explicitly authorized infrastructure exception."""

import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """No operator database access."""


@pytest.fixture
def runner():
    path = Path(__file__).parents[1] / "scripts/install-minikube-netpol.py"
    spec = importlib.util.spec_from_file_location("netpol_install", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_controller_does_not_replace_cni_or_kube_proxy(runner):
    objects = runner.controller_objects()
    deployment = objects[-1]
    pod = deployment["spec"]["template"]["spec"]
    assert pod["hostNetwork"] is True
    assert "hostPID" not in pod and "initContainers" not in pod
    container = pod["containers"][0]
    for flag in ("--run-router=false", "--run-service-proxy=false", "--enable-cni=false"):
        assert flag in container["args"]
    assert not container["securityContext"].get("privileged")
    assert container["securityContext"]["capabilities"]["add"] == ["NET_ADMIN", "NET_RAW"]
    assert container["imagePullPolicy"] == "Never" and "@sha256:" in container["image"]
    assert not any(v.get("hostPath", {}).get("path") in ("/etc/cni/net.d", "/opt", "/var/run/docker.sock")
                   for v in pod["volumes"])


def test_rbac_reads_no_secrets_and_cannot_mutate_cluster(runner):
    role = runner.controller_objects()[1]
    for rule in role["rules"]:
        assert set(rule["verbs"]) == {"get", "list", "watch"}
        assert "secrets" not in rule["resources"] and "*" not in rule["resources"]


def test_additive_rules_are_owned_and_scoped(runner):
    for item in runner.connectivity_policies():
        assert item["metadata"]["name"].startswith(runner.NAME)
        assert item["spec"]["podSelector"]["matchLabels"]
        for direction in ("ingress", "egress"):
            for rule in item["spec"].get(direction, []):
                assert rule["ports"] and (rule.get("to") or rule.get("from"))


def test_failed_controller_stop_never_removes_firewall_or_rbac(runner, monkeypatch):
    remove = Mock()
    monkeypatch.setattr(runner, "remove_owned_firewall", remove)
    deletion = Mock(side_effect=RuntimeError("api unavailable"))
    monkeypatch.setattr(runner, "delete_owned", deletion)
    result = runner.rollback(runner.controller_objects(), "owner")
    assert result[0]["stage"] == "stop_controller"
    remove.assert_not_called()
    assert deletion.call_count == 1


def test_monitoring_restoration_attempts_both_after_timeout(runner, monkeypatch):
    calls = []
    def kube(*args, **kwargs):
        calls.append(args)
        if "deployment/grafana" in args:
            raise subprocess.TimeoutExpired("kubectl", 30)
        return SimpleNamespace(stdout=json.dumps({"spec": {"replicas": 1}, "status": {"readyReplicas": 1}}).encode())
    monkeypatch.setattr(runner, "kube", kube)
    failures = runner.restore_monitoring([("deployment", "grafana", 1), ("statefulset", "prometheus", 1)])
    assert len(failures) == 1 and failures[0]["name"] == "grafana"
    assert any("statefulset/prometheus" in args for args in calls)


def test_ambiguous_created_resource_deleted_with_uid_precondition(runner, monkeypatch):
    obj = runner.controller_objects()[0]
    resource = {"metadata": {"uid": "synthetic-uid", "labels": {runner.OWNER_LABEL: "owner"}}}
    calls = []
    def kube(*args, **kwargs):
        calls.append((args, kwargs))
        raw = json.dumps(resource).encode() if len(calls) == 1 else b""
        return SimpleNamespace(stdout=raw)
    monkeypatch.setattr(runner, "kube", kube)
    runner.delete_owned(obj, "owner")
    assert calls[1][1]["obj"]["preconditions"] == {"uid": "synthetic-uid"}
    assert "--raw" in calls[1][0]


def test_changed_ownership_never_deleted(runner, monkeypatch):
    resource = {"metadata": {"uid": "foreign", "labels": {runner.OWNER_LABEL: "another"}}}
    kube = Mock(return_value=SimpleNamespace(stdout=json.dumps(resource).encode()))
    monkeypatch.setattr(runner, "kube", kube)
    with pytest.raises(RuntimeError, match="ownership_changed"):
        runner.delete_owned(runner.controller_objects()[0], "owner")
    assert kube.call_count == 1


def test_ipset_cleanup_does_not_mask_listing_failure(runner, monkeypatch):
    run = Mock()
    monkeypatch.setattr(runner, "run", run)
    runner.remove_owned_firewall()
    script = run.call_args.args[0][-1]
    assert "names=$(ipset list -name)" in script
    assert "ipset list -name |" not in script
    assert "set -eu" in script


def test_incomplete_status_is_returned_to_shell():
    source = (Path(__file__).parents[1] / "scripts/install-minikube-netpol.py").read_text()
    assert 'return int(report["status"] != "controller_running_pending_enforcement_probe")' in source
    assert "raise SystemExit(main())" in source
