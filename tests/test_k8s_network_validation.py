"""Offline checks for the owned Kubernetes enforcement probe."""

import importlib.util
import re
from pathlib import Path

import pytest
import yaml

from tests.test_helm_attachments import render


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """No operator database access."""


def test_probe_uses_cached_image_and_bounded_restricted_pods():
    path = Path(__file__).parents[1] / "scripts/validation-k8s-network.py"
    spec = importlib.util.spec_from_file_location("network_probe", path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    pod = runner.pod("client", "owned-test", "pass")
    assert pod["spec"]["activeDeadlineSeconds"] == 300
    assert pod["spec"]["automountServiceAccountToken"] is False
    assert pod["spec"]["securityContext"]["runAsNonRoot"] is True
    container = pod["spec"]["containers"][0]
    assert "@sha256:" in container["image"]
    assert container["imagePullPolicy"] == "Never"
    assert container["resources"]["limits"] == {"memory": "64Mi", "cpu": "100m"}
    assert container["securityContext"]["capabilities"] == {"drop": ["ALL"]}
    assert container["securityContext"]["readOnlyRootFilesystem"] is True


def test_both_runtime_images_pin_same_minimal_runtime():
    root = Path(__file__).parents[1]
    references = []
    for name in ("Dockerfile", "docker/Dockerfile.admin"):
        matches = re.findall(r"^FROM (\S+) AS runtime$", (root / name).read_text(), re.MULTILINE)
        assert len(matches) == 1
        assert re.fullmatch(r"cgr\.dev/chainguard/python@sha256:[a-f0-9]{64}", matches[0])
        references.append(matches[0])
    assert references[0] == references[1], "Update proxy and admin base digests together"


def test_dependabot_groups_both_container_directories():
    root = Path(__file__).parents[1]
    updates = yaml.safe_load((root / ".github/dependabot.yml").read_text())["updates"]
    docker = [entry for entry in updates if entry["package-ecosystem"] == "docker"]
    assert len(docker) == 1
    assert set(docker[0]["directories"]) == {"/", "/docker"}
    assert "directory" not in docker[0]
    assert docker[0]["groups"]["container-bases"]["patterns"] == ["*"]


def test_chart_agent_registry_uses_runtime_setting():
    from src.config import Settings

    config = render()["ConfigMap", "proxy-config"]["data"]
    assert "BULWARK_AGENTS_FILE" not in config
    assert config["BULWARK_AGENTS_CONFIG"] == "/app/shared/admin/agents.yaml"
    assert "agents_config" in Settings.model_fields


def test_compose_does_not_mix_source_revisions():
    root = Path(__file__).parents[1]
    compose = yaml.safe_load((root / "docker-compose.yml").read_text())
    assert not any("/app/admin" in mount or ":/app/src" in mount
                   for mount in compose["services"]["admin"]["volumes"])
    for role in ("proxy", "admin"):
        assert compose["services"][role]["healthcheck"]["test"][1] == "python3"


def test_selective_probe_requires_matching_client_label_in_both_directions():
    path = Path(__file__).parents[1] / "scripts/validation-k8s-network.py"
    spec = importlib.util.spec_from_file_location("network_probe_selective", path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    server, client = runner.selective_policies("owned-test")
    assert server["metadata"]["namespace"] == client["metadata"]["namespace"] == "owned-test"
    client_selector = {"matchLabels": {"app": "client", "probe-access": "allowed"}}
    assert client["spec"]["podSelector"] == client_selector
    assert server["spec"]["ingress"] == [{"from": [{"podSelector": client_selector}],
                                         "ports": [{"port": 8080, "protocol": "TCP"}]}]
    assert client["spec"]["egress"] == [{"to": [{"podSelector": server["spec"]["podSelector"]}],
                                       "ports": [{"port": 8080, "protocol": "TCP"}]}]
    for direction, role in (("Ingress", "server"), ("Egress", "client")):
        deny, allow = runner.directional_policies("owned-test", direction)
        assert deny["spec"]["policyTypes"] == allow["spec"]["policyTypes"] == [direction]
        assert deny["spec"]["podSelector"] == {"matchLabels": {"app": role}}
        assert set(deny["spec"]) == {"podSelector", "policyTypes", direction.lower()}
