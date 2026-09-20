"""Offline deployment contracts; Helm renders only, never starts infrastructure."""

import copy
import hashlib
import shutil
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "helm/bulwark-gateway/templates/executor.yaml"
EXAMPLE = ROOT / "config/examples/executor-values.yaml"
HELM = shutil.which("helm")


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Override the shared admin DB fixture: no database or services in this suite."""


@pytest.fixture
def values():
    return yaml.safe_load(EXAMPLE.read_text())


@pytest.fixture
def enabled(values):
    executor = values["executor"]
    executor["enabled"] = True
    # Synthetic reference exclusively for local rendering, NOT a deployment image.
    digest = hashlib.sha256(b"executor offline render fixture; never pull").hexdigest()
    executor["image"] = f"registry.invalid/operator/executor@sha256:{digest}"
    executor["tls"]["confirmed"] = True
    executor["redis"]["durabilityConfirmed"] = True
    return values


def render(values):
    if HELM is None:
        pytest.skip("Helm unavailable: static contracts do not prove successful rendering")
    result = subprocess.run(  # noqa: S603 - fixed local Helm argv; values go via stdin, no shell.
        [HELM, "template", "executor-contract", str(ROOT / "helm/bulwark-gateway"),
         "--set", "backend.type=none", "--set", "proxy.enrichment.enabled=false", "-f", "-"],
        input=yaml.safe_dump(values), text=True, capture_output=True, timeout=30,
        check=False,
    )
    return result


def resources(values):
    result = render(values)
    assert result.returncode == 0, result.stderr
    return [doc for doc in yaml.safe_load_all(result.stdout)
            if doc and doc.get("metadata", {}).get("name", "").endswith("-executor")]


def test_static_opt_in_and_example_contract(values):
    source = TEMPLATE.read_text()
    assert ".Values.executor | default dict" in source
    assert "{{- if $executor.enabled -}}" in source
    assert set(values) == {"executor"}
    executor = values["executor"]
    assert executor["enabled"] is False
    assert executor["image"] == ""
    assert executor["tls"]["confirmed"] is False
    assert executor["redis"]["durabilityConfirmed"] is False
    assert executor["network"]["toolDestinations"] == []
    assert {"publicKey", "redisPassword", "redisCA", "toolCredential"} == set(executor["secrets"])
    assert "repo@sha256" in source and 'fail "executor.image' in source
    assert "type: Recreate" in source and "replicas: 1" in source
    assert "type: ClusterIP" in source
    assert "automountServiceAccountToken: false" in source
    assert "readOnlyRootFilesystem: true" in source
    assert 'drop: ["ALL"]' in source and "type: RuntimeDefault" in source
    assert "policyTypes: [Ingress, Egress]" in source
    assert "kind: HorizontalPodAutoscaler" not in source
    assert "kind: Ingress" not in source
    for forbidden in ("hostPath:", "docker.sock", "envFrom:", "secretKeyRef:",
                      "0.0.0.0/0", "::/0", "podSelector: {}", "to: []", "PRIVATE_KEY"):
        assert forbidden not in source


def test_reference_factory_refuses_before_io(monkeypatch):
    from config.examples import executor_operator

    assert executor_operator.TOOLS == {}
    assert executor_operator.POLICIES == []
    assert executor_operator.PRINCIPALS == frozenset()
    client = Mock(side_effect=AssertionError("Must not create a client"))
    read = Mock(side_effect=AssertionError("Must not read credentials"))
    monkeypatch.setattr(executor_operator, "get_redis_client", client)
    monkeypatch.setattr(Path, "read_text", read)
    with pytest.raises(RuntimeError, match="Operator tools, strict policies and principals"):
        executor_operator.create_executor()
    client.assert_not_called()
    read.assert_not_called()


def test_render_without_helm_is_explicitly_skipped(monkeypatch):
    monkeypatch.setitem(render.__globals__, "HELM", None)
    with pytest.raises(pytest.skip.Exception, match="static contracts do not prove"):
        render({})


@pytest.mark.parametrize("configured", [{}, {"executor": {}}, {"executor": {"enabled": False}}])
def test_absent_or_disabled_emits_nothing(configured):
    assert resources(configured) == []


def test_example_disabled_and_invalid_unused_config_are_inert(values):
    assert resources(values) == []
    values["executor"]["image"] = "not-an-image"
    values["executor"]["factoryModule"] = "../untrusted.py"
    assert resources(values) == []


def test_enabled_manifest_security_and_secret_contract(enabled):
    docs = {doc["kind"]: doc for doc in resources(enabled)}
    assert set(docs) == {"Deployment", "Service", "NetworkPolicy"}
    deployment = docs["Deployment"]["spec"]
    assert deployment["replicas"] == 1
    assert deployment["strategy"] == {"type": "Recreate"}
    pod = deployment["template"]["spec"]
    assert pod["automountServiceAccountToken"] is False
    for field in ("hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace", "enableServiceLinks"):
        assert pod[field] is False
    assert "initContainers" not in pod
    assert pod["securityContext"] == {
        "runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
        "fsGroup": 65532, "seccompProfile": {"type": "RuntimeDefault"},
    }
    assert len(pod["containers"]) == 1
    container = pod["containers"][0]
    assert container["image"] == enabled["executor"]["image"]
    assert container["command"] == ["python3", "-m", "uvicorn"]
    args = container["args"]
    assert args[0] == "config.examples.executor_operator:create_executor"
    assert args[args.index("--workers") + 1] == "1"
    assert "--factory" in args and "--no-access-log" in args
    assert "--reload" not in args
    assert container["securityContext"] == {
        "allowPrivilegeEscalation": False, "privileged": False,
        "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]},
    }
    for probe in ("startupProbe", "readinessProbe", "livenessProbe"):
        assert container[probe]["tcpSocket"] == {"port": "executor"}
        assert "httpGet" not in container[probe] and "exec" not in container[probe]
    for budget in ("requests", "limits"):
        assert set(container["resources"][budget]) == {"cpu", "memory"}
    env = {item["name"]: item["value"] for item in container["env"]}
    assert len(env) == 11
    assert env["BULWARK_EXECUTOR_REDIS_PORT"] == "6380"
    assert env["BULWARK_EXECUTOR_REPLAY_DURABILITY_CONFIRMED"] == "true"
    assert len(pod["volumes"]) == len(container["volumeMounts"]) == 4
    for field, ref in enabled["executor"]["secrets"].items():
        volume = next(v for v in pod["volumes"] if v["name"] == field.lower())
        assert set(volume) == {"name", "secret"}
        assert volume["secret"] == {
            "secretName": ref["name"], "defaultMode": 0o440,
            "items": [{"key": ref["key"], "path": "value"}],
        }
        mount = next(v for v in container["volumeMounts"] if v["name"] == field.lower())
        assert mount == {"name": field.lower(), "mountPath": f"/run/executor/{field}", "readOnly": True}
        assert f"/run/executor/{field}/value" in env.values()
    selector = deployment["selector"]["matchLabels"]
    assert docs["Service"]["spec"]["selector"] == selector
    assert docs["NetworkPolicy"]["spec"]["podSelector"]["matchLabels"] == selector
    assert len(docs["NetworkPolicy"]["spec"]["egress"]) == 2  # DNS and Redis only.
    service = docs["Service"]["spec"]
    assert set(service) == {"type", "selector", "ports"}
    assert service["type"] == "ClusterIP"
    assert service["ports"] == [{"name": "executor", "port": 8091, "targetPort": "executor", "protocol": "TCP"}]


def test_network_scopes_peers_and_remains_enabled_without_shared_policies(enabled):
    enabled["networkPolicies"] = {"enabled": False}
    enabled["executor"]["network"]["toolDestinations"] = [
        {"namespace": "tools", "podLabels": {"app": "approved-api"}, "port": 443},
        {"namespace": "egress", "podLabels": {"app": "fixed-destination-gateway"}, "port": 8443},
    ]
    enabled["executor"]["redis"]["port"] = 16380
    docs = resources(enabled)
    policy = next(doc["spec"] for doc in docs if doc["kind"] == "NetworkPolicy")
    assert policy["policyTypes"] == ["Ingress", "Egress"]
    ingress = policy["ingress"]
    assert len(ingress) == len(ingress[0]["from"]) == 1
    assert ingress[0]["from"][0] == {
        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "corporate-authorizer"}},
        "podSelector": {"matchLabels": {"app.kubernetes.io/name": "action-authorizer"}},
    }
    assert ingress[0]["ports"] == [{"port": 8091, "protocol": "TCP"}]
    egress = policy["egress"]
    assert len(egress) == 4
    for rule, namespace, labels in zip(
        egress,
        ["kube-system", "executor-storage", "tools", "egress"],
        [{"k8s-app": "kube-dns"}, {"app.kubernetes.io/name": "executor-replay"},
         {"app": "approved-api"}, {"app": "fixed-destination-gateway"}], strict=True,
    ):
        assert rule["to"] == [{
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": namespace}},
            "podSelector": {"matchLabels": labels},
        }]
    assert egress[0]["ports"] == [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}]
    assert [rule["ports"] for rule in egress[1:]] == [
        [{"port": port, "protocol": "TCP"}] for port in (16380, 443, 8443)
    ]


@pytest.mark.parametrize(("path", "value", "error"), [
    ("enabled", "false", "executor.enabled must be a boolean"),
    ("image", "", "executor.image is required"),
    ("image", "operator/executor:latest", "executor.image must be"),
    ("image", "operator/executor@sha256:abc", "executor.image must be"),
    ("image", "operator/executor:1.0@sha256:" + "a" * 64, "executor.image must be"),
    ("factoryModule", "", "executor.factoryModule is required"),
    ("factoryModule", "operator.factory:create_executor", "dotted Python module"),
    ("factoryModule", "../operator.py", "dotted Python module"),
    ("factoryModule", "operator.factory;id", "dotted Python module"),
    ("factoryModule", "operator.factory --workers 2", "dotted Python module"),
    ("factoryModule", "operator.f\u0430ctory", "dotted Python module"),
    ("replicas", 2, "executor.replicas must be 1"),
    ("replicas", 0, "executor.replicas must be 1"),
    ("workers", 4, "executor.workers must be 1"),
    ("workers", 1.5, "executor.workers must be 1"),
    ("autoscaling", {"enabled": True}, "executor autoscaling is unsupported"),
    ("tls.confirmed", False, "executor.tls requires"),
    ("tls.confirmed", "true", "executor.tls requires"),
    ("tls.boundary", "publicIngress", "executor.tls requires"),
    ("redis.durabilityConfirmed", False, "executor.redis.durabilityConfirmed must be true"),
    ("redis.durabilityConfirmed", "true", "executor.redis.durabilityConfirmed must be true"),
    ("redis.host", "rediss://user:password@redis", "fixed hostname"),
    ("redis.host", "", "executor.redis.host is required"),
    ("redis.username", "", "executor.redis.username is required"),
    ("redis.port", 0, "executor.redis.port must be an integer"),
    ("redis.port", 65536, "executor.redis.port must be an integer"),
    ("issuer", "", "executor.issuer is required"),
    ("audience", "", "executor.audience is required"),
    ("secrets.toolCredential.name", "", "executor.secrets.toolCredential.name is required"),
    ("secrets.publicKey.key", "", "executor.secrets.publicKey.key is required"),
    ("secrets.redisPassword.name", "executor-tool-credential", "distinct dedicated Secrets"),
    ("secrets.toolCredential.name", "invalid/name", "valid DNS subdomains"),
    ("secrets.toolCredential.key", "../../private.pem", "valid non-path keys"),
    ("network.authorizer.podLabels", {}, "nonempty explicit podLabels"),
    ("network.authorizer.namespace", "", "explicit namespace"),
    ("network.authorizer.namespace", "*", "exact DNS label"),
    ("network.redis.podLabels", {}, "nonempty explicit podLabels"),
    ("network.redis.podLabels", {"app": ""}, "nonempty strings"),
    ("network.toolDestinations", [{"namespace": "tools", "podLabels": {}, "port": 443}], "nonempty explicit podLabels"),
    ("network.toolDestinations", [{"namespace": "tools", "podLabels": {"app": "tool"}}], "explicit TCP port"),
    ("network.toolDestinations", [{"ipBlock": {"cidr": "0.0.0.0/0"}}], "no allow-any or raw rules"),
    ("network.toolDestinations", [{"namespace": "tools", "podLabels": {"app": "tool"}, "port": 65536}], "explicit TCP port"),
])
def test_unsafe_or_incomplete_config_fails_render(enabled, path, value, error):
    cursor = enabled["executor"]
    parts = path.split(".")
    for part in parts[:-1]:
        cursor = cursor[part]
    cursor[parts[-1]] = copy.deepcopy(value)
    result = render(enabled)
    assert result.returncode != 0
    assert error in result.stderr


def test_custom_baked_module_and_private_ingress_are_valid(enabled):
    enabled["executor"]["factoryModule"] = "corporate.approved_factory"
    enabled["executor"]["tls"]["boundary"] = "internalIngress"
    docs = resources(enabled)
    deployment = next(doc for doc in docs if doc["kind"] == "Deployment")
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    assert container["args"][0] == "corporate.approved_factory:create_executor"


def test_opt_in_without_image_and_missing_secret_fail_closed(enabled):
    result = render({"executor": {"enabled": True}})
    assert result.returncode != 0
    assert "executor.image is required" in result.stderr
    del enabled["executor"]["secrets"]["toolCredential"]
    result = render(enabled)
    assert result.returncode != 0
    assert "executor.secrets.toolCredential.name is required" in result.stderr
