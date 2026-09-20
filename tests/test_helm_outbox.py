"""Offline Helm P8 contracts, including execution of rendered init validators."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "helm/bulwark-gateway"
HELM = shutil.which("helm")
pytestmark = pytest.mark.skipif(HELM is None, reason="local Helm CLI unavailable")


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Override the suite's DB-writing fixture: template tests need no services."""


def render(values: dict, *, error: str | None = None) -> dict:
    result = subprocess.run(  # noqa: S603
        [HELM, "template", "outbox-test", str(CHART), "-f", "-"],
        input=yaml.safe_dump(values), text=True, capture_output=True, timeout=30,
        check=False,
    )
    if error:
        assert result.returncode != 0
        assert error in result.stderr
        return {}
    assert result.returncode == 0, result.stderr
    return {
        (doc["kind"], doc["metadata"]["name"]): doc
        for doc in yaml.safe_load_all(result.stdout) if doc
    }


@pytest.fixture
def values() -> dict:
    return {
        "backend": {"type": "none"},
        "secrets": {"create": False},
        "proxy": {},
    }


@pytest.fixture
def local(values: dict) -> dict:
    values["persistence"] = {"accessMode": "ReadWriteMany"}
    values["telemetry"] = {"outbox": {"mode": "local-durable"}}
    values["proxy"].update(replicas=1, workers=1, autoscaling={"enabled": False})
    return values


@pytest.fixture
def shared(values: dict) -> dict:
    values["persistence"] = {"accessMode": "ReadWriteMany"}
    values["telemetry"] = {"outbox": {
        "mode": "shared-postgresql",
        "postgresql": {
            "existingSecret": "corporate-outbox", "urlKey": "dsn",
            "host": "pg.example.test", "port": 5432,
            "egress": {"cidr": "10.20.30.40/32"},
        },
    }}
    return values


def pod(docs: dict) -> dict:
    return docs["Deployment", "proxy"]["spec"]["template"]["spec"]


def named(items: list, name: str) -> dict:
    return next(item for item in items if item["name"] == name)


def test_legacy_preserved(values: dict) -> None:
    docs = render(values)
    config = docs["ConfigMap", "proxy-config"]["data"]
    assert config["BULWARK_TELEMETRY_DURABLE"] == "false"
    assert config["BULWARK_TELEMETRY_SHARED_OUTBOX"] == "false"
    assert config["BULWARK_AUDIT_ADMISSION_REQUIRED"] == "false"
    assert config["BULWARK_AUDIT_ADMISSION_TIMEOUT_MS"] == "250"
    assert "BULWARK_ADMIN_DB_URL_FILE" not in config
    assert "emptyDir" in named(pod(docs)["volumes"], "telemetry-data")
    assert ("PersistentVolumeClaim", "proxy-outbox") not in docs
    assert not any("outbox-pg" in item["name"] for item in pod(docs)["volumes"])
    assert docs["Deployment", "proxy"]["spec"]["strategy"]["type"] == "RollingUpdate"


def test_default_enrichment_needs_no_override() -> None:
    docs = render({"backend": {"type": "none"}})
    assert not any("enrichment" in item["name"] for item in pod(docs)["initContainers"])
    assert not any("enrichment" in item["name"] for item in pod(docs)["volumes"])
    assert ("PersistentVolumeClaim", "enrichment-data") not in docs
    assert docs["ConfigMap", "proxy-config"]["data"].get("BULWARK_ENRICHMENT_ENABLED", "false") == "false"


@pytest.mark.parametrize("fixture", ["local", "shared"])
@pytest.mark.parametrize("timeout", [1, 250, 10000])
def test_audit_admission_durable_modes(request: pytest.FixtureRequest, fixture: str, timeout: int) -> None:
    values = request.getfixturevalue(fixture)
    values["telemetry"]["auditAdmission"] = {"required": True, "timeoutMs": timeout}
    docs = render(values)
    config = docs["ConfigMap", "proxy-config"]["data"]
    assert config["BULWARK_AUDIT_ADMISSION_REQUIRED"] == "true"
    assert config["BULWARK_AUDIT_ADMISSION_TIMEOUT_MS"] == str(timeout)
    assert "BULWARK_AUDIT_ADMISSION_REQUIRED" not in docs["ConfigMap", "admin-config"]["data"]


@pytest.mark.parametrize("mode,enabled", [
    ("legacy", False), ("legacy", True),
    ("local-durable", False), ("shared-postgresql", False),
])
def test_audit_admission_requires_durable_telemetry(values: dict, mode: str, enabled: bool) -> None:
    values["telemetry"] = {
        "enabled": enabled, "outbox": {"mode": mode}, "auditAdmission": {"required": True},
    }
    render(values, error="auditAdmission.required requires telemetry.enabled=true")


@pytest.mark.parametrize("timeout", [0, -1, 10001, 1.5, True, "", "invalid", 10**30])
def test_audit_admission_rejects_invalid_timeout_even_when_disabled(values: dict, timeout: object) -> None:
    values["telemetry"] = {"auditAdmission": {"timeoutMs": timeout}}
    render(values, error="auditAdmission.timeoutMs must be an integer in 1..10000")


@pytest.mark.parametrize("required", ["false", "true", 0, 1])
def test_audit_admission_requires_boolean(values: dict, required: object) -> None:
    values["telemetry"] = {"auditAdmission": {"required": required}}
    render(values, error="auditAdmission.required must be a YAML boolean")


def test_local_pvc_and_single_exporter(local: dict) -> None:
    docs = render(local)
    config = docs["ConfigMap", "proxy-config"]["data"]
    assert config["BULWARK_TELEMETRY_DURABLE"] == "true"
    assert config["BULWARK_TELEMETRY_SHARED_OUTBOX"] == "false"
    assert config["BULWARK_TELEMETRY_DISK_PATH"] == "/app/data/telemetry_queue.db"
    assert named(pod(docs)["volumes"], "telemetry-data")["persistentVolumeClaim"] == {
        "claimName": "proxy-outbox",
    }
    claim = docs["PersistentVolumeClaim", "proxy-outbox"]
    assert claim["spec"]["accessModes"] == ["ReadWriteOnce"]
    assert claim["metadata"]["annotations"]["helm.sh/resource-policy"] == "keep"
    assert docs["Deployment", "proxy"]["spec"]["strategy"] == {"type": "Recreate"}
    assert ("HorizontalPodAutoscaler", "proxy") not in docs


def test_local_existing_claim(local: dict) -> None:
    local["telemetry"]["outbox"]["local"] = {
        "existingClaim": "dedicated-local-outbox", "accessMode": "ReadWriteOncePod",
    }
    docs = render(local)
    assert ("PersistentVolumeClaim", "proxy-outbox") not in docs
    assert named(pod(docs)["volumes"], "telemetry-data")["persistentVolumeClaim"]["claimName"] == "dedicated-local-outbox"


@pytest.mark.parametrize("override", [
    {"workers": 2}, {"workers": 1.5}, {"replicas": 2},
    {"autoscaling": {"enabled": True, "minReplicas": 1, "maxReplicas": 1}},
])
def test_local_rejects_concurrent_exporters(local: dict, override: dict) -> None:
    local["proxy"].update(override)
    render(local, error="requires proxy.workers=1")


@pytest.mark.parametrize("options,error", [
    ({"accessMode": "ReadWriteMany"}, "accessMode must be"),
    ({"existingClaim": "telemetry-data"}, "dedicated proxy-only"),
    ({"size": ""}, "nonempty local.size"),
])
def test_local_rejects_unsafe_storage(local: dict, options: dict, error: str) -> None:
    local["telemetry"]["outbox"]["local"] = options
    render(local, error=error)


@pytest.mark.parametrize("mode", ["local-durable", "shared-postgresql"])
def test_durable_rejects_shared_rwo(local: dict, mode: str) -> None:
    local["telemetry"]["outbox"]["mode"] = mode
    local["persistence"]["accessMode"] = "ReadWriteOnce"
    render(local, error="persistence.accessMode=ReadWriteMany")


def test_invalid_mode(values: dict) -> None:
    values["telemetry"] = {"outbox": {"mode": "shared-sqlite"}}
    render(values, error="telemetry.outbox.mode must be")


def test_disabled_telemetry(local: dict) -> None:
    local["telemetry"]["enabled"] = False
    render(local, error="requires telemetry.enabled=true")


def test_dedicated_not_silently_unwired(local: dict) -> None:
    local["dedicatedTenants"] = {"enabled": True}
    render(local, error="not wired for dedicatedTenants")


@pytest.mark.parametrize("mode", ["require", "verify-ca", "verify-full"])
def test_shared_secrets_ssl_and_scaling(shared: dict, mode: str) -> None:
    pg = shared["telemetry"]["outbox"]["postgresql"]
    pg.update(sslMode=mode, caKey="corporate-ca.pem")
    shared["proxy"].update(workers=4, replicas=3)
    docs = render(shared)
    config = docs["ConfigMap", "proxy-config"]["data"]
    assert config["BULWARK_TELEMETRY_SHARED_OUTBOX"] == "true"
    assert config["BULWARK_TELEMETRY_DURABLE"] == "false"
    assert config["BULWARK_ADMIN_DB_SSL"] == "true"
    assert config["BULWARK_ADMIN_DB_SSL_MODE"] == mode
    assert config["BULWARK_SHARED_OUTBOX_MAX_BYTES"] == "52428800"
    assert config["BULWARK_ADMIN_DB_URL_FILE"] == "/run/outbox-pg/postgresql-url"
    assert config["SSL_CERT_FILE"] == "/run/outbox-pg/ca.crt"
    assert "BULWARK_ADMIN_DB_URL" not in config
    secret = named(pod(docs)["volumes"], "outbox-pg-secret")["secret"]
    assert secret["secretName"] == "corporate-outbox"
    assert secret["defaultMode"] == 0o440
    assert secret["items"] == [
        {"key": "dsn", "path": "postgresql-url"},
        {"key": "corporate-ca.pem", "path": "ca.crt"},
    ]
    assert not any(kind == "Secret" for kind, _ in docs)
    mounts = named(pod(docs)["containers"], "proxy")["volumeMounts"]
    assert named(mounts, "outbox-pg-config")["readOnly"] is True
    assert not any(item["name"] == "outbox-pg-secret" for item in mounts)
    assert ("HorizontalPodAutoscaler", "proxy") in docs
    assert ("PersistentVolumeClaim", "proxy-outbox") not in docs


@pytest.mark.parametrize("options,error", [
    ({"existingSecret": ""}, "existingSecret, urlKey and host"),
    ({"host": ""}, "existingSecret, urlKey and host"),
    ({"urlKey": ""}, "existingSecret, urlKey and host"),
    ({"ssl": False}, "requires ssl=true"),
    ({"ssl": "false"}, "requires ssl=true"),
    ({"sslMode": "prefer"}, "requires ssl=true"),
    ({"sslMode": "disable"}, "requires ssl=true"),
    ({"poolMin": 21}, "out of range"),
    ({"port": 65536}, "out of range"),
    ({"port": 0}, "positive integer"),
    ({"port": 5432.5}, "positive integer"),
    ({"maxEvents": 10000001}, "out of range"),
    ({"maxBytes": 1099511627777}, "out of range"),
    ({"host": "https://pg.example.test"}, "host must be"),
    ({"existingSecret": "../../secret"}, "Secret name"),
    ({"urlKey": "../dsn"}, "Secret keys"),
])
def test_shared_invalid_config(shared: dict, options: dict, error: str) -> None:
    shared["telemetry"]["outbox"]["postgresql"].update(options)
    render(shared, error=error)


@pytest.mark.parametrize("cidr", [
    "", "0.0.0.0/0", "::/0", "10.0.0.0/7", "10.0.0.999/32",
    "10.0.0.1/24", "010.0.0.1/32", "10.0.0.1/32\n0.0.0.0/0",
])
def test_pg_egress_fail_closed(shared: dict, cidr: str) -> None:
    shared["telemetry"]["outbox"]["postgresql"]["egress"] = {"cidr": cidr}
    render(shared, error="PostgreSQL egress")


def test_shared_requires_netpol(shared: dict) -> None:
    shared["networkPolicies"] = {"enabled": False}
    render(shared, error="requires networkPolicies.enabled=true")


@pytest.mark.parametrize("override,error", [
    ({"minReplicas": 0}, "integer HPA replica bounds"),
    ({"maxReplicas": 1}, "valid HPA replica bounds"),
    ({"minReplicas": 1.5}, "integer HPA replica bounds"),
    ({"enabled": "false"}, "YAML booleans"),
])
def test_shared_invalid_hpa(shared: dict, override: dict, error: str) -> None:
    shared["proxy"]["autoscaling"] = override
    render(shared, error=error)


@pytest.mark.parametrize("mode,flag", [("disable", "false"), ("require", "true"), ("verify-full", "true")])
def test_admin_ssl_flag_and_mode(values: dict, mode: str, flag: str) -> None:
    values["admin"] = {"database": {"type": "postgresql", "postgresql": {
        "internal": False, "host": "pg.example.test", "sslMode": mode, "egressCIDR": "10.20.30.40/32",
    }}}
    config = render(values)["ConfigMap", "admin-config"]["data"]
    assert config["BULWARK_ADMIN_DB_SSL"] == flag
    assert config["BULWARK_ADMIN_DB_SSL_MODE"] == mode


@pytest.mark.parametrize("mode", ["require", "verify-ca", "verify-full"])
def test_bundled_postgresql_cannot_claim_unprovisioned_tls(values: dict, mode: str) -> None:
    values["admin"] = {"database": {"type": "postgresql", "postgresql": {"sslMode": mode}}}
    render(values, error="Bundled PostgreSQL has no TLS provisioning")


@pytest.mark.parametrize("port", [5432, 6432, 443, 8000])
def test_pg_egress_scoped_even_on_legacy_https_port(shared: dict, port: int) -> None:
    shared["telemetry"]["outbox"]["postgresql"]["port"] = port
    docs = render(shared)
    rules = docs["NetworkPolicy", "proxy-access"]["spec"]["egress"]
    pg_rules = [rule for rule in rules if any(p["port"] == port for p in rule["ports"])]
    assert pg_rules == [{
        "to": [{"ipBlock": {"cidr": "10.20.30.40/32"}}],
        "ports": [{"port": port, "protocol": "TCP"}],
    }]


@pytest.mark.parametrize("namespace", ["corporate-database", "bulwark-gateway"])
def test_pg_selector_is_namespace_and_pod(shared: dict, namespace: str) -> None:
    shared["telemetry"]["outbox"]["postgresql"]["egress"] = {
        "namespace": namespace, "podLabels": {"app": "outbox-db"},
    }
    docs = render(shared)
    rule = next(rule for rule in docs["NetworkPolicy", "proxy-access"]["spec"]["egress"]
                if rule.get("ports") == [{"port": shared["telemetry"]["outbox"]["postgresql"]["port"], "protocol": "TCP"}])
    assert rule["to"] == [{
        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": namespace}},
        "podSelector": {"matchLabels": {"app": "outbox-db"}},
    }]
    assert (("NetworkPolicy", "outbox-postgresql-ingress") in docs) == (namespace == "bulwark-gateway")


@pytest.mark.parametrize("egress", [
    {"namespace": "corp", "podLabels": {}},
    {"namespace": "", "podLabels": {"app": "pg"}},
    {"namespace": "*", "podLabels": {"app": "pg"}},
    {"namespace": "corp", "podLabels": {"app": "*"}},
    {"cidr": "10.0.0.1/32", "namespace": "corp", "podLabels": {"app": "pg"}},
])
def test_pg_rejects_wildcard_or_ambiguous_peers(shared: dict, egress: dict) -> None:
    shared["telemetry"]["outbox"]["postgresql"]["egress"] = egress
    render(shared, error="PostgreSQL egress")


@pytest.fixture
def enriched(values: dict) -> dict:
    digest = hashlib.sha256(b"synthetic test asset").hexdigest()
    values["proxy"]["enrichment"] = {
        "enabled": True, "existingModelClaim": "approved-models",
        "modelManifest": dict.fromkeys([
            "config.json", "tokenizer.json", "modules.json", "model.safetensors",
            "1_Pooling/config.json",
        ], digest),
    }
    return values


def test_enrichment_requires_provisioning(values: dict) -> None:
    values["proxy"]["enrichment"] = {"enabled": True}
    render(values, error="enrichment requires existingModelClaim")


def test_explicit_enrichment_claim_without_manifest_fails(values: dict) -> None:
    values["proxy"]["enrichment"] = {"enabled": True, "existingModelClaim": "approved-models"}
    render(values, error="enrichment requires existingModelClaim and a trusted SHA-256 modelManifest")


@pytest.mark.parametrize("path,digest", [
    ("../escape", "a" * 64), ("/absolute", "a" * 64),
    ("a/../../escape", "a" * 64), ("a//b", "a" * 64),
    ("config.json", ""), ("config.json", "g" * 64),
    ('evil\");print(1)#', "a" * 64),
])
def test_enrichment_manifest_rejects_bypass(enriched: dict, path: str, digest: str) -> None:
    enriched["proxy"]["enrichment"]["modelManifest"][path] = digest
    render(enriched, error="safe relative paths and 64-character SHA-256")


def test_enrichment_requires_weights(enriched: dict) -> None:
    del enriched["proxy"]["enrichment"]["modelManifest"]["model.safetensors"]
    render(enriched, error="missing required file model.safetensors")


@pytest.mark.parametrize("options,error", [
    ({"modelMaxBytes": 0}, "modelMaxBytes"),
    ({"modelMaxBytes": 1073741825}, "modelMaxBytes"),
    ({"modelMaxBytes": 1.5}, "modelMaxBytes"),
    ({"initImage": "python:latest"}, "no longer supported"),
    ({"download": True}, "no longer supported"),
])
def test_enrichment_invalid_options(enriched: dict, options: dict, error: str) -> None:
    enriched["proxy"]["enrichment"].update(options)
    render(enriched, error=error)


def test_enrichment_no_download_and_readonly_runtime(enriched: dict) -> None:
    docs = render(enriched)
    spec = pod(docs)
    init = named(spec["initContainers"], "init-enrichment-model")
    proxy = named(spec["containers"], "proxy")
    assert init["image"] == proxy["image"]
    assert init["command"][:2] == ["python3", "-c"]
    assert init["securityContext"]["readOnlyRootFilesystem"] is True
    assert "urllib" not in init["command"][2]
    assert "resolve/main" not in (CHART / "templates/proxy.yaml").read_text()
    assert named(proxy["volumeMounts"], "enrichment-model-verified")["readOnly"] is True
    assert not any(m["name"] == "enrichment-model-source" for m in proxy["volumeMounts"])
    config = docs["ConfigMap", "proxy-config"]["data"]
    assert config["HF_HUB_OFFLINE"] == config["TRANSFORMERS_OFFLINE"] == "1"
    assert config["BULWARK_EMBED_MODEL"] == "/app/verified-enrichment"


@pytest.mark.parametrize("failure", [None, "missing", "tampered", "symlink", "budget"])
def test_rendered_model_validator(enriched: dict, tmp_path: Path, failure: str | None) -> None:
    init = named(pod(render(enriched))["initContainers"], "init-enrichment-model")
    source, target = tmp_path / "source", tmp_path / "target"
    source.mkdir()
    target.mkdir()
    for name in enriched["proxy"]["enrichment"]["modelManifest"]:
        asset = source / name
        asset.parent.mkdir(exist_ok=True)
        asset.write_bytes(b"synthetic test asset")
    (source / "unverified.py").write_bytes(b"never copied")
    (target / "stale.bin").write_bytes(b"left by prior init")
    config = source / "config.json"
    if failure == "missing":
        config.unlink()
    elif failure == "tampered":
        config.write_bytes(b"corrupted")
    elif failure == "symlink":
        config.unlink()
        config.symlink_to(source / "tokenizer.json")
    env = {**os.environ, **{item["name"]: item["value"] for item in init["env"]}}
    if failure == "budget":
        env["MODEL_MAX_BYTES"] = "1"
    code = init["command"][2].replace('"/provisioned-model"', repr(str(source))).replace(
        '"/app/verified-enrichment"', repr(str(target)),
    )
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code], env=env, text=True, capture_output=True,
        timeout=10, check=False,
    )
    assert (result.returncode != 0) == (failure is not None), result.stderr
    assert not (target / "unverified.py").exists()
    assert not (target / "stale.bin").exists()
    if failure is None:
        assert (target / "model.safetensors").read_bytes() == b"synthetic test asset"


@pytest.mark.parametrize("url,missing_driver,success", [
    ("postgresql://user:fixture-password@pg.example.test/outbox", False, True),
    ("sqlite:///data/admin.db", False, False),
    ("", False, False),
    ("postgresql://user:fixture-password@other.example.test/outbox", False, False),
    ("postgresql://user:fixture-password@pg.example.test:6432/outbox", False, False),
    ("postgresql://user:fixture-password@pg.example.test/outbox?sslmode=disable", False, False),
    ("postgresql://user:fixture-password@pg.example.test/outbox", True, False),
])
def test_rendered_pg_validator(shared: dict, tmp_path: Path, url: str, missing_driver: bool, success: bool) -> None:
    init = named(pod(render(shared))["initContainers"], "validate-outbox-postgresql")
    source, target = tmp_path / "source", tmp_path / "target"
    source.mkdir()
    target.mkdir()
    (source / "postgresql-url").write_text(url)
    code = init["command"][2].replace('"/run/outbox-source"', repr(str(source))).replace(
        '"/run/outbox-pg"', repr(str(target)),
    )
    # Isolate optional driver availability without installing/importing a driver.
    code = "import importlib.util\nimportlib.util.find_spec = lambda name: " + (
        "None\n" if missing_driver else "object()\n"
    ) + code
    env = {**os.environ, **{item["name"]: item["value"] for item in init["env"]}}
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code], env=env, text=True, capture_output=True,
        timeout=10, check=False,
    )
    assert (result.returncode == 0) == success, result.stderr
    assert "fixture-password" not in result.stdout + result.stderr
    if success:
        assert (target / "postgresql-url").read_text() == url
        assert (target / "postgresql-url").stat().st_mode & 0o777 == 0o400
        (source / "postgresql-url").write_text("sqlite:///changed-after-validation.db")
        assert (target / "postgresql-url").read_text() == url
    else:
        assert not (target / "postgresql-url").exists()
