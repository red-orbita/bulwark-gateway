"""Opt-in attachment deployment contracts; rendering only, no cluster changes."""

import copy
import subprocess

import pytest
import yaml

from tests.test_helm_attachments import CHART, HELM

pytestmark = pytest.mark.skipif(HELM is None, reason="local Helm unavailable")


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """No DB or infrastructure needed for rendering."""


def values():
    return {
        "backend": {"type": "none"}, "secrets": {"create": False},
        "persistence": {"accessMode": "ReadWriteMany"},
        "proxy": {
            "replicas": 1, "workers": 1, "autoscaling": {"enabled": False},
            "image": {"digest": "sha256:" + "a" * 64},  # Synthetic test digest, never deployed.
            "attachments": {"service": {"enabled": True, "storageProtectionConfirmed": True}},
        },
    }


def render(config):
    result = subprocess.run(  # noqa: S603
        [HELM, "template", "attachments", str(CHART), "-f", "-"],
        input=yaml.safe_dump(config), text=True, capture_output=True, timeout=30, check=False,
    )
    return result


def documents(config):
    result = render(config)
    assert result.returncode == 0, result.stderr
    return {(doc["kind"], doc["metadata"]["name"]): doc for doc in yaml.safe_load_all(result.stdout) if doc}


def test_local_dedicated_storage_lifecycle_and_probe():
    docs = documents(values())
    config = docs["ConfigMap", "proxy-config"]["data"]
    assert config["BULWARK_ATTACHMENT_SERVICE_ENABLED"] == "true"
    assert config["BULWARK_ATTACHMENT_SERVICE_DB_URL_FILE"] == "/run/attachment-config/database-url"
    assert docs["ConfigMap", "attachment-storage-config"]["data"]["database-url"] == "sqlite:////app/attachments/documents.db"
    assert docs["PersistentVolumeClaim", "proxy-attachments"]["metadata"]["annotations"]["helm.sh/resource-policy"] == "keep"
    deployment = docs["Deployment", "proxy"]["spec"]
    assert deployment["strategy"] == {"type": "Recreate"}
    pod = deployment["template"]["spec"]
    proxy = pod["containers"][0]
    assert proxy["readinessProbe"]["httpGet"]["path"] == "/ready/attachments"
    assert proxy["livenessProbe"]["httpGet"]["path"] == "/health"
    assert proxy["securityContext"]["readOnlyRootFilesystem"] is True
    assert {v["name"]: v for v in pod["volumes"]}["attachment-data"]["persistentVolumeClaim"]["claimName"] == "proxy-attachments"
    admin = docs["Deployment", "admin"]["spec"]["template"]["spec"]
    assert not any(v["name"].startswith("attachment") for v in admin["volumes"])


def test_default_disabled_has_no_attachment_storage():
    docs = documents({"backend": {"type": "none"}, "secrets": {"create": False}})
    assert docs["ConfigMap", "proxy-config"]["data"]["BULWARK_ATTACHMENT_SERVICE_ENABLED"] == "false"
    assert ("PersistentVolumeClaim", "proxy-attachments") not in docs
    assert ("ConfigMap", "attachment-storage-config") not in docs


def test_existing_claim_not_recreated():
    config = values()
    config["proxy"]["attachments"]["service"]["local"] = {"existingClaim": "private-documents"}
    docs = documents(config)
    assert ("PersistentVolumeClaim", "proxy-attachments") not in docs
    volumes = docs["Deployment", "proxy"]["spec"]["template"]["spec"]["volumes"]
    assert next(v for v in volumes if v["name"] == "attachment-data")["persistentVolumeClaim"]["claimName"] == "private-documents"


@pytest.mark.parametrize("field,value", [("enabled", "true"), ("storageProtectionConfirmed", False),
    ("storage", "unknown"), ("maxDocuments", "1"), ("maxDocuments", 0), ("maxDocuments", 10001),
    ("maxBytes", True), ("maxBytes", 1048575), ("maxBytes", 1073741825),
    ("maxPerTenant", 1001), ("ttlSeconds", 59), ("ttlSeconds", 86401),
    ("local", {"accessMode": "ReadWriteMany"}), ("local", {"existingClaim": "admin-data"}),
    ("local", {"size": "50Mi"}), ("local", {"existingClaim": "../bad"}),
])
def test_invalid_service_config_rejected(field, value):
    config = values()
    config["proxy"]["attachments"]["service"][field] = value
    assert render(config).returncode != 0


@pytest.mark.parametrize("field,value", [("workers", 2), ("replicas", 2), ("workers", "1"),
                                      ("autoscaling", {"enabled": True}), ("image", {"digest": ""})])
def test_unsafe_deployment_rejected(field, value):
    config = values()
    config["proxy"][field] = value
    assert render(config).returncode != 0


def test_postgresql_uses_validated_secret_tls_and_egress_snapshot():
    config = values()
    config["proxy"]["attachments"]["service"]["storage"] = "shared-postgresql"
    assert render(config).returncode != 0
    config["telemetry"] = {"outbox": {"mode": "shared-postgresql", "postgresql": {
        "existingSecret": "database-credentials", "host": "pg.example", "sslMode": "verify-full",
        "egress": {"cidr": "10.20.30.0/24"},
    }}}
    docs = documents(config)
    assert docs["ConfigMap", "proxy-config"]["data"]["BULWARK_ATTACHMENT_SERVICE_DB_URL_FILE"] == "/run/outbox-pg/postgresql-url"
    assert ("PersistentVolumeClaim", "proxy-attachments") not in docs
    unsafe = copy.deepcopy(config)
    unsafe["telemetry"]["outbox"]["postgresql"]["sslMode"] = "require"
    assert render(unsafe).returncode != 0
