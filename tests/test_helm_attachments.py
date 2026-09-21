"""Offline Helm contracts for strict chat attachment configuration."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

CHART = Path(__file__).resolve().parents[1] / "helm/bulwark-gateway"
HELM = shutil.which("helm")
pytestmark = pytest.mark.skipif(HELM is None, reason="local Helm CLI unavailable")


@pytest.fixture(autouse=True)
def _clear_force_password_change() -> None:
    """Override the suite's DB-writing fixture: rendering needs no services."""


def render(attachments: object = None, *, error: str | None = None,
           flags: tuple[str, ...] = ()) -> dict:
    values = {"backend": {"type": "none"}, "secrets": {"create": False}}
    if attachments is not None:
        values["proxy"] = {"attachments": attachments}
    result = subprocess.run(  # noqa: S603
        [HELM, "template", "attachments-test", str(CHART), "-f", "-", *flags],
        input=yaml.safe_dump(values), text=True, capture_output=True,
        timeout=30, check=False,
    )
    if error is not None:
        assert result.returncode != 0
        assert error in result.stderr
        return {}
    assert result.returncode == 0, result.stderr
    return {
        (doc["kind"], doc["metadata"]["name"]): doc
        for doc in yaml.safe_load_all(result.stdout) if doc
    }


@pytest.mark.parametrize("enabled", [None, False, True])
def test_defaults_and_explicit_switch_without_ml(enabled: bool | None) -> None:
    docs = render(None if enabled is None else {"enabled": enabled})
    config = docs["ConfigMap", "proxy-config"]["data"]
    expected = {
        "BULWARK_ATTACHMENT_GUARD_ENABLED": "true" if enabled else "false",
        "BULWARK_ATTACHMENT_MAX_FILE_BYTES": "16000",
        "BULWARK_ATTACHMENT_MAX_TOTAL_BYTES": "65536",
        "BULWARK_ATTACHMENT_MAX_COUNT": "5",
        "BULWARK_ATTACHMENT_EXTRACT_DOCUMENTS": "false",
        "BULWARK_ATTACHMENT_MAX_DOCUMENT_BYTES": "2097152",
        "BULWARK_ATTACHMENT_EXTRACTION_WORK_DIR": "/tmp",
        "BULWARK_ATTACHMENT_EXTRACTION_LANGUAGES": "eng",
        "BULWARK_ATTACHMENT_PARSER_ISOLATION_CONFIRMED": "false",
    }
    assert {key: config[key] for key in expected} == expected
    assert not expected.keys() & docs["ConfigMap", "admin-config"]["data"].keys()
    assert config.get("BULWARK_ML_ENABLED", "false") == "false"
    assert config.get("BULWARK_ENRICHMENT_ENABLED", "false") == "false"
    spec = docs["Deployment", "proxy"]["spec"]["template"]["spec"]
    proxy = next(item for item in spec["containers"] if item["name"] == "proxy")
    assert {"configMapRef": {"name": "proxy-config"}} in proxy["envFrom"]
    assert not any("model" in item["name"] for item in spec.get("initContainers", []))
    assert ("PersistentVolumeClaim", "ml-models") not in docs


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("file_bytes,total_bytes,count", [(1, 1, 1), (65536, 65536, 5)])
def test_integer_boundaries(enabled: bool, file_bytes: int, total_bytes: int, count: int) -> None:
    config = render({
        "enabled": enabled, "maxFileBytes": file_bytes,
        "maxTotalBytes": total_bytes, "maxCount": count,
    })["ConfigMap", "proxy-config"]["data"]
    assert config["BULWARK_ATTACHMENT_MAX_FILE_BYTES"] == str(file_bytes)
    assert config["BULWARK_ATTACHMENT_MAX_TOTAL_BYTES"] == str(total_bytes)
    assert config["BULWARK_ATTACHMENT_MAX_COUNT"] == str(count)


@pytest.mark.parametrize("value", ["false", "true", "", 0, 1, 1.5, None, [], {}])
def test_switch_requires_boolean(value: object) -> None:
    render({"enabled": value}, error="proxy.attachments.enabled must be a YAML boolean")


@pytest.mark.parametrize("field,maximum", [
    ("maxFileBytes", 65536), ("maxTotalBytes", 65536), ("maxCount", 5),
])
@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("value", [
    0, -1, 1.5, True, False, "1", "65536", "", "invalid", None, [], {}, 10**30,
])
def test_invalid_limits_fail_closed(field: str, maximum: int, enabled: bool, value: object) -> None:
    render({"enabled": enabled, field: value},
           error=f"proxy.attachments.{field} must be an integer in 1..{maximum}")


@pytest.mark.parametrize("field,maximum", [
    ("maxFileBytes", 65536), ("maxTotalBytes", 65536), ("maxCount", 5),
])
def test_limit_above_maximum(field: str, maximum: int) -> None:
    render({field: maximum + 1},
           error=f"proxy.attachments.{field} must be an integer in 1..{maximum}")


@pytest.mark.parametrize("value", [False, "false", 1, []])
def test_attachments_requires_map(value: object) -> None:
    render(value, error="proxy.attachments must be a YAML map")


def test_cli_set_preserves_types() -> None:
    config = render(flags=(
        "--set", "proxy.attachments.enabled=true,proxy.attachments.maxFileBytes=12000,"
        "proxy.attachments.maxTotalBytes=24000,proxy.attachments.maxCount=3",
    ))["ConfigMap", "proxy-config"]["data"]
    assert config["BULWARK_ATTACHMENT_GUARD_ENABLED"] == "true"
    assert config["BULWARK_ATTACHMENT_MAX_FILE_BYTES"] == "12000"
    assert config["BULWARK_ATTACHMENT_MAX_TOTAL_BYTES"] == "24000"
    assert config["BULWARK_ATTACHMENT_MAX_COUNT"] == "3"


@pytest.mark.parametrize("setting", ["enabled=false", "maxFileBytes=16000", "maxCount=5"])
def test_cli_set_string_cannot_bypass_validation(setting: str) -> None:
    render(flags=("--set-string", f"proxy.attachments.{setting}"),
           error=f"proxy.attachments.{setting.split('=')[0]} must be")


@pytest.mark.parametrize("enabled,extract", [(False, False), (False, True), (True, True)])
def test_document_extraction_and_policy_only_provisioning(enabled: bool, extract: bool) -> None:
    baseline = render({"enabled": enabled})
    docs = render({
        "enabled": enabled, "extractDocuments": extract,
        "parserIsolationConfirmed": True, "maxDocumentBytes": 1024,
        "extractionLanguages": "eng+spa",
    })
    config = docs["ConfigMap", "proxy-config"]["data"]
    assert config["BULWARK_ATTACHMENT_GUARD_ENABLED"] == str(enabled).lower()
    assert config["BULWARK_ATTACHMENT_EXTRACT_DOCUMENTS"] == str(extract).lower()
    assert config["BULWARK_ATTACHMENT_PARSER_ISOLATION_CONFIRMED"] == "true"
    assert config["BULWARK_ATTACHMENT_EXTRACTION_WORK_DIR"] == "/tmp"
    assert config["BULWARK_ATTACHMENT_EXTRACTION_LANGUAGES"] == "eng+spa"
    assert config["BULWARK_ATTACHMENT_MAX_DOCUMENT_BYTES"] == "1024"
    assert not any(key.startswith("BULWARK_ATTACHMENT_")
                   for key in docs["ConfigMap", "admin-config"]["data"])
    assert {k: v for k, v in config.items() if not k.startswith("BULWARK_ATTACHMENT_")} == {
        k: v for k, v in baseline["ConfigMap", "proxy-config"]["data"].items()
        if not k.startswith("BULWARK_ATTACHMENT_")
    }
    pod = docs["Deployment", "proxy"]["spec"]["template"]["spec"]
    base_pod = baseline["Deployment", "proxy"]["spec"]["template"]["spec"]
    scratch = next(v["emptyDir"] for v in pod["volumes"] if v["name"] == "tmp")
    assert scratch == {"medium": "Memory", "sizeLimit": "256Mi"}
    scratch["sizeLimit"] = "50Mi"
    # No changed resources/security contexts, host mounts, bootstrap or installation.
    assert pod == base_pod
    assert docs.keys() == baseline.keys()


@pytest.mark.parametrize("field", ["extractDocuments", "parserIsolationConfirmed"])
@pytest.mark.parametrize("value", ["true", "false", 1, 0, None, [], {}])
def test_document_switches_require_strict_boolean(field: str, value: object) -> None:
    render({field: value}, error=f"proxy.attachments.{field} must be a YAML boolean")


@pytest.mark.parametrize("value", [0, -1, 2097153, 1.5, True, "2097152", None, [], {}, 10**30])
def test_document_byte_limit_is_bounded(value: object) -> None:
    render({"maxDocumentBytes": value}, error="maxDocumentBytes must be an integer in 1..2097152")


@pytest.mark.parametrize("value", [1, 2097152])
def test_document_byte_boundaries(value: int) -> None:
    config = render({"maxDocumentBytes": value})["ConfigMap", "proxy-config"]["data"]
    assert config["BULWARK_ATTACHMENT_MAX_DOCUMENT_BYTES"] == str(value)


def test_document_extraction_requires_isolation_confirmation() -> None:
    render({"extractDocuments": True}, error="requires parserIsolationConfirmed=true")


@pytest.mark.parametrize("value", ["", "relative", "/tmp/document-extraction", "/app/data", None])
def test_document_parent_must_be_existing_chart_mount(value: object) -> None:
    render({"extractionWorkDir": value}, error="extractionWorkDir must be /tmp")


@pytest.mark.parametrize("value", ["", "ENG", "e", "eng+spa+fra+deu", "eng;id", "a" * 33, None, ["eng"]])
def test_languages_match_runtime_restrictions(value: object) -> None:
    render({"extractionLanguages": value}, error="extractionLanguages must match the runtime")


@pytest.mark.parametrize("value", ["eng", "eng+spa", "eng+spa+fra"])
def test_valid_language_configuration(value: str) -> None:
    config = render({"extractionLanguages": value})["ConfigMap", "proxy-config"]["data"]
    assert config["BULWARK_ATTACHMENT_EXTRACTION_LANGUAGES"] == value


@pytest.mark.parametrize("value", ["50Mi", "255Mi", "4097Mi", "1Gi", 256, None])
def test_scratch_budget_is_bounded(value: object) -> None:
    render({"extractionTmpSize": value}, error="extractionTmpSize must be whole Mi in 256..4096Mi")


@pytest.mark.parametrize("workers,size", [(2, "512Mi"), (16, "4096Mi")])
def test_scratch_scales_with_processes(workers: int, size: str) -> None:
    docs = render({"parserIsolationConfirmed": True, "extractionTmpSize": size},
                  flags=("--set", f"proxy.workers={workers}"))
    pod = docs["Deployment", "proxy"]["spec"]["template"]["spec"]
    assert next(v["emptyDir"]["sizeLimit"] for v in pod["volumes"] if v["name"] == "tmp") == size


@pytest.mark.parametrize("workers", [0, 2, 17, 10**30])
def test_undersized_or_invalid_worker_configuration(workers: int) -> None:
    render({"parserIsolationConfirmed": True}, flags=("--set", f"proxy.workers={workers}"),
           error="integer proxy.workers in 1..16 and at least 256Mi per worker")


def test_dedicated_proxy_scratch_is_not_silently_undersized() -> None:
    render({"parserIsolationConfirmed": True}, flags=("--set", "dedicatedTenants.enabled=true"),
           error="Document extraction is not provisioned for dedicatedTenants")


@pytest.mark.parametrize("confirmed,size", [(False, "500Mi"), (True, "500Mi")])
def test_enrichment_scratch_minimum_is_preserved(confirmed: bool, size: str) -> None:
    manifest = ("config.json", "tokenizer.json", "modules.json", "model.safetensors", "1_Pooling/config.json")
    docs = render({"parserIsolationConfirmed": confirmed}, flags=(
        "--set", "proxy.enrichment.enabled=true,proxy.enrichment.existingModelClaim=operator-models",
        "--set-json", "proxy.enrichment.modelManifest=" + json.dumps({name: "a" * 64 for name in manifest}),
    ))
    pod = docs["Deployment", "proxy"]["spec"]["template"]["spec"]
    assert next(v["emptyDir"]["sizeLimit"] for v in pod["volumes"] if v["name"] == "tmp") == size
