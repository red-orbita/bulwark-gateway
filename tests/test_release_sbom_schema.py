"""Official schema, offline reference resolution and resource failure contracts."""

import importlib
import json
import socket
import subprocess
from pathlib import Path

import pytest


@pytest.fixture
def schema(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    return importlib.import_module("release_sbom_schema")


def bom():
    return {"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
            "components": [{"type": "library", "name": "example", "version": "1",
                            "licenses": [{"license": {"id": "Apache-2.0"}}]}]}


@pytest.mark.parametrize("fault", [None, "unknown_field", "bad_license", "bad_hash", "bad_signature", "bad_crypto"])
def test_official_schema_with_external_resources(schema, monkeypatch, fault):
    def no_network(*args, **kwargs):
        pytest.fail("Schema validation attempted network access")
    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    document = bom()
    if fault == "unknown_field":
        document["unrecognized"] = True
    elif fault == "bad_license":
        document["components"][0]["licenses"][0]["license"]["id"] = "not-a-real-SPDX-license"
    elif fault == "bad_hash":
        document["components"][0]["hashes"] = [{"alg": "SHA-256", "content": "invalid"}]
    elif fault == "bad_signature":
        document["signature"] = {"algorithm": 42, "value": "x"}
    elif fault == "bad_crypto":
        document["components"][0]["cryptoProperties"] = {
            "assetType": "algorithm", "algorithmProperties": {"algorithmFamily": "invented"}}
    if fault:
        with pytest.raises(ValueError):
            schema.validate_document(json.dumps(document).encode())
    else:
        schema.validate_document(json.dumps(document).encode())


@pytest.mark.parametrize("raw", [b'{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}',
                                 b'{"version":NaN}', b'{"version":1e999}', b'[]'])
def test_malformed_or_nonfinite_document_rejected(schema, raw):
    with pytest.raises(ValueError):
        schema.validate_document(raw)


@pytest.mark.parametrize("fault", ["depth", "nodes", "bytes", "missing", "tampered", "symlink"])
def test_schema_and_input_budgets_fail_closed(schema, monkeypatch, tmp_path, fault):
    document = bom()
    if fault == "depth":
        monkeypatch.setattr(schema, "MAX_DEPTH", 1)
    elif fault == "nodes":
        monkeypatch.setattr(schema, "MAX_NODES", 1)
    elif fault == "bytes":
        monkeypatch.setattr(schema, "MAX_BYTES", 1)
    else:
        original = schema.SCHEMA_DIR
        monkeypatch.setattr(schema, "SCHEMA_DIR", tmp_path)
        if fault == "tampered":
            (tmp_path / "bom-1.7.schema.json").write_text('{}')
        elif fault == "symlink":
            (tmp_path / "bom-1.7.schema.json").symlink_to(original / "bom-1.7.schema.json")
    with pytest.raises((ValueError, OSError)):
        schema.validate_document(json.dumps(document).encode())


def test_actual_isolated_worker_accepts_valid_and_rejects_invalid(schema):
    schema.validate_schema(json.dumps(bom()).encode())
    with pytest.raises(ValueError, match="Offline SBOM"):
        schema.validate_schema(b'{"bomFormat":"wrong"}')


def test_all_schema_references_are_bundled(schema):
    from urllib.parse import urldefrag

    resources = {name for name in schema.SCHEMA_FILES if name.endswith(".json")}
    for name in resources:
        pending = [json.loads((schema.SCHEMA_DIR / name).read_bytes())]
        while pending:
            node = pending.pop()
            if isinstance(node, dict):
                if "$ref" in node:
                    target, _ = urldefrag(node["$ref"])
                    assert not target or target in resources
                pending.extend(node.values())
            elif isinstance(node, list):
                pending.extend(node)


def test_worker_enforces_resource_limits_before_reading(schema, monkeypatch):
    import io

    calls = []
    monkeypatch.setattr(schema.resource, "setrlimit", lambda kind, bounds: calls.append((kind, bounds)))
    monkeypatch.setattr(schema.sys, "stdin", type("Input", (), {"buffer": io.BytesIO(json.dumps(bom()).encode())})())
    assert schema.main() == 0
    assert calls == [(schema.resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2)),
                     (schema.resource.RLIMIT_CPU, (10, 10)), (schema.resource.RLIMIT_CORE, (0, 0))]


@pytest.mark.parametrize("fault", ["timeout", "exit", "unavailable"])
def test_worker_failure_is_generic_and_environment_is_clean(schema, monkeypatch, fault):
    def run(args, **kwargs):
        assert args[1] == "-I"
        assert kwargs["timeout"] == 15
        assert kwargs["env"] == {"PATH": "/usr/bin:/bin"}
        assert kwargs["stdout"] == kwargs["stderr"] == subprocess.DEVNULL
        if fault == "timeout":
            raise subprocess.TimeoutExpired(args, 15)
        if fault == "unavailable":
            raise OSError("private diagnostic")
        return subprocess.CompletedProcess(args, 1)
    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(ValueError, match="^Offline SBOM schema validation failed$"):
        schema.validate_schema(json.dumps(bom()).encode())
