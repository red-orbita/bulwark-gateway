"""Offline configuration safety for phased current-chart validation."""

import base64
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """No operator user store required."""


def test_phases_keep_one_application_component_and_no_extra_lab():
    path = Path(__file__).parents[1] / "scripts/validation-k8s-chart.py"
    spec = importlib.util.spec_from_file_location("chart_runner", path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    for phase in ("admin", "proxy"):
        config = runner.values("owned-test", phase)
        assert config["admin"]["replicas"] + config["proxy"]["replicas"] == 1
        assert not config["wazuh"]["enabled"] and not config["ingress"]["enabled"]
        assert not config["monitoring"]["prometheus"]["enabled"]
        assert not config["proxy"]["enrichment"]["enabled"]
        for role in ("proxy", "admin"):
            assert config[role]["image"]["pullPolicy"] == "Never"
    text = path.read_text()
    assert '"strict=True\\n" + login' in text
    assert "if strict and not stored.is_file()" in text
    assert "if strict: raise RuntimeError('password_change_state_not_persisted')" in text
    assert "bootstrap_credential_still_valid" in text


def test_embedded_backend_and_exercise_programs_compile():
    import ast

    tree = ast.parse((Path(__file__).parents[1] / "scripts/validation-k8s-chart.py").read_text())
    programs = {node.targets[0].id: node.value.value for node in ast.walk(tree)
                if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id in {"server", "exercise", "seed"} and isinstance(node.value, ast.Constant)}
    assert programs.keys() == {"server", "exercise", "seed"}
    for name, program in programs.items():
        compile(program, name, "exec")


@pytest.fixture
def runner():
    path = Path(__file__).parents[1] / "scripts/validation-k8s-chart.py"
    spec = importlib.util.spec_from_file_location("chart_runner_tls", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_test_ca_and_leaf_are_scoped_and_private_key_not_saved(runner, tmp_path, monkeypatch):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    calls = []
    def k(*args, **kwargs):
        calls.append((args, kwargs))
        return json.dumps({"spec": {"ports": [{"port": 443, "nodePort": 32468}]}}).encode()
    monkeypatch.setattr(runner, "k", k)
    tls = runner.provision_tls("synthetic-test", tmp_path)
    secret = json.loads(calls[0][1]["data"])
    leaf = x509.load_pem_x509_certificate(base64.b64decode(secret["data"]["tls.crt"]))
    ca = x509.load_pem_x509_certificate((tmp_path / "validation-ca.pem").read_bytes())
    wrong = x509.load_pem_x509_certificate((tmp_path / "validation-wrong-ca.pem").read_bytes())
    leaf.verify_directly_issued_by(ca)
    assert leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) == list(tls["hosts"].values())
    assert ca.subject != wrong.subject
    private = serialization.load_pem_private_key(base64.b64decode(secret["data"]["tls.key"]), password=None)
    assert private.public_key() == leaf.public_key()
    assert {path.name for path in tmp_path.iterdir()} == {"validation-ca.pem", "validation-wrong-ca.pem"}


@pytest.mark.parametrize("invalid_code", [0, 7, 28, 35])
def test_https_negative_checks_do_not_accept_transport_failure(runner, tmp_path, monkeypatch, invalid_code):
    results = iter([SimpleNamespace(returncode=0, stdout=b"200"),
                    SimpleNamespace(returncode=invalid_code, stdout=b"000"),
                    SimpleNamespace(returncode=1, stdout=b"", stderr=b"hostname mismatch")])
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: next(results))
    with pytest.raises(RuntimeError, match="certificate_rejection_codes"):
        runner.check_https({"hosts": {"admin": "admin.test"}, "port": 32468}, "admin", "/admin/health", tmp_path)


def test_attachment_overlay_does_not_claim_encrypted_storage(runner, monkeypatch):
    calls = []
    monkeypatch.setattr(runner, "k", lambda *a, **kw: calls.append((a, kw)))
    runner.enable_lab_attachments("synthetic-test")
    objects = [json.loads(kw["data"]) for _, kw in calls]
    assert objects[0]["metadata"]["namespace"] == "synthetic-test"
    assert objects[0]["metadata"]["name"] == "validation-attachments"
    patch = objects[-1]["spec"]
    assert patch["strategy"]["type"] == "Recreate"
    assert "storageProtectionConfirmed" not in json.dumps(objects)
    assert "storage_encryption_attested=False" in runner.attachment_program()
    assert "persisted_across_pod_restart" in runner.attachment_program("att_test")


def test_proxy_cors_values_are_explicit_and_validated():
    from tests.test_helm_attachments import render

    docs = render(flags=("--set", "proxy.corsOrigins[0]=https://chat.example"))
    assert docs["ConfigMap", "proxy-config"]["data"]["BULWARK_CORS_ORIGINS"] == '["https://chat.example"]'
    for value in ("*", "https://chat.example/path", "javascript:alert"):
        render(flags=("--set", "proxy.corsOrigins[0]=" + value), error="proxy.corsOrigins")


@pytest.mark.parametrize("code,body", [(7, b""), (28, b""), (0, b"502")])
def test_foreign_cors_transport_or_server_errors_never_pass(runner, monkeypatch, tmp_path, code, body):
    positive = (b"HTTP/1.1 200 OK\r\naccess-control-allow-origin: https://admin.test\r\n"
                b"access-control-allow-methods: POST\r\n"
                b"access-control-allow-headers: authorization, content-type\r\n\r\n200")
    responses = iter([
        SimpleNamespace(returncode=0, stdout=b"200"),
        SimpleNamespace(returncode=60, stdout=b""),
        SimpleNamespace(returncode=1, stdout=b"", stderr=b"hostname mismatch"),
        SimpleNamespace(returncode=0, stdout=positive),
        SimpleNamespace(returncode=code, stdout=body),
    ])
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **kw: next(responses))
    with pytest.raises(RuntimeError, match="cors_ingress"):
        runner.check_https({"hosts": {"admin": "admin.test", "proxy": "proxy.test"}, "port": 32468},
                           "proxy", "/health", tmp_path)


def test_signal_restored_even_when_cleanup_raises(runner, monkeypatch):
    import signal

    original = signal.getsignal(signal.SIGTERM)
    def fail():
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        raise RuntimeError("cleanup failure")
    monkeypatch.setattr(runner, "_main", fail)
    with pytest.raises(RuntimeError):
        runner.main()
    assert signal.getsignal(signal.SIGTERM) == original


def test_source_snapshot_detects_new_chart_files(runner, tmp_path, monkeypatch):
    directory = tmp_path / "helm/bulwark-gateway"
    directory.mkdir(parents=True)
    script = tmp_path / "runner.py"
    script.write_text("test")
    monkeypatch.setattr(runner, "ROOT", tmp_path)
    monkeypatch.setattr(runner, "__file__", str(script))
    before = runner.source_snapshot()
    (directory / "new-template.yaml").write_text("kind: ConfigMap")
    assert runner.source_snapshot() != before


def stream_fixture():
    content = {"choices": [{"delta": {"content": "Public test response"}, "finish_reason": None}]}
    finish = {"choices": [{"delta": {}, "finish_reason": "stop"}]}
    return ("data: " + json.dumps(content) + "\n\ndata: " + json.dumps(finish) + "\n\ndata: [DONE]\n\n").encode()


@pytest.mark.parametrize("fault", [None, "missing_done", "missing_finish", "extra_after_done", "wrong_text", "invalid_json"])
def test_https_sse_requires_exact_complete_protocol(runner, fault):
    raw = stream_fixture()
    if fault == "missing_done":
        raw = raw.replace(b"data: [DONE]\n\n", b"")
    elif fault == "missing_finish":
        raw = raw.replace(b'"finish_reason": "stop"', b'"finish_reason": null')
    elif fault == "extra_after_done":
        raw += b"data: {}\n\n"
    elif fault == "wrong_text":
        raw = raw.replace(b"Public test response", b"not the expected response")
    elif fault == "invalid_json":
        raw = b"data: {invalid}\n\n"
    if fault:
        with pytest.raises(ValueError):
            runner.validate_chat_body(raw, True)
    else:
        runner.validate_chat_body(raw, True)


@pytest.mark.parametrize("transport_failure", [False, True])
def test_https_credentials_private_and_cleanup_on_failure(runner, tmp_path, monkeypatch, transport_failure):
    key = "synthetic-key-no-argv"
    calls = []

    def run(args, **kwargs):
        assert key not in str(args)
        assert "--cacert" in args and "--insecure" not in args
        assert "--location" not in args and kwargs["timeout"] == 20
        headers = Path(args[args.index("--header") + 1][1:])
        assert headers.stat().st_mode & 0o077 == 0
        assert key in headers.read_text()
        calls.append(args)
        if transport_failure:
            return SimpleNamespace(returncode=60, stdout=b"000")
        body = json.loads(kwargs["input"])
        malicious = body["messages"][0]["content"] != "Hello"
        raw = b"{}" if malicious else stream_fixture() if body["stream"] else json.dumps({
            "choices": [{"message": {"content": "Public test response"}}]}).encode()
        Path(args[args.index("--output") + 1]).write_bytes(raw)
        return SimpleNamespace(returncode=0, stdout=b"403" if malicious else b"200")

    monkeypatch.setattr(runner.subprocess, "run", run)
    tls = {"hosts": {"proxy": "proxy.test"}, "port": 32468}
    if transport_failure:
        with pytest.raises(RuntimeError, match="transport_failed"):
            runner.check_proxy_https(tls, tmp_path, key, False)
    else:
        result = runner.check_proxy_https(tls, tmp_path, key, False)
        assert result["complete_sse"] and len(calls) == 4
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("poll_failure", ["busy", "unavailable", "blocked"])
@pytest.mark.parametrize("owner_fault", [None, "unauthorized", "leak"])
@pytest.mark.parametrize("identity", ["owner", "tenant"])
@pytest.mark.parametrize("delete_busy", [False, True])
def test_https_attachment_retries_only_explicit_read_contention(
    runner, tmp_path, monkeypatch, poll_failure, owner_fault, identity, delete_busy,
):
    identifier = "att_" + "a" * 64
    owner_id = "att_" + "b" * 64
    polls = uploads = 0
    own_deletes = 0
    deleted = False

    def run(args, **kwargs):
        nonlocal polls, uploads, deleted, own_deletes
        path = args[-1].split("proxy.test", 1)[1]
        method = args[args.index("--request") + 1]
        headers = Path(args[args.index("--header") + 1][1:]).read_text()
        second_owner = "Bearer other-owner" in headers
        assert "other-owner" not in str(args)
        status, response = 200, {}
        if path == "/v1/attachments":
            uploads += 1
            status, response = (401, {}) if second_owner and owner_fault == "unauthorized" else (
                202, {"id": owner_id if second_owner else identifier})
        elif path.endswith(owner_id):
            assert second_owner and method == "DELETE"
            own_deletes += 1
            status, response = (429, {"detail": "busy"}) if delete_busy and own_deletes == 1 else (204, {})
        elif path.endswith(identifier):
            if second_owner:
                status = 200 if owner_fault == "leak" else 404
            elif "other-validation" in headers:
                status = 404
            elif method == "DELETE":
                deleted = True
                status = 204
            else:
                polls += 1
                if polls == 1:
                    status, response = {"busy": (429, {"detail": "busy"}),
                                        "unavailable": (503, {"detail": "unavailable"}),
                                        "blocked": (200, {"state": "blocked"})}[poll_failure]
                else:
                    response = {"state": "approved"}
        else:
            body = json.loads(kwargs["input"])
            content = body["messages"][0]["content"]
            if isinstance(content, str) and content != "Hello":
                status = 403
            elif deleted or second_owner:
                status = 404
            elif body.get("stream"):
                response = stream_fixture()
            else:
                response = {"choices": [{"message": {"content": "Public test response"}}]}
        raw = response if isinstance(response, bytes) else json.dumps(response).encode()
        Path(args[args.index("--output") + 1]).write_bytes(raw)
        return SimpleNamespace(returncode=0, stdout=str(status).encode())

    monkeypatch.setattr(runner.subprocess, "run", run)
    monkeypatch.setattr(runner.time, "sleep", lambda seconds: None)
    tls = {"hosts": {"proxy": "proxy.test"}, "port": 32468}
    extra = {identity + "_key": "other-owner"}
    if poll_failure == "busy" and owner_fault is None:
        result = runner.check_proxy_https(tls, tmp_path, "fixture", True, **extra)
        assert result["attachment_flow"] and result[f"attachment_cross_{identity}_get_delete_chat"]
        assert result["explicit_store_busy_retries"] == 1 + int(delete_busy)
        assert own_deletes == 1 + int(delete_busy)
        assert polls == 2
    elif poll_failure == "busy":
        with pytest.raises(RuntimeError, match=f"other_{identity}|cross_{identity}"):
            runner.check_proxy_https(tls, tmp_path, "fixture", True, **extra)
        assert polls == 2
    else:
        with pytest.raises(RuntimeError, match="processing_failed"):
            runner.check_proxy_https(tls, tmp_path, "fixture", True, **extra)
        assert polls == 1
    assert uploads == (2 if poll_failure == "busy" else 1) and list(tmp_path.iterdir()) == []
