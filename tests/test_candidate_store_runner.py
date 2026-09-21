"""Candidate store runner containment and truthful failure reporting, no services."""

import importlib
import json
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parents[1]


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Never initialize the operator database."""


@pytest.mark.parametrize("store", ["postgres", "redis"])
@pytest.mark.parametrize("fault", [None, "worker", "timeout", "cleanup"])
def test_owned_client_and_store_cleanup(monkeypatch, tmp_path, store, fault):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    runner = importlib.import_module("validation-candidate-postgres")
    lab_module = importlib.import_module("validation-live-stores")
    safety = importlib.import_module("validation_safety")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "shared").mkdir()
    monkeypatch.setattr(runner, "__file__", str(tmp_path / "scripts/probe.py"))
    monkeypatch.setattr(sys, "argv", ["probe", "--store", store, "--image", "sha256:" + "a" * 64])
    active = False
    labs = []

    @contextmanager
    def slot(root):
        nonlocal active
        assert root == tmp_path
        active = True
        yield
        active = False

    class Lab:
        def __init__(self, directory, stores):
            assert stores == (store,)
            self.directory = directory
            self.name = directory.name
            assert self.name.startswith("bulwark-validation-")
            self.containers = []
            self.report = {"cleanup": []}
            labs.append(self)

        def preflight(self):
            assert active

        def create(self, kind):
            config = self.directory / kind
            config.mkdir()
            for name in ("password", "ca.pem", "wrong-ca.pem"):
                (config / name).write_text("synthetic")
            self.containers.append(self.name + "-" + kind)
            return self.containers[-1]

        def cleanup(self):
            assert active
            self.report["cleanup"] = [{"resource": name, "status": "failed" if fault == "cleanup" else "removed"}
                                      for name in reversed(self.containers)]

    def run(command, **kwargs):
        assert active
        lab = labs[0]
        assert lab.containers[-1] == lab.name + "-client"
        assert "--network=container:" + lab.name + "-" + store in command
        assert "--read-only" in command and "--pull=never" in command and "--cap-drop=ALL" in command
        assert f"{lab_module.LABEL}={lab.name}" in command
        assert "synthetic" not in " ".join(command)
        assert kwargs["timeout"] == 110
        if fault == "timeout":
            raise subprocess.TimeoutExpired(command, 110)
        result = {"python": "3.14.7+", "production_approved": False,
                  "tls_rejected": ["wrong_ca", "wrong_hostname"], "migrations_idempotent": True,
                  "text_timestamp_parity": True, "direct_connection": True, "transaction_rollback": True,
                  "reopen": True, "attachment_scope_policy_and_leases": True, "outbox_scope_and_ack_fencing": True,
                  "jwt_accepted_before_revocation": True, "revoked_jwt_rejected": True}
        return SimpleNamespace(returncode=int(fault == "worker"), stdout=json.dumps(result).encode(),
                               stderr=b"candidate_postgres_validation_failed:RuntimeError")

    monkeypatch.setattr(safety, "validation_slot", slot)
    monkeypatch.setattr(lab_module, "Lab", Lab)
    monkeypatch.setattr(runner.subprocess, "run", run)
    (tmp_path / "scripts/probe.py").write_text("# synthetic runner")
    if fault:
        with pytest.raises((RuntimeError, subprocess.TimeoutExpired)):
            runner.main()
    else:
        runner.main()
    report = json.loads((labs[0].directory / "report.json").read_text())
    assert report["status"] == ("passed" if fault is None else "cleanup_failed" if fault == "cleanup" else "failed")
    assert len(report["cleanup"]) == 2


@pytest.mark.parametrize("image", ["latest", "repo:tag", "sha256:abc"])
def test_invalid_candidate_id_refused_before_resources(monkeypatch, image):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    runner = importlib.import_module("validation-candidate-postgres")
    monkeypatch.setattr(sys, "argv", ["probe", "--image", image])
    with pytest.raises(SystemExit):
        runner.main()


@pytest.mark.parametrize("store", ["postgres", "redis"])
@pytest.mark.parametrize("fault", ["empty", "wrong_python", "tls_missing", "integer_flag", "approval"])
def test_incomplete_or_ambiguous_worker_results_fail_closed(monkeypatch, store, fault):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    runner = importlib.import_module("validation-candidate-postgres")
    result = {"python": "3.14.7+", "production_approved": False,
              "tls_rejected": ["wrong_ca", "wrong_hostname"], "migrations_idempotent": True,
              "text_timestamp_parity": True, "direct_connection": True, "transaction_rollback": True,
              "reopen": True, "attachment_scope_policy_and_leases": True, "outbox_scope_and_ack_fencing": True,
              "jwt_accepted_before_revocation": True, "revoked_jwt_rejected": True}
    runner.validate_result(result, store)
    if fault == "empty":
        result = {}
    elif fault == "wrong_python":
        result["python"] = "3.13.5"
    elif fault == "tls_missing":
        result["tls_rejected"] = ["wrong_ca"]
    elif fault == "integer_flag":
        result["reopen" if store == "postgres" else "revoked_jwt_rejected"] = 1
    else:
        result["production_approved"] = True
    with pytest.raises(ValueError, match="incomplete"):
        runner.validate_result(result, store)
