"""PR48 exceptions identify exact historical non-secret fixtures, never whole paths."""

import os
import secrets
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
FIXTURE_FILES = (
    "tests/test_adapter_structured_contracts.py",
    "tests/test_input_dlp.py",
    "tests/test_executor_service.py",
)


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """No user store needed for source/scanner checks."""


def test_gitleaks_exceptions_are_exact_reviewed_commit_fingerprints():
    entries = [line for line in (ROOT / ".gitleaksignore").read_text().splitlines()
               if line.strip() and not line.startswith("#")]
    commit = "b33b3a0dcd89658d14c6a46305f4b3155038e65b:"
    assert set(entries) == {
        commit + "tests/test_adapter_structured_contracts.py:generic-api-key:439",
        commit + "tests/test_adapter_structured_contracts.py:generic-api-key:450",
        commit + "tests/test_input_dlp.py:generic-api-key:29",
        commit + "tests/test_executor_service.py:aws-access-token:379",
    }
    assert len(entries) == 4


def test_security_scanners_fail_closed_and_do_not_publish_raw_secrets():
    workflow = yaml.safe_load((ROOT / ".github/workflows/security.yml").read_text())
    jobs = workflow["jobs"]
    for job in ("sast-semgrep", "sast-bandit"):
        for step in jobs[job]["steps"]:
            if "run" in step:
                assert "|| true" not in step["run"]
                assert not step.get("continue-on-error")
    secret_steps = jobs["secret-scanning"]["steps"]
    scans = [step for step in secret_steps if step.get("name", "").startswith("truffleHog scan")]
    assert len(scans) == 2
    for step in scans:
        assert "--json --fail" in step["run"]
        assert "--output" not in step["run"]
        assert "|| true" not in step["run"]
        assert '$RUNNER_TEMP/' in step["run"]
    assert not any("actions/upload-artifact" in step.get("uses", "") for step in secret_steps)
    assert "always()" in jobs["pr-summary"]["if"]
    summary = next(step for step in jobs["pr-summary"]["steps"] if step.get("name") == "Generate PR comment")
    assert "toJSON(needs)" in summary["env"]["SCAN_JOBS"]
    assert "except: print(0)" not in summary["run"]


@pytest.mark.skipif(not os.environ.get("BULWARK_TEST_GITLEAKS"), reason="Requires explicitly provisioned Gitleaks")
@pytest.mark.parametrize("unlisted", [False, True])
def test_current_fixtures_clean_but_new_token_still_detected(tmp_path, unlisted):
    for filename in FIXTURE_FILES:
        destination = tmp_path / filename
        destination.parent.mkdir(exist_ok=True)
        destination.write_bytes((ROOT / filename).read_bytes())
    if unlisted:
        # Generated synthetic token, never issued by a provider; tests that no
        # blanket test-file exemption can hide an additional high-entropy key.
        (tmp_path / FIXTURE_FILES[0]).write_text('api_key = "' + secrets.token_hex(24) + '"\n')
    result = subprocess.run(  # noqa: S603
        [os.environ["BULWARK_TEST_GITLEAKS"], "dir", str(tmp_path), "--redact", "--exit-code=2",
         "--config", str(ROOT / ".gitleaks.toml"), "--gitleaks-ignore-path", str(ROOT / ".gitleaksignore")],
        capture_output=True, timeout=30, check=False,
    )
    assert result.returncode == (2 if unlisted else 0), "Unexpected scanner outcome (details withheld)"
