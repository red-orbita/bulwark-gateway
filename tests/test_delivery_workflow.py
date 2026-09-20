from pathlib import Path

import pytest
import yaml


def workflow():
    return yaml.safe_load((Path(__file__).parents[1] / ".github/workflows/deploy.yml").read_text())


def test_ci_runs_for_actual_default_branch():
    data = workflow()
    triggers = data.get("on", data.get(True))  # PyYAML's YAML 1.1 treats 'on' as true.
    assert triggers["pull_request"]["branches"] == ["master"]
    assert triggers["push"]["branches"] == ["master"]
    assert data["permissions"] == {"contents": "read"}


def test_publication_and_deploy_require_explicit_opt_in():
    jobs = workflow()["jobs"]
    for job, flag in (("build", "BULWARK_PUBLISH_IMAGES"), ("deploy-staging", "BULWARK_DEPLOY_STAGING"),
                      ("deploy-production", "BULWARK_DEPLOY_PRODUCTION")):
        assert f"vars.{flag} == 'true'" in jobs[job]["if"]


def test_evidence_and_postgres_skip_gate_present():
    jobs = workflow()["jobs"]
    for name in ("test", "test-postgres"):
        steps = jobs[name]["steps"]
        commands = "\n".join(step.get("run", "") for step in steps)
        assert '--require-hashes -r "$RUNNER_TEMP/ci-runtime.lock"' in commands
        assert "python tests/packaging_locks.py verify" in commands
        assert '-c "$RUNNER_TEMP/ci-runtime.constraints"' in commands
        assert "-r requirements-test.lock -r requirements-lint.lock" in commands
        assert "verify requirements-test.lock requirements-lint.lock docker/requirements-test-cp314.lock" in commands
        assert "ci-tooling.in" not in commands
        assert "pip install -e" not in commands
        assert "--junitxml=" in commands
        assert any(step.get("with", {}).get("python-version") == "3.13" for step in steps)
    assert any("case.find('skipped')" in step.get("run", "") for step in jobs["test-postgres"]["steps"])
    postgres = {step.get("name"): step for step in jobs["test-postgres"]["steps"]}
    command = postgres["PostgreSQL parity tests"]["run"]
    gate = postgres["Refuse silently skipped PostgreSQL tests"]["run"]
    for suite in ("test_postgres_parity", "test_postgres_release_contract"):
        assert f"tests/{suite}.py" in command
        assert suite in gate
    assert "PostgreSQL suite missing" in gate


def test_builds_request_sbom_and_provenance():
    builds = [step for step in workflow()["jobs"]["build"]["steps"]
              if step.get("uses", "").startswith("docker/build-push-action@")]
    assert len(builds) == 2
    assert all(step["with"]["sbom"] is True and step["with"]["provenance"] == "mode=max" for step in builds)
    assert all(step["uses"] == "docker/build-push-action@2cdde995de11925a030ce8070c3d77a52ffcf1c0" for step in builds)


@pytest.mark.parametrize("evidence", ["complete", "missing_contract", "skipped_contract", "missing_legacy", "empty"])
def test_postgres_gate_requires_both_executed_suites(tmp_path, monkeypatch, evidence):
    from xml.etree import ElementTree

    root = ElementTree.Element("testsuite")
    if evidence != "empty":
        for suite in ("test_postgres_parity", "test_postgres_release_contract"):
            if evidence == "missing_contract" and suite.endswith("release_contract"):
                continue
            if evidence == "missing_legacy" and suite.endswith("parity"):
                continue
            case = ElementTree.SubElement(root, "testcase", classname=f"tests.{suite}")
            if evidence == "skipped_contract" and suite.endswith("release_contract"):
                ElementTree.SubElement(case, "skipped")
    ElementTree.ElementTree(root).write(tmp_path / "postgres-results.xml")
    step = next(step for step in workflow()["jobs"]["test-postgres"]["steps"]
                if step.get("name") == "Refuse silently skipped PostgreSQL tests")
    source = step["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    monkeypatch.chdir(tmp_path)
    if evidence == "complete":
        exec(compile(source, "postgres-skip-gate", "exec"), {})  # noqa: S102
    else:
        with pytest.raises(AssertionError, match="PostgreSQL suite"):
            exec(compile(source, "postgres-skip-gate", "exec"), {})  # noqa: S102


def test_every_action_uses_full_sha_and_no_mutable_latest():
    import re
    for job in workflow()["jobs"].values():
        for step in job["steps"]:
            if "uses" in step:
                assert re.fullmatch(r"[\w/-]+@[0-9a-f]{40}", step["uses"])
            assert ":latest" not in step.get("with", {}).get("tags", "")


def test_production_order_and_fail_closed_gates():
    jobs = workflow()["jobs"]
    assert jobs["build"]["needs"] == ["test", "test-postgres", "test-runtime-locks"]
    assert jobs["deploy-production"]["needs"] == "build"
    for name in ("build", "deploy-production", "deploy-staging"):
        assert "github.event_name == 'push'" in jobs[name]["if"]
    production = jobs["deploy-production"]
    assert production["environment"] == "production"
    assert production["permissions"] == {"contents": "read", "packages": "read"}
    steps = production["steps"]
    names = [step.get("name") for step in steps]
    order = ["Validate immutable build outputs", "Install checksum-verified Trivy",
             "Scan exact production digests before signing", "Sign scanned release with protected production key",
             "Verify signature and scans before cluster credentials", "Preserve signed release evidence",
             "Configure kubeconfig", "Deploy with Helm"]
    assert [names.index(name) for name in order] == sorted(names.index(name) for name in order)
    for name in order:
        step = steps[names.index(name)]
        assert not step.get("continue-on-error")
        assert "if" not in step
    scan = steps[names.index(order[2])]["run"]
    assert "'--exit-code', '1'" in scan
    assert "'--image-src', 'remote'" in scan
    assert "'--severity', 'UNKNOWN,HIGH,CRITICAL'" in scan
    assert "'--ignore-unfixed=false'" in scan
    assert "for role in ('proxy', 'admin')" in scan
    assert "os.environ[f'{role.upper()}_IMAGE']" in scan
    install = steps[names.index(order[1])]["run"]
    assert install.index("sha256sum --check --strict") < install.index("tar -xzf")
    assert "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a" in install


def test_only_verified_build_digests_reach_production_helm():
    jobs = workflow()["jobs"]
    for role in ("proxy", "admin"):
        assert jobs["build"]["outputs"][f"{role}-digest"] == f"${{{{ steps.{role}.outputs.digest }}}}"
    steps = {step.get("name"): step for step in jobs["deploy-production"]["steps"]}
    verify = steps["Verify signature and scans before cluster credentials"]["run"]
    assert '--expected-revision "$GITHUB_SHA"' in verify
    assert '--expected-proxy-image "$PROXY_IMAGE"' in verify
    assert '--expected-admin-image "$ADMIN_IMAGE"' in verify
    assert '--helm-values "$RUNNER_TEMP/verified-images.json"' in verify
    deploy = steps["Deploy with Helm"]["run"]
    assert deploy.index('"$RUNNER_TEMP/values-prod.yaml" \\') < deploy.index('"$RUNNER_TEMP/verified-images.json"')
    assert "image.tag" not in deploy and "--set" not in deploy
    assert "--atomic" in deploy


def test_staging_pins_build_digests_instead_of_mutable_tags():
    step = next(step for step in workflow()["jobs"]["deploy-staging"]["steps"] if step.get("name") == "Deploy with Helm")
    for role in ("proxy", "admin"):
        assert step["env"][f"{role.upper()}_DIGEST"] == f"${{{{ needs.build.outputs.{role}-digest }}}}"
        assert f'--set-string {role}.image.digest="${role.upper()}_DIGEST"' in step["run"]
        assert f"--set-string {role}.image.repository=" in step["run"]
    assert "image.tag" not in step["run"] and "--atomic" in step["run"]


def test_signing_secrets_scoped_and_not_uploaded():
    steps = workflow()["jobs"]["deploy-production"]["steps"]
    private_steps = [step for step in steps if "secrets.BULWARK_RELEASE_SIGNING_KEY" in str(step)]
    assert len(private_steps) == 1
    signing = private_steps[0]["run"]
    assert "TemporaryDirectory" in signing and "0o600" in signing
    assert "os.environ.pop('RELEASE_SIGNING_KEY')" in signing
    assert "BULWARK_RELEASE_SIGNING_KEY_FILE" in signing
    assert "check=True" in signing and "timeout=60" in signing
    upload = next(step for step in steps if step.get("name") == "Preserve signed release evidence")
    assert "*" not in upload["with"]["path"]
    assert "key" not in upload["with"]["path"]
    assert "pub" not in upload["with"]["path"]
    assert upload["with"]["if-no-files-found"] == "error"
    for step in steps:
        assert "${{ secrets." not in step.get("run", "")


def test_ci_publishes_coverage_and_refuses_skipped_release_tests():
    steps = workflow()["jobs"]["test"]["steps"]
    unit = next(step for step in steps if step.get("name") == "Unit tests")["run"]
    assert "trace.Trace(count=True" in unit
    assert "raise SystemExit(status)" in unit
    gate = next(step for step in steps if step.get("name") == "Require executed release security tests")["run"]
    assert "case.find('skipped')" in gate
    for suite in ("test_release_verification", "test_release_signing", "test_delivery_workflow", "test_packaging_locks", "test_documentation_publication", "test_release_sbom_schema", "test_release_scan_policy", "test_anyio_tls_idna", "test_ci_tool_locks"):
        assert suite in gate
    upload = next(step for step in steps if step.get("name") == "Upload test evidence including skips")
    assert "coverage.json" in upload["with"]["path"]
    assert upload["if"] == "always()"


def test_stdlib_coverage_report_counts_unexecuted_files(tmp_path):
    # Execute only the checked-in pure report function, not CI's pytest invocation.
    import ast
    import dis
    import types
    unit = next(step for step in workflow()["jobs"]["test"]["steps"] if step.get("name") == "Unit tests")["run"]
    tree = ast.parse(unit.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0])
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "coverage_report")
    namespace = {"dis": dis, "types": types}
    exec(compile(ast.Module(body=[function], type_ignores=[]), "coverage-report", "exec"), namespace)  # noqa: S102
    directory = tmp_path / "src"
    directory.mkdir()
    path = directory / "covered.py"
    path.write_text("def example():\n    return 1\nexample()\n")
    missed = directory / "missed.py"
    missed.write_text("value = 1\n")
    report = namespace["coverage_report"](tmp_path, {(str(path), 1): 1, (str(path), 3): 1})
    assert report["files"]["src/missed.py"]["covered"] == 0
    assert report["files"]["src/covered.py"]["missing"] == [2]
    assert report["covered"] == 2 and report["executable"] == 4
    assert report["percent"] == 50.0
    assert report["branch_coverage"] is False
    with pytest.raises(RuntimeError, match="Missing coverage evidence"):
        namespace["coverage_report"](tmp_path, {})


def test_workflow_shell_and_embedded_python_syntax():
    import ast
    import re
    import subprocess
    for job in workflow()["jobs"].values():
        for step in job["steps"]:
            if "run" not in step:
                continue
            command = step["run"]
            subprocess.run(["bash", "-n"], input=command, text=True, check=True, timeout=5)  # noqa: S603, S607
            for python in re.findall(r"<<'PY'\n(.*?)\nPY(?:\n|$)", command, re.DOTALL):
                ast.parse(python)


@pytest.mark.parametrize("failure", [None, "proxy", "admin", "timeout", "convert", "stale_db", "missing_db"])
def test_production_scan_isolates_policy_and_propagates_failure(tmp_path, monkeypatch, failure):
    import json
    import os
    import subprocess
    from datetime import datetime, timedelta, timezone

    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))

    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / ".trivyignore").write_text("CVE-2026-1234\n")
    (checkout / ".trivyignore.yaml").write_text("vulnerabilities:\n  - id: CVE-2026-1234\n")
    (checkout / "trivy.yaml").write_text("exit-code: 0\nseverity: [LOW]\nignore-unfixed: true\n")
    runner = tmp_path / "runner"
    runner.mkdir()
    monkeypatch.chdir(checkout)
    poison = {
        "TRIVY_CONFIG": str(checkout / "trivy.yaml"),
        "TRIVY_IGNOREFILE": str(checkout / ".trivyignore"),
        "TRIVY_IGNORE_UNFIXED": "true", "TRIVY_IGNORE_STATUS": "affected,will_not_fix",
        "TRIVY_IGNORE_POLICY": "suppress.rego", "TRIVY_SEVERITY": "LOW",
        "TRIVY_EXIT_CODE": "0", "TRIVY_SCANNERS": "secret",
        "TRIVY_SECURITY_CHECKS": "config", "TRIVY_SKIP_FILES": "**/*",
        "TRIVY_SKIP_DIRS": "**", "TRIVY_VULN_TYPE": "library",
        "TRIVY_SKIP_DB_UPDATE": "true", "TRIVY_DB_REPOSITORY": "untrusted.invalid/db",
        "TRIVY_INSECURE": "true", "TRIVY_SERVER": "https://untrusted.invalid",
        "TRIVY_PLUGIN_DIR": str(checkout), "TRIVY_FUTURE_POLICY_OVERRIDE": "true",
        "HOME": str(checkout), "XDG_CONFIG_HOME": str(checkout),
        "DOCKER_CONFIG": str(checkout), "SSL_CERT_FILE": str(checkout / "untrusted.pem"),
        "HTTPS_PROXY": "https://untrusted.invalid", "UNRELATED_SECRET": "must-not-inherit",
    }
    for name, value in poison.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("RUNNER_TEMP", str(runner))
    monkeypatch.setenv("TRIVY_USERNAME", "fixture-user")
    monkeypatch.setenv("TRIVY_PASSWORD", "fixture-registry-secret")
    for role, digest in (("PROXY", "a"), ("ADMIN", "b")):
        monkeypatch.setenv(f"{role}_IMAGE", f"ghcr.io/example/{role.lower()}@sha256:{digest * 64}")

    calls = []
    directories = []

    def run(args, *, cwd, env, check, timeout):
        # Exercise the actual embedded launcher, replacing only the scanner boundary.
        role = ("proxy", "admin")[len(calls) // 2]
        if args[1] == "convert":
            calls.append(role + "-sbom")
            assert args[-1] == str(runner / "release-scans" / f"{role}-scan.json")
            assert args[args.index("--format") + 1] == "cyclonedx"
            assert args[args.index("--output") + 1] == str(runner / "release-scans" / f"{role}.cdx.json")
            assert env == {"PATH": "/usr/bin:/bin", "HOME": str(cwd), "TMPDIR": str(cwd)}
            assert check is True and timeout == 60
            if failure == "convert":
                raise subprocess.CalledProcessError(1, args)
            return subprocess.CompletedProcess(args, 0)
        calls.append(role)
        directories.append(cwd)
        assert cwd.is_dir() and cwd.parent == runner and cwd != checkout
        assert not (cwd / ".trivyignore").exists()
        assert not (cwd / ".trivyignore.yaml").exists()
        assert set(env) == {"PATH", "HOME", "TMPDIR", "TRIVY_USERNAME", "TRIVY_PASSWORD"}
        assert env == {"PATH": "/usr/bin:/bin", "HOME": str(cwd), "TMPDIR": str(cwd),
                       "TRIVY_USERNAME": "fixture-user", "TRIVY_PASSWORD": "fixture-registry-secret"}
        assert args[:2] == [str(runner / "trivy-bin/trivy"), "image"]
        assert args[-1] == os.environ[f"{role.upper()}_IMAGE"]
        config = Path(args[args.index("--config") + 1])
        ignore = Path(args[args.index("--ignorefile") + 1])
        assert config.parent == cwd and yaml.safe_load(config.read_text()) == {}
        assert ignore.parent == cwd and ignore.read_bytes() == b""
        for flag, value in (("--cache-dir", str(cwd / "cache")), ("--image-src", "remote"),
                            ("--scanners", "vuln"), ("--ignore-status", ""), ("--exit-code", "1"),
                            ("--severity", "UNKNOWN,HIGH,CRITICAL"), ("--format", "json"),
                            ("--timeout", "10m"), ("--output", str(runner / "release-scans" / f"{role}-scan.json"))):
            assert args[args.index(flag) + 1] == value
        assert "--ignore-unfixed=false" in args
        assert "--list-all-pkgs" in args
        assert "fixture-registry-secret" not in str(args)
        assert check is True and timeout == 660
        if failure == "timeout":
            raise subprocess.TimeoutExpired(args, timeout)
        if failure == role:
            raise subprocess.CalledProcessError(1, args)
        if failure != "missing_db":
            metadata = cwd / "cache/db/metadata.json"
            metadata.parent.mkdir(parents=True, exist_ok=True)
            now = datetime.now(timezone.utc)
            updated = now - timedelta(days=2) if failure == "stale_db" else now
            metadata.write_text(json.dumps({"Version": 2, "UpdatedAt": updated.isoformat(),
                                           "DownloadedAt": now.isoformat(),
                                           "NextUpdate": (updated + timedelta(hours=24)).isoformat()}))
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(subprocess, "run", run)
    step = next(step for step in workflow()["jobs"]["deploy-production"]["steps"]
                if step.get("name") == "Scan exact production digests before signing")
    assert step["run"].startswith("python -I - <<'PY'\n")
    source = step["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    code = compile(source, "production-scan-step", "exec")
    if failure:
        with pytest.raises((subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError, FileNotFoundError)):
            exec(code, {})  # noqa: S102
    else:
        exec(code, {})  # noqa: S102
    expected = ["proxy", "proxy-sbom", "admin", "admin-sbom"]
    if failure in ("proxy", "timeout", "stale_db", "missing_db"):
        expected = expected[:1]
    elif failure == "convert":
        expected = expected[:2]
    elif failure == "admin":
        expected = expected[:3]
    assert calls == expected
    assert directories and all(not directory.exists() for directory in directories)


def test_both_cyclonedx_artifacts_are_preserved():
    step = next(s for s in workflow()["jobs"]["deploy-production"]["steps"]
                if s.get("name") == "Preserve signed release evidence")
    for role in ("proxy", "admin"):
        assert f"release-scans/{role}.cdx.json" in step["with"]["path"]
        assert f"release-scans/{role}-database.json" in step["with"]["path"]
