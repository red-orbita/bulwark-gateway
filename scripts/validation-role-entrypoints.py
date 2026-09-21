"""Run actual candidate entrypoints and healthchecks with owned temporary storage."""

import argparse
import json
import os
import re
import secrets
import subprocess
import tempfile
import time
from pathlib import Path

from validation_safety import validation_slot

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admin", required=True)
    parser.add_argument("--proxy", required=True)
    args = parser.parse_args()
    if any(not re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in (args.admin, args.proxy)):
        parser.error("Immutable cached image IDs required")
    with validation_slot(ROOT):
        directory = Path(tempfile.mkdtemp(prefix="role-entrypoints-", dir=ROOT / "shared"))
        report = {"images": {}, "production_approved": False}
        for role in ("admin", "proxy"):
            credentials = directory / role
            credentials.mkdir(mode=0o700)
            for key in ("ADMIN_JWT_SECRET", "BULWARK_JWT_SECRET", "ADMIN_PASSWORD", "SECURITY_PASSWORD",
                        "AUDITOR_PASSWORD", "DB_ENCRYPTION_KEY"):
                (credentials / key).write_text(secrets.token_hex(32))
                os.chmod(credentials / key, 0o600)
            name = "bulwark-role-probe-" + secrets.token_hex(6)
            image = getattr(args, role)
            command = ["docker", "run", "-d", "--pull=never", "--name", name, "--network=none", "--read-only",
                       f"--user={os.getuid()}:{os.getgid()}", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                       "--memory=512m", "--memory-swap=512m", "--cpus=1", "--pids-limit=64",
                       "--health-interval=2s", "--health-start-period=5s",
                       "--mount", f"type=bind,src={credentials},dst=/run/secrets,readonly"]
            for path in ("/tmp", "/app/data", "/app/shared", "/app/reports"):  # noqa: S108 - container tmpfs only
                command += ["--tmpfs", f"{path}:rw,nosuid,size=64m,uid={os.getuid()},gid={os.getgid()}"]
            for key in ("ADMIN_JWT_SECRET", "BULWARK_JWT_SECRET", "ADMIN_PASSWORD", "SECURITY_PASSWORD",
                        "AUDITOR_PASSWORD", "DB_ENCRYPTION_KEY"):
                command += ["--env", f"{key}_FILE=/run/secrets/{key}"]
            command += ["--env", "BULWARK_ENRICHMENT_ENABLED=false", "--env", "BULWARK_TELEMETRY_ENABLED=false",
                        "--env", "BULWARK_WORKERS=1",
                        "--env", "BULWARK_INTEGRATION_RECONCILE_POLL_ENABLED=false", image]
            created = False
            try:
                subprocess.run(command, check=True, capture_output=True, timeout=30)  # noqa: S603
                created = True
                deadline = time.monotonic() + 60
                while time.monotonic() < deadline:
                    state = json.loads(subprocess.run(  # noqa: S603
                        ["docker", "inspect", "--format", "{{json .State}}", name],  # noqa: S607
                        check=True, capture_output=True, timeout=10).stdout)
                    if not state["Running"]:
                        raise RuntimeError("candidate_entrypoint_exited")
                    if state.get("Health", {}).get("Status") == "healthy":
                        break
                    time.sleep(1)
                else:
                    raise RuntimeError("candidate_health_timeout")
                subprocess.run(["docker", "stop", "--timeout=10", name], check=True,  # noqa: S603,S607
                               capture_output=True, timeout=20)
                state = json.loads(subprocess.run(  # noqa: S603
                    ["docker", "inspect", "--format", "{{json .State}}", name],  # noqa: S607
                    check=True, capture_output=True, timeout=10).stdout)
                if state["ExitCode"] != 0 or state["OOMKilled"]:
                    raise RuntimeError("candidate_shutdown_failed")
                report["images"][role] = {"image": image, "healthcheck": "healthy", "shutdown_exit": 0}
            finally:
                if created:
                    subprocess.run(["docker", "rm", "-f", name], check=True, capture_output=True, timeout=20)  # noqa: S603,S607
                for path in credentials.iterdir():
                    path.unlink()
                (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(str(directory.relative_to(ROOT) / "report.json"))


if __name__ == "__main__":
    main()
