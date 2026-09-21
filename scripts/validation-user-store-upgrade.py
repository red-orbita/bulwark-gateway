"""Cross-runtime SQLCipher compatibility on owned synthetic data, not user volumes."""

import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import tempfile
from pathlib import Path

from validation_safety import validation_slot

ROOT = Path(__file__).resolve().parents[1]
PROGRAM = '''
import os, pathlib, sys
from admin.services.user_store import UserStore
root = pathlib.Path('/state')
password = (root / 'password').read_text()
updated = (root / 'updated').read_text()
store = UserStore('/state/users.db')
store.initialize()
phase = sys.argv[1]
if phase == 'seed':
    store.create_user('migration-user', password, 'viewer', tenant_scope='migration-tenant')
else:
    user = store.verify_password('migration-user', updated if phase == 'rollback-read' else password)
    if not user or user['tenant_scope'] != 'migration-tenant':
        raise RuntimeError('compatibility check failed')
    if phase == 'upgrade-write':
        if not store.change_password(user['id'], updated):
            raise RuntimeError('password update failed')
print('verified:' + phase)
'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous", required=True)
    parser.add_argument("--candidate", required=True)
    args = parser.parse_args()
    if any(not re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in (args.previous, args.candidate)):
        parser.error("Require immutable cached image IDs")
    with validation_slot(ROOT):
        directory = Path(tempfile.mkdtemp(prefix="user-store-upgrade-", dir=ROOT / "shared"))
        state = directory / "state"
        state.mkdir(mode=0o700)
        for name in ("key", "jwt", "admin", "security", "auditor", "password", "updated"):
            with (state / name).open("x") as stream:
                os.chmod(state / name, 0o600)
                stream.write("Password!" + secrets.token_hex(20) if name in ("password", "updated")
                             else secrets.token_hex(32))
        report = {"previous": args.previous, "candidate": args.candidate, "checks": [],
                  "production_approved": False, "scope": "synthetic SQLCipher UserStore only",
                  "probe_sha256": hashlib.sha256(PROGRAM.encode()).hexdigest()}
        try:
            for phase, image in (("seed", args.previous), ("upgrade-write", args.candidate),
                                 ("rollback-read", args.previous)):
                command = ["docker", "run", "--rm", "--pull=never", "--network=none", "--read-only",
                           f"--user={os.getuid()}:{os.getgid()}", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                           "--memory=256m", "--memory-swap=256m", "--cpus=1", "--pids-limit=32",
                           "--mount", f"type=bind,src={state},dst=/state", "--workdir=/state",
                           "--env", "PYTHONPATH=/app:/opt/packages:/opt/venv/lib/python3.13/site-packages",
                           "--env", "PYTHONDONTWRITEBYTECODE=1", "--env", "DB_ENCRYPTION_KEY_FILE=/state/key",
                           "--env", "ADMIN_JWT_SECRET_FILE=/state/jwt", "--env", "ADMIN_PASSWORD_FILE=/state/admin",
                           "--env", "SECURITY_PASSWORD_FILE=/state/security",
                           "--env", "AUDITOR_PASSWORD_FILE=/state/auditor",
                           "--entrypoint=python3", image, "-c", PROGRAM, phase]
                result = subprocess.run(command, check=False, capture_output=True, timeout=45)  # noqa: S603
                if result.returncode or result.stdout.strip() != ("verified:" + phase).encode():
                    raise RuntimeError("user_store_upgrade_probe_failed")
                report["checks"].append(phase)
            with (state / "users.db").open("rb") as stream:
                if stream.read(16) == b"SQLite format 3\x00":
                    raise RuntimeError("unencrypted_database")
            report["encrypted_header"] = True
        finally:
            (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            print(str(directory.relative_to(ROOT) / "report.json"))


if __name__ == "__main__":
    main()
