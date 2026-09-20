"""Install and verify the exact CI composition in a new isolated local venv.

No modification of developer/runtime environments. Downloads hash-approved wheels
only. Retains the owned validation directory for evidence; no services started.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from validation_safety import validation_slot

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from packaging_locks import ci_entries  # noqa: E402


def main() -> None:
    with validation_slot(ROOT):
        directory = Path(tempfile.mkdtemp(prefix="ci-tools-", dir=ROOT / "shared"))
        runtime = directory / "runtime.lock"
        runtime.write_text("\n".join(ci_entries().values()) + "\n")
        subprocess.run([sys.executable, "-m", "venv", str(directory / "venv")], check=True, timeout=60)  # noqa: S603
        python = str(directory / "venv/bin/python")
        locks = [str(runtime), str(ROOT / "requirements-test.lock"), str(ROOT / "requirements-lint.lock"),
                 str(ROOT / "docker/requirements-test-cp314.lock")]
        subprocess.run([python, "-m", "pip", "install", "--only-binary=:all:", "--require-hashes",  # noqa: S603
                        *[arg for lock in locks for arg in ("-r", lock)]], check=True, timeout=180)  # noqa: S603
        subprocess.run([python, "-m", "pip", "check"], check=True, timeout=30)  # noqa: S603
        subprocess.run([python, str(ROOT / "tests/packaging_locks.py"), "verify", *locks],  # noqa: S603
                       check=True, timeout=30)  # noqa: S603
        (directory / "report.json").write_text(json.dumps({"installed_and_verified": True,
            "runtime_composition": "admin-plus-schema", "python": sys.version.split()[0],
            "remote_ci_executed": False}) + "\n")
        print(str(directory.relative_to(ROOT) / "report.json"))


if __name__ == "__main__":
    main()
