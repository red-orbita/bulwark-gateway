#!/usr/bin/env python3
"""Probe cached immutable runtime candidates without touching running services.

Evidence only: absence of known binaries is not a VEX authorization. No pulls,
volumes, credentials, network, application startup or vulnerability suppressions.
"""

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

from validation_safety import validation_slot

PROBE = r'''
import hashlib, importlib.util, json, os, pathlib, sys
import pyexpat, sqlite3, ssl
paths = ["/bin/sh", "/usr/bin/sh", "/bin/mount", "/usr/bin/mount",
         "/usr/bin/nsenter", "/bin/nsenter", "/usr/bin/infocmp", "/bin/infocmp"]
libraries = []
for directory in ("/lib", "/usr/lib", "/usr/local/lib"):
    root = pathlib.Path(directory)
    if root.exists():
        for pattern in ("libmount.so*", "libuuid.so*", "liblzma.so*", "libexpat.so*"):
            for path in root.rglob(pattern):
                if path.is_file():
                    libraries.append({"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
modules = {}
for name in ("tarfile", "html.parser", "_lzma", "pyexpat", "_elementtree", "_uuid"):
    spec = importlib.util.find_spec(name)
    path = pathlib.Path(spec.origin) if spec and spec.origin else None
    modules[name] = {"present": spec is not None,
                     "sha256": hashlib.sha256(path.read_bytes()).hexdigest() if path and path.is_file() else None}
print(json.dumps({"python": sys.version.split()[0], "executable": sys.executable,
                  "expat": pyexpat.EXPAT_VERSION, "sqlite": sqlite3.sqlite_version,
                  "openssl": ssl.OPENSSL_VERSION, "uid": os.getuid(),
                  "paths": {p: pathlib.Path(p).exists() for p in paths},
                  "libraries": libraries, "modules": modules}, sort_keys=True))
'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", action="append", required=True)
    args = parser.parse_args()
    if not 1 <= len(args.image) <= 4 or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", i) for i in args.image):
        parser.error("Supply one to four cached immutable sha256 image IDs")
    root = Path(__file__).resolve().parents[1]
    with validation_slot(root):
        directory = Path(tempfile.mkdtemp(prefix="runtime-cve-probe-", dir=root / "shared"))
        report = {"scope": "cached-runtime-probe", "vex_authorized": False,
                  "probe_sha256": hashlib.sha256(PROBE.encode()).hexdigest(), "images": []}
        for image in args.image:
            result = subprocess.run(  # noqa: S603
                ["docker", "run", "--rm", "--pull=never", "--network=none", "--read-only",  # noqa: S607
                 "--user=65532:65532", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                 "--memory=256m", "--memory-swap=256m", "--cpus=1", "--pids-limit=32",
                 "--entrypoint=python3", image, "-I", "-B", "-c", PROBE],
                capture_output=True, timeout=45, check=True,
            )
            if len(result.stdout) > 128 * 1024:
                raise ValueError("Unexpected probe output size")
            report["images"].append({"image": image, "runtime": json.loads(result.stdout)})
        (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"report": str(directory.relative_to(root) / "report.json"), **report}, sort_keys=True))


if __name__ == "__main__":
    main()
