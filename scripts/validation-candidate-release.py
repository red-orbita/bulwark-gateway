"""Sequential local candidate scans and offline SBOM validation, never approval.

Requires cached immutable images and an already refreshed Trivy database. Exports
only specified images. Does not sign, publish or alter existing services.
"""

import argparse
import hashlib
import importlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from release_scan_policy import validate_database_metadata
from validation_safety import validation_slot

ROOT = Path(__file__).resolve().parents[1]
SCANNER = "aquasec/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admin", required=True)
    parser.add_argument("--proxy", required=True)
    parser.add_argument("--cache", required=True, type=Path)
    args = parser.parse_args()
    images = {"admin": args.admin, "proxy": args.proxy}
    if any(not re.fullmatch(r"sha256:[0-9a-f]{64}", image) for image in images.values()):
        parser.error("Use immutable cached image IDs")
    cache = args.cache.resolve(strict=True)
    if not cache.is_relative_to(ROOT / "shared") or "," in str(cache):
        parser.error("Use the private workspace Trivy cache")
    verifier = importlib.import_module("verify-release")
    with validation_slot(ROOT):
        metadata = json.loads(verifier.read_regular(cache / "db/metadata.json", 8192))
        validate_database_metadata(metadata)
        directory = Path(tempfile.mkdtemp(prefix="candidate-release-", dir=ROOT / "shared"))
        report = {"production_approved": False, "registry_digest_pull": False, "images": {},
                  "database": metadata, "database_freshness_checked": True}
        try:
            for role, image in images.items():
                archive = directory / f"{role}.tar"
                subprocess.run(["docker", "image", "save", "--output", str(archive), image],  # noqa: S603,S607
                               check=True, timeout=90)
                base = ["docker", "run", "--rm", "--pull=never", "--network=none", "--read-only",
                         f"--user={os.getuid()}:{os.getgid()}", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                        "--memory=1g", "--memory-swap=1g", "--cpus=1", "--pids-limit=64",
                        "--tmpfs=/tmp:rw,noexec,nosuid,size=128m", "--workdir=/tmp",
                        "--mount", f"type=bind,src={directory},dst=/evidence",
                        "--mount", f"type=bind,src={cache},dst=/cache", SCANNER]
                subprocess.run(base + ["image", "--input", f"/evidence/{role}.tar", "--cache-dir", "/cache",  # noqa: S603
                               "--scanners", "vuln", "--format", "json", "--list-all-pkgs",
                               "--output", f"/evidence/{role}-scan.json", "--offline-scan", "--skip-db-update",
                               "--skip-java-db-update", "--no-progress", "--ignore-unfixed=false",
                               "--severity", "UNKNOWN,HIGH,CRITICAL", "--exit-code", "1", "--timeout=2m"],
                               check=True, timeout=150)  # noqa: S603
                subprocess.run(base + ["convert", "--format", "cyclonedx", "--output",  # noqa: S603
                               f"/evidence/{role}.cdx.json", f"/evidence/{role}-scan.json"],
                               check=True, timeout=30)  # noqa: S603
                scan = verifier.read_regular(directory / f"{role}-scan.json", verifier.MAX_REPORT_BYTES)
                sbom = verifier.read_regular(directory / f"{role}.cdx.json", verifier.MAX_REPORT_BYTES)
                name = f"/evidence/{role}.tar"
                verifier.validate_scan(scan, name)
                verifier.validate_sbom(sbom, name, scan)
                after = json.loads(verifier.read_regular(cache / "db/metadata.json", 8192))
                validate_database_metadata(after)
                if after != metadata:
                    raise ValueError("Vulnerability database changed during validation")
                verifier.validate_scan_freshness(json.loads(scan), metadata, current=True)
                (directory / f"{role}-database.json").write_text(json.dumps(metadata) + "\n")
                report["images"][role] = {"id": image, "scan_passed": True, "sbom_passed": True,
                    "scan_sha256": hashlib.sha256(scan).hexdigest(), "sbom_sha256": hashlib.sha256(sbom).hexdigest()}
        finally:
            (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            print(str(directory.relative_to(ROOT) / "report.json"))


if __name__ == "__main__":
    main()
