#!/usr/bin/env python3
"""Explicit maintainer-only retrieval of pinned inert schemas, never run by verification."""

import hashlib
import subprocess
from pathlib import Path

from release_sbom_schema import SCHEMA_FILES, SCHEMA_REVISION


def main() -> None:
    destination = Path(__file__).parent / "schemas/cyclonedx"
    # Check every download before changing the local bundle. No executable assets.
    payloads = {}
    for name, digest in SCHEMA_FILES.items():
        source = name if name == "LICENSE" else f"schema/{name}"
        response = subprocess.run(  # noqa: S603
            ["gh", "api",  # noqa: S607
             f"repos/CycloneDX/specification/contents/{source}?ref={SCHEMA_REVISION}",
             "-H", "Accept: application/vnd.github.raw+json"],
            capture_output=True, check=True, timeout=30,
        )
        if len(response.stdout) > 512 * 1024 or hashlib.sha256(response.stdout).hexdigest() != digest:
            raise ValueError("Pinned schema download mismatch")
        payloads[name] = response.stdout
    destination.mkdir(parents=True, exist_ok=True)
    for name, raw in payloads.items():
        path = destination / name
        # Do not follow existing links or silently overwrite edited resources.
        with path.open("xb") as stream:
            stream.write(raw)
    print("Verified CycloneDX schema bundle provisioned")


if __name__ == "__main__":
    main()
