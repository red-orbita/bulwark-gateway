"""Offline packaging checks and deterministic CI lock composition (stdlib only).

CI uses admin versions for shared packages, plus the proxy's JSON-schema closure.
This is an explicit test environment, NOT evidence of proxy runtime parity.
The separate clean runtime matrix verifies each shipped lock without test extras.
"""

import argparse
import importlib.metadata
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CI_PROXY_PACKAGES = {"attrs", "jsonschema", "jsonschema-specifications", "referencing", "rpds-py"}


def lock_entries(text: str) -> dict[str, str]:
    entries = {}
    for line in text.replace("\\\n", " ").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([\w.-]+)(?:\[[\w,.-]+\])?==([\w.]+)((?:\s+--hash=sha256:[a-f0-9]{64})+)", line)
        if not match:
            raise ValueError("Expected an exact version and SHA-256 hashes")
        name = re.sub(r"[-_.]+", "-", match[1]).lower()
        if name in entries:
            raise ValueError(f"Duplicate locked package: {name}")
        entries[name] = line
    return entries


def ci_entries() -> dict[str, str]:
    admin = lock_entries((ROOT / "requirements-admin.lock").read_text())
    proxy = lock_entries((ROOT / "requirements.lock").read_text())
    if CI_PROXY_PACKAGES & admin.keys():
        raise ValueError("Review CI composition: proxy supplement overlaps admin lock")
    return admin | {name: proxy[name] for name in sorted(CI_PROXY_PACKAGES)}


def verify_installed(entries: dict[str, str]) -> None:
    for name, entry in entries.items():
        expected = entry.split("==", 1)[1].split()[0]
        if importlib.metadata.version(name) != expected:
            raise ValueError(f"Installed version differs from lock: {name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("ci", "constraints", "verify", "tooling"))
    parser.add_argument("locks", nargs="*")
    args = parser.parse_args()
    if args.mode == "tooling":
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())
        print("\n".join(project["project"]["optional-dependencies"]["dev"]))
        return
    entries = {}
    for filename in args.locks:
        for name, entry in lock_entries(Path(filename).read_text()).items():
            if name in entries and entries[name] != entry:
                raise ValueError(f"Conflicting locks: {name}")
            entries[name] = entry
    if not args.locks:
        entries = ci_entries()
    if args.mode == "verify":
        verify_installed(entries)
        print(f"Verified {len(entries)} installed locked versions")
    else:
        for name in sorted(entries):
            entry = entries[name]
            if args.mode == "constraints":
                # pip constraints cannot carry extras or trigger hash mode for tooling.
                entry = name + "==" + entry.split("==", 1)[1].split()[0]
            print(entry)


if __name__ == "__main__":
    main()
