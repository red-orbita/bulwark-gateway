"""Build-time checks in the actual release interpreter. No network or secrets."""

import importlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import re
import sys
from pathlib import Path


def verify_dependencies(packages: dict[str, str], extras: dict[str, set[str]]) -> None:
    # Trusted read-only build mount, absent from the final filesystem.
    sys.path.insert(0, "/verification")
    from packaging.markers import default_environment
    from packaging.requirements import Requirement
    from packaging.specifiers import SpecifierSet
    from packaging.utils import canonicalize_name

    environment = default_environment()
    # CPython vendor builds may report "3.14.7+", not a PEP440 version. Use the
    # interpreter's numeric release tuple for dependency markers/Requires-Python.
    environment["python_full_version"] = ".".join(str(part) for part in sys.version_info[:3])
    environment["python_version"] = ".".join(str(part) for part in sys.version_info[:2])
    pending = [(name, extra) for name in packages for extra in ({""} | extras.get(name, set()))]
    visited = set()
    while pending:
        name, extra = pending.pop()
        if (name, extra) in visited:
            continue
        visited.add((name, extra))
        if len(visited) > 10000 or len(pending) > 10000:
            raise ValueError("Dependency verification exceeds budget")
        distribution = importlib.metadata.distribution(name)
        python_requirement = distribution.metadata.get("Requires-Python")
        if python_requirement and environment["python_full_version"] not in SpecifierSet(python_requirement):
            raise ValueError("Dependency does not support target Python")
        for text in distribution.requires or []:
            requirement = Requirement(text)
            if requirement.marker and not requirement.marker.evaluate({**environment, "extra": extra}):
                continue
            dependency = canonicalize_name(requirement.name)
            if (requirement.url or dependency not in packages
                    or packages[dependency] not in requirement.specifier):
                raise ValueError("Target runtime dependency closure mismatch")
            pending.extend((dependency, requested) for requested in ({""} | requirement.extras))


def verify(role: str, directory: Path = Path("/usr/share/bulwark/locks")) -> dict:
    if role not in ("proxy", "admin"):
        raise ValueError("Unsupported role")
    if sys.version_info[:2] != (3, 14) or platform.machine() != "x86_64" or os.getuid() != 65532:
        raise ValueError("Unsupported release runtime")
    expected_files = {"requirements-admin.lock"} if role == "admin" else {"requirements.lock"}
    files = {p.name for p in directory.iterdir()}
    postgres = role == "proxy" and "requirements-postgres.lock" in files
    if postgres:
        expected_files.add("requirements-postgres.lock")
    if files != expected_files:
        raise ValueError("Runtime lock set mismatch")
    packages = {}
    extras = {}
    for name in sorted(files):
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 256 * 1024:
            raise ValueError("Invalid runtime lock")
        for line in path.read_text().replace("\\\n", " ").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.fullmatch(r"([\w.-]+)(?:\[([\w,.-]+)\])?==([\w.]+)(?:\s+--hash=sha256:[a-f0-9]{64})+", line)
            if match is None:
                raise ValueError("Unpinned runtime dependency")
            name, requested, version = match.groups()
            name = re.sub(r"[-_.]+", "-", name).lower()
            if name in packages or importlib.metadata.version(name) != version:
                raise ValueError("Installed runtime version mismatch")
            packages[name] = version
            extras[name] = set(requested.split(",")) if requested else set()
    verify_dependencies(packages, extras)
    modules = ["pydantic_core._pydantic_core", "yaml._yaml", "ssl", "sqlite3", "pyexpat"]
    if role == "admin":
        modules += ["sqlcipher3._sqlite3", "bcrypt._bcrypt", "cryptography.hazmat.bindings._rust",
                    "asyncpg.protocol.protocol"]
    else:
        if Path("/app/admin").exists() or importlib.util.find_spec("admin") is not None:
            raise ValueError("Admin source present in proxy")
        modules += ["uvloop.loop", "httptools.parser.parser", "rpds.rpds"]
        if postgres:
            modules.append("asyncpg.protocol.protocol")
        elif importlib.util.find_spec("asyncpg") is not None:
            raise ValueError("Unexpected PostgreSQL driver")
    for name in modules:
        importlib.import_module(name)
    for binary in ("/bin/sh", "/usr/bin/sh", "/bin/bash", "/usr/bin/bash", "/sbin/apk", "/usr/bin/apt"):
        if Path(binary).exists():
            raise ValueError("Unexpected shell or package manager executable")
    return {"role": role, "python": platform.python_version(), "locked_packages": len(packages),
            "native_imports": modules, "target_dependency_closure": True,
            "postgres": postgres or role == "admin", "production_approved": False}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Expected role")
    print(json.dumps(verify(sys.argv[1]), sort_keys=True))
