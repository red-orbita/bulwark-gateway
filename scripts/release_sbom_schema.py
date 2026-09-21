"""Offline CycloneDX Draft-07 validation in a bounded, separate process.

Vendored schemas are data, never executable. The caller's document cannot select
a schema or trigger network retrieval. Format keywords retain Draft-07 annotation
semantics; no optional format plugins are silently depended upon.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import resource
import stat
import subprocess
import sys
from pathlib import Path

SCHEMA_REVISION = "b29bae660048e0ad2fbc5f2972927b442ce951c4"
SCHEMA_FILES = {
    "bom-1.7.schema.json": "73308edec3ab2d38bfffd993e96a042b594314143b6971a6e9ed98bbb6bd76ce",
    "cryptography-defs.schema.json": "027b059a729a06d591bac79a584ef04f83fc32d91a826fdba6ad3c98a10e5b44",
    "jsf-0.82.schema.json": "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae",
    "spdx.schema.json": "ea6e844ee6fba1e93473d94834d0ee0996970533497935f932f73d488ffdf4a3",
    "LICENSE": "6c29f22a4a7385285c6f579ec9f33c5e989f00739d6b257243a0b082ec9447ae",
}
SCHEMA_DIR = Path(__file__).parent / "schemas/cyclonedx"
MAX_BYTES = 16 * 1024**2
MAX_NODES = 200000
MAX_DEPTH = 64


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def validate_document(raw: bytes) -> None:
    """Worker-only validation. Parent enforces process resources and wall time."""
    from jsonschema import Draft7Validator
    from referencing import Registry, Resource
    from referencing.exceptions import NoSuchResource

    if len(raw) > MAX_BYTES:
        raise ValueError("SBOM exceeds budget")
    document = json.loads(raw, object_pairs_hook=_unique)
    pending = [(document, 0)]
    visited = 0
    while pending:
        value, depth = pending.pop()
        visited += 1
        if visited > MAX_NODES or depth > MAX_DEPTH:
            raise ValueError("SBOM structural budget exceeded")
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("Non-finite JSON number")
        children = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
        if len(pending) + len(children) + visited > MAX_NODES:
            raise ValueError("SBOM structural budget exceeded")
        pending.extend((child, depth + 1) for child in children)

    def refuse_retrieval(uri):
        raise NoSuchResource(ref=uri)

    registry = Registry(retrieve=refuse_retrieval)
    schemas = {}
    for name, expected in SCHEMA_FILES.items():
        fd = os.open(SCHEMA_DIR / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 512 * 1024:
                raise ValueError("Invalid schema bundle resource")
            data = stream.read(512 * 1024 + 1)
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("Schema bundle integrity mismatch")
        if name == "LICENSE":
            continue
        schema = json.loads(data, object_pairs_hook=_unique)
        Draft7Validator.check_schema(schema)
        schemas[name] = schema
        entry = Resource.from_contents(schema)
        # Relative references resolve against the official HTTP $id, without I/O.
        registry = registry.with_resource(f"http://cyclonedx.org/schema/{name}", entry)
        registry = registry.with_resource(f"https://cyclonedx.org/schema/{name}", entry)
    validator = Draft7Validator(schemas["bom-1.7.schema.json"], registry=registry)
    if next(validator.iter_errors(document), None) is not None:
        raise ValueError("SBOM does not conform to CycloneDX schema")


def validate_schema(raw: bytes) -> None:
    """Fail closed on invalid data, missing resources/dependencies or worker failure."""
    if len(raw) > MAX_BYTES:
        raise ValueError("SBOM exceeds budget")
    try:
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-I", str(Path(__file__).resolve())], input=raw,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin"}, timeout=15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("Offline SBOM schema validation failed") from None
    if result.returncode:
        raise ValueError("Offline SBOM schema validation failed")


def main() -> int:
    try:
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2))
        resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        validate_document(sys.stdin.buffer.read(MAX_BYTES + 1))
    except Exception:
        # Never include validation paths, instance values or schema diagnostics.
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
