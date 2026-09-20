#!/usr/bin/env python3
"""Verify an operator-signed release manifest and local artifacts, offline.

Signature: Ed25519 over DOMAIN + exact manifest bytes. The public key must come
from an independent trusted channel, never from the package being verified.
No keys are generated, no artifacts are executed or deserialized, no network I/O.
Requires the existing operator/admin cryptography dependency, not the proxy image.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from release_sbom_schema import validate_schema
from release_scan_policy import validate_scan_freshness

DOMAIN = b"bulwark-release-manifest-v1\x00"
MAX_MANIFEST_BYTES = 128 * 1024
MAX_ARTIFACT_BYTES = 4 * 1024**3
MAX_TOTAL_BYTES = 16 * 1024**3
MAX_REPORT_BYTES = 16 * 1024**2
IMAGE_PATTERN = r"[a-z0-9]+(?:[._:-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+@sha256:[0-9a-f]{64}"


class Images(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    proxy: str = Field(max_length=512, pattern=rf"^{IMAGE_PATTERN}$")
    admin: str = Field(max_length=512, pattern=rf"^{IMAGE_PATTERN}$")


class Artifact(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int = Field(ge=0, le=MAX_ARTIFACT_BYTES)


class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: int = Field(ge=1, le=1)
    revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    artifacts: list[Artifact] = Field(min_length=1, max_length=128)
    # Existing offline artifact manifests remain usable; deployment requires images.
    images: Images | None = None

    @field_validator("artifacts")
    @classmethod
    def unique_bounded_artifacts(cls, artifacts: list[Artifact]) -> list[Artifact]:
        if len({item.name for item in artifacts}) != len(artifacts):
            raise ValueError("Duplicate artifact name")
        if sum(item.size for item in artifacts) > MAX_TOTAL_BYTES:
            raise ValueError("Release exceeds total verification budget")
        return artifacts


def read_regular(path: Path, limit: int, *, private: bool = False) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("Invalid verification input")
        if private and (info.st_mode & 0o077 or info.st_uid != os.getuid()):
            raise ValueError("Private key must be owner-only")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Verification input exceeded budget")
    return data


def unique_keys(pairs: list[tuple[str, object]]) -> dict:
    values = {}
    for key, value in pairs:
        if key in values:
            raise ValueError("Duplicate JSON key")
        values[key] = value
    return values


def validate_scan(raw: bytes, image: str) -> None:
    """Require a successful Trivy image report for this immutable build output."""
    report = json.loads(raw, object_pairs_hook=unique_keys)
    if (not isinstance(report, dict) or report.get("SchemaVersion") != 2
            or report.get("ArtifactName") != image or report.get("ArtifactType") != "container_image"
            or not isinstance(report.get("Results"), list) or not report["Results"]):
        raise ValueError("Missing or mismatched image scan")
    inspected_os = inspected_python = False
    for result in report["Results"]:
        if (not isinstance(result, dict) or result.get("Class") not in ("os-pkgs", "lang-pkgs")
                or not isinstance(result.get("Type"), str)):
            raise ValueError("Invalid image scan result")
        inspected_os |= result["Class"] == "os-pkgs"
        inspected_python |= result["Class"] == "lang-pkgs" and result["Type"] in ("python-pkg", "pip")
        vulnerabilities = result.get("Vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            raise ValueError("Invalid vulnerability results")
        for vulnerability in vulnerabilities:
            if (not isinstance(vulnerability, dict)
                    or vulnerability.get("Severity") not in ("LOW", "MEDIUM")):
                raise ValueError("Release contains high, critical or unclassified vulnerabilities")
    if not inspected_os or not inspected_python:
        raise ValueError("Release scan must include operating system and Python packages")


def validate_sbom(raw: bytes, image: str, scan_raw: bytes) -> None:
    """Check the official schema and the narrower Trivy 0.74 release profile.

    Package inventory and config identity must agree with the separately gated
    scan. This cannot prove scanner completeness or source-to-image provenance.
    """
    if max(len(raw), len(scan_raw)) > MAX_REPORT_BYTES:
        raise ValueError("Image evidence exceeds budget")
    validate_schema(raw)
    bom = json.loads(raw, object_pairs_hook=unique_keys)
    scan = json.loads(scan_raw, object_pairs_hook=unique_keys)
    if (not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX"
            or bom.get("specVersion") != "1.7" or type(bom.get("version")) is not int
            or bom["version"] < 1 or not isinstance(scan, dict)):
        raise ValueError("Invalid CycloneDX release profile")
    metadata = bom.get("metadata")
    root = metadata.get("component") if isinstance(metadata, dict) else None
    scan_metadata = scan.get("Metadata")
    if (not isinstance(root, dict) or root.get("type") != "container"
            or root.get("name") != image or scan.get("ArtifactName") != image
            or not isinstance(scan_metadata, dict)):
        raise ValueError("SBOM image identity mismatch")
    image_id = scan_metadata.get("ImageID")
    if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise ValueError("Missing scan config identity")
    properties = root.get("properties")
    if not isinstance(properties, list) or any(not isinstance(p, dict) for p in properties):
        raise ValueError("Invalid SBOM image properties")
    if [p.get("value") for p in properties if p.get("name") == "aquasecurity:trivy:ImageID"] != [image_id]:
        raise ValueError("SBOM config identity mismatch")
    components = bom.get("components")
    if not isinstance(components, list) or not 1 <= len(components) <= 20000:
        raise ValueError("Missing or excessive SBOM inventory")
    inventory = set()
    refs = set()
    for component in [root, *components]:
        if (not isinstance(component, dict) or not isinstance(component.get("name"), str)
                or not component["name"] or not isinstance(component.get("bom-ref"), str)
                or not component["bom-ref"] or component["bom-ref"] in refs):
            raise ValueError("Invalid or duplicate SBOM component")
        refs.add(component["bom-ref"])
        if component.get("type") == "library":
            purl = component.get("purl")
            if (not isinstance(purl, str) or not purl.startswith("pkg:")
                    or not isinstance(component.get("version"), str) or not component["version"]):
                raise ValueError("Unidentified SBOM package")
            inventory.add(purl)
    expected = set()
    os_inventory = set()
    python_inventory = set()
    results = scan.get("Results")
    if not isinstance(results, list):
        raise ValueError("Missing scan inventory")
    for result in results:
        packages = result.get("Packages") if isinstance(result, dict) else None
        if not isinstance(packages, list) or not packages:
            raise ValueError("Missing scan packages; enable list-all-pkgs")
        for package in packages:
            identifier = package.get("Identifier") if isinstance(package, dict) else None
            purl = identifier.get("PURL") if isinstance(identifier, dict) else None
            if not isinstance(purl, str) or not purl.startswith("pkg:"):
                raise ValueError("Unidentified scan package")
            expected.add(purl)
            if result.get("Class") == "os-pkgs":
                os_inventory.add(purl)
            elif result.get("Class") == "lang-pkgs" and result.get("Type") in ("python-pkg", "pip"):
                python_inventory.add(purl)
    os_info = scan_metadata.get("OS")
    family = os_info.get("Family") if isinstance(os_info, dict) else None
    prefix = {"debian": "pkg:deb/debian/", "wolfi": "pkg:apk/wolfi/"}.get(family)
    if (prefix is None or not os_inventory or not python_inventory or inventory != expected
            or any(not p.startswith(prefix) for p in os_inventory)
            or any(not p.startswith("pkg:pypi/") for p in python_inventory)
            or any(r.get("Type") != family for r in results if r.get("Class") == "os-pkgs")):
        raise ValueError("SBOM must match the supported OS and Python scan inventory")


def verify_release(manifest_path: Path, signature_path: Path, public_key_path: Path,
                   artifact_dir: Path, expected_revision: str, expected_images: Images | None = None) -> dict:
    """Verify identity and bytes; deployment must consume immutable verified files."""
    if not re.fullmatch(r"[0-9a-f]{40}", expected_revision):
        raise ValueError("Expected full revision is required")
    raw = read_regular(manifest_path, MAX_MANIFEST_BYTES)
    key_text = read_regular(public_key_path, 128).decode("ascii").strip()
    signature_text = read_regular(signature_path, 256).decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", key_text) or not re.fullmatch(r"[0-9a-fA-F]{128}", signature_text):
        raise ValueError("Invalid key or signature encoding")
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_text)).verify(bytes.fromhex(signature_text), DOMAIN + raw)
    # Authenticated JSON is still validated; disallow duplicate keys for portable interpretation.
    manifest = Manifest.model_validate(json.loads(raw, object_pairs_hook=unique_keys))
    if manifest.revision != expected_revision:
        raise ValueError("Release revision does not match expected revision")
    if expected_images is not None and manifest.images != expected_images:
        raise ValueError("Release images do not match build outputs")
    scan_images = {}
    sbom_images = {}
    database_images = {}
    if manifest.images is not None:
        scan_images = {f"{role}-scan.json": image for role, image in manifest.images.model_dump().items()}
        sbom_images = {f"{role}.cdx.json": image for role, image in manifest.images.model_dump().items()}
        database_images = {f"{role}-database.json": image for role, image in manifest.images.model_dump().items()}
        if not (scan_images.keys() | sbom_images.keys() | database_images.keys()) <= {
            item.name for item in manifest.artifacts
        }:
            raise ValueError("Release is missing image scans, SBOMs or database metadata")
    evidence = {}
    directory_fd = os.open(artifact_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for artifact in manifest.artifacts:
            fd = os.open(artifact.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size != artifact.size:
                    raise ValueError("Artifact type or size mismatch")
                digest = hashlib.sha256()
                report = bytearray()
                is_report = artifact.name in (scan_images.keys() | sbom_images.keys() | database_images.keys())
                if artifact.name in database_images and artifact.size > 8192:
                    raise ValueError("Database metadata exceeds budget")
                if is_report and artifact.size > MAX_REPORT_BYTES:
                    raise ValueError("Image evidence exceeds budget")
                remaining = artifact.size
                while remaining:
                    chunk = stream.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("Artifact truncated while verifying")
                    digest.update(chunk)
                    if is_report:
                        report.extend(chunk)
                    remaining -= len(chunk)
                if stream.read(1) or digest.hexdigest() != artifact.sha256:
                    raise ValueError("Artifact integrity mismatch")
                current = os.fstat(stream.fileno())
                if (current.st_size, current.st_mtime_ns, current.st_ctime_ns) != (
                    info.st_size, info.st_mtime_ns, info.st_ctime_ns,
                ):
                    raise ValueError("Artifact changed during verification")
                if artifact.name in scan_images:
                    validate_scan(bytes(report), scan_images[artifact.name])
                if is_report:
                    evidence[artifact.name] = bytes(report)
    finally:
        os.close(directory_fd)
    for name, image in sbom_images.items():
        validate_sbom(evidence[name], image, evidence[name.replace(".cdx.json", "-scan.json")])
    for name in database_images:
        validate_scan_freshness(
            json.loads(evidence[name.replace("-database.json", "-scan.json")], object_pairs_hook=unique_keys),
            json.loads(evidence[name], object_pairs_hook=unique_keys), current=expected_images is not None)
    result = {"verified": True, "revision": manifest.revision, "artifacts": len(manifest.artifacts),
              "manifest_sha256": hashlib.sha256(raw).hexdigest()}
    if manifest.images is not None:
        result["images"] = manifest.images.model_dump()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--expected-proxy-image")
    parser.add_argument("--expected-admin-image")
    parser.add_argument("--helm-values", type=Path, help="Write verified image values; requires both expected images")
    args = parser.parse_args()
    try:
        expected_images = None
        if args.expected_proxy_image or args.expected_admin_image or args.helm_values:
            expected_images = Images(proxy=args.expected_proxy_image, admin=args.expected_admin_image)
        result = verify_release(args.manifest, args.signature, args.public_key, args.artifacts,
                                args.expected_revision, expected_images)
        if args.helm_values:
            values = {role: {"image": dict(zip(("repository", "digest"), image.split("@"), strict=True))}
                      for role, image in result["images"].items()}
            # Never follow or overwrite a pre-existing output (including a symlink).
            with args.helm_values.open("x", encoding="ascii") as stream:
                json.dump(values, stream, sort_keys=True)
    except (OSError, ValueError, ValidationError, InvalidSignature, UnicodeError, RecursionError):
        print("Release verification failed", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
