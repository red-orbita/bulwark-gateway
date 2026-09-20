#!/usr/bin/env python3
"""Sign scanned CI image digests with an operator-provisioned Ed25519 key file.

No key generation, network access, artifact execution or proxy dependencies.
The private key is a 32-byte Ed25519 seed encoded as hex, read ONLY from
BULWARK_RELEASE_SIGNING_KEY_FILE outside the checkout and release directory.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib
import json
import os
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Share the wire format and validators, not a second interpretation of the manifest.
verifier = importlib.import_module("verify-release")


def sign_release(revision: str, proxy_image: str, admin_image: str,
                 artifact_dir: Path, public_key_path: Path, output_dir: Path) -> dict:
    images = verifier.Images(proxy=proxy_image, admin=admin_image)
    artifacts = []
    for role, image in images.model_dump().items():
        name = f"{role}-scan.json"
        raw = verifier.read_regular(artifact_dir / name, verifier.MAX_REPORT_BYTES)
        verifier.validate_scan(raw, image)
        artifacts.append(verifier.Artifact(name=name, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw)))
        name = f"{role}.cdx.json"
        sbom = verifier.read_regular(artifact_dir / name, verifier.MAX_REPORT_BYTES)
        verifier.validate_sbom(sbom, image, raw)
        artifacts.append(verifier.Artifact(name=name, sha256=hashlib.sha256(sbom).hexdigest(), size=len(sbom)))
        name = f"{role}-database.json"
        metadata = verifier.read_regular(artifact_dir / name, 8192)
        verifier.validate_scan_freshness(json.loads(raw, object_pairs_hook=verifier.unique_keys),
                                         json.loads(metadata, object_pairs_hook=verifier.unique_keys), current=True)
        artifacts.append(verifier.Artifact(name=name, sha256=hashlib.sha256(metadata).hexdigest(), size=len(metadata)))
    manifest = verifier.Manifest(schema_version=1, revision=revision, artifacts=artifacts, images=images)
    raw = manifest.model_dump_json().encode("ascii")
    key_path = Path(os.environ["BULWARK_RELEASE_SIGNING_KEY_FILE"])
    if any(key_path.resolve().is_relative_to(directory.resolve())
           for directory in (Path(__file__).parents[1], artifact_dir, output_dir)):
        raise ValueError("Private key must be outside release and checkout")
    key_text = verifier.read_regular(key_path, 128, private=True).decode("ascii").strip()
    public_text = verifier.read_regular(public_key_path, 128).decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", key_text) or not re.fullmatch(r"[0-9a-fA-F]{64}", public_text):
        raise ValueError("Invalid signing key encoding")
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_text))
    if not hmac.compare_digest(private.public_key().public_bytes_raw(), bytes.fromhex(public_text)):
        raise ValueError("Signing key does not match trusted public key")
    signature = private.sign(verifier.DOMAIN + raw).hex()
    # An exclusive new directory prevents mixing a failed run with a stale signature.
    output_dir.mkdir(mode=0o700)
    (output_dir / "release.json").write_bytes(raw)
    (output_dir / "release.sig").write_text(signature, encoding="ascii")
    return {"signed": True, "revision": revision, "manifest_sha256": hashlib.sha256(raw).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--proxy-image", required=True)
    parser.add_argument("--admin-image", required=True)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = sign_release(args.revision, args.proxy_image, args.admin_image,
                              args.artifacts, args.public_key, args.output)
    except (OSError, ValueError, KeyError, RecursionError):
        print("Release signing failed", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
