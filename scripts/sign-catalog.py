#!/usr/bin/env python3
"""Sign, verify, and key-generate for the Bulwark signed plugin catalog.

Bulwark has no public plugin marketplace. An operator curates a JSON catalog of
vetted scanner plugins and signs it with their OWN Ed25519 key. The admin service
verifies that detached signature (against ``BULWARK_PLUGIN_CATALOG_PUBKEY``)
before showing any entry or allowing a one-click install — so the catalog is the
operator's supply-chain allowlist and is fail-closed.

This tool is the out-of-band signing companion (never runs inside the gateway).

Usage
-----
Generate a keypair (writes ``<out>.key`` private + ``<out>.pub`` hex public)::

    python scripts/sign-catalog.py generate-key --out catalog-key

Sign a catalog (writes ``<catalog>.sig`` next to it)::

    python scripts/sign-catalog.py sign \\
        --catalog config/plugin-catalog.json --key catalog-key.key

Verify a catalog against a public key::

    python scripts/sign-catalog.py verify \\
        --catalog config/plugin-catalog.json --pub catalog-key.pub

The public key value printed by ``generate-key`` (64-char hex) is what you set as
``BULWARK_PLUGIN_CATALOG_PUBKEY`` (or its ``_FILE`` Docker-secret variant) so the
admin service trusts catalogs signed by the matching private key.

Security
--------
* Private key is written ``0600``. Keep it OUT of the repo and out of the image —
  ``.gitignore`` blocks ``*.key``. Store it in your secret manager / HSM workflow.
* The signature is Ed25519 (RFC 8032) over the EXACT catalog bytes on disk. Any
  post-signing edit invalidates it — re-sign after every change.
"""

from __future__ import annotations

import argparse
import binascii
import os
import stat
import sys
from pathlib import Path

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except ImportError:  # pragma: no cover - operator-side dependency hint
    sys.stderr.write(
        "ERROR: this tool requires the 'cryptography' package.\n"
        "Install it with:  pip install cryptography\n"
    )
    raise SystemExit(2) from None


def _read_hex_key(path: Path, expected_len: int) -> bytes:
    raw = path.read_text(encoding="utf-8").strip()
    try:
        data = binascii.unhexlify(raw)
    except (binascii.Error, ValueError) as exc:
        raise SystemExit(f"ERROR: {path} is not valid hex: {exc}") from exc
    if len(data) != expected_len:
        raise SystemExit(
            f"ERROR: {path} decodes to {len(data)} bytes, expected {expected_len}."
        )
    return data


def cmd_generate_key(args: argparse.Namespace) -> int:
    out = Path(args.out)
    priv_path = out.with_suffix(".key")
    pub_path = out.with_suffix(".pub")

    if (priv_path.exists() or pub_path.exists()) and not args.force:
        raise SystemExit(
            f"ERROR: {priv_path} or {pub_path} already exists (use --force to overwrite)."
        )

    private_key = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization

    priv_raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # Write private key 0600 (owner read/write only).
    priv_path.write_text(binascii.hexlify(priv_raw).decode("ascii") + "\n", encoding="utf-8")
    os.chmod(priv_path, stat.S_IRUSR | stat.S_IWUSR)

    pub_hex = binascii.hexlify(pub_raw).decode("ascii")
    pub_path.write_text(pub_hex + "\n", encoding="utf-8")

    print(f"Private key written to {priv_path} (mode 0600 — keep it secret).")
    print(f"Public key written to  {pub_path}")
    print()
    print("Set this as BULWARK_PLUGIN_CATALOG_PUBKEY in the admin service:")
    print(f"  {pub_hex}")
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    catalog_path = Path(args.catalog)
    key_path = Path(args.key)
    if not catalog_path.is_file():
        raise SystemExit(f"ERROR: catalog file not found: {catalog_path}")
    if not key_path.is_file():
        raise SystemExit(f"ERROR: private key file not found: {key_path}")

    priv_raw = _read_hex_key(key_path, 32)
    private_key = Ed25519PrivateKey.from_private_bytes(priv_raw)

    catalog_bytes = catalog_path.read_bytes()
    signature = private_key.sign(catalog_bytes)
    sig_path = catalog_path.with_name(catalog_path.name + ".sig")
    sig_path.write_text(binascii.hexlify(signature).decode("ascii") + "\n", encoding="utf-8")

    print(f"Signed {catalog_path} ({len(catalog_bytes)} bytes).")
    print(f"Detached signature written to {sig_path}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    catalog_path = Path(args.catalog)
    pub_path = Path(args.pub)
    sig_path = catalog_path.with_name(catalog_path.name + ".sig")

    if not catalog_path.is_file():
        raise SystemExit(f"ERROR: catalog file not found: {catalog_path}")
    if not pub_path.is_file():
        raise SystemExit(f"ERROR: public key file not found: {pub_path}")
    if not sig_path.is_file():
        raise SystemExit(f"ERROR: signature file not found: {sig_path}")

    pub_raw = _read_hex_key(pub_path, 32)
    public_key = Ed25519PublicKey.from_public_bytes(pub_raw)

    catalog_bytes = catalog_path.read_bytes()
    try:
        signature = binascii.unhexlify(sig_path.read_text(encoding="utf-8").strip())
    except (binascii.Error, ValueError) as exc:
        raise SystemExit(f"ERROR: signature is not valid hex: {exc}") from exc

    try:
        public_key.verify(signature, catalog_bytes)
    except InvalidSignature:
        print("INVALID — signature does not match (catalog would be REJECTED).")
        return 1

    print("VALID — signature verifies. The admin service will accept this catalog.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Sign/verify the Bulwark signed plugin catalog (Ed25519)."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_gen = sub.add_parser("generate-key", help="Generate an Ed25519 keypair")
    p_gen.add_argument("--out", default="catalog-key", help="Output basename (.key/.pub)")
    p_gen.add_argument("--force", action="store_true", help="Overwrite existing files")
    p_gen.set_defaults(func=cmd_generate_key)

    p_sign = sub.add_parser("sign", help="Sign a catalog file")
    p_sign.add_argument("--catalog", required=True, help="Path to the catalog JSON")
    p_sign.add_argument("--key", required=True, help="Path to the hex private key (.key)")
    p_sign.set_defaults(func=cmd_sign)

    p_verify = sub.add_parser("verify", help="Verify a catalog signature")
    p_verify.add_argument("--catalog", required=True, help="Path to the catalog JSON")
    p_verify.add_argument("--pub", required=True, help="Path to the hex public key (.pub)")
    p_verify.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
