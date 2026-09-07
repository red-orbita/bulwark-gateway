"""Signed plugin catalog — operator-owned (BYO) curated plugin registry.

Bulwark has no public plugin marketplace. Instead, an operator (or enterprise)
curates a list of vetted scanner plugins into a JSON *catalog* and signs it with
their own Ed25519 key. Bulwark verifies that signature before showing any entry
or allowing a one-click install, so the admin UI can only ever offer plugins the
operator has explicitly blessed — the catalog is the operator's supply-chain
allowlist.

Trust model (fail-closed)
-------------------------
* There is **no embedded project key**. The trust root is the operator's public
  key, supplied via ``BULWARK_PLUGIN_CATALOG_PUBKEY`` (raw 32-byte Ed25519 key,
  hex-encoded — or a PEM ``PUBLIC KEY``) or its ``_FILE`` Docker-secret variant.
* The catalog file (``BULWARK_PLUGIN_CATALOG_PATH``, default
  ``config/plugin-catalog.json``) is accompanied by a detached signature at
  ``<path>.sig`` (hex-encoded Ed25519 signature over the exact catalog bytes).
* If the public key is not configured, the catalog file is absent, the signature
  is missing, or verification fails, the catalog resolves to **zero entries**
  (never a partial/unverified list). A tampered or unsigned catalog is logged at
  ``critical`` and yields nothing installable.

Signing / key generation is done out-of-band with ``scripts/sign-catalog.py``.

This module lives under ``admin/`` because ``cryptography`` ships only in the
admin image; the proxy (``src/``) stays dependency-free.
"""

from __future__ import annotations

import binascii
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from pydantic import BaseModel, Field

from admin.services.secrets import read_secret

logger = logging.getLogger("bulwark.plugin_catalog")

# Default on-disk location of the signed catalog (and its `.sig` sibling).
_DEFAULT_CATALOG_PATH = (
    Path("/app/config/plugin-catalog.json")
    if Path("/app").exists()
    else Path("config/plugin-catalog.json")
)

# Bound the catalog file size — a signed manifest is small; refuse absurd inputs
# before hashing/parsing (defence against a hostile writable-volume mount).
_MAX_CATALOG_BYTES = 1 * 1024 * 1024  # 1 MiB


class CatalogEntry(BaseModel):
    """A single curated plugin advertised by the signed catalog."""

    name: str = Field(..., description="Plugin identifier (kebab-case)")
    description: str = Field(default="", description="Human-readable summary")
    author: str = Field(default="", description="Plugin author/organization")
    version: str = Field(default="", description="Advertised version")
    category: str = Field(default="", description="Grouping label (e.g. pii, injection)")
    git_url: str = Field(..., description="HTTPS Git URL used for install")
    branch: str = Field(default="main", description="Git branch to clone")
    homepage: str = Field(default="", description="Project/docs URL")
    tags: list[str] = Field(default_factory=list, description="Free-form tags")


class CatalogResult(BaseModel):
    """Outcome of loading + verifying the catalog (safe to serialize to the UI)."""

    pubkey_configured: bool
    catalog_present: bool
    verified: bool
    entries: list[CatalogEntry] = Field(default_factory=list)
    signer_fingerprint: str = ""  # sha256(pubkey)[:16], for display only
    catalog_version: str = ""
    updated_at: str = ""
    source_path: str = ""
    error: Optional[str] = None


# ─── public key resolution ────────────────────────────────────────────────────


def _resolve_pubkey() -> Optional[Ed25519PublicKey]:
    """Load the operator's trusted Ed25519 public key, or None if not configured.

    Accepts either a 64-char hex-encoded raw 32-byte key or a PEM
    ``-----BEGIN PUBLIC KEY-----`` block. Any malformed value is treated as
    "not configured" (fail-closed) and logged.
    """
    raw = read_secret("BULWARK_PLUGIN_CATALOG_PUBKEY").strip()
    if not raw:
        return None

    # PEM path.
    if "BEGIN PUBLIC KEY" in raw:
        try:
            key = load_pem_public_key(raw.encode("utf-8"))
            if isinstance(key, Ed25519PublicKey):
                return key
            logger.critical("plugin_catalog_pubkey_wrong_type", extra={"type": type(key).__name__})
            return None
        except Exception as exc:  # noqa: BLE001 - malformed key must fail closed
            logger.critical("plugin_catalog_pubkey_pem_invalid", extra={"error": str(exc)[:200]})
            return None

    # Hex raw-key path.
    try:
        key_bytes = binascii.unhexlify(raw)
    except (binascii.Error, ValueError):
        logger.critical("plugin_catalog_pubkey_not_hex")
        return None
    if len(key_bytes) != 32:
        logger.critical("plugin_catalog_pubkey_bad_length", extra={"length": len(key_bytes)})
        return None
    try:
        return Ed25519PublicKey.from_public_bytes(key_bytes)
    except Exception as exc:  # noqa: BLE001
        logger.critical("plugin_catalog_pubkey_invalid", extra={"error": str(exc)[:200]})
        return None


def _fingerprint(pubkey: Ed25519PublicKey) -> str:
    from cryptography.hazmat.primitives import serialization

    raw = pubkey.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:16]


def _catalog_path() -> Path:
    override = os.getenv("BULWARK_PLUGIN_CATALOG_PATH", "").strip()
    return Path(override) if override else _DEFAULT_CATALOG_PATH


# ─── load + verify ─────────────────────────────────────────────────────────────


def _parse_entries(raw_bytes: bytes) -> tuple[list[CatalogEntry], str, str]:
    """Parse verified catalog bytes into entries. Returns (entries, version, updated_at).

    A structurally-broken entry is skipped (logged), never aborts the whole
    catalog — one bad row must not deny every vetted plugin.
    """
    doc = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(doc, dict):
        raise ValueError("catalog root must be a JSON object")

    version = str(doc.get("catalog_version", ""))
    updated_at = str(doc.get("updated_at", ""))
    rows = doc.get("plugins", [])
    if not isinstance(rows, list):
        raise ValueError("catalog 'plugins' must be a list")

    entries: list[CatalogEntry] = []
    for row in rows:
        try:
            entries.append(CatalogEntry(**row))
        except Exception as exc:  # noqa: BLE001 - skip malformed entry, keep the rest
            logger.warning("plugin_catalog_entry_invalid", extra={"error": str(exc)[:200]})
    return entries, version, updated_at


def load_catalog() -> CatalogResult:
    """Load, verify, and parse the signed catalog. Always fail-closed.

    Returns a ``CatalogResult`` whose ``entries`` is non-empty only when the
    public key is configured, the catalog + detached signature are present, and
    the Ed25519 signature verifies over the exact catalog bytes.
    """
    path = _catalog_path()
    sig_path = path.with_name(path.name + ".sig")
    result = CatalogResult(
        pubkey_configured=False,
        catalog_present=path.is_file(),
        verified=False,
        source_path=str(path),
    )

    pubkey = _resolve_pubkey()
    result.pubkey_configured = pubkey is not None
    if pubkey is None:
        result.error = "No catalog public key configured (BULWARK_PLUGIN_CATALOG_PUBKEY)."
        return result
    result.signer_fingerprint = _fingerprint(pubkey)

    if not path.is_file():
        result.error = f"Catalog file not found at {path}."
        return result

    try:
        if path.stat().st_size > _MAX_CATALOG_BYTES:
            result.error = "Catalog file exceeds the maximum allowed size."
            logger.critical("plugin_catalog_too_large", extra={"path": str(path)})
            return result
        raw_bytes = path.read_bytes()
    except OSError as exc:
        result.error = "Catalog file could not be read."
        logger.warning("plugin_catalog_read_failed", extra={"error": str(exc)[:200]})
        return result

    if not sig_path.is_file():
        result.error = f"Catalog signature not found at {sig_path} — refusing unsigned catalog."
        logger.critical("plugin_catalog_signature_missing", extra={"path": str(sig_path)})
        return result

    try:
        signature = binascii.unhexlify(sig_path.read_text(encoding="utf-8").strip())
    except (OSError, binascii.Error, ValueError) as exc:
        result.error = "Catalog signature is unreadable or not valid hex."
        logger.critical("plugin_catalog_signature_malformed", extra={"error": str(exc)[:200]})
        return result

    try:
        pubkey.verify(signature, raw_bytes)
    except InvalidSignature:
        result.error = "Catalog signature verification FAILED — catalog rejected."
        logger.critical("plugin_catalog_signature_invalid", extra={"path": str(path)})
        return result

    # Signature is valid → parse.
    try:
        entries, version, updated_at = _parse_entries(raw_bytes)
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        result.error = "Catalog signed but its content is malformed."
        logger.critical("plugin_catalog_content_invalid", extra={"error": str(exc)[:200]})
        return result

    result.verified = True
    result.entries = entries
    result.catalog_version = version
    result.updated_at = updated_at
    result.error = None
    logger.info(
        "plugin_catalog_loaded",
        extra={"entries": len(entries), "signer": result.signer_fingerprint, "version": version},
    )
    return result


def get_entry(name: str) -> Optional[CatalogEntry]:
    """Return a verified catalog entry by name, or None.

    Only ever returns an entry from a fully-verified catalog — an unverified or
    tampered catalog yields no entries, so install-by-name is fail-closed.
    """
    result = load_catalog()
    if not result.verified:
        return None
    for entry in result.entries:
        if entry.name == name:
            return entry
    return None
