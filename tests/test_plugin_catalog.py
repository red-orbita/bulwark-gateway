"""Tests for the signed plugin catalog (operator-owned / BYO trust root).

These tests exercise the fail-closed contract end to end:
  * a correctly-signed catalog verifies and yields its entries;
  * an unconfigured public key, a missing/tampered catalog, a missing/bad
    signature, or an oversized file all resolve to ZERO entries;
  * install-by-name refuses whenever the catalog is not fully verified.

Signing uses the same Ed25519 primitive the shipped ``scripts/sign-catalog.py``
tool uses, so the tests double as a guard on the on-disk signature format.
"""

from __future__ import annotations

import binascii
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from admin.services import plugin_catalog

# ─── helpers ──────────────────────────────────────────────────────────────────


def _new_key() -> tuple[Ed25519PrivateKey, str]:
    """Return (private_key, hex_public_key)."""
    priv = Ed25519PrivateKey.generate()
    pub_hex = binascii.hexlify(
        priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    return priv, pub_hex


def _write_catalog(tmp_path: Path, doc: dict, priv: Ed25519PrivateKey | None) -> Path:
    """Write a catalog JSON (and, if a key is given, a valid detached .sig)."""
    catalog_path = tmp_path / "plugin-catalog.json"
    raw = json.dumps(doc, indent=2).encode("utf-8")
    catalog_path.write_bytes(raw)
    if priv is not None:
        sig = priv.sign(raw)
        catalog_path.with_name(catalog_path.name + ".sig").write_text(
            binascii.hexlify(sig).decode("ascii")
        )
    return catalog_path


_SAMPLE_DOC = {
    "catalog_version": "1.2.3",
    "updated_at": "2026-01-01T00:00:00Z",
    "plugins": [
        {
            "name": "acme-pii",
            "description": "ACME PII scanner",
            "author": "ACME",
            "version": "1.0.0",
            "category": "pii",
            "git_url": "https://git.example.com/acme/pii.git",
            "branch": "main",
        }
    ],
}


@pytest.fixture(autouse=True)
def _clear_catalog_env(monkeypatch):
    """Each test starts from a clean env (no ambient pubkey / path)."""
    monkeypatch.delenv("BULWARK_PLUGIN_CATALOG_PUBKEY", raising=False)
    monkeypatch.delenv("BULWARK_PLUGIN_CATALOG_PUBKEY_FILE", raising=False)
    monkeypatch.delenv("BULWARK_PLUGIN_CATALOG_PATH", raising=False)


# ─── happy path ───────────────────────────────────────────────────────────────


def test_valid_signed_catalog_verifies(tmp_path, monkeypatch):
    priv, pub_hex = _new_key()
    catalog_path = _write_catalog(tmp_path, _SAMPLE_DOC, priv)
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PUBKEY", pub_hex)
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PATH", str(catalog_path))

    result = plugin_catalog.load_catalog()

    assert result.verified is True
    assert result.pubkey_configured is True
    assert result.catalog_present is True
    assert result.error is None
    assert result.catalog_version == "1.2.3"
    assert [e.name for e in result.entries] == ["acme-pii"]
    assert result.entries[0].git_url == "https://git.example.com/acme/pii.git"
    assert result.signer_fingerprint  # non-empty display fingerprint


def test_get_entry_returns_verified_entry(tmp_path, monkeypatch):
    priv, pub_hex = _new_key()
    catalog_path = _write_catalog(tmp_path, _SAMPLE_DOC, priv)
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PUBKEY", pub_hex)
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PATH", str(catalog_path))

    entry = plugin_catalog.get_entry("acme-pii")
    assert entry is not None
    assert entry.branch == "main"
    assert plugin_catalog.get_entry("does-not-exist") is None


# ─── fail-closed paths ────────────────────────────────────────────────────────


def test_no_pubkey_configured_is_inert(tmp_path, monkeypatch):
    priv, _pub_hex = _new_key()
    catalog_path = _write_catalog(tmp_path, _SAMPLE_DOC, priv)
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PATH", str(catalog_path))
    # No pubkey env set.

    result = plugin_catalog.load_catalog()
    assert result.pubkey_configured is False
    assert result.verified is False
    assert result.entries == []
    assert plugin_catalog.get_entry("acme-pii") is None


def test_missing_catalog_file_is_inert(tmp_path, monkeypatch):
    _priv, pub_hex = _new_key()
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PUBKEY", pub_hex)
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PATH", str(tmp_path / "absent.json"))

    result = plugin_catalog.load_catalog()
    assert result.pubkey_configured is True
    assert result.catalog_present is False
    assert result.verified is False
    assert result.entries == []


def test_missing_signature_is_rejected(tmp_path, monkeypatch):
    _priv, pub_hex = _new_key()
    catalog_path = _write_catalog(tmp_path, _SAMPLE_DOC, priv=None)  # no .sig
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PUBKEY", pub_hex)
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PATH", str(catalog_path))

    result = plugin_catalog.load_catalog()
    assert result.verified is False
    assert result.entries == []
    assert "signature" in (result.error or "").lower()


def test_tampered_catalog_fails_verification(tmp_path, monkeypatch):
    priv, pub_hex = _new_key()
    catalog_path = _write_catalog(tmp_path, _SAMPLE_DOC, priv)
    # Tamper AFTER signing — flip the git_url to an attacker repo.
    doc = json.loads(catalog_path.read_text())
    doc["plugins"][0]["git_url"] = "https://evil.example/attacker/repo.git"
    catalog_path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PUBKEY", pub_hex)
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PATH", str(catalog_path))

    result = plugin_catalog.load_catalog()
    assert result.verified is False
    assert result.entries == []
    assert "FAILED" in (result.error or "") or "fail" in (result.error or "").lower()


def test_signature_from_wrong_key_is_rejected(tmp_path, monkeypatch):
    priv_signer, _ = _new_key()
    _priv_other, pub_hex_other = _new_key()  # trust a DIFFERENT key
    catalog_path = _write_catalog(tmp_path, _SAMPLE_DOC, priv_signer)
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PUBKEY", pub_hex_other)
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PATH", str(catalog_path))

    result = plugin_catalog.load_catalog()
    assert result.verified is False
    assert result.entries == []


def test_malformed_signature_hex_is_rejected(tmp_path, monkeypatch):
    priv, pub_hex = _new_key()
    catalog_path = _write_catalog(tmp_path, _SAMPLE_DOC, priv)
    catalog_path.with_name(catalog_path.name + ".sig").write_text("not-hex-zzzz")
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PUBKEY", pub_hex)
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PATH", str(catalog_path))

    result = plugin_catalog.load_catalog()
    assert result.verified is False
    assert result.entries == []


def test_bad_pubkey_length_is_inert(tmp_path, monkeypatch):
    priv, _ = _new_key()
    catalog_path = _write_catalog(tmp_path, _SAMPLE_DOC, priv)
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PUBKEY", "deadbeef")  # 4 bytes
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PATH", str(catalog_path))

    result = plugin_catalog.load_catalog()
    assert result.pubkey_configured is False
    assert result.verified is False


def test_non_hex_pubkey_is_inert(tmp_path, monkeypatch):
    priv, _ = _new_key()
    catalog_path = _write_catalog(tmp_path, _SAMPLE_DOC, priv)
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PUBKEY", "zzzz-not-hex")
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PATH", str(catalog_path))

    result = plugin_catalog.load_catalog()
    assert result.pubkey_configured is False
    assert result.verified is False


def test_oversized_catalog_is_rejected(tmp_path, monkeypatch):
    priv, pub_hex = _new_key()
    big_doc = {
        "catalog_version": "1",
        "plugins": [
            {"name": f"p{i}", "git_url": "https://x.example/x.git", "description": "x" * 100}
            for i in range(20000)
        ],
    }
    catalog_path = _write_catalog(tmp_path, big_doc, priv)
    assert catalog_path.stat().st_size > plugin_catalog._MAX_CATALOG_BYTES
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PUBKEY", pub_hex)
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PATH", str(catalog_path))

    result = plugin_catalog.load_catalog()
    assert result.verified is False
    assert result.entries == []


def test_malformed_entry_is_skipped_not_fatal(tmp_path, monkeypatch):
    priv, pub_hex = _new_key()
    doc = {
        "catalog_version": "1",
        "plugins": [
            {"name": "good", "git_url": "https://x.example/good.git"},
            {"description": "missing name and git_url"},  # invalid → skipped
        ],
    }
    catalog_path = _write_catalog(tmp_path, doc, priv)
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PUBKEY", pub_hex)
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PATH", str(catalog_path))

    result = plugin_catalog.load_catalog()
    assert result.verified is True
    assert [e.name for e in result.entries] == ["good"]


def test_pem_public_key_accepted(tmp_path, monkeypatch):
    priv, _ = _new_key()
    pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    catalog_path = _write_catalog(tmp_path, _SAMPLE_DOC, priv)
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PUBKEY", pem)
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PATH", str(catalog_path))

    result = plugin_catalog.load_catalog()
    assert result.verified is True
    assert result.entries[0].name == "acme-pii"


# ─── shipped example fixture ──────────────────────────────────────────────────


def test_shipped_example_catalog_verifies_with_documented_key(monkeypatch):
    """The bundled example must verify against its documented example pubkey."""
    repo_root = Path(__file__).resolve().parent.parent
    example = repo_root / "config" / "examples" / "plugin-catalog.example.json"
    if not example.is_file():
        pytest.skip("example catalog not present")
    # Documented example public key (see config/examples/PLUGIN-CATALOG-README.md).
    pub_hex = "b6b9cf93d874e62a8d97b43e2916d1a8c0f0a88f4cd06a8ceb16f498e7523128"
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PUBKEY", pub_hex)
    monkeypatch.setenv("BULWARK_PLUGIN_CATALOG_PATH", str(example))

    result = plugin_catalog.load_catalog()
    assert result.verified is True
    assert result.entries
