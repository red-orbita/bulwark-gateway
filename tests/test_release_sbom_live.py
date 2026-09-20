"""Opt-in compatibility checks against local Trivy evidence, never signed here."""

import hashlib
import importlib
import json
import os
from pathlib import Path

import pytest


@pytest.mark.skipif(os.environ.get("BULWARK_SBOM_LIVE") != "1", reason="Requires local image inventory evidence")
@pytest.mark.parametrize("role,filename", [
    ("admin", "admin.cdx.json"), ("proxy", "proxy.cdx.json"),
    ("admin", "admin-converted.cdx.json"),
])
def test_actual_trivy_inventory_matches_scan_without_waiving_cves(monkeypatch, role, filename):
    root = Path(__file__).parents[1]
    monkeypatch.syspath_prepend(str(root / "scripts"))
    verifier = importlib.import_module("verify-release")
    evidence = root / "shared/recovery-release-check"
    raw = verifier.read_regular(evidence / filename, verifier.MAX_REPORT_BYTES)
    scan_raw = verifier.read_regular(evidence / f"{role}-current-db-scan.json", verifier.MAX_REPORT_BYTES)
    scan = json.loads(scan_raw)
    # Local tar names are retained unchanged. This is NOT registry-digest acceptance.
    verifier.validate_sbom(raw, scan["ArtifactName"], scan_raw)
    with pytest.raises(ValueError, match="vulnerabilities"):
        verifier.validate_scan(scan_raw, scan["ArtifactName"])
    bom = json.loads(raw)
    print(json.dumps({"artifact": filename, "sha256": hashlib.sha256(raw).hexdigest(),
                      "components": len(bom["components"]), "spec_version": bom["specVersion"],
                      "inventory_matches": True, "release_cve_gate": "blocked"}, sort_keys=True))
