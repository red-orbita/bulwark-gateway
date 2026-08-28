"""The /v2/scan MITRE ATT&CK annotation derives from the compliance SSOT.

Previously scan.py kept its own ``_MITRE_MAP`` copy that could drift from the
central mapping tagged onto SIEM exports. It now derives the primary ATT&CK
technique from ``src/telemetry/compliance.py`` — this test locks that in.
"""

from __future__ import annotations

from src.routes.v2.scan import _primary_mitre_attack
from src.telemetry.compliance import compliance_for


def test_primary_mitre_attack_matches_ssot_first_code():
    """For every mapped category, scan.py returns the SSOT's first ATT&CK code."""
    for category in [
        "prompt_injection",
        "exfiltration",
        "credential_access",
        "reverse_shell",
        "memory_manipulation",
    ]:
        mapping = compliance_for(category)
        assert mapping is not None and mapping.mitre_attack
        assert _primary_mitre_attack(category) == mapping.mitre_attack[0]


def test_primary_mitre_attack_none_when_no_attack_code():
    """Categories with only ATLAS/agency refs (no ATT&CK) return None, not a stale code."""
    # excessive_agency maps to ATLAS + OWASP but no ATT&CK technique.
    assert compliance_for("excessive_agency").mitre_attack == ()
    assert _primary_mitre_attack("excessive_agency") is None


def test_primary_mitre_attack_none_for_unknown_category():
    assert _primary_mitre_attack("totally_made_up") is None
