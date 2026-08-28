"""
Pin SkillSpector's OWASP tags to the 2025 LLM Top 10, cross-checked against the
compliance SSOT (src/telemetry/compliance.py).

The Bulwark-overlay rules in admin/services/skill_scanner.py carry OWASP tags
(e.g. ``OWASP-LLM06``). These previously used the 2023 numbering — "Excessive
Agency" as LLM08 and "Overreliance" as LLM09 — which the 2025 revision renumbered
(Excessive Agency → LLM06; Overreliance retired, LLM09 is now "Misinformation").

This test enforces that:
  1. No rule carries a retired-2023 code (LLM08 as agency / LLM09 as overreliance),
     including the structural findings whose tags live inside methods (checked via
     module source so they can't slip through).
  2. Every OWASP code a rule uses exists in the 2025 REFERENCE_CATALOG.
  3. Each rule's OWASP code is consistent with the compliance SSOT mapping for the
     rule's threat category — so the two surfaces can never silently diverge.

admin → src imports are allowed (the reverse is forbidden), so importing the SSOT
here is fine.
"""

from __future__ import annotations

import inspect

from admin.services import skill_scanner
from admin.services.skill_scanner import _BULWARK_RULES
from src.telemetry.compliance import REFERENCE_CATALOG, compliance_for

# skill_scanner uses a couple of category strings that are NOT ThreatCategory enum
# values (they are scanner-local groupings). Map them to the 2025 OWASP risk they
# represent so the SSOT cross-check has an authoritative expectation for them too.
_LOCAL_CATEGORY_OWASP = {
    "privilege_escalation": "LLM06",  # over-privilege → Excessive Agency (2025)
}


def _owasp_codes(tags: list[str]) -> list[str]:
    return [t.replace("OWASP-", "") for t in tags if t.startswith("OWASP-")]


def test_no_retired_2023_owasp_codes_anywhere_in_module():
    """LLM08/LLM09 no longer denote agency/overreliance in 2025 — none must remain.

    Scans the whole module source so structural-finding tags (defined inside
    methods, not in _BULWARK_RULES) are covered too.
    """
    source = inspect.getsource(skill_scanner)
    assert "OWASP-LLM08" not in source
    assert "OWASP-LLM09" not in source


def test_every_owasp_code_is_in_2025_catalog():
    for rule in _BULWARK_RULES:
        for code in _owasp_codes(rule.tags):
            assert code in REFERENCE_CATALOG, (
                f"{rule.id} references {code} which is absent from the 2025 "
                f"REFERENCE_CATALOG"
            )


def test_rule_owasp_codes_match_compliance_ssot():
    """Each rule's OWASP tag agrees with the SSOT mapping for its category."""
    for rule in _BULWARK_RULES:
        codes = _owasp_codes(rule.tags)
        if not codes:
            continue

        if rule.category in _LOCAL_CATEGORY_OWASP:
            expected = {_LOCAL_CATEGORY_OWASP[rule.category]}
        else:
            mapping = compliance_for(rule.category)
            assert mapping is not None, (
                f"{rule.id} category '{rule.category}' has no SSOT compliance "
                f"mapping (and is not a known scanner-local category)"
            )
            expected = set(mapping.owasp_llm)

        for code in codes:
            assert code in expected, (
                f"{rule.id} (category '{rule.category}') tags OWASP {code}, but the "
                f"compliance SSOT expects one of {sorted(expected)}"
            )
