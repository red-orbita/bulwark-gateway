"""Tests for the declarative compliance mapping and its ECS/CEF/LEEF surfacing.

Covers:
  * completeness — every ThreatCategory has a non-empty, defensible mapping
  * lookup semantics (enum + string, unknown → None)
  * OWASP 2025 revision + MITRE ATLAS axis
  * reference catalog completeness — every mapped code has a label/URL entry
  * `bulwark.compliance.*` in the ECS export (present for mapped, absent for ad-hoc)
  * compliance surfaced in the CEF and LEEF legacy converters
"""

from __future__ import annotations

from src.models import ThreatCategory
from src.telemetry.compliance import (
    OWASP_LLM_VERSION,
    REFERENCE_CATALOG,
    ComplianceMapping,
    all_mappings,
    compliance_for,
    reference_catalog,
)
from src.telemetry.schema import from_security_event

# ---------------------------------------------------------------------------
# Mapping table — completeness + shape
# ---------------------------------------------------------------------------


def test_owasp_version_is_2025():
    """The SSOT is pinned to the OWASP LLM Top 10 2025 revision."""
    assert OWASP_LLM_VERSION == "2025"


def test_every_threat_category_has_a_nonempty_mapping():
    """A new ThreatCategory cannot ship without a compliance mapping (honesty gate)."""
    for category in ThreatCategory:
        mapping = compliance_for(category)
        assert mapping is not None, f"no compliance mapping for {category.value}"
        assert not mapping.is_empty(), f"empty compliance mapping for {category.value}"


def test_mappings_reference_known_framework_prefixes():
    """Sanity-check the shape of each ref so typos don't ship silently."""
    for category, mapping in all_mappings().items():
        for code in mapping.owasp_llm:
            assert code.startswith("LLM"), f"{category}: bad OWASP code {code}"
        for atlas in mapping.mitre_atlas:
            assert atlas.startswith("AML.T"), f"{category}: bad MITRE ATLAS technique {atlas}"
        for tech in mapping.mitre_attack:
            assert tech.startswith("T") and tech[1:].split(".")[0].isdigit(), (
                f"{category}: bad MITRE ATT&CK technique {tech}"
            )
        for ref in mapping.nist_ai_rmf:
            assert ref.split("-")[0] in {"GOVERN", "MAP", "MEASURE", "MANAGE"}, (
                f"{category}: bad NIST AI RMF ref {ref}"
            )
        for art in mapping.eu_ai_act:
            assert art.startswith("Article "), f"{category}: bad EU AI Act ref {art}"


def test_every_mapped_code_has_a_catalog_entry():
    """Every OWASP/ATLAS/ATT&CK code used by a mapping must be in the catalog.

    Guards against a mapping referencing a code the UI can't label/link (which
    would be silently dropped from the reference badges).
    """
    catalog = reference_catalog()
    for category, mapping in all_mappings().items():
        for code in mapping.display_codes():
            assert code in catalog, f"{category}: code {code} missing from REFERENCE_CATALOG"


def test_catalog_entries_are_well_formed():
    """Each catalog entry has a label, an https URL, and a known framework."""
    for code, ref in REFERENCE_CATALOG.items():
        assert ref.label, f"{code}: empty label"
        assert ref.url.startswith("https://"), f"{code}: non-https url {ref.url}"
        assert ref.framework in {"owasp", "atlas", "attack"}, (
            f"{code}: unknown framework {ref.framework}"
        )


def test_compliance_for_accepts_enum_and_string_and_rejects_unknown():
    by_enum = compliance_for(ThreatCategory.PROMPT_INJECTION)
    by_str = compliance_for("prompt_injection")
    assert by_enum == by_str
    assert isinstance(by_enum, ComplianceMapping)
    # Ad-hoc / unknown category strings must NOT fabricate a mapping.
    assert compliance_for("totally_made_up") is None
    assert compliance_for(None) is None


def test_prompt_injection_specific_refs():
    m = compliance_for(ThreatCategory.PROMPT_INJECTION)
    assert m is not None
    assert "LLM01" in m.owasp_llm
    assert "AML.T0051" in m.mitre_atlas
    assert "Article 15" in m.eu_ai_act
    assert "MEASURE-2.7" in m.nist_ai_rmf


def test_model_theft_is_unbounded_consumption_in_2025():
    """OWASP 2025 folded Model Theft into LLM10 Unbounded Consumption."""
    m = compliance_for(ThreatCategory.MODEL_THEFT)
    assert m is not None
    assert m.owasp_llm == ("LLM10",)
    assert "AML.T0024" in m.mitre_atlas


def test_display_codes_order_is_owasp_then_atlas_then_attack():
    m = compliance_for(ThreatCategory.MEMORY_MANIPULATION)
    assert m is not None
    assert m.display_codes() == ["LLM08", "AML.T0070", "T1565"]


# ---------------------------------------------------------------------------
# ECS export — bulwark.compliance.*
# ---------------------------------------------------------------------------


def _event(category: str | None):
    return from_security_event(
        verdict="block",
        rule_id="R1",
        rule_description="desc",
        threat_category=category,
        tenant_id="t1",
        agent_id="a1",
        guardrail_layer="input",
        latency_ms=1.0,
    )


def test_ecs_export_includes_compliance_for_mapped_category():
    ecs = _event("exfiltration").to_ecs_json()
    comp = ecs["bulwark"]["compliance"]
    assert comp["owasp_llm"] == ["LLM02"]
    assert comp["owasp_llm_version"] == OWASP_LLM_VERSION
    assert comp["mitre_attack"] == ["T1041"]
    assert "Article 15" in comp["eu_ai_act"]
    assert "MEASURE-2.7" in comp["nist_ai_rmf"]


def test_ecs_export_includes_mitre_atlas_axis():
    ecs = _event("prompt_injection").to_ecs_json()
    comp = ecs["bulwark"]["compliance"]
    assert comp["mitre_atlas"] == ["AML.T0051"]


def test_ecs_export_omits_mitre_atlas_when_absent():
    # exfiltration maps to ATT&CK but not ATLAS → atlas axis dropped.
    ecs = _event("exfiltration").to_ecs_json()
    assert "mitre_atlas" not in ecs["bulwark"]["compliance"]


def test_ecs_export_omits_compliance_for_unmapped_category():
    ecs = _event("some_adhoc_category").to_ecs_json()
    # exclude_none drops the whole compliance block when there is no mapping.
    assert "compliance" not in ecs["bulwark"]


def test_ecs_export_omits_compliance_when_category_none():
    ecs = _event(None).to_ecs_json()
    assert "compliance" not in ecs["bulwark"]


def test_policy_violation_has_no_owasp_but_keeps_nist_and_eu():
    ecs = _event("policy_violation").to_ecs_json()
    comp = ecs["bulwark"]["compliance"]
    assert "owasp_llm" not in comp  # empty axis dropped
    assert "owasp_llm_version" not in comp  # only set when owasp present
    assert comp["nist_ai_rmf"]
    assert comp["eu_ai_act"] == ["Article 9"]


# ---------------------------------------------------------------------------
# Legacy converters — CEF / LEEF
# ---------------------------------------------------------------------------


def test_cef_includes_compliance_summary():
    cef = _event("prompt_injection").to_cef()
    assert "cs6Label=Compliance" in cef
    assert "LLM01" in cef
    assert "Article 15" in cef


def test_cef_compliance_none_when_unmapped():
    cef = _event("adhoc").to_cef()
    assert "cs6=none cs6Label=Compliance" in cef


def test_leef_includes_compliance_fields():
    leef = _event("prompt_injection").to_leef()
    assert "owaspLlm=LLM01" in leef
    assert "mitreAtlas=AML.T0051" in leef
    assert "mitreAttack=T1059" in leef
    assert "euAiAct=" in leef and "Article 15" in leef


def test_leef_compliance_none_when_unmapped():
    leef = _event("adhoc").to_leef()
    assert "owaspLlm=none" in leef
    assert "mitreAtlas=none" in leef
    assert "mitreAttack=none" in leef
