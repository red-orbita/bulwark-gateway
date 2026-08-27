"""Declarative compliance mapping — ThreatCategory → regulatory/standards refs.

Bulwark's guardrails already classify every detection into a :class:`ThreatCategory`.
This module attaches, in ONE auditable place, the external framework references
that a security/compliance team needs when a detection lands in their SIEM:

  * ``owasp_llm``    — OWASP Top 10 for LLM Applications (2023 numbering, matching
                       the annotations already in ``src/models.py``).
  * ``mitre_attack`` — MITRE ATT&CK technique IDs (same convention already used by
                       the Wazuh rules and the skill scanner tags).
  * ``nist_ai_rmf``  — NIST AI Risk Management Framework (AI 100-1) subcategory
                       refs (e.g. ``MEASURE-2.7`` = AI system security & resilience;
                       ``MANAGE-4.1`` = post-deployment monitoring — Bulwark IS a
                       runtime monitor, so that applies broadly).
  * ``eu_ai_act``    — EU AI Act (Regulation 2024/1689) article refs. Article 15
                       (accuracy, robustness & cybersecurity) is the anchor for
                       adversarial threats; Article 10 (data governance) for
                       poisoning/PII; Article 14 (human oversight) for agency/tool
                       abuse; Article 9 (risk-management system) for policy.

Design notes / honesty guardrails:
  * This is a pure, side-effect-free lookup table. No network, no inference.
  * Mappings are intentionally CONSERVATIVE — each ref is one a compliance auditor
    can defend, not an exhaustive "everything touches everything" spray. Unknown /
    ad-hoc category strings return ``None`` (no fabricated mapping).
  * Completeness against the ``ThreatCategory`` enum is enforced by a unit test, so
    a newly added category cannot silently ship without a compliance mapping.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.models import ThreatCategory

# Version of the OWASP LLM Top 10 the `owasp_llm` codes refer to. Pinned to 2023
# because that is the numbering the ThreatCategory enum comments in models.py
# already use (e.g. INSECURE_OUTPUT = LLM02, MODEL_THEFT = LLM10). Recorded on
# every exported event so downstream consumers are never guessing the revision.
OWASP_LLM_VERSION = "2023"


@dataclass(frozen=True)
class ComplianceMapping:
    """Framework references for a single threat category (all optional).

    Tuples (not lists) so the mapping is immutable and safely shared.
    """

    owasp_llm: tuple[str, ...] = ()
    mitre_attack: tuple[str, ...] = ()
    nist_ai_rmf: tuple[str, ...] = ()
    eu_ai_act: tuple[str, ...] = ()

    def is_empty(self) -> bool:
        return not (self.owasp_llm or self.mitre_attack or self.nist_ai_rmf or self.eu_ai_act)

    def to_dict(self) -> dict[str, list[str]]:
        """Compact dict for the ECS export — omits empty axes."""
        out: dict[str, list[str]] = {}
        if self.owasp_llm:
            out["owasp_llm"] = list(self.owasp_llm)
        if self.mitre_attack:
            out["mitre_attack"] = list(self.mitre_attack)
        if self.nist_ai_rmf:
            out["nist_ai_rmf"] = list(self.nist_ai_rmf)
        if self.eu_ai_act:
            out["eu_ai_act"] = list(self.eu_ai_act)
        return out


# MEASURE-2.7 ("AI system security and resilience are evaluated and documented")
# and MANAGE-4.1 ("post-deployment monitoring") apply to essentially every
# runtime detection Bulwark makes, so they recur below by design.
_MEASURE_SEC = "MEASURE-2.7"
_MANAGE_MON = "MANAGE-4.1"

# EU AI Act cybersecurity anchor (Art. 15 covers resilience against adversarial
# manipulation, data/model poisoning, and confidentiality attacks).
_EU_CYBER = "Article 15"
_EU_DATA_GOV = "Article 10"
_EU_HUMAN_OVERSIGHT = "Article 14"
_EU_RISK_MGMT = "Article 9"


_COMPLIANCE: dict[ThreatCategory, ComplianceMapping] = {
    ThreatCategory.PROMPT_INJECTION: ComplianceMapping(
        owasp_llm=("LLM01",),
        mitre_attack=("T1059",),
        nist_ai_rmf=(_MEASURE_SEC, _MANAGE_MON),
        eu_ai_act=(_EU_CYBER,),
    ),
    ThreatCategory.JAILBREAK: ComplianceMapping(
        owasp_llm=("LLM01",),
        mitre_attack=("T1190",),
        nist_ai_rmf=(_MEASURE_SEC, _MANAGE_MON),
        eu_ai_act=(_EU_CYBER,),
    ),
    ThreatCategory.TOOL_ABUSE: ComplianceMapping(
        owasp_llm=("LLM07", "LLM08"),  # Insecure Plugin Design + Excessive Agency
        mitre_attack=("T1059",),
        nist_ai_rmf=(_MEASURE_SEC, "MANAGE-2.1"),
        eu_ai_act=(_EU_HUMAN_OVERSIGHT, _EU_CYBER),
    ),
    ThreatCategory.EXFILTRATION: ComplianceMapping(
        owasp_llm=("LLM06",),  # Sensitive Information Disclosure
        mitre_attack=("T1041",),
        nist_ai_rmf=(_MEASURE_SEC, _MANAGE_MON),
        eu_ai_act=(_EU_DATA_GOV, _EU_CYBER),
    ),
    ThreatCategory.CREDENTIAL_ACCESS: ComplianceMapping(
        owasp_llm=("LLM06",),
        mitre_attack=("T1552",),
        nist_ai_rmf=(_MEASURE_SEC,),
        eu_ai_act=(_EU_CYBER,),
    ),
    ThreatCategory.REVERSE_SHELL: ComplianceMapping(
        owasp_llm=("LLM02",),  # Insecure Output Handling → downstream code exec
        mitre_attack=("T1059", "T1090"),
        nist_ai_rmf=(_MEASURE_SEC,),
        eu_ai_act=(_EU_CYBER,),
    ),
    ThreatCategory.MALICIOUS_DOMAIN: ComplianceMapping(
        owasp_llm=("LLM02",),
        mitre_attack=("T1071",),
        nist_ai_rmf=(_MEASURE_SEC,),
        eu_ai_act=(_EU_CYBER,),
    ),
    ThreatCategory.PII_LEAK: ComplianceMapping(
        owasp_llm=("LLM06",),
        mitre_attack=("T1552.005",),
        nist_ai_rmf=(_MEASURE_SEC, "MAP-5.1"),
        eu_ai_act=(_EU_DATA_GOV, _EU_CYBER),
    ),
    ThreatCategory.POLICY_VIOLATION: ComplianceMapping(
        nist_ai_rmf=("GOVERN-1.1", "MANAGE-2.1"),
        eu_ai_act=(_EU_RISK_MGMT,),
    ),
    ThreatCategory.RATE_LIMIT: ComplianceMapping(
        owasp_llm=("LLM04",),  # Model Denial of Service
        mitre_attack=("T1499",),
        nist_ai_rmf=(_MEASURE_SEC,),
        eu_ai_act=(_EU_CYBER,),
    ),
    ThreatCategory.INSECURE_OUTPUT: ComplianceMapping(
        owasp_llm=("LLM02",),
        nist_ai_rmf=(_MEASURE_SEC,),
        eu_ai_act=(_EU_CYBER,),
    ),
    ThreatCategory.DENIAL_OF_SERVICE: ComplianceMapping(
        owasp_llm=("LLM04",),
        mitre_attack=("T1499",),
        nist_ai_rmf=(_MEASURE_SEC,),
        eu_ai_act=(_EU_CYBER,),
    ),
    ThreatCategory.EXCESSIVE_AGENCY: ComplianceMapping(
        owasp_llm=("LLM08",),  # Excessive Agency
        nist_ai_rmf=("MANAGE-2.1", "GOVERN-1.1"),
        eu_ai_act=(_EU_HUMAN_OVERSIGHT,),
    ),
    ThreatCategory.MODEL_THEFT: ComplianceMapping(
        owasp_llm=("LLM10",),  # Model Theft
        mitre_attack=("T1020",),
        nist_ai_rmf=(_MEASURE_SEC,),
        eu_ai_act=(_EU_CYBER,),
    ),
    ThreatCategory.PRIVACY_ATTACK: ComplianceMapping(
        owasp_llm=("LLM06",),  # Sensitive Information Disclosure
        mitre_attack=("T1005",),
        nist_ai_rmf=(_MEASURE_SEC, "MAP-5.1"),
        eu_ai_act=(_EU_DATA_GOV, _EU_CYBER),
    ),
    ThreatCategory.PLAN_CORRUPTION: ComplianceMapping(
        owasp_llm=("LLM01",),
        nist_ai_rmf=(_MEASURE_SEC, _MANAGE_MON),
        eu_ai_act=(_EU_CYBER,),
    ),
    ThreatCategory.CROSS_AGENT_INJECTION: ComplianceMapping(
        owasp_llm=("LLM01",),  # indirect prompt injection propagation
        nist_ai_rmf=(_MEASURE_SEC, _MANAGE_MON),
        eu_ai_act=(_EU_CYBER,),
    ),
    ThreatCategory.MEMORY_MANIPULATION: ComplianceMapping(
        owasp_llm=("LLM03",),  # Training Data Poisoning (RAG/vector poisoning)
        mitre_attack=("T1565",),
        nist_ai_rmf=(_MEASURE_SEC, "MAP-2.3"),
        eu_ai_act=(_EU_DATA_GOV, _EU_CYBER),
    ),
}


def compliance_for(category: str | ThreatCategory | None) -> ComplianceMapping | None:
    """Return the compliance mapping for a threat category, or ``None``.

    Accepts either a :class:`ThreatCategory` or its string value (the exporter
    passes the ``.value``). Unknown/ad-hoc strings return ``None`` — no mapping is
    fabricated, so free-form categories used in tests or future code never emit a
    misleading compliance tag.
    """
    if category is None:
        return None
    if isinstance(category, ThreatCategory):
        return _COMPLIANCE.get(category)
    try:
        return _COMPLIANCE.get(ThreatCategory(category))
    except ValueError:
        return None


def all_mappings() -> dict[str, ComplianceMapping]:
    """All mappings keyed by the threat-category string value (for admin/docs)."""
    return {cat.value: mapping for cat, mapping in _COMPLIANCE.items()}
