"""Declarative compliance mapping — ThreatCategory → regulatory/standards refs.

Bulwark's guardrails already classify every detection into a :class:`ThreatCategory`.
This module is the SINGLE SOURCE OF TRUTH for the external framework references a
security/compliance team needs when a detection lands in their SIEM — and for the
threat-intel reference badges rendered in the admin UI (which fetch this table via
``GET /admin/compliance/mappings`` rather than keeping their own copy).

Axes:

  * ``owasp_llm``    — OWASP Top 10 for LLM Applications, **2025** numbering
                       (LLM01 Prompt Injection … LLM10 Unbounded Consumption).
  * ``mitre_atlas``  — MITRE ATLAS technique IDs (``AML.T*``) — the AI-specific
                       adversary framework (prompt injection, jailbreak, model
                       extraction, RAG poisoning, …).
  * ``mitre_attack`` — MITRE ATT&CK technique IDs (``T*``) — the classic
                       enterprise framework, for the conventional exploitation a
                       detection also implies (command execution, exfiltration, …).
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
  * :data:`REFERENCE_CATALOG` gives every OWASP/ATLAS/ATT&CK code its human label
    and canonical URL. It is the display companion to the code-only mappings, so
    the admin UI never re-hardcodes labels/links. A unit test enforces that every
    code referenced by a mapping has a catalog entry (no dangling codes).

OWASP 2023 → 2025 note: the 2025 revision renumbered several risks. Notably the
old *LLM10 Model Theft* was folded into **LLM10 Unbounded Consumption** (which
covers model extraction via excessive querying), *Insecure Output Handling*
(2023 LLM02) became **LLM05 Improper Output Handling**, and *Sensitive
Information Disclosure* moved from LLM06 to **LLM02**. Exports carry
``owasp_llm_version`` so downstream consumers are never guessing the revision.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.models import ThreatCategory

# Version of the OWASP LLM Top 10 the `owasp_llm` codes refer to. Recorded on
# every exported event so downstream consumers are never guessing the revision.
OWASP_LLM_VERSION = "2025"


@dataclass(frozen=True)
class ComplianceMapping:
    """Framework references for a single threat category (all optional).

    Tuples (not lists) so the mapping is immutable and safely shared.
    """

    owasp_llm: tuple[str, ...] = ()
    mitre_atlas: tuple[str, ...] = ()
    mitre_attack: tuple[str, ...] = ()
    nist_ai_rmf: tuple[str, ...] = ()
    eu_ai_act: tuple[str, ...] = ()

    def is_empty(self) -> bool:
        return not (
            self.owasp_llm
            or self.mitre_atlas
            or self.mitre_attack
            or self.nist_ai_rmf
            or self.eu_ai_act
        )

    def to_dict(self) -> dict[str, list[str]]:
        """Compact dict for the ECS export — omits empty axes."""
        out: dict[str, list[str]] = {}
        if self.owasp_llm:
            out["owasp_llm"] = list(self.owasp_llm)
        if self.mitre_atlas:
            out["mitre_atlas"] = list(self.mitre_atlas)
        if self.mitre_attack:
            out["mitre_attack"] = list(self.mitre_attack)
        if self.nist_ai_rmf:
            out["nist_ai_rmf"] = list(self.nist_ai_rmf)
        if self.eu_ai_act:
            out["eu_ai_act"] = list(self.eu_ai_act)
        return out

    def display_codes(self) -> list[str]:
        """Ordered OWASP → ATLAS → ATT&CK codes for UI reference badges.

        NIST/EU axes are policy references without a per-code catalog entry, so
        they are not surfaced as clickable badges.
        """
        return list(self.owasp_llm) + list(self.mitre_atlas) + list(self.mitre_attack)


@dataclass(frozen=True)
class Reference:
    """Display metadata for a single framework code (label + canonical URL)."""

    label: str
    url: str
    framework: str  # "owasp" | "atlas" | "attack"

    def to_dict(self) -> dict[str, str]:
        return {"label": self.label, "url": self.url, "framework": self.framework}


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


# ── Reference catalog: code → human label + canonical URL ────────────────────
# Every OWASP/ATLAS/ATT&CK code used in a mapping below MUST appear here (a unit
# test enforces it), so the admin UI can render a labelled, clickable badge
# without re-hardcoding the label/link.
REFERENCE_CATALOG: dict[str, Reference] = {
    # OWASP GenAI 2025 — LLM Top 10 (only the risks actually mapped below)
    "LLM01": Reference(
        "OWASP LLM01: Prompt Injection",
        "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
        "owasp",
    ),
    "LLM02": Reference(
        "OWASP LLM02: Sensitive Information Disclosure",
        "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/",
        "owasp",
    ),
    "LLM05": Reference(
        "OWASP LLM05: Improper Output Handling",
        "https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/",
        "owasp",
    ),
    "LLM06": Reference(
        "OWASP LLM06: Excessive Agency",
        "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
        "owasp",
    ),
    "LLM08": Reference(
        "OWASP LLM08: Vector & Embedding Weaknesses",
        "https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/",
        "owasp",
    ),
    "LLM10": Reference(
        "OWASP LLM10: Unbounded Consumption",
        "https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/",
        "owasp",
    ),
    # MITRE ATLAS — AI-specific adversary techniques
    "AML.T0024": Reference(
        "ATLAS AML.T0024: Exfiltration via AI Inference API",
        "https://atlas.mitre.org/techniques/AML.T0024",
        "atlas",
    ),
    "AML.T0029": Reference(
        "ATLAS AML.T0029: Denial of AI Service",
        "https://atlas.mitre.org/techniques/AML.T0029",
        "atlas",
    ),
    "AML.T0048": Reference(
        "ATLAS AML.T0048: External Harms",
        "https://atlas.mitre.org/techniques/AML.T0048",
        "atlas",
    ),
    "AML.T0051": Reference(
        "ATLAS AML.T0051: LLM Prompt Injection",
        "https://atlas.mitre.org/techniques/AML.T0051",
        "atlas",
    ),
    "AML.T0054": Reference(
        "ATLAS AML.T0054: LLM Jailbreak",
        "https://atlas.mitre.org/techniques/AML.T0054",
        "atlas",
    ),
    "AML.T0057": Reference(
        "ATLAS AML.T0057: LLM Data Leakage",
        "https://atlas.mitre.org/techniques/AML.T0057",
        "atlas",
    ),
    "AML.T0070": Reference(
        "ATLAS AML.T0070: RAG Poisoning",
        "https://atlas.mitre.org/techniques/AML.T0070",
        "atlas",
    ),
    # MITRE ATT&CK — classic enterprise techniques
    "T1005": Reference(
        "ATT&CK T1005: Data from Local System",
        "https://attack.mitre.org/techniques/T1005/",
        "attack",
    ),
    "T1020": Reference(
        "ATT&CK T1020: Automated Exfiltration",
        "https://attack.mitre.org/techniques/T1020/",
        "attack",
    ),
    "T1041": Reference(
        "ATT&CK T1041: Exfiltration Over C2 Channel",
        "https://attack.mitre.org/techniques/T1041/",
        "attack",
    ),
    "T1059": Reference(
        "ATT&CK T1059: Command & Scripting Interpreter",
        "https://attack.mitre.org/techniques/T1059/",
        "attack",
    ),
    "T1071": Reference(
        "ATT&CK T1071: Application Layer Protocol",
        "https://attack.mitre.org/techniques/T1071/",
        "attack",
    ),
    "T1090": Reference(
        "ATT&CK T1090: Proxy",
        "https://attack.mitre.org/techniques/T1090/",
        "attack",
    ),
    "T1190": Reference(
        "ATT&CK T1190: Exploit Public-Facing Application",
        "https://attack.mitre.org/techniques/T1190/",
        "attack",
    ),
    "T1499": Reference(
        "ATT&CK T1499: Endpoint Denial of Service",
        "https://attack.mitre.org/techniques/T1499/",
        "attack",
    ),
    "T1552": Reference(
        "ATT&CK T1552: Unsecured Credentials",
        "https://attack.mitre.org/techniques/T1552/",
        "attack",
    ),
    "T1552.005": Reference(
        "ATT&CK T1552.005: Cloud Instance Metadata API",
        "https://attack.mitre.org/techniques/T1552/005/",
        "attack",
    ),
    "T1565": Reference(
        "ATT&CK T1565: Data Manipulation",
        "https://attack.mitre.org/techniques/T1565/",
        "attack",
    ),
}


_COMPLIANCE: dict[ThreatCategory, ComplianceMapping] = {
    ThreatCategory.PROMPT_INJECTION: ComplianceMapping(
        owasp_llm=("LLM01",),
        mitre_atlas=("AML.T0051",),
        mitre_attack=("T1059",),
        nist_ai_rmf=(_MEASURE_SEC, _MANAGE_MON),
        eu_ai_act=(_EU_CYBER,),
    ),
    ThreatCategory.JAILBREAK: ComplianceMapping(
        owasp_llm=("LLM01",),
        mitre_atlas=("AML.T0054",),
        mitre_attack=("T1190",),
        nist_ai_rmf=(_MEASURE_SEC, _MANAGE_MON),
        eu_ai_act=(_EU_CYBER,),
    ),
    ThreatCategory.TOOL_ABUSE: ComplianceMapping(
        owasp_llm=("LLM06",),  # Excessive Agency (2025 — absorbs Insecure Plugin Design)
        mitre_attack=("T1059",),
        nist_ai_rmf=(_MEASURE_SEC, "MANAGE-2.1"),
        eu_ai_act=(_EU_HUMAN_OVERSIGHT, _EU_CYBER),
    ),
    ThreatCategory.EXFILTRATION: ComplianceMapping(
        owasp_llm=("LLM02",),  # Sensitive Information Disclosure (2025)
        mitre_attack=("T1041",),
        nist_ai_rmf=(_MEASURE_SEC, _MANAGE_MON),
        eu_ai_act=(_EU_DATA_GOV, _EU_CYBER),
    ),
    ThreatCategory.CREDENTIAL_ACCESS: ComplianceMapping(
        owasp_llm=("LLM02",),
        mitre_attack=("T1552",),
        nist_ai_rmf=(_MEASURE_SEC,),
        eu_ai_act=(_EU_CYBER,),
    ),
    ThreatCategory.REVERSE_SHELL: ComplianceMapping(
        owasp_llm=("LLM05",),  # Improper Output Handling → downstream code exec (2025)
        mitre_attack=("T1059", "T1090"),
        nist_ai_rmf=(_MEASURE_SEC,),
        eu_ai_act=(_EU_CYBER,),
    ),
    ThreatCategory.MALICIOUS_DOMAIN: ComplianceMapping(
        owasp_llm=("LLM05",),  # model emitting a malicious URL = improper output handling
        mitre_attack=("T1071",),
        nist_ai_rmf=(_MEASURE_SEC,),
        eu_ai_act=(_EU_CYBER,),
    ),
    ThreatCategory.PII_LEAK: ComplianceMapping(
        owasp_llm=("LLM02",),
        mitre_atlas=("AML.T0057",),
        mitre_attack=("T1552.005",),
        nist_ai_rmf=(_MEASURE_SEC, "MAP-5.1"),
        eu_ai_act=(_EU_DATA_GOV, _EU_CYBER),
    ),
    ThreatCategory.POLICY_VIOLATION: ComplianceMapping(
        # Not an OWASP LLM risk — a governance/policy control, so no owasp_llm code.
        nist_ai_rmf=("GOVERN-1.1", "MANAGE-2.1"),
        eu_ai_act=(_EU_RISK_MGMT,),
    ),
    ThreatCategory.RATE_LIMIT: ComplianceMapping(
        owasp_llm=("LLM10",),  # Unbounded Consumption (2025 — absorbs Model DoS)
        mitre_attack=("T1499",),
        nist_ai_rmf=(_MEASURE_SEC,),
        eu_ai_act=(_EU_CYBER,),
    ),
    ThreatCategory.INSECURE_OUTPUT: ComplianceMapping(
        owasp_llm=("LLM05",),  # Improper Output Handling (2025)
        mitre_attack=("T1059",),
        nist_ai_rmf=(_MEASURE_SEC,),
        eu_ai_act=(_EU_CYBER,),
    ),
    ThreatCategory.DENIAL_OF_SERVICE: ComplianceMapping(
        owasp_llm=("LLM10",),  # Unbounded Consumption (2025)
        mitre_atlas=("AML.T0029",),
        mitre_attack=("T1499",),
        nist_ai_rmf=(_MEASURE_SEC,),
        eu_ai_act=(_EU_CYBER,),
    ),
    ThreatCategory.EXCESSIVE_AGENCY: ComplianceMapping(
        owasp_llm=("LLM06",),  # Excessive Agency
        mitre_atlas=("AML.T0048",),
        nist_ai_rmf=("MANAGE-2.1", "GOVERN-1.1"),
        eu_ai_act=(_EU_HUMAN_OVERSIGHT,),
    ),
    ThreatCategory.MODEL_THEFT: ComplianceMapping(
        owasp_llm=("LLM10",),  # Unbounded Consumption (2025 — model extraction via querying)
        mitre_atlas=("AML.T0024",),
        mitre_attack=("T1020",),
        nist_ai_rmf=(_MEASURE_SEC,),
        eu_ai_act=(_EU_CYBER,),
    ),
    ThreatCategory.PRIVACY_ATTACK: ComplianceMapping(
        owasp_llm=("LLM02",),  # Sensitive Information Disclosure
        mitre_atlas=("AML.T0024",),
        mitre_attack=("T1005",),
        nist_ai_rmf=(_MEASURE_SEC, "MAP-5.1"),
        eu_ai_act=(_EU_DATA_GOV, _EU_CYBER),
    ),
    ThreatCategory.PLAN_CORRUPTION: ComplianceMapping(
        owasp_llm=("LLM01",),
        mitre_atlas=("AML.T0051",),
        nist_ai_rmf=(_MEASURE_SEC, _MANAGE_MON),
        eu_ai_act=(_EU_CYBER,),
    ),
    ThreatCategory.CROSS_AGENT_INJECTION: ComplianceMapping(
        owasp_llm=("LLM01",),  # indirect prompt injection propagation
        mitre_atlas=("AML.T0051",),
        nist_ai_rmf=(_MEASURE_SEC, _MANAGE_MON),
        eu_ai_act=(_EU_CYBER,),
    ),
    ThreatCategory.MEMORY_MANIPULATION: ComplianceMapping(
        owasp_llm=("LLM08",),  # Vector & Embedding Weaknesses (2025 — RAG/vector poisoning)
        mitre_atlas=("AML.T0070",),
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


def reference_catalog() -> dict[str, Reference]:
    """Code → :class:`Reference` (label + URL + framework) for every mapped code."""
    return dict(REFERENCE_CATALOG)
