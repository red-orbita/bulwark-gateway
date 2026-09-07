"""Lethal-trifecta config-time analyzer for agents and MCP toolsets.

The *lethal trifecta* (a framing popularised by Simon Willison) is the
observation that a prompt-injection attack only becomes a data-breach when an
agent simultaneously holds **all three** of these capability pillars:

1. **DATA_ACCESS** — reach to private / sensitive data (files, DB rows,
   secrets, environment).
2. **UNTRUSTED_EXPOSURE** — ingestion of attacker-controllable content (web
   fetches, search results, arbitrary network responses).
3. **EXFILTRATION** — an outbound channel able to carry data off (network
   POST, file write, upload).

Any single pillar is benign in isolation; two pillars are a warning; **all
three at once is the breach-enabling configuration**. Crucially the trifecta is
usually an *emergent* property of a whole toolset / agent policy rather than of
one tool — so this analyzer aggregates capabilities across every tool an agent
can reach before deciding.

This module is **pure, deterministic, and stdlib-only**. It performs no I/O,
emits no security events, and has zero coupling to ``admin`` — it is a
config-time assessment surface (reachable via the admin discovery API) that
reuses the capability vocabulary already established in ``mcp_inventory``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from src.discovery.mcp_inventory import MCPInventory, MCPTool


class TrifectaPillar(str, Enum):
    """The three capability pillars of the lethal trifecta."""

    DATA_ACCESS = "data_access"
    UNTRUSTED_EXPOSURE = "untrusted_exposure"
    EXFILTRATION = "exfiltration"


# Human-readable labels for findings / recommendations.
_PILLAR_LABELS: dict[TrifectaPillar, str] = {
    TrifectaPillar.DATA_ACCESS: "access to private data",
    TrifectaPillar.UNTRUSTED_EXPOSURE: "exposure to untrusted content",
    TrifectaPillar.EXFILTRATION: "an outbound exfiltration channel",
}

# Canonical capability -> the pillars it contributes to.
#
# Rationale for the multi-pillar assignments:
#   * network_access ingests attacker-controllable responses (exposure) AND can
#     POST data outward (exfiltration).
#   * execution capabilities (shell/code/process) can read any local data, pull
#     untrusted content, and ship it out — so they light up all three pillars on
#     their own and are inherently trifecta-complete.
_ALL_PILLARS: frozenset[TrifectaPillar] = frozenset(TrifectaPillar)

_CAPABILITY_PILLARS: dict[str, frozenset[TrifectaPillar]] = {
    # --- execution: spans every pillar by itself ---
    "shell_exec": _ALL_PILLARS,
    "code_execution": _ALL_PILLARS,
    "process_spawn": _ALL_PILLARS,
    # --- data access ---
    "file_read": frozenset({TrifectaPillar.DATA_ACCESS}),
    "database_read": frozenset({TrifectaPillar.DATA_ACCESS}),
    "secret_read": frozenset({TrifectaPillar.DATA_ACCESS}),
    "env_access": frozenset({TrifectaPillar.DATA_ACCESS}),
    # --- untrusted exposure ---
    "search": frozenset({TrifectaPillar.UNTRUSTED_EXPOSURE}),
    # --- untrusted exposure + exfiltration ---
    "network_access": frozenset(
        {TrifectaPillar.UNTRUSTED_EXPOSURE, TrifectaPillar.EXFILTRATION}
    ),
    # --- exfiltration ---
    "file_write": frozenset({TrifectaPillar.EXFILTRATION}),
    "database_write": frozenset({TrifectaPillar.EXFILTRATION}),
}

# Reconcile the neighbouring capability vocabularies (mcp_privilege, ad-hoc tool
# manifests) down to the canonical names above so a single analyzer covers them
# all. Values map a raw capability string -> canonical capability key.
_CAPABILITY_SYNONYMS: dict[str, str] = {
    # mcp_privilege / filesystem phrasing
    "filesystem_read": "file_read",
    "filesystem_write": "file_write",
    "fs_read": "file_read",
    "fs_write": "file_write",
    "read_file": "file_read",
    "write_file": "file_write",
    # database phrasing
    "database": "database_read",
    "db_read": "database_read",
    "db_write": "database_write",
    "sql": "database_read",
    # environment / secrets
    "environment": "env_access",
    "env": "env_access",
    "secrets": "secret_read",
    "credential_read": "secret_read",
    # network phrasing
    "network": "network_access",
    "http": "network_access",
    "fetch": "network_access",
    "web": "network_access",
    "http_request": "network_access",
    "upload": "network_access",
    "download": "network_access",
    # execution phrasing
    "shell": "shell_exec",
    "exec": "code_execution",
    "execute": "code_execution",
    "eval": "code_execution",
    "subprocess": "process_spawn",
    "spawn": "process_spawn",
}


def _canonicalize(capability: str) -> str:
    """Map any known capability spelling to its canonical key."""
    key = capability.strip().lower()
    return _CAPABILITY_SYNONYMS.get(key, key)


def pillars_for_capabilities(capabilities: list[str]) -> set[TrifectaPillar]:
    """Map a raw capability list to the set of trifecta pillars it satisfies.

    Pure, deterministic, side-effect-free. Unknown/benign capabilities (e.g.
    ``text_generation``) contribute no pillar. This is the SSOT capability→pillar
    projection reused by both the config-time :class:`LethalTrifectaAnalyzer` and
    the runtime accumulator (:mod:`src.correlation.trifecta_runtime`), so the two
    surfaces can never diverge on what a capability means.

    Args:
        capabilities: Capability strings in any supported spelling.

    Returns:
        The set of :class:`TrifectaPillar` the capabilities collectively light up.
    """
    pillars: set[TrifectaPillar] = set()
    for raw in capabilities:
        mapped = _CAPABILITY_PILLARS.get(_canonicalize(raw))
        if mapped:
            pillars.update(mapped)
    return pillars


def pillars_for_tools(tool_names: list[str]) -> set[TrifectaPillar]:
    """Map a list of *tool names* to the trifecta pillars they collectively satisfy.

    Capabilities are inferred from each tool name via the established
    :meth:`MCPInventory._infer_capabilities` name heuristic (name only — no
    description/schema at runtime), then projected onto pillars. Pure and
    deterministic; performs no I/O and emits no events.

    Args:
        tool_names: Names of the tools invoked/available.

    Returns:
        The union of pillars across every tool's inferred capabilities.
    """
    if not tool_names:
        return set()
    inventory = MCPInventory()
    caps: list[str] = []
    for name in tool_names:
        if not name:
            continue
        caps.extend(inventory._infer_capabilities(name, "", {}))
    return pillars_for_capabilities(caps)


@dataclass
class TrifectaAssessment:
    """Result of a lethal-trifecta analysis over a capability set."""

    score: float  # 0-10
    verdict: str  # "critical" | "warn" | "safe"
    complete: bool  # all three pillars present
    pillars_present: list[str] = field(default_factory=list)
    pillar_evidence: dict[str, list[str]] = field(default_factory=dict)
    findings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    break_recommendation: str | None = None


class LethalTrifectaAnalyzer:
    """Deterministic lethal-trifecta assessor for capabilities, tools, agents.

    The analyzer never mutates state and performs no I/O. All three entry points
    ultimately funnel through :meth:`analyze_capabilities`, which maps a set of
    capabilities onto the three pillars and scores the combination.
    """

    # Score bands keyed on the number of distinct pillars present.
    _SCORE_COMPLETE = 9.0  # all three -> critical
    _SCORE_TWO = 5.0       # two pillars -> warn
    _SCORE_ONE = 2.0       # one pillar  -> safe/low
    _SCORE_NONE = 0.0

    def analyze_capabilities(self, capabilities: list[str]) -> TrifectaAssessment:
        """Assess a raw capability list for the lethal trifecta.

        Args:
            capabilities: Capability strings (any supported spelling).

        Returns:
            A :class:`TrifectaAssessment` describing which pillars are present,
            the evidence, a 0-10 score, and — when complete — the cheapest
            pillar to remove to break the trifecta.
        """
        evidence: dict[TrifectaPillar, list[str]] = {
            pillar: [] for pillar in TrifectaPillar
        }

        for raw in capabilities:
            canonical = _canonicalize(raw)
            pillars = _CAPABILITY_PILLARS.get(canonical)
            if not pillars:
                continue
            for pillar in pillars:
                if canonical not in evidence[pillar]:
                    evidence[pillar].append(canonical)

        present = [p for p in TrifectaPillar if evidence[p]]
        pillar_count = len(present)
        complete = pillar_count == 3

        if complete:
            score = self._SCORE_COMPLETE
            verdict = "critical"
        elif pillar_count == 2:
            score = self._SCORE_TWO
            verdict = "warn"
        elif pillar_count == 1:
            score = self._SCORE_ONE
            verdict = "safe"
        else:
            score = self._SCORE_NONE
            verdict = "safe"

        findings = self._build_findings(evidence, present, complete)
        recommendations, break_reco = self._build_recommendations(
            evidence, present, complete
        )

        return TrifectaAssessment(
            score=round(score, 1),
            verdict=verdict,
            complete=complete,
            pillars_present=[p.value for p in present],
            pillar_evidence={
                p.value: sorted(evidence[p]) for p in present
            },
            findings=findings,
            recommendations=recommendations,
            break_recommendation=break_reco,
        )

    def analyze_tools(self, tools: list[MCPTool]) -> TrifectaAssessment:
        """Assess a *toolset* — the trifecta as an emergent property.

        Capabilities are pooled across every tool because the breach-enabling
        combination frequently spans multiple tools (e.g. one tool reads
        secrets, another fetches URLs) even when no single tool is dangerous.

        Args:
            tools: The tools an agent can reach.

        Returns:
            A :class:`TrifectaAssessment` over the union of tool capabilities.
        """
        pooled: list[str] = []
        for tool in tools:
            pooled.extend(tool.capabilities)
        return self.analyze_capabilities(pooled)

    def analyze_agent(
        self,
        *,
        allowed_tools: list[str] | None = None,
        denied_tools: list[str] | None = None,
        allow_command_execution: bool = False,
        allow_file_write: bool = False,
        allow_network_access: bool = True,
    ) -> TrifectaAssessment:
        """Assess an agent's *effective* capability exposure under its policy.

        Capabilities are inferred from the names of the agent's allowed (and not
        denied) tools, then filtered by the policy's boolean gates: a capability
        the policy blocks at runtime is not counted, because it cannot actually
        contribute to a breach. This mirrors the fields on
        :class:`src.guardrails.tool_policy.AgentPolicy` so a caller can pass a
        policy straight through.

        Args:
            allowed_tools: Tool names the agent may call (empty/None = the
                inference is name-driven only, so no tools => no capabilities).
            denied_tools: Tool names explicitly blocked — excluded from analysis.
            allow_command_execution: Gate for shell/code/process capabilities.
            allow_file_write: Gate for file-write capability.
            allow_network_access: Gate for network capability.

        Returns:
            A :class:`TrifectaAssessment` over the effective capability set.
        """
        allowed = allowed_tools or []
        denied = {name.strip().lower() for name in (denied_tools or [])}
        inventory = MCPInventory()

        _EXEC_CAPS = {"shell_exec", "code_execution", "process_spawn"}
        effective: list[str] = []

        for name in allowed:
            if name.strip().lower() in denied:
                continue
            # Reuse the established name/description inference (name only here).
            for cap in inventory._infer_capabilities(name, "", {}):
                # Apply the policy gates: a blocked capability cannot contribute.
                if cap in _EXEC_CAPS and not allow_command_execution:
                    continue
                if cap == "file_write" and not allow_file_write:
                    continue
                if cap == "network_access" and not allow_network_access:
                    continue
                effective.append(cap)

        return self.analyze_capabilities(effective)

    # --- internal helpers ---

    def _build_findings(
        self,
        evidence: dict[TrifectaPillar, list[str]],
        present: list[TrifectaPillar],
        complete: bool,
    ) -> list[str]:
        findings: list[str] = []
        for pillar in present:
            caps = sorted(evidence[pillar])
            findings.append(
                f"Pillar '{pillar.value}' ({_PILLAR_LABELS[pillar]}) satisfied "
                f"by: {', '.join(caps)}"
            )
        if complete:
            findings.insert(
                0,
                "LETHAL TRIFECTA COMPLETE: the agent simultaneously has data "
                "access, untrusted-content exposure, and an exfiltration channel "
                "— a prompt injection here can turn into a data breach.",
            )
        elif len(present) == 2:
            missing = [p for p in TrifectaPillar if p not in present][0]
            findings.insert(
                0,
                f"Two of three trifecta pillars present; only missing "
                f"'{missing.value}' ({_PILLAR_LABELS[missing]}). One added "
                f"capability would complete the breach configuration.",
            )
        return findings

    def _build_recommendations(
        self,
        evidence: dict[TrifectaPillar, list[str]],
        present: list[TrifectaPillar],
        complete: bool,
    ) -> tuple[list[str], str | None]:
        recommendations: list[str] = []
        break_reco: str | None = None

        if complete:
            # The cheapest pillar to break is the one backed by the fewest
            # capabilities (fewest tools/permissions to revoke).
            cheapest = min(
                present,
                key=lambda p: (len(evidence[p]), p.value),
            )
            caps = sorted(evidence[cheapest])
            break_reco = (
                f"Break the trifecta by removing pillar '{cheapest.value}' "
                f"({_PILLAR_LABELS[cheapest]}): revoke capability/tool(s) "
                f"{caps}. Removing any one pillar renders the combination safe."
            )
            recommendations.append(break_reco)
            recommendations.append(
                "Prefer isolating untrusted-content ingestion from private-data "
                "access, or gating the outbound channel behind human approval."
            )
        elif len(present) == 2:
            recommendations.append(
                "Do not grant the remaining pillar to this agent without "
                "compensating controls (sandboxing, egress filtering, or "
                "human-in-the-loop on the outbound action)."
            )
        else:
            recommendations.append(
                "No lethal-trifecta risk: fewer than two pillars present."
            )

        return recommendations, break_reco
