# Sentinel Gateway — Market Comparison & Growth Strategy

Date: June 13, 2026
Version: 0.4.3 | Enterprise Score: 8.7/10

---

## Executive Summary

Sentinel Gateway is the **only open-source, self-hosted AI security proxy** that combines:
- Zero-LLM-call hot path (pure regex, <5ms decision time)
- Native SIEM/SOC integration (ECS format, 6 transports)
- Multi-tenant architecture with per-agent RBAC
- Threat intelligence feeds (ThreatFox, URLhaus, OTX, AbuseIPDB)
- MCP tool security scanning (138 patterns)
- Built-in red teaming framework (95% live detection rate)

The market is consolidating rapidly (Lakera→Check Point, LLM Guard→Palo Alto, Robust Intelligence→Cisco), creating a gap for an independent, self-hosted alternative that security teams can own and operate.

---

## Competitive Landscape

### Market Consolidation (2024-2026)

| Company | Acquired By | Reported Price | Impact |
|---------|-------------|----------------|--------|
| Robust Intelligence | Cisco | ~$1B | Became "Cisco AI Defense" |
| Protect AI (LLM Guard) | Palo Alto Networks | Undisclosed | Part of "Prisma AIRS" |
| Lakera | Check Point Software | Undisclosed | Bundled into Check Point AI Security |

**Implication**: Standalone guardrail tools are being absorbed into mega-vendor platforms. Enterprises that want independence, transparency, or multi-vendor security stacks need alternatives.

### Detailed Competitor Matrix

| Capability | Sentinel Gateway | Lakera (Check Point) | LLM Guard (Palo Alto) | NeMo Guardrails | Guardrails AI | Prompt Security |
|---|---|---|---|---|---|---|
| **Deployment** | Self-hosted (K8s/Docker) | SaaS only | OSS library + Palo Alto SaaS | Self-hosted library | OSS + SaaS (Snowglobe) | SaaS + Self-hosted |
| **License** | GPL-3.0 | Proprietary | MIT (OSS), Proprietary (enterprise) | Apache 2.0 | Apache 2.0 | Proprietary |
| **Detection Approach** | Regex + async ML (hybrid) | ML-only (proprietary models) | ML + NER + regex (modular) | LLM-based (requires LLM calls) | Validator framework | ML + rules (hybrid) |
| **Hot-path Latency** | <5ms (regex), <50ms (with ML blocking) | <50ms | Variable (ML model-dependent) | 200-2000ms (LLM calls) | Variable | Unknown |
| **Detection Rate** | 98.2% (standard), 97.2% (exhaustive) | Unknown (claims <0.01% FPR) | Unknown | N/A | N/A | Unknown |
| **False Positive Rate** | 0.0% (benchmarked) | <0.01% (claimed) | Unknown | Unknown | Unknown | Unknown |
| **SIEM Integration** | Native (Splunk, Elastic, QRadar, Sentinel, Datadog, Wazuh) | Unknown | No | No | No | Unknown |
| **Multi-tenant** | Yes (per-tenant policies, rate limits, backends) | Unknown | No | No | No | Yes |
| **Tool/Agent RBAC** | Yes (per-agent allowed/denied tools, argument validation) | Limited | No | Limited (Colang flows) | No | Yes (MCP Gateway) |
| **IOC/Threat Intel** | Yes (ThreatFox, URLhaus, OTX, AbuseIPDB) | No (ML-based detection only) | MaliciousURLs scanner only | No | No | No |
| **Streaming SSE Filter** | Yes (256-char sliding window) | Unknown | No | No | No | Unknown |
| **Red Teaming** | Built-in (4 categories, template+mutation+encoding) | Gandalf (separate product) | Via Recon (separate product) | No | Via Snowglobe (separate) | Yes (separate) |
| **MCP Security** | Yes (SkillSpector 138 patterns: poisoning, privilege, overlay) | Yes (claimed) | No | No | No | Yes (MCP Gateway) |
| **Shadow AI Discovery** | Yes (29 known AI endpoints, DNS classification) | Yes (Workforce AI product) | No | No | No | Yes |
| **Admin Dashboard** | Yes (HTMX/Alpine.js, real-time SSE metrics) | SaaS console | No (library only) | No | SaaS console | SaaS console |
| **SSRF Protection** | Yes (RFC1918, CGNAT, cloud metadata, DNS rebinding) | N/A (SaaS) | No | No | No | Unknown |
| **Pricing** | Free (GPL-3.0) | Enterprise (sales-driven) | Free (OSS) / Enterprise (Palo Alto) | Free | Free (OSS) / Enterprise | Enterprise (sales-driven) |

### Where Sentinel Gateway Wins

1. **Security Operations Focus**: Only product with native SIEM integration, ECS-formatted events, Wazuh rules with MITRE ATT&CK mapping. Built FOR security teams, not just developers.

2. **Deterministic + Explainable**: Every block has an exact pattern ID, description, and category. No ML black box. Auditable for compliance.

3. **Zero External Dependencies in Hot Path**: No LLM calls, no cloud API calls, no network calls during request processing. Works air-gapped.

4. **Multi-Tenant by Design**: Not bolted on — every component (policies, rate limits, agent routing, telemetry) is tenant-aware from the ground up.

5. **Threat Intelligence Integration**: Bridges traditional SecOps (IOC feeds) with AI security. No other guardrail product does this.

6. **Self-Hosted + Open Source**: Full control over data, no vendor lock-in, no data leaving the network. Critical for regulated industries (healthcare, finance, government).

7. **MCP Security Depth**: 138 detection patterns across tool poisoning, privilege escalation, and behavioral analysis. Most competitors offer only basic MCP awareness.

### Where Competitors Win

| Competitor | Their Advantage |
|------------|----------------|
| Lakera | Crowdsourced attack data (1M+ hackers); ML catches novel semantic attacks regex cannot; 100+ languages natively |
| LLM Guard | Broader scanner ecosystem (35+ scanners); MIT license (more permissive); Palo Alto enterprise backing |
| NeMo | Programmable dialog flows (Colang); deep NVIDIA ecosystem integration; NVIDIA brand trust |
| Guardrails AI | Hub marketplace (65+ validators); Snowglobe eval platform; Andrew Ng endorsement |
| Prompt Security | Broadest coverage (employees + apps + code assistants + agents); MCP Gateway product; browser extension for shadow AI |

---

## Target Market Segments

### Primary: Security-First Organizations (Self-Hosted)

**Profile**: Fortune 500 companies with dedicated SOC/SIEM teams deploying AI internally.

| Characteristic | Details |
|---|---|
| Industries | Financial services, healthcare, defense, government, critical infrastructure |
| Team | 5-50 person security team with SIEM (Splunk/Elastic/QRadar) already deployed |
| AI Maturity | Deploying internal LLM agents (Ollama, vLLM, Azure OpenAI) |
| Requirements | Data sovereignty, audit trail, compliance (SOC 2, HIPAA, FedRAMP), no external data sharing |
| Pain Point | "We have AI agents in production but no visibility or control from the SOC" |
| Budget | $50K-$500K/year for AI security tooling |

**Why they choose Sentinel**: Self-hosted, SIEM-native, explainable blocks, multi-tenant, no data leaves the network.

### Secondary: Platform Companies (Multi-Tenant)

**Profile**: SaaS companies offering AI features to their customers who need tenant isolation.

| Characteristic | Details |
|---|---|
| Industries | B2B SaaS, AI platforms, managed service providers |
| Team | Platform engineering + security team |
| AI Maturity | Multi-model, multi-tenant LLM serving |
| Requirements | Per-tenant policies, rate limiting, usage tracking, tool-call RBAC |
| Pain Point | "Each customer has different security requirements for their AI agents" |
| Budget | $100K-$1M/year (or % of platform revenue) |

**Why they choose Sentinel**: Multi-tenant architecture, per-agent policies, rate limiting, tenant-aware telemetry.

### Tertiary: Compliance-Driven Organizations

**Profile**: Organizations adopting AI under regulatory pressure (EU AI Act, NIST AI RMF).

| Characteristic | Details |
|---|---|
| Industries | Banking (PCI DSS), healthcare (HIPAA), EU companies (AI Act), US government (EO 14110) |
| Team | Compliance + legal + security |
| Requirements | Audit trail, explainable decisions, policy documentation, incident response |
| Pain Point | "We need to prove our AI systems are safe for regulators" |

**Why they choose Sentinel**: Deterministic decisions, audit log, MITRE ATT&CK mapping, policy-as-code, incident response integration.

---

## Growth Strategy

### Phase 1: Community Building (Months 1-3)

**Objective**: 500 GitHub stars, 50 active deployments, community recognition.

| Channel | Action | Target |
|---------|--------|--------|
| Reddit | Technical deep-dives (r/netsec, r/MachineLearning, r/selfhosted, r/cybersecurity) | 5 posts, 10K+ views |
| Hacker News | "Show HN" launch post | Front page, 200+ points |
| GitHub | Optimize README, add badges, contribution guide, issue templates | 500 stars |
| DEV.to / Medium | Architecture blog posts (SSRF protection, regex engine design, SIEM integration) | 3 articles |
| YouTube | Demo video: "Block prompt injection in 5 minutes" | 1 video, 5K views |
| Discord/Slack | Community server for users and contributors | 100 members |

### Phase 2: Enterprise Validation (Months 3-6)

**Objective**: 3-5 enterprise design partners, production deployments.

| Action | Details |
|--------|---------|
| SOC 2 Type I | Formal audit of security controls |
| OWASP LLM Top 10 coverage mapping | Publish compliance matrix |
| Enterprise support tier | 24/7 support, SLA, dedicated Slack |
| Terraform provider | Infrastructure-as-code deployment |
| Benchmark publication | Reproducible results vs competitors |

### Phase 3: Commercial (Months 6-12)

**Objective**: Revenue, managed offering, partner ecosystem.

| Action | Details |
|--------|---------|
| Managed SaaS option | For teams that don't want to self-host |
| Partner integrations | LangChain, LlamaIndex, CrewAI official integration |
| Consulting services | Deployment, policy design, custom patterns |
| Training/certification | "Sentinel Gateway Administrator" program |
| Plugin marketplace | Community-contributed scanners |

---

## Pricing Strategy (Future)

| Tier | Target | Price | Includes |
|------|--------|-------|----------|
| **Community** | Individual developers, small teams | Free (GPL-3.0) | Full product, community support |
| **Professional** | Mid-market, single-tenant | $500/month | Priority support, SLA, update notifications |
| **Enterprise** | Fortune 500, multi-tenant | $2,000-$10,000/month | 24/7 support, custom patterns, compliance reports, dedicated CSM |
| **Managed** | Teams that don't want to self-host | $5,000-$25,000/month | Fully managed, hosted in customer's VPC |

### Value Metric

Price per protected agent per month (not per request — more predictable for enterprises).

---

## Key Metrics to Track

| Metric | Current | 3-Month Target | 6-Month Target |
|--------|---------|----------------|----------------|
| GitHub stars | ~0 | 500 | 2,000 |
| Docker pulls | ~0 | 5,000 | 50,000 |
| Active deployments | 1 (dev) | 50 | 200 |
| Enterprise design partners | 0 | 3 | 5 |
| Detection rate (benchmark) | 98.2% | 99%+ | 99%+ |
| False positive rate | 0.0% | <0.01% | <0.01% |
| Community contributors | 1 | 10 | 30 |
| Reddit/HN mentions | 0 | 20 | 50 |

---

## Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| GPL-3.0 scares enterprise legal | Offer commercial license option (dual-license); GPL is fine for internal deployment (not SaaS redistribution) |
| Mega-vendors bundle guardrails free with cloud | Differentiate on depth, transparency, multi-cloud neutrality |
| Pure regex misses novel semantic attacks | Hybrid approach: regex hot path + async ML enrichment; publish detection rates transparently |
| Small team vs. funded competitors | Focus on self-hosted niche; leverage community; don't compete on ML training data |
| No SaaS offering limits growth | Start with self-hosted (differentiator), add managed offering in Phase 3 |

---

## Appendix: OWASP LLM Top 10 Coverage

| # | Risk | Sentinel Coverage |
|---|------|-------------------|
| LLM01 | Prompt Injection | Input guardrail (4615 lines), ML async scanner, encoding detection |
| LLM02 | Insecure Output Handling | Output filter (secrets/PII), schema validation |
| LLM03 | Training Data Poisoning | Out of scope (data pipeline security) |
| LLM04 | Model Denial of Service | Rate limiting, token budget enforcement |
| LLM05 | Supply Chain Vulnerabilities | SkillSpector (MCP tool scanning), plugin security audit |
| LLM06 | Sensitive Information Disclosure | Output filter, PII redaction, credential detection |
| LLM07 | Insecure Plugin Design | Tool policy RBAC, argument validation, SkillSpector |
| LLM08 | Excessive Agency | Tool call limits, sandbox levels, denied_tools |
| LLM09 | Overreliance | Hallucination detector, grounding scanner, relevance check |
| LLM10 | Model Theft | Authentication, SSRF protection, network policies |
