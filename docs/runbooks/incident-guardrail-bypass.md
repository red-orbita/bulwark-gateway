# Runbook: Guardrail Bypass Detected

## Classification

- **Incident Type**: Security control failure — adversary successfully evaded detection
- **Minimum Severity**: P1 — Critical
- **MITRE ATT&CK**: T1190 (Exploit Public-Facing Application), T1027 (Obfuscated Files or Information)
- **Owner**: Security Engineering

## When to Use This Playbook

Activate when ANY of the following are confirmed:

- A known-malicious payload was not blocked (identified via manual review, SIEM correlation, or customer report)
- Prompt injection reached the backend LLM and influenced its behavior
- Jailbreak attempt succeeded (LLM produced disallowed output)
- Encoded/obfuscated attack evaded multi-layer decoding
- Tool policy was circumvented (unauthorized tool execution confirmed)
- An attacker publicly discloses a bypass technique affecting Sentinel Gateway
- Red team/penetration test identifies a live bypass

**This differs from a data breach** in that no data was necessarily exfiltrated — the security control itself failed. If data was exposed, also activate [incident-data-breach.md](incident-data-breach.md).

---

## Phase 1: Immediate Response (0–15 Minutes)

### 1.1 Declare the Incident

```
Post to #sentinel-incidents:

:shield: P1 INCIDENT — Guardrail Bypass Confirmed

**Type**: Security control evasion
**Attack vector**: [injection/jailbreak/encoding/tool_abuse]
**Discovery method**: [alert/SIEM/manual/customer report/public disclosure]
**IC**: @[name]
**Status**: Investigating — guardrails still active for other patterns

Immediate concern: Can this bypass be replicated at scale?
```

### 1.2 Preserve the Attack Payload

```bash
# Collect evidence (includes attack payloads in recent_blocks and logs)
./scripts/ir-collect-evidence.sh --namespace sentinel-gateway --since 1h

# Specifically capture the bypass payload for pattern development
kubectl logs deploy/proxy -n sentinel-gateway --since=1h | \
  jq 'select(.verdict=="ALLOW") | select(.category!=null)' > /tmp/bypass-payloads.jsonl

# If reported externally (bug bounty, public disclosure), save the original report
# Document: reporter, payload, date, channel
```

### 1.3 Assess Bypass Scope

| Question | How to Determine |
|----------|-----------------|
| Which category was bypassed? | Analyze the payload against category patterns |
| Is the bypass technique novel? | Compare to `src/guardrails/input_guardrail.py` patterns |
| Can it be automated? | Is it a simple encoding trick or complex multi-step? |
| How many requests used this technique? | Search logs for similar patterns |
| Is it being actively exploited? | Check for multiple occurrences from different tenants |

```bash
# Search for similar payloads (adjust pattern to match the bypass technique)
kubectl logs deploy/proxy -n sentinel-gateway --since=24h | \
  jq 'select(.verdict=="ALLOW")' | grep -i "<bypass_technique_indicator>"

# Check if pattern was supposed to catch this
# Review input_guardrail.py patterns for the relevant category
# Example: check prompt injection patterns
kubectl exec deploy/proxy -n sentinel-gateway -- \
  python -c "from src.guardrails.input_guardrail import InputGuardrail; g=InputGuardrail(); print(len(g.patterns))"
```

### 1.4 Immediate Containment

**If actively exploited** (multiple occurrences observed):

```bash
# Option 1: Tighten fail-closed mode (blocks on any internal error)
kubectl set env deploy/proxy SENTINEL_FAIL_MODE=closed -n sentinel-gateway

# Option 2: Add emergency pattern (quick regex to block the specific technique)
curl -X POST http://admin:8090/admin/guardrails/ \
  -H "Content-Type: application/json" \
  -d '{
    "pattern": "<emergency_regex_for_bypass>",
    "category": "prompt_injection",
    "severity": "critical",
    "description": "Emergency: blocks bypass technique INC-XXXX"
  }'

# Option 3: If bypass uses specific encoding, force strict decoding
kubectl set env deploy/proxy SENTINEL_STRICT_DECODING=true -n sentinel-gateway

# Option 4: If tool policy bypass, restrict all tool calls temporarily
# Update policy to deny all tools except explicitly allowed
```

**If NOT actively exploited** (discovered proactively):

```bash
# Develop and test the fix before deploying
# Use admin API to test pattern against the payload
curl -X POST http://admin:8090/admin/guardrails/test \
  -H "Content-Type: application/json" \
  -d '{"content": "<the bypass payload>", "dry_run": true}'
```

---

## Phase 2: Pattern Development (15 Minutes – 2 Hours)

### 2.1 Analyze the Bypass Technique

Categorize the bypass:

| Technique | Description | Detection Approach |
|-----------|-------------|-------------------|
| **Encoding evasion** | Base64, hex, URL, Unicode escapes, Morse, Braille, NATO | Add to multi-layer decode pipeline |
| **Homoglyph substitution** | Cyrillic а instead of Latin a | Strengthen NFKC normalization |
| **Zero-width injection** | U+200B, U+FEFF between keywords | Strip zero-width chars before matching |
| **Chunked injection** | Split payload across multiple messages | Add cross-message correlation |
| **Semantic evasion** | Rephrase without matching regex | Add ML scanner pattern or expand regex |
| **Role confusion** | Convince LLM to ignore system prompt | Add role boundary patterns |
| **Tool name manipulation** | Encode tool names to bypass policy | Normalize tool names before policy check |
| **Indirect injection** | Payload in retrieved context, not user message | Add RAG content scanning |

### 2.2 Develop the Fix

```bash
# 1. Create a test case for the bypass (MUST have this before deploying fix)
# Add to tests/test_input_guardrail.py:
#
#   def test_bypass_inc_xxxx():
#       """Regression: bypass technique from INC-XXXX."""
#       guardrail = InputGuardrail()
#       payload = "<the exact bypass payload>"
#       result = guardrail.scan(payload)
#       assert result.verdict == Verdict.BLOCK

# 2. Develop the pattern fix
# Edit src/guardrails/input_guardrail.py (or output_filter.py)

# 3. Run tests to verify fix catches the bypass AND doesn't cause false positives
pytest tests/test_input_guardrail.py -v -k "bypass or injection"

# 4. Run full test suite to check for regressions
pytest tests/ -q --tb=short

# 5. Run legitimate flow tests
pytest tests/ -q -k "legit or false_positive"
```

### 2.3 Test the Fix in Staging

```bash
# Deploy to staging first (if available)
# Or test via admin API dry-run against the bypass payload:
curl -X POST http://admin:8090/admin/guardrails/test \
  -H "Content-Type: application/json" \
  -d '{"content": "<bypass_payload>", "pattern_id": "<new_pattern_id>"}'

# Also test legitimate content that is similar to the bypass
curl -X POST http://admin:8090/admin/guardrails/test \
  -H "Content-Type: application/json" \
  -d '{"content": "<similar but legitimate content>", "pattern_id": "<new_pattern_id>"}'
```

### 2.4 Deploy the Fix

```bash
# Option A: Hot-add pattern via admin (no restart required)
curl -X POST http://admin:8090/admin/guardrails/ \
  -H "Content-Type: application/json" \
  -d '{
    "pattern": "<new_detection_regex>",
    "category": "<category>",
    "severity": "critical",
    "description": "Detects bypass technique from INC-XXXX"
  }'

# Trigger hot-reload on proxy
curl -X POST http://proxy:8080/admin/policies/reload

# Option B: Code fix (requires deployment)
# Commit fix → CI pipeline → Deploy
# Use rolling update to avoid downtime

# Verify fix in production
kubectl logs deploy/proxy -n sentinel-gateway --since=2m | \
  jq 'select(.event=="pattern_loaded")'

# Run security smoke test
python scripts/security-smoke-test.py --host http://proxy:8080
```

---

## Phase 3: Exposure Assessment

### 3.1 Determine What Happened During Bypass Window

```bash
# Time window: from bypass first possible to fix deployed
# Search for requests that may have exploited the gap

# All ALLOW verdicts during the window that match the bypass pattern
kubectl logs deploy/proxy -n sentinel-gateway --since=<window> | \
  jq 'select(.verdict=="ALLOW")' | grep -i "<bypass_indicator>"

# Check if any backend responses contained harmful content
kubectl logs deploy/proxy -n sentinel-gateway --since=<window> | \
  jq 'select(.event=="response_sent" and .output_filter_triggered==true)'

# Check tool executions during the window
kubectl logs deploy/proxy -n sentinel-gateway --since=<window> | \
  jq 'select(.event=="tool_call") | {tenant: .tenant_id, tool: .tool_name, args: .tool_args}'
```

### 3.2 Impact Classification

| Question | Answer Determines |
|----------|-------------------|
| Were any payloads exploited during the window? | Whether this is also a data breach |
| Did any tool calls succeed that should have been blocked? | Whether to activate tool abuse response |
| Was any data returned to users that should have been redacted? | Whether to activate data breach playbook |
| How long was the bypass window? | Severity and regulatory implications |

**If data was exposed → Also activate [incident-data-breach.md](incident-data-breach.md)**

---

## Phase 4: Hardening

After the immediate fix, implement defense-in-depth:

```bash
# 1. Add the bypass technique to the red team evaluation suite
# Update src/evaluation/attacks.py with the new technique

# 2. Run full adversarial evaluation to find similar gaps
curl -X POST http://admin:8090/admin/evaluation/run \
  -H "Content-Type: application/json" \
  -d '{"categories": ["prompt_injection", "jailbreak", "encoding_evasion"]}'

# 3. If encoding-based bypass, verify all decode layers are chained
# Check src/guardrails/input_guardrail.py decode pipeline

# 4. Consider ML scanner addition if regex alone is insufficient
# Check if ml scanner would have caught this:
# Prometheus: sentinel_verdicts_total{verdict="block", source="ml_scanner"}

# 5. Update security smoke test with the bypass payload
# Add to scripts/security-smoke-test.py
```

---

## Escalation

- If bypass is being actively exploited at scale → Maintain P1, expand war room
- If bypass allows data exfiltration → Activate [incident-data-breach.md](incident-data-breach.md)
- If bypass is publicly disclosed (0-day) → Emergency patch, notify all customers
- If fix has false positive risk → Involve security + platform leads in deployment decision
- If bypass affects multiple guardrail categories → Systemic issue, engage full security team

## Related Runbooks

- [IR Plan](ir-plan.md) — Overall incident response framework
- [Data Breach](incident-data-breach.md) — If bypass led to data exposure
- [High Block Rate](alert-high-block-rate.md) — New pattern may spike block rate initially
- [Guardrail Latency](alert-guardrail-latency.md) — New patterns may impact latency

## Post-Incident

- [ ] Complete Post-Incident Review within 5 business days
- [ ] Add regression test for the specific bypass technique
- [ ] Update red team evaluation dataset
- [ ] Run full adversarial evaluation to find similar gaps
- [ ] Update security-smoke-test.py with the bypass payload
- [ ] Review all related patterns for similar weakness
- [ ] Publish internal security advisory (if technique is novel)
- [ ] If externally reported, follow responsible disclosure response process
- [ ] Update `src/guardrails/input_guardrail.py` documentation/comments
- [ ] Consider whether this reveals a systemic detection gap
- [ ] Update this runbook with lessons learned
