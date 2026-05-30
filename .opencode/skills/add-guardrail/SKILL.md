# Skill: Add Guardrail Pattern

## Purpose
Add a new detection pattern to the input guardrail or output filter.

## Workflow

1. **Identify the threat category**:
   - `prompt_injection` — User tries to override system prompt
   - `jailbreak` — DAN, roleplay, persona injection
   - `tool_abuse` — Tricks agent into running dangerous commands
   - `exfiltration` — Data theft to external services
   - `credential_access` — Reading sensitive files
   - `reverse_shell` — Shell payload execution
   - `pii_leak` — PII in responses

2. **Determine target engine**:
   - User input threats → `src/guardrails/input_guardrail.py`
   - Response content threats → `src/guardrails/output_filter.py`

3. **Write the pattern**:
   ```python
   Pattern(
       re.compile(r"<regex>", re.I),
       ThreatCategory.<CATEGORY>,
       "<severity>",  # low, medium, high, critical
       "<human-readable description>",
   )
   ```

4. **Add to the appropriate list**:
   - `INJECTION_PATTERNS` — prompt override attempts
   - `TOOL_ABUSE_PATTERNS` — dangerous command patterns
   - `SOCIAL_ENGINEERING_PATTERNS` — manipulation tactics
   - `REDACTION_PATTERNS` — secrets in output
   - `PII_PATTERNS` — PII in output

5. **Write tests** in the corresponding test file:
   - Positive test: input that SHOULD trigger the pattern
   - Negative test: benign input that should NOT trigger

6. **Run tests**: `pytest tests/test_input_guardrail.py -v` or `pytest tests/test_output_filter.py -v`

7. **Verify no regressions**: `pytest -v`

## Severity Guidelines

| Severity | When to use | Result |
|----------|------------|--------|
| `low` | Informational, might be false positive | WARN (logged) |
| `medium` | Suspicious but could be legitimate | WARN (logged) |
| `high` | Likely malicious, low false positive rate | BLOCK |
| `critical` | Definitely malicious, zero tolerance | BLOCK |

## Example

Adding detection for Unicode smuggling:

```python
# In INJECTION_PATTERNS:
Pattern(
    re.compile(r"[\u200b-\u200f\u2028-\u202f\ufeff]", re.I),
    ThreatCategory.PROMPT_INJECTION,
    "high",
    "Unicode zero-width/invisible characters (potential smuggling)",
),
```

Test:
```python
def test_unicode_smuggling(self, guardrail):
    result = guardrail.inspect("Hello\u200b world")
    assert result.verdict == Verdict.BLOCK
```
