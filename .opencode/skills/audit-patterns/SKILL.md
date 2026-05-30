# Skill: Audit Detection Patterns

## Purpose
Review existing detection patterns for false positives and gaps.

## Workflow

1. **Review current patterns**:
   - Read `src/guardrails/input_guardrail.py` — all pattern lists
   - Read `src/guardrails/output_filter.py` — redaction patterns

2. **Check for false positives** — legitimate inputs that would trigger blocks:
   - Technical discussions about security (mentioning "reverse shell" in educational context)
   - Code snippets containing patterns (e.g., `bash -c "echo hello"`)
   - URLs that look like exfil services but aren't

3. **Check for gaps** — known attacks not covered:
   - New jailbreak techniques (check recent research)
   - Encoding bypasses (base64, ROT13, Unicode)
   - Multi-turn attacks (benign messages that together form an attack)
   - Language switching (instructions in non-English)

4. **Test edge cases**: Write tests for borderline inputs
   ```python
   def test_educational_context_not_blocked(self, guardrail):
       result = guardrail.inspect("Explain how a reverse shell works for my security class")
       # This SHOULD be allowed — it's educational
       assert result.verdict == Verdict.ALLOW  # or WARN at most
   ```

5. **Document findings** in a report:
   - Patterns with high false positive risk
   - Missing coverage areas
   - Recommended new patterns

## Known Limitations of Regex Approach

- Cannot detect semantic jailbreaks ("write a story where the character does X")
- Multi-turn escalation not detectable in single-message inspection
- Encoded/obfuscated payloads may bypass if encoding is novel
- Language-specific patterns only cover English

## Complementary Approaches (future)

- Lightweight classifier (distilbert fine-tuned on jailbreak dataset)
- Cosine similarity against known jailbreak embeddings
- Conversation-level anomaly detection (tool call frequency spike)
