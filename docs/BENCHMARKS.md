# Sentinel Gateway — Benchmark Results

Performance and detection benchmarks for the Sentinel Gateway security guardrail engine.

All results are deterministic and reproducible (seeded random generators).
Only the regex-based input scanner is benchmarked here — ML scanners are additive and async.

---

## Quick Summary

| Metric | Standard (220) | Exhaustive (1020) |
|--------|---------------|-------------------|
| Detection Rate | **98.2%** | **97.2%** |
| False Positive Rate | **0.0%** | **0.0%** |
| Bypass Rate | 1.8% | 2.8% |
| Latency P50 | 51 ms | 51 ms |
| Latency P95 | 129 ms | 129 ms |
| Latency P99 | 203 ms | 193 ms |

---

## Methodology

### Engine Under Test

- **Scanner**: `RegexInputScanner` (deterministic, ~435 compiled patterns)
- **Defense layers**: Unicode NFKC normalization, Shannon entropy detection, multi-layer decoding (base64, hex, URL, Unicode escapes), pre-compiled regex matching
- **No ML**: Benchmarks measure pure regex performance only. ML scanners add ~10-30ms async latency but are not included to ensure reproducibility.

### Datasets

| Dataset | Count | Source | Purpose |
|---------|-------|--------|---------|
| Generated attacks | 200/1000 | `AttackGenerator` (seed=42/1337) | Mutated, encoded, templated attack payloads |
| External-style attacks | 20 | Hand-crafted (BIPIA/PromptBench-inspired) | Indirect injection, academic framing, encoding tricks |
| Benign samples | 90 | `BenignDataset` + 30 hard benign | FPR measurement: security discussions, code with "dangerous" keywords |

### Attack Categories

- **Prompt Injection**: Direct instruction override, role manipulation, context injection
- **Jailbreak**: DAN roleplay, academic framing, creative writing pretext, translation attacks
- **Exfiltration**: Webhook URLs, markdown image injection, system prompt extraction
- **Credential Access**: Command injection, reverse shells, file read of sensitive paths

### Difficulty Levels

- **Easy**: Plaintext well-known patterns
- **Medium**: Single encoding layer or light obfuscation
- **Hard**: Multi-layer encoding, zero-width characters, homoglyphs, novel phrasing

---

## Standard Benchmark (220 Attacks + 90 Benign)

```
Mode: standard | Seed: 42 | Scanner: regex_input (deterministic)

SUMMARY
  Total Attacks:      220
  Detected:           216
  Missed (Bypassed):  4
  False Positives:    0

  Detection Rate:     98.2%
  False Positive Rate: 0.0%
  Bypass Rate:         1.8%

LATENCY
  P50:  50.97 ms
  P95: 129.05 ms
  P99: 203.31 ms
```

### Per-Category Breakdown

| Category | Detected | Total | Rate | Easy | Medium | Hard |
|----------|----------|-------|------|------|--------|------|
| Credential Access | 53 | 53 | **100%** | 5/5 | 14/14 | 34/34 |
| Exfiltration | 52 | 53 | **98%** | 7/7 | 10/10 | 35/36 |
| Jailbreak | 53 | 55 | **96%** | 11/11 | 6/6 | 36/38 |
| Prompt Injection | 58 | 59 | **98%** | 7/7 | 14/14 | 37/38 |

---

## Exhaustive Benchmark (1020 Attacks + 90 Benign)

```
Mode: exhaustive | Seed: 1337 | Scanner: regex_input (deterministic)

SUMMARY
  Total Attacks:      1020
  Detected:           991
  Missed (Bypassed):  29
  False Positives:    0

  Detection Rate:     97.2%
  False Positive Rate: 0.0%
  Bypass Rate:         2.8%

LATENCY
  P50:  50.98 ms
  P95: 128.65 ms
  P99: 192.85 ms
```

### Per-Category Breakdown

| Category | Detected | Total | Rate | Easy | Medium | Hard |
|----------|----------|-------|------|------|--------|------|
| Credential Access | 249 | 253 | **98.4%** | 43/43 (100%) | 59/59 (100%) | 147/151 (97%) |
| Exfiltration | 249 | 253 | **98.4%** | 25/25 (100%) | 50/51 (98%) | 174/177 (98%) |
| Jailbreak | 244 | 255 | **95.7%** | 46/46 (100%) | 44/46 (96%) | 154/163 (94%) |
| Prompt Injection | 249 | 259 | **96.1%** | 56/56 (100%) | 49/49 (100%) | 144/154 (94%) |

### Category Latency (P50 / P95)

| Category | P50 (ms) | P95 (ms) |
|----------|----------|----------|
| Credential Access | 45.8 | 122.1 |
| Exfiltration | 63.3 | 132.0 |
| Jailbreak | 37.2 | 156.7 |
| Prompt Injection | 67.1 | 119.1 |

---

## Performance Characteristics

### Why Latency Varies

The regex scanner processes messages through multiple defense layers sequentially:
1. **Unicode normalization** (~1ms) — NFKC, zero-width char removal
2. **Entropy check** (~2ms) — Shannon entropy for encoded payload detection
3. **Multi-layer decode** (~5-30ms) — Attempts base64, hex, URL, Unicode decode passes
4. **Pattern matching** (~20-80ms) — 435 pre-compiled regex patterns, early-exit on match

Longer messages and encoded content increase decode time. The P99 represents worst-case multi-layer decoding of heavily obfuscated payloads.

### Throughput

| Metric | Standard | Exhaustive |
|--------|----------|------------|
| Total time | 50.6s | 92.5s |
| Throughput | ~4 req/s | ~11 req/s |

Note: Throughput is measured single-threaded. In production with 4 uvicorn workers and HPA scaling (2-10 replicas), effective throughput is 8-110 req/s per category evaluation.

### Comparison: Hot-Path Only vs Full Pipeline

| Scenario | P50 | P95 | Notes |
|----------|-----|-----|-------|
| Regex only (benchmarked) | 51ms | 129ms | Input guardrail scan time |
| Full proxy (with backend) | 200-5000ms | 3000-8000ms | Dominated by LLM response time |
| Enrichment (async) | +0ms | +0ms | Fire-and-forget, doesn't add to response time |
| ML scanners (async) | +0ms | +0ms | Same — async, no latency impact |
| ML scanners (blocking) | +30ms | +80ms | Only if `SENTINEL_ML_BLOCKING=true` |

---

## Reproducing Results

```bash
# Activate virtualenv
source .venv/bin/activate

# Standard benchmark (220 attacks, seed=42)
python scripts/run-benchmarks.py --save

# Exhaustive benchmark (1020 attacks, seed=1337)
python scripts/run-benchmarks.py --exhaustive --save

# JSON output for CI integration
python scripts/run-benchmarks.py --output json

# Results saved to reports/benchmarks/
ls reports/benchmarks/
```

### CI Integration

The benchmark script exits with code 1 if detection rate drops below 90%:
```bash
# In CI pipeline
python scripts/run-benchmarks.py || exit 1
```

---

## Test Coverage

In addition to benchmarks, the project has ~431 unit/integration tests:

```bash
pytest tests/ -q --tb=short
```

Key test files:
- `test_input_guardrail.py` — Regex pattern positive/negative cases
- `test_output_filter.py` — Secret/PII redaction
- `test_tool_policy.py` — RBAC enforcement
- `test_scanner_framework.py` — Pipeline orchestration (37 tests)
- `test_ml_scanners.py` — ML classifier mocking (35 tests)
- `test_phase8_evaluation.py` — Red teaming framework (19 tests)
- `test_exhaustive_integration.py` — Cross-phase integration (41 tests)

---

## Version History

| Date | Version | Detection | FPR | Notes |
|------|---------|-----------|-----|-------|
| 2026-06-12 | 0.4.3 | 97.2% (1020) | 0.0% | Exhaustive benchmark baseline |
| 2026-06-12 | 0.4.3 | 98.2% (220) | 0.0% | Standard benchmark baseline |

---

## Limitations

1. **Regex only**: These benchmarks test the deterministic regex engine. ML scanners provide additional async detection for novel/semantic attacks.
2. **Generated attacks**: While attacks include external-style (BIPIA/PromptBench-inspired) payloads, real-world adversaries may use techniques not in the corpus.
3. **English-focused**: Primary patterns target English payloads. Multilingual scanner (10 languages) is available but not included in this benchmark.
4. **Single-turn**: Benchmarks test individual messages. Multi-turn dialog evasion is tested separately via the dialog engine.
5. **No network dependencies**: Benchmarks run offline. IOC/threat intel enrichment adds detection of known-bad indicators in production.
