# Sentinel Gateway — Load Testing Suite

Performance benchmarks for enterprise readiness validation using [k6](https://k6.io/).

## Quick Start

```bash
# Ensure gateway is running
docker-compose up -d

# Run all benchmarks
./tests/load/run-benchmarks.sh

# Run single scenario
./tests/load/run-benchmarks.sh --scenario guardrail-only

# Quick mode (shorter duration, fewer VUs)
./tests/load/run-benchmarks.sh --quick

# Custom target
./tests/load/run-benchmarks.sh --target-url http://staging.internal:8080 --vus 100
```

## Prerequisites

- **k6** installed ([installation guide](https://k6.io/docs/get-started/installation/))
- **Sentinel Gateway** running and accessible (proxy on port 8080)
- **Redis** running (for rate limiting tests)

```bash
# Install k6
# macOS
brew install k6

# Debian/Ubuntu
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg \
  --keyserver hkp://keyserver.ubuntu.com:80 \
  --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D68
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" \
  | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update && sudo apt-get install k6

# Docker (no install required)
docker run --rm -i --net=host grafana/k6 run - < tests/load/scenario-guardrail-only.js
```

## Scenarios

| Scenario | File | Description |
|----------|------|-------------|
| Guardrail Only | `scenario-guardrail-only.js` | Raw regex pattern matching performance |
| Full Pipeline | `scenario-full-pipeline.js` | End-to-end proxy path (auth + guardrail + IOC + forward + filter) |
| Streaming | `scenario-streaming.js` | SSE response TTFB and chunk-level filtering |
| Multi-Tenant | `scenario-multi-tenant.js` | Tenant isolation fairness under concurrent load |
| Spike | `scenario-spike.js` | 10x burst resilience and recovery time |

## Performance Targets

Enterprise SLA requirements (from readiness report):

| Scenario | p50 | p95 | p99 | Min Throughput |
|----------|-----|-----|-----|----------------|
| Regex guardrail only | <1ms | <2ms | <3ms | 15,000 RPS |
| Regex + IOC check | <2ms | <3ms | <5ms | 12,000 RPS |
| Full pipeline (no ML) | <3ms | <5ms | <8ms | 8,000 RPS |
| Streaming (TTFB) | <5ms | <10ms | <15ms | 5,000 RPS |

These targets assume:
- No ML/embedding scanners enabled (pure regex hot path)
- Backend LLM response time excluded (measured as added latency only)
- Redis available locally (< 1ms RTT)

## Traffic Mix

All scenarios use a realistic production traffic mix:
- **80% legitimate requests** — normal user questions, coding help, explanations
- **20% attack payloads** — prompt injection, jailbreaks, encoded exploits

This ensures we measure both the "allow" path and "block" path performance.

## Test Phases

Each scenario follows a standard profile:

```
|  Warm-up  |     Steady State      | Ramp-down |
|   30s     |        2 min          |    30s    |
|  0→N VUs  |       N VUs           |  N→0 VUs  |
```

The spike scenario uses an extended profile with a 10x burst:

```
| Warm-up | Baseline | Spike Up | Hold Spike | Spike Down | Recovery | Ramp-down |
|  30s    |   1min   |   10s    |    30s     |    10s     |   1min   |    30s    |
| 0→N     |    N     |  N→10N   |    10N     |   10N→N    |    N     |   N→0     |
```

## Running Individual Scenarios

```bash
# Direct k6 execution with custom parameters
k6 run \
  --env TARGET_URL=http://localhost:8080 \
  --env VUS=100 \
  --env API_KEY=my-test-key \
  --out json=results/my-test.json \
  tests/load/scenario-full-pipeline.js
```

## CI Integration

The orchestrator exits non-zero if any threshold is violated:

```yaml
# GitHub Actions example
- name: Run load tests
  run: |
    ./tests/load/run-benchmarks.sh \
      --target-url http://localhost:8080 \
      --vus 50

- name: Upload results
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: load-test-results
    path: tests/load/results/
```

Results are written as JSON for programmatic analysis:
- `results/summary.json` — Combined results from all scenarios
- `results/<scenario>.json` — Per-scenario detailed results
- `results/<scenario>-raw.json` — Raw k6 output (full metric stream)
- `results/<scenario>.log` — k6 console output

## Interpreting Results

### Pass/Fail Criteria

A scenario **passes** if ALL thresholds are met:
- Latency percentiles within target
- Error rate < 1% (< 5% during spike)
- No request timeouts (< 0.5%)

### Multi-Tenant Fairness

The multi-tenant scenario measures a **fairness ratio**:
```
fairness = max(tenant_p95) / min(tenant_p95)
```
Target: < 2.0x (no tenant more than 2x slower than the fastest)

### Spike Recovery

The spike scenario measures **recovery ratio**:
```
recovery = recovery_p95 / baseline_p95
```
Target: < 2.0x (system returns to near-baseline within 60s of spike ending)

## Customization

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TARGET_URL` | `http://localhost:8080` | Proxy endpoint |
| `VUS` | `50` | Virtual users per scenario |
| `API_KEY` | `test-api-key-load-bench` | Bearer token for auth |
| `DURATION` | `2m` | Steady-state duration |

### Adding Custom Scenarios

1. Create `scenario-<name>.js` importing from `k6-config.js`
2. Define `options` with scenarios and thresholds
3. Implement `handleSummary()` to write `results/<name>.json`
4. Add entry to `run-benchmarks.sh` SCENARIOS array

## Architecture Notes

The load tests measure **proxy overhead only** — the time Sentinel Gateway adds
on top of normal request processing. This includes:

1. JWT/API key validation (~0.1ms)
2. Rate limit check via Redis (~0.2ms)
3. Input guardrail regex scan (~0.5-1ms for 4600+ patterns)
4. IOC database lookup (~0.2ms)
5. SSRF validation on backend URL (~0.1ms)
6. Tool policy check on response (~0.2ms)
7. Output filter scan (~0.3ms)
8. Telemetry event emission (async, non-blocking)

Total expected overhead: **1-3ms per request** (p95) with all security layers active.
