# Chaos Testing Suite — Sentinel Gateway

Comprehensive chaos engineering experiments using [LitmusChaos v3.x](https://litmuschaos.io/)
to validate system resilience under failure conditions.

## Purpose

Enterprise customers require evidence that Sentinel Gateway degrades gracefully
under real-world failure conditions. This suite proves:

- **No security bypass on failure** — fail-closed guarantees hold under chaos
- **Graceful degradation** — requests continue with reduced functionality
- **Fast recovery** — pods restart and reconnect within SLA bounds
- **Observable failures** — all degradations emit structured logs/alerts

## Prerequisites

```bash
# 1. LitmusChaos operator installed (v3.x)
kubectl apply -f https://litmuschaos.github.io/litmus/litmus-operator-v3.0.0.yaml

# 2. Sentinel Gateway deployed in target namespace
helm install sentinel ./helm/sentinel-gateway --namespace sentinel-gateway

# 3. LitmusChaos CRDs available
kubectl get crds | grep chaos

# 4. RBAC for chaos experiments
kubectl apply -f tests/chaos/rbac.yaml
```

## Experiment Matrix

| # | Experiment | Duration | Target | Expected Behavior | Pass Criteria |
|---|-----------|----------|--------|-------------------|---------------|
| 1 | Redis Kill | 60s | redis pod | Proxy continues with in-memory fallback, rate limiting degrades gracefully | Zero 500 errors, requests still processed |
| 2 | Proxy Pod Kill | 30s | proxy pod | HPA recovers, PDB prevents total outage | <5s recovery, zero dropped connections |
| 3 | Network Partition | 45s | proxy↔redis | Proxy isolates from Redis, falls back to local state | No 500s, warn log emitted |
| 4 | CPU Stress (80%) | 120s | proxy pod | Latency increases but requests complete | P99 < 500ms, no timeouts |
| 5 | Memory Stress (90%) | 60s | proxy pod | OOMKill possible, pod restarts cleanly | Recovery <10s, no data loss |
| 6 | DNS Failure | 30s | cluster DNS | Backend unreachable, returns 502 gracefully | Error message clear, no panic |
| 7 | Backend Latency (+5s) | 120s | backend svc | Requests timeout gracefully, circuit breaker trips | Clear timeout errors, no hung connections |

## MITRE ATT&CK Mapping

These experiments validate resilience against known attack patterns:

| Technique | ID | Experiments |
|-----------|-----|-------------|
| Endpoint Denial of Service | T1499 | CPU Stress, Memory Stress, Backend Latency |
| Service Stop | T1489 | Redis Kill, Proxy Pod Kill |
| Network Denial of Service | T1498 | Network Partition, DNS Failure |

## Running the Suite

### Full Suite

```bash
# Run all experiments sequentially with steady-state checks
./tests/chaos/run-chaos-suite.sh --namespace sentinel-gateway

# Dry-run (validate manifests only, no execution)
./tests/chaos/run-chaos-suite.sh --namespace sentinel-gateway --dry-run
```

### Individual Experiments

```bash
# Apply a single experiment
kubectl apply -f tests/chaos/experiments/redis-kill.yaml -n sentinel-gateway

# Monitor experiment status
kubectl get chaosengine -n sentinel-gateway -w

# Check result
kubectl get chaosresult -n sentinel-gateway
```

### Steady-State Validation

```bash
# Run health checks independently
./tests/chaos/steady-state-check.sh --namespace sentinel-gateway
```

## Output

The orchestrator generates:

- `chaos-report.json` — Machine-readable results (CI/CD integration)
- `chaos-report.md` — Human-readable markdown table
- Exit code 0 on full pass, non-zero on any failure

### Report Format (JSON)

```json
{
  "suite_run_id": "uuid",
  "timestamp": "2024-01-15T10:30:00Z",
  "namespace": "sentinel-gateway",
  "experiments": [
    {
      "name": "redis-kill",
      "status": "pass",
      "duration_seconds": 60,
      "steady_state_before": true,
      "steady_state_after": true,
      "observations": ["proxy continued serving", "rate limiting fell back to in-memory"]
    }
  ],
  "overall": "pass",
  "pass_count": 7,
  "fail_count": 0
}
```

## Architecture

```
run-chaos-suite.sh
  │
  ├── steady-state-check.sh (pre-check)
  │
  ├── For each experiment:
  │   ├── kubectl apply -f experiment.yaml
  │   ├── Wait for ChaosEngine completion
  │   ├── Validate pass criteria
  │   ├── Collect observations
  │   └── kubectl delete -f experiment.yaml
  │
  ├── steady-state-check.sh (between experiments)
  │
  └── Generate report (JSON + Markdown)
```

## Abort Conditions

Each experiment includes abort conditions. The orchestrator will halt if:

1. Any pod enters `CrashLoopBackOff` and does NOT recover within tolerance
2. The proxy `/health` endpoint returns non-200 for >30s after experiment ends
3. Security events indicate a bypass (403 responses stop being emitted for known attacks)
4. More than 3 consecutive experiments fail

## Extending

### Adding a New Experiment

1. Create YAML in `experiments/` following the ChaosEngine CRD format
2. Add entry to the experiment matrix in this README
3. Add to the `EXPERIMENTS` array in `run-chaos-suite.sh`
4. Define pass criteria in the experiment's annotations

### Custom Probes

LitmusChaos probes are used for automated validation:

- **httpProbe** — Validates `/health` returns 200
- **cmdProbe** — Runs custom validation commands
- **k8sProbe** — Checks Kubernetes resource state
