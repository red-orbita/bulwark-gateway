#!/usr/bin/env bash
#
# Sentinel Gateway — Chaos Testing Orchestrator
#
# Runs all chaos experiments sequentially with steady-state validation
# between each experiment. Generates JSON + Markdown reports.
#
# Usage:
#   ./tests/chaos/run-chaos-suite.sh [--namespace NS] [--dry-run] [--timeout SECONDS]
#
# Prerequisites:
#   - kubectl configured with cluster access
#   - LitmusChaos v3.x operator installed
#   - Sentinel Gateway deployed in target namespace
#

set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────

NAMESPACE="sentinel-gateway"
DRY_RUN=false
TIMEOUT=600  # Max wait per experiment (seconds)
MAX_CONSECUTIVE_FAILURES=3
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPERIMENTS_DIR="${SCRIPT_DIR}/experiments"
STEADY_STATE_SCRIPT="${SCRIPT_DIR}/steady-state-check.sh"
REPORT_DIR="${SCRIPT_DIR}/reports"
SUITE_RUN_ID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || date +%s)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Ordered list of experiments
EXPERIMENTS=(
  "redis-kill"
  "proxy-pod-kill"
  "network-partition"
  "cpu-stress"
  "memory-stress"
  "dns-failure"
  "backend-latency"
)

# Experiment durations (for timeout calculation)
declare -A EXPERIMENT_DURATIONS=(
  ["redis-kill"]=60
  ["proxy-pod-kill"]=30
  ["network-partition"]=45
  ["cpu-stress"]=120
  ["memory-stress"]=60
  ["dns-failure"]=30
  ["backend-latency"]=120
)

# ─── Argument Parsing ────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case $1 in
    --namespace|-n)
      NAMESPACE="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --timeout|-t)
      TIMEOUT="$2"
      shift 2
      ;;
    --help|-h)
      echo "Usage: $0 [--namespace NS] [--dry-run] [--timeout SECONDS]"
      echo ""
      echo "Options:"
      echo "  --namespace, -n    Target namespace (default: sentinel-gateway)"
      echo "  --dry-run          Validate manifests without executing experiments"
      echo "  --timeout, -t      Max wait per experiment in seconds (default: 600)"
      echo "  --help, -h         Show this help"
      exit 0
      ;;
    *)
      echo "ERROR: Unknown option: $1"
      exit 1
      ;;
  esac
done

# ─── Output Formatting ───────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()  { echo -e "${BLUE}[INFO]${NC}  $(date +%H:%M:%S) $*"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC}  $(date +%H:%M:%S) $*"; }
log_fail()  { echo -e "${RED}[FAIL]${NC}  $(date +%H:%M:%S) $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $(date +%H:%M:%S) $*"; }
log_step()  { echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; echo -e "${BLUE}  $*${NC}"; echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"; }

# ─── Prerequisite Checks ─────────────────────────────────────────────────────

check_prerequisites() {
  log_step "Checking Prerequisites"

  # kubectl available
  if ! command -v kubectl &>/dev/null; then
    log_fail "kubectl not found in PATH"
    exit 1
  fi
  log_pass "kubectl available"

  # Cluster connectivity
  if ! kubectl cluster-info &>/dev/null; then
    log_fail "Cannot connect to Kubernetes cluster"
    exit 1
  fi
  log_pass "Cluster connectivity OK"

  # Namespace exists
  if ! kubectl get namespace "$NAMESPACE" &>/dev/null; then
    log_fail "Namespace '$NAMESPACE' does not exist"
    exit 1
  fi
  log_pass "Namespace '$NAMESPACE' exists"

  # LitmusChaos CRDs installed
  if ! kubectl get crd chaosengines.litmuschaos.io &>/dev/null; then
    log_fail "LitmusChaos CRDs not found. Install LitmusChaos v3.x first."
    echo "  kubectl apply -f https://litmuschaos.github.io/litmus/litmus-operator-v3.0.0.yaml"
    exit 1
  fi
  log_pass "LitmusChaos CRDs installed"

  # ChaosServiceAccount exists
  if ! kubectl get sa litmus-chaos-sa -n "$NAMESPACE" &>/dev/null; then
    log_warn "ServiceAccount 'litmus-chaos-sa' not found in $NAMESPACE"
    log_info "Creating chaos RBAC resources..."
    create_chaos_rbac
  fi
  log_pass "Chaos ServiceAccount ready"

  # Sentinel Gateway pods running
  PROXY_PODS=$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/component=proxy --no-headers 2>/dev/null | wc -l)
  if [ "$PROXY_PODS" -lt 1 ]; then
    log_fail "No proxy pods found in namespace '$NAMESPACE'"
    exit 1
  fi
  log_pass "Found $PROXY_PODS proxy pod(s)"

  # Experiment files exist
  for exp in "${EXPERIMENTS[@]}"; do
    if [ ! -f "${EXPERIMENTS_DIR}/${exp}.yaml" ]; then
      log_fail "Experiment file not found: ${EXPERIMENTS_DIR}/${exp}.yaml"
      exit 1
    fi
  done
  log_pass "All experiment manifests found"
}

# ─── RBAC Setup ──────────────────────────────────────────────────────────────

create_chaos_rbac() {
  kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: litmus-chaos-sa
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/part-of: sentinel-gateway
    app.kubernetes.io/component: chaos-testing
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: litmus-chaos-role
  labels:
    app.kubernetes.io/part-of: sentinel-gateway
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log", "pods/exec", "events", "services", "endpoints"]
    verbs: ["create", "delete", "get", "list", "patch", "update", "watch", "deletecollection"]
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets", "statefulsets", "daemonsets"]
    verbs: ["get", "list", "patch", "update"]
  - apiGroups: ["batch"]
    resources: ["jobs"]
    verbs: ["create", "delete", "get", "list", "patch", "update"]
  - apiGroups: ["policy"]
    resources: ["poddisruptionbudgets"]
    verbs: ["get", "list"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["create", "delete", "get", "list", "patch"]
  - apiGroups: ["litmuschaos.io"]
    resources: ["chaosengines", "chaosexperiments", "chaosresults"]
    verbs: ["create", "delete", "get", "list", "patch", "update", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: litmus-chaos-binding
  labels:
    app.kubernetes.io/part-of: sentinel-gateway
subjects:
  - kind: ServiceAccount
    name: litmus-chaos-sa
    namespace: ${NAMESPACE}
roleRef:
  kind: ClusterRole
  name: litmus-chaos-role
  apiGroup: rbac.authorization.k8s.io
EOF
}

# ─── Dry Run ─────────────────────────────────────────────────────────────────

dry_run_validate() {
  log_step "Dry Run — Validating Manifests"

  local errors=0
  for exp in "${EXPERIMENTS[@]}"; do
    local file="${EXPERIMENTS_DIR}/${exp}.yaml"
    if kubectl apply --dry-run=server -f "$file" -n "$NAMESPACE" &>/dev/null; then
      log_pass "  ${exp}.yaml — valid"
    else
      log_fail "  ${exp}.yaml — INVALID"
      kubectl apply --dry-run=server -f "$file" -n "$NAMESPACE" 2>&1 | head -5
      errors=$((errors + 1))
    fi
  done

  if [ $errors -gt 0 ]; then
    log_fail "$errors manifest(s) failed validation"
    exit 1
  fi

  log_pass "All manifests valid"
  log_info "Dry run complete. No experiments were executed."
  exit 0
}

# ─── Experiment Execution ────────────────────────────────────────────────────

wait_for_chaos_completion() {
  local engine_name="$1"
  local max_wait="$2"
  local elapsed=0
  local poll_interval=5

  while [ $elapsed -lt "$max_wait" ]; do
    local status
    status=$(kubectl get chaosengine "$engine_name" -n "$NAMESPACE" \
      -o jsonpath='{.status.engineStatus}' 2>/dev/null || echo "unknown")

    case "$status" in
      "completed"|"stopped")
        return 0
        ;;
      "failed"|"error")
        return 1
        ;;
    esac

    sleep $poll_interval
    elapsed=$((elapsed + poll_interval))
  done

  log_warn "Timeout waiting for $engine_name (${max_wait}s)"
  return 2
}

get_chaos_result() {
  local engine_name="$1"
  kubectl get chaosresult -n "$NAMESPACE" \
    -l "chaosUID" \
    -o jsonpath='{.items[0].status.experimentStatus.verdict}' 2>/dev/null || echo "unknown"
}

get_probe_results() {
  local engine_name="$1"
  kubectl get chaosresult -n "$NAMESPACE" \
    -o json 2>/dev/null | \
    python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for item in data.get('items', []):
        name = item.get('metadata', {}).get('name', 'unknown')
        status = item.get('status', {}).get('experimentStatus', {})
        verdict = status.get('verdict', 'unknown')
        probes = status.get('probeSuccessPercentage', 'N/A')
        print(f'{name}: verdict={verdict}, probes_pass={probes}%')
except:
    print('unable to parse results')
" 2>/dev/null || echo "results unavailable"
}

run_experiment() {
  local exp_name="$1"
  local exp_file="${EXPERIMENTS_DIR}/${exp_name}.yaml"
  local duration="${EXPERIMENT_DURATIONS[$exp_name]:-60}"
  local max_wait=$((duration + TIMEOUT))

  log_step "Experiment: ${exp_name} (duration: ${duration}s)"

  # Apply experiment
  log_info "Applying ${exp_name}.yaml..."
  if ! kubectl apply -f "$exp_file" -n "$NAMESPACE"; then
    log_fail "Failed to apply experiment manifest"
    return 1
  fi

  # Determine ChaosEngine name from file
  local engine_name
  engine_name=$(grep -m1 'name:' "$exp_file" | awk '{print $2}' | tr -d '"')

  log_info "Waiting for ChaosEngine '${engine_name}' to complete (timeout: ${max_wait}s)..."

  # Wait for completion
  local wait_result
  wait_for_chaos_completion "$engine_name" "$max_wait"
  wait_result=$?

  # Collect results
  local verdict="unknown"
  local probe_results=""

  if [ $wait_result -eq 0 ]; then
    verdict=$(get_chaos_result "$engine_name")
    probe_results=$(get_probe_results "$engine_name")
  elif [ $wait_result -eq 2 ]; then
    verdict="timeout"
  else
    verdict="error"
  fi

  # Log result
  case "$verdict" in
    "Pass"|"pass")
      log_pass "Experiment ${exp_name}: PASSED"
      ;;
    "Fail"|"fail")
      log_fail "Experiment ${exp_name}: FAILED"
      log_info "Probe results: ${probe_results}"
      ;;
    "timeout")
      log_warn "Experiment ${exp_name}: TIMEOUT"
      ;;
    *)
      log_warn "Experiment ${exp_name}: ${verdict}"
      ;;
  esac

  # Cleanup: delete ChaosEngine to reset state
  log_info "Cleaning up ChaosEngine '${engine_name}'..."
  kubectl delete chaosengine "$engine_name" -n "$NAMESPACE" --ignore-not-found &>/dev/null

  # Store result
  echo "${exp_name}|${verdict}|${duration}|${probe_results}" >> "${REPORT_DIR}/raw_results.txt"

  # Return based on verdict
  case "$verdict" in
    "Pass"|"pass") return 0 ;;
    *) return 1 ;;
  esac
}

# ─── Steady State ────────────────────────────────────────────────────────────

run_steady_state_check() {
  local phase="$1"
  log_info "Running steady-state check (${phase})..."

  if [ -x "$STEADY_STATE_SCRIPT" ]; then
    if "$STEADY_STATE_SCRIPT" --namespace "$NAMESPACE" --quiet; then
      log_pass "Steady-state check passed (${phase})"
      return 0
    else
      log_fail "Steady-state check FAILED (${phase})"
      return 1
    fi
  else
    log_warn "Steady-state script not executable, using basic check"
    # Fallback: basic pod readiness check
    local not_ready
    not_ready=$(kubectl get pods -n "$NAMESPACE" --no-headers | grep -v "Running\|Completed" | wc -l)
    if [ "$not_ready" -eq 0 ]; then
      log_pass "All pods running (${phase})"
      return 0
    else
      log_fail "${not_ready} pod(s) not ready (${phase})"
      return 1
    fi
  fi
}

wait_for_steady_state() {
  local max_retries=6
  local retry_interval=10
  local attempt=1

  while [ $attempt -le $max_retries ]; do
    if run_steady_state_check "recovery attempt ${attempt}/${max_retries}"; then
      return 0
    fi
    log_info "Waiting ${retry_interval}s for recovery..."
    sleep $retry_interval
    attempt=$((attempt + 1))
  done

  log_fail "System did not recover to steady state within $((max_retries * retry_interval))s"
  return 1
}

# ─── Report Generation ───────────────────────────────────────────────────────

generate_report() {
  log_step "Generating Reports"

  local pass_count=0
  local fail_count=0
  local results_json="[]"

  # Parse raw results
  while IFS='|' read -r name verdict duration probes; do
    local status="fail"
    if [[ "$verdict" == "Pass" || "$verdict" == "pass" ]]; then
      status="pass"
      pass_count=$((pass_count + 1))
    else
      fail_count=$((fail_count + 1))
    fi

    results_json=$(echo "$results_json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
data.append({
    'name': '${name}',
    'status': '${status}',
    'verdict': '${verdict}',
    'duration_seconds': ${duration},
    'probe_results': '${probes}'
})
print(json.dumps(data))
" 2>/dev/null || echo "$results_json")
  done < "${REPORT_DIR}/raw_results.txt"

  local total=$((pass_count + fail_count))
  local overall="pass"
  if [ $fail_count -gt 0 ]; then
    overall="fail"
  fi

  # JSON Report
  cat > "${REPORT_DIR}/chaos-report.json" <<EOF
{
  "suite_run_id": "${SUITE_RUN_ID}",
  "timestamp": "${TIMESTAMP}",
  "namespace": "${NAMESPACE}",
  "litmus_version": "3.x",
  "total_experiments": ${total},
  "pass_count": ${pass_count},
  "fail_count": ${fail_count},
  "overall": "${overall}",
  "experiments": ${results_json}
}
EOF

  # Markdown Report
  cat > "${REPORT_DIR}/chaos-report.md" <<EOF
# Chaos Test Report — Sentinel Gateway

**Run ID**: \`${SUITE_RUN_ID}\`
**Timestamp**: ${TIMESTAMP}
**Namespace**: ${NAMESPACE}
**Overall Result**: ${overall^^}

## Results

| # | Experiment | Duration | Verdict | Status |
|---|-----------|----------|---------|--------|
EOF

  local i=1
  while IFS='|' read -r name verdict duration probes; do
    local icon="[FAIL]"
    if [[ "$verdict" == "Pass" || "$verdict" == "pass" ]]; then
      icon="[PASS]"
    fi
    echo "| ${i} | ${name} | ${duration}s | ${verdict} | ${icon} |" >> "${REPORT_DIR}/chaos-report.md"
    i=$((i + 1))
  done < "${REPORT_DIR}/raw_results.txt"

  cat >> "${REPORT_DIR}/chaos-report.md" <<EOF

## Summary

- **Total**: ${total} experiments
- **Passed**: ${pass_count}
- **Failed**: ${fail_count}
- **Pass rate**: $(( (pass_count * 100) / (total > 0 ? total : 1) ))%

## Environment

- Kubernetes cluster: $(kubectl cluster-info 2>/dev/null | head -1 | sed 's/\x1b\[[0-9;]*m//g' || echo "unknown")
- LitmusChaos version: 3.x
- Sentinel Gateway namespace: ${NAMESPACE}
EOF

  log_pass "JSON report: ${REPORT_DIR}/chaos-report.json"
  log_pass "Markdown report: ${REPORT_DIR}/chaos-report.md"

  # Print summary
  echo ""
  echo "════════════════════════════════════════════════════════════════"
  echo "  CHAOS TEST SUITE RESULTS"
  echo "════════════════════════════════════════════════════════════════"
  echo "  Total:   ${total}"
  echo "  Passed:  ${pass_count}"
  echo "  Failed:  ${fail_count}"
  echo "  Result:  ${overall^^}"
  echo "════════════════════════════════════════════════════════════════"
  echo ""

  return $fail_count
}

# ─── Main ────────────────────────────────────────────────────────────────────

main() {
  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║     Sentinel Gateway — Chaos Testing Suite                  ║"
  echo "║     LitmusChaos v3.x                                        ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
  log_info "Namespace: ${NAMESPACE}"
  log_info "Dry run: ${DRY_RUN}"
  log_info "Suite ID: ${SUITE_RUN_ID}"
  echo ""

  # Setup report directory
  mkdir -p "$REPORT_DIR"
  rm -f "${REPORT_DIR}/raw_results.txt"
  touch "${REPORT_DIR}/raw_results.txt"

  # Prerequisites
  check_prerequisites

  # Dry run mode
  if [ "$DRY_RUN" = true ]; then
    dry_run_validate
  fi

  # Initial steady-state validation
  log_step "Initial Steady-State Validation"
  if ! run_steady_state_check "pre-suite"; then
    log_fail "System not in steady state before starting. Fix issues first."
    exit 1
  fi

  # Run experiments
  local consecutive_failures=0

  for exp in "${EXPERIMENTS[@]}"; do
    # Check abort condition
    if [ $consecutive_failures -ge $MAX_CONSECUTIVE_FAILURES ]; then
      log_fail "ABORTING: ${MAX_CONSECUTIVE_FAILURES} consecutive failures reached"
      log_fail "Remaining experiments skipped: ${EXPERIMENTS[*]:$((${#EXPERIMENTS[@]} - consecutive_failures))}"
      break
    fi

    # Run experiment
    if run_experiment "$exp"; then
      consecutive_failures=0
    else
      consecutive_failures=$((consecutive_failures + 1))
    fi

    # Wait for steady state recovery between experiments
    log_info "Waiting for system recovery before next experiment..."
    sleep 15  # Grace period for pods to stabilize

    if ! wait_for_steady_state; then
      log_warn "System not fully recovered, proceeding with caution..."
    fi
  done

  # Generate report
  generate_report
  local exit_code=$?

  # Cleanup
  log_info "Cleaning up any remaining ChaosEngines..."
  kubectl delete chaosengine --all -n "$NAMESPACE" --ignore-not-found &>/dev/null || true

  exit $exit_code
}

main "$@"
