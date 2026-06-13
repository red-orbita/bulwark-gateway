#!/usr/bin/env bash
# =============================================================================
# Sentinel Gateway — Load Test Orchestrator
#
# Runs all k6 load test scenarios sequentially, collects results,
# and produces a summary report.
#
# Usage:
#   ./tests/load/run-benchmarks.sh [OPTIONS]
#
# Options:
#   --target-url URL    Target proxy URL (default: http://localhost:8080)
#   --vus N             Virtual users per scenario (default: 50)
#   --api-key KEY       API key for auth (default: test-api-key-load-bench)
#   --scenario NAME     Run single scenario (guardrail|pipeline|streaming|multi-tenant|spike)
#   --quick             Run shortened version (30s steady state)
#   --output-dir DIR    Results output directory (default: tests/load/results)
#   --help              Show this help
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

TARGET_URL="${TARGET_URL:-http://localhost:8080}"
VUS="${VUS:-50}"
API_KEY="${API_KEY:-test-api-key-load-bench}"
SCENARIO=""
QUICK=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/results"
OVERALL_EXIT=0

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
  case $1 in
    --target-url)
      TARGET_URL="$2"
      shift 2
      ;;
    --vus)
      VUS="$2"
      shift 2
      ;;
    --api-key)
      API_KEY="$2"
      shift 2
      ;;
    --scenario)
      SCENARIO="$2"
      shift 2
      ;;
    --quick)
      QUICK=true
      shift
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --help|-h)
      sed -n '3,18p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *)
      echo "ERROR: Unknown option: $1"
      exit 1
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------

echo "============================================================"
echo " Sentinel Gateway — Load Test Suite"
echo "============================================================"
echo ""
echo " Target:     ${TARGET_URL}"
echo " VUs:        ${VUS}"
echo " Quick mode: ${QUICK}"
echo " Output:     ${OUTPUT_DIR}"
echo ""

# Check k6 is installed
if ! command -v k6 &> /dev/null; then
  echo "ERROR: k6 is not installed."
  echo ""
  echo "Install k6:"
  echo "  macOS:   brew install k6"
  echo "  Linux:   sudo gpg -k && sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D68 && echo 'deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main' | sudo tee /etc/apt/sources.list.d/k6.list && sudo apt-get update && sudo apt-get install k6"
  echo "  Docker:  docker run --rm -i grafana/k6 run -"
  echo ""
  echo "See: https://k6.io/docs/get-started/installation/"
  exit 1
fi

echo " k6 version: $(k6 version)"
echo ""

# Check target is reachable
echo -n " Health check: ${TARGET_URL}/health ... "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}/health" 2>/dev/null || echo "000")
if [[ "$HTTP_CODE" == "200" ]]; then
  echo "OK (200)"
elif [[ "$HTTP_CODE" == "000" ]]; then
  echo "UNREACHABLE"
  echo ""
  echo "ERROR: Cannot connect to ${TARGET_URL}"
  echo "       Make sure the proxy is running: docker-compose up -d"
  exit 1
else
  echo "WARNING (HTTP ${HTTP_CODE})"
  echo "       Proceeding anyway — some tests may fail."
fi
echo ""

# Create output directory
mkdir -p "${OUTPUT_DIR}"

# ---------------------------------------------------------------------------
# Quick mode overrides
# ---------------------------------------------------------------------------

DURATION="2m"
if [[ "$QUICK" == "true" ]]; then
  DURATION="30s"
  VUS=$((VUS / 2))
  echo " [QUICK MODE] Reduced duration=${DURATION}, VUs=${VUS}"
  echo ""
fi

# ---------------------------------------------------------------------------
# Scenario runner
# ---------------------------------------------------------------------------

declare -a SCENARIO_RESULTS=()
declare -a SCENARIO_NAMES=()
declare -a SCENARIO_STATUS=()
declare -a SCENARIO_DURATIONS=()

run_scenario() {
  local name="$1"
  local script="$2"
  local description="$3"

  echo "------------------------------------------------------------"
  echo " Scenario: ${name}"
  echo " ${description}"
  echo "------------------------------------------------------------"

  local start_time
  start_time=$(date +%s)

  local exit_code=0
  k6 run \
    --env "TARGET_URL=${TARGET_URL}" \
    --env "VUS=${VUS}" \
    --env "API_KEY=${API_KEY}" \
    --env "DURATION=${DURATION}" \
    --out "json=${OUTPUT_DIR}/${name}-raw.json" \
    "${script}" 2>&1 | tee "${OUTPUT_DIR}/${name}.log" || exit_code=$?

  local end_time
  end_time=$(date +%s)
  local duration=$((end_time - start_time))

  SCENARIO_NAMES+=("${name}")
  SCENARIO_DURATIONS+=("${duration}s")

  if [[ $exit_code -eq 0 ]]; then
    SCENARIO_STATUS+=("PASS")
    echo ""
    echo " Result: PASS (${duration}s)"
  elif [[ $exit_code -eq 99 ]]; then
    # k6 exit code 99 = thresholds violated
    SCENARIO_STATUS+=("FAIL")
    OVERALL_EXIT=1
    echo ""
    echo " Result: FAIL — thresholds violated (${duration}s)"
  else
    SCENARIO_STATUS+=("ERROR")
    OVERALL_EXIT=1
    echo ""
    echo " Result: ERROR — exit code ${exit_code} (${duration}s)"
  fi

  echo ""
}

# ---------------------------------------------------------------------------
# Run scenarios
# ---------------------------------------------------------------------------

SCENARIOS=(
  "guardrail-only|${SCRIPT_DIR}/scenario-guardrail-only.js|Regex guardrail performance (target: p99 <3ms)"
  "full-pipeline|${SCRIPT_DIR}/scenario-full-pipeline.js|Full request pipeline without ML (target: p99 <8ms)"
  "streaming|${SCRIPT_DIR}/scenario-streaming.js|SSE streaming TTFB performance (target: p99 <15ms)"
  "multi-tenant|${SCRIPT_DIR}/scenario-multi-tenant.js|Multi-tenant isolation under load"
  "spike|${SCRIPT_DIR}/scenario-spike.js|Spike/burst traffic resilience (10x load)"
)

if [[ -n "$SCENARIO" ]]; then
  # Run single scenario
  found=false
  for entry in "${SCENARIOS[@]}"; do
    IFS='|' read -r name script desc <<< "$entry"
    if [[ "$name" == "$SCENARIO" || "$name" == *"$SCENARIO"* ]]; then
      run_scenario "$name" "$script" "$desc"
      found=true
      break
    fi
  done
  if [[ "$found" == "false" ]]; then
    echo "ERROR: Unknown scenario '${SCENARIO}'"
    echo "Available: guardrail-only, full-pipeline, streaming, multi-tenant, spike"
    exit 1
  fi
else
  # Run all scenarios
  for entry in "${SCENARIOS[@]}"; do
    IFS='|' read -r name script desc <<< "$entry"
    run_scenario "$name" "$script" "$desc"
  done
fi

# ---------------------------------------------------------------------------
# Collect summary
# ---------------------------------------------------------------------------

echo ""
echo "============================================================"
echo " BENCHMARK RESULTS SUMMARY"
echo "============================================================"
echo ""
printf " %-20s %-10s %-10s\n" "SCENARIO" "STATUS" "DURATION"
printf " %-20s %-10s %-10s\n" "--------------------" "----------" "----------"

for i in "${!SCENARIO_NAMES[@]}"; do
  local_status="${SCENARIO_STATUS[$i]}"
  if [[ "$local_status" == "PASS" ]]; then
    printf " %-20s \033[32m%-10s\033[0m %-10s\n" "${SCENARIO_NAMES[$i]}" "${local_status}" "${SCENARIO_DURATIONS[$i]}"
  else
    printf " %-20s \033[31m%-10s\033[0m %-10s\n" "${SCENARIO_NAMES[$i]}" "${local_status}" "${SCENARIO_DURATIONS[$i]}"
  fi
done

echo ""

# ---------------------------------------------------------------------------
# Generate combined JSON summary
# ---------------------------------------------------------------------------

SUMMARY_FILE="${OUTPUT_DIR}/summary.json"

# Build JSON from individual results
echo "{" > "${SUMMARY_FILE}"
echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"," >> "${SUMMARY_FILE}"
echo "  \"target_url\": \"${TARGET_URL}\"," >> "${SUMMARY_FILE}"
echo "  \"vus\": ${VUS}," >> "${SUMMARY_FILE}"
echo "  \"quick_mode\": ${QUICK}," >> "${SUMMARY_FILE}"
echo "  \"overall_passed\": $([ $OVERALL_EXIT -eq 0 ] && echo "true" || echo "false")," >> "${SUMMARY_FILE}"
echo "  \"scenarios\": {" >> "${SUMMARY_FILE}"

first=true
for i in "${!SCENARIO_NAMES[@]}"; do
  name="${SCENARIO_NAMES[$i]}"
  status="${SCENARIO_STATUS[$i]}"
  duration="${SCENARIO_DURATIONS[$i]}"
  result_file="${OUTPUT_DIR}/${name}.json"

  if [[ "$first" == "true" ]]; then
    first=false
  else
    echo "," >> "${SUMMARY_FILE}"
  fi

  echo -n "    \"${name}\": {\"status\": \"${status}\", \"duration\": \"${duration}\"" >> "${SUMMARY_FILE}"

  # Include detailed results if available
  if [[ -f "$result_file" ]]; then
    # Extract key metrics from scenario result JSON
    results=$(cat "$result_file" 2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    r = d.get('results', {})
    print(json.dumps(r))
except:
    print('{}')
" 2>/dev/null || echo "{}")
    echo -n ", \"results\": ${results}" >> "${SUMMARY_FILE}"
  fi

  echo -n "}" >> "${SUMMARY_FILE}"
done

echo "" >> "${SUMMARY_FILE}"
echo "  }" >> "${SUMMARY_FILE}"
echo "}" >> "${SUMMARY_FILE}"

echo " Summary written to: ${SUMMARY_FILE}"
echo ""

# ---------------------------------------------------------------------------
# Performance targets table
# ---------------------------------------------------------------------------

echo " Enterprise Performance Targets:"
echo ""
printf " %-25s %-8s %-8s %-8s %-12s\n" "Scenario" "p50" "p95" "p99" "Min RPS"
printf " %-25s %-8s %-8s %-8s %-12s\n" "-------------------------" "--------" "--------" "--------" "------------"
printf " %-25s %-8s %-8s %-8s %-12s\n" "Regex guardrail only" "<1ms" "<2ms" "<3ms" "15,000"
printf " %-25s %-8s %-8s %-8s %-12s\n" "Regex + IOC check" "<2ms" "<3ms" "<5ms" "12,000"
printf " %-25s %-8s %-8s %-8s %-12s\n" "Full pipeline (no ML)" "<3ms" "<5ms" "<8ms" "8,000"
printf " %-25s %-8s %-8s %-8s %-12s\n" "Streaming (TTFB)" "<5ms" "<10ms" "<15ms" "5,000"
echo ""

# ---------------------------------------------------------------------------
# Exit
# ---------------------------------------------------------------------------

if [[ $OVERALL_EXIT -ne 0 ]]; then
  echo " RESULT: FAIL — One or more scenarios violated thresholds."
  echo ""
  exit 1
else
  echo " RESULT: PASS — All scenarios within targets."
  echo ""
  exit 0
fi
