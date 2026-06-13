#!/usr/bin/env bash
#
# Sentinel Gateway — Steady-State Health Check
#
# Validates that the system is in a healthy state before/after chaos experiments.
# Used by run-chaos-suite.sh between experiments and can be run independently.
#
# Checks:
#   1. All proxy pods Ready
#   2. Redis pod Ready
#   3. Admin pod Ready
#   4. /health returns 200 from proxy
#   5. /admin/health returns 200 from admin
#   6. Redis PING succeeds
#   7. No pods in CrashLoopBackOff
#
# Usage:
#   ./tests/chaos/steady-state-check.sh [--namespace NS] [--quiet] [--strict]
#

set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────

NAMESPACE="sentinel-gateway"
QUIET=false
STRICT=false
PROXY_SERVICE="sentinel-proxy"
ADMIN_SERVICE="sentinel-admin"
PROXY_PORT=8080
ADMIN_PORT=8090

# ─── Argument Parsing ────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case $1 in
    --namespace|-n)
      NAMESPACE="$2"
      shift 2
      ;;
    --quiet|-q)
      QUIET=true
      shift
      ;;
    --strict|-s)
      STRICT=true
      shift
      ;;
    --help|-h)
      echo "Usage: $0 [--namespace NS] [--quiet] [--strict]"
      echo ""
      echo "Options:"
      echo "  --namespace, -n  Target namespace (default: sentinel-gateway)"
      echo "  --quiet, -q      Only output on failure"
      echo "  --strict, -s     Fail on warnings (not just errors)"
      echo "  --help, -h       Show this help"
      exit 0
      ;;
    *)
      echo "ERROR: Unknown option: $1"
      exit 1
      ;;
  esac
done

# ─── Output ─────────────────────────────────────────────────────────────────

CHECKS_PASSED=0
CHECKS_FAILED=0
CHECKS_WARNED=0

log() {
  if [ "$QUIET" = false ]; then
    echo "$@"
  fi
}

check_pass() {
  CHECKS_PASSED=$((CHECKS_PASSED + 1))
  log "  [PASS] $1"
}

check_fail() {
  CHECKS_FAILED=$((CHECKS_FAILED + 1))
  echo "  [FAIL] $1" >&2
}

check_warn() {
  CHECKS_WARNED=$((CHECKS_WARNED + 1))
  log "  [WARN] $1"
}

# ─── Health Checks ───────────────────────────────────────────────────────────

check_proxy_pods_ready() {
  local total ready not_ready

  total=$(kubectl get pods -n "$NAMESPACE" \
    -l app.kubernetes.io/component=proxy \
    --no-headers 2>/dev/null | wc -l)

  if [ "$total" -eq 0 ]; then
    check_fail "No proxy pods found"
    return 1
  fi

  ready=$(kubectl get pods -n "$NAMESPACE" \
    -l app.kubernetes.io/component=proxy \
    --no-headers 2>/dev/null | grep -c "Running" || echo "0")

  not_ready=$((total - ready))

  if [ "$not_ready" -eq 0 ]; then
    check_pass "All proxy pods Ready (${ready}/${total})"
    return 0
  else
    check_fail "Proxy pods not ready: ${not_ready}/${total} unhealthy"
    return 1
  fi
}

check_redis_pod_ready() {
  local redis_pods

  redis_pods=$(kubectl get pods -n "$NAMESPACE" \
    -l app.kubernetes.io/component=redis \
    --no-headers 2>/dev/null | wc -l)

  if [ "$redis_pods" -eq 0 ]; then
    # Redis might be external — check if configured
    local redis_url
    redis_url=$(kubectl get configmap -n "$NAMESPACE" -o json 2>/dev/null | \
      grep -o "SENTINEL_REDIS_URL[^,]*" | head -1 || echo "")

    if [ -n "$redis_url" ]; then
      check_warn "No Redis pod (external Redis configured)"
    else
      check_warn "No Redis pod found (may be optional)"
    fi
    return 0
  fi

  local ready
  ready=$(kubectl get pods -n "$NAMESPACE" \
    -l app.kubernetes.io/component=redis \
    --no-headers 2>/dev/null | grep -c "Running" || echo "0")

  if [ "$ready" -ge 1 ]; then
    check_pass "Redis pod Ready (${ready}/${redis_pods})"
    return 0
  else
    check_fail "Redis pod not ready"
    return 1
  fi
}

check_admin_pod_ready() {
  local admin_pods

  admin_pods=$(kubectl get pods -n "$NAMESPACE" \
    -l app.kubernetes.io/component=admin \
    --no-headers 2>/dev/null | wc -l)

  if [ "$admin_pods" -eq 0 ]; then
    check_warn "No admin pods found (may be optional)"
    return 0
  fi

  local ready
  ready=$(kubectl get pods -n "$NAMESPACE" \
    -l app.kubernetes.io/component=admin \
    --no-headers 2>/dev/null | grep -c "Running" || echo "0")

  if [ "$ready" -ge 1 ]; then
    check_pass "Admin pod Ready (${ready}/${admin_pods})"
    return 0
  else
    check_fail "Admin pod not ready"
    return 1
  fi
}

check_proxy_health_endpoint() {
  local proxy_pod response_code

  proxy_pod=$(kubectl get pod -n "$NAMESPACE" \
    -l app.kubernetes.io/component=proxy \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

  if [ -z "$proxy_pod" ]; then
    check_fail "Cannot find proxy pod for health check"
    return 1
  fi

  # Use kubectl exec to call health endpoint from within the cluster
  response_code=$(kubectl exec -n "$NAMESPACE" "$proxy_pod" -- \
    wget -qO- --spider -S "http://localhost:${PROXY_PORT}/health" 2>&1 | \
    grep "HTTP/" | awk '{print $2}' | tail -1 || echo "000")

  # Fallback: try with python (proxy image has python)
  if [ "$response_code" = "000" ]; then
    response_code=$(kubectl exec -n "$NAMESPACE" "$proxy_pod" -- \
      python3 -c "
import urllib.request
try:
    r = urllib.request.urlopen('http://localhost:${PROXY_PORT}/health', timeout=5)
    print(r.status)
except Exception as e:
    print('000')
" 2>/dev/null || echo "000")
  fi

  if [ "$response_code" = "200" ]; then
    check_pass "Proxy /health returns 200"
    return 0
  else
    check_fail "Proxy /health returned ${response_code} (expected 200)"
    return 1
  fi
}

check_admin_health_endpoint() {
  local admin_pod response_code

  admin_pod=$(kubectl get pod -n "$NAMESPACE" \
    -l app.kubernetes.io/component=admin \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

  if [ -z "$admin_pod" ]; then
    check_warn "Cannot find admin pod for health check (may be optional)"
    return 0
  fi

  response_code=$(kubectl exec -n "$NAMESPACE" "$admin_pod" -- \
    python3 -c "
import urllib.request
try:
    r = urllib.request.urlopen('http://localhost:${ADMIN_PORT}/admin/health', timeout=5)
    print(r.status)
except Exception as e:
    print('000')
" 2>/dev/null || echo "000")

  if [ "$response_code" = "200" ]; then
    check_pass "Admin /admin/health returns 200"
    return 0
  else
    check_fail "Admin /admin/health returned ${response_code} (expected 200)"
    return 1
  fi
}

check_redis_ping() {
  local redis_pod

  redis_pod=$(kubectl get pod -n "$NAMESPACE" \
    -l app.kubernetes.io/component=redis \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

  if [ -z "$redis_pod" ]; then
    check_warn "No Redis pod for PING check (external Redis or optional)"
    return 0
  fi

  local ping_result
  ping_result=$(kubectl exec -n "$NAMESPACE" "$redis_pod" -- \
    redis-cli PING 2>/dev/null || echo "FAILED")

  if [ "$ping_result" = "PONG" ]; then
    check_pass "Redis PING → PONG"
    return 0
  else
    check_fail "Redis PING failed (got: ${ping_result})"
    return 1
  fi
}

check_no_crashloopbackoff() {
  local crashloop_pods

  crashloop_pods=$(kubectl get pods -n "$NAMESPACE" --no-headers 2>/dev/null | \
    grep -c "CrashLoopBackOff" || echo "0")

  if [ "$crashloop_pods" -eq 0 ]; then
    check_pass "No pods in CrashLoopBackOff"
    return 0
  else
    check_fail "${crashloop_pods} pod(s) in CrashLoopBackOff"
    kubectl get pods -n "$NAMESPACE" --no-headers 2>/dev/null | \
      grep "CrashLoopBackOff" | awk '{print "         -> " $1}' >&2
    return 1
  fi
}

# ─── Additional Checks (strict mode) ────────────────────────────────────────

check_no_pending_pods() {
  local pending_pods

  pending_pods=$(kubectl get pods -n "$NAMESPACE" --no-headers 2>/dev/null | \
    grep -c "Pending" || echo "0")

  if [ "$pending_pods" -eq 0 ]; then
    check_pass "No pods in Pending state"
    return 0
  else
    check_warn "${pending_pods} pod(s) in Pending state"
    return 0
  fi
}

check_no_recent_restarts() {
  local high_restart_pods

  high_restart_pods=$(kubectl get pods -n "$NAMESPACE" \
    -o jsonpath='{range .items[*]}{.metadata.name}{" "}{range .status.containerStatuses[*]}{.restartCount}{" "}{end}{"\n"}{end}' 2>/dev/null | \
    awk '{for(i=2;i<=NF;i++) if($i+0 > 5) print $1}' | wc -l)

  if [ "$high_restart_pods" -eq 0 ]; then
    check_pass "No pods with excessive restarts (>5)"
    return 0
  else
    check_warn "${high_restart_pods} pod(s) with >5 restarts"
    return 0
  fi
}

# ─── Main ────────────────────────────────────────────────────────────────────

main() {
  log ""
  log "Sentinel Gateway — Steady-State Health Check"
  log "Namespace: ${NAMESPACE}"
  log "─────────────────────────────────────────────"
  log ""

  # Core checks (always run)
  check_proxy_pods_ready
  check_redis_pod_ready
  check_admin_pod_ready
  check_proxy_health_endpoint
  check_admin_health_endpoint
  check_redis_ping
  check_no_crashloopbackoff

  # Extended checks
  check_no_pending_pods
  check_no_recent_restarts

  # Summary
  local total=$((CHECKS_PASSED + CHECKS_FAILED + CHECKS_WARNED))
  log ""
  log "─────────────────────────────────────────────"
  log "Results: ${CHECKS_PASSED} passed, ${CHECKS_FAILED} failed, ${CHECKS_WARNED} warnings (${total} total)"
  log ""

  # Exit code
  if [ "$CHECKS_FAILED" -gt 0 ]; then
    log "STEADY STATE: UNHEALTHY"
    exit 1
  fi

  if [ "$STRICT" = true ] && [ "$CHECKS_WARNED" -gt 0 ]; then
    log "STEADY STATE: DEGRADED (strict mode)"
    exit 1
  fi

  log "STEADY STATE: HEALTHY"
  exit 0
}

main
