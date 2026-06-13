#!/usr/bin/env bash
# ============================================================================
# Sentinel Gateway — Incident Response Evidence Collection
#
# Automated forensic evidence collection for security incidents.
# Produces a timestamped tarball with SHA-256 chain-of-custody manifest.
#
# IMPORTANT: This script performs READ-ONLY operations.
# It does NOT modify any running state, pods, or data.
#
# Usage:
#   ./scripts/ir-collect-evidence.sh [OPTIONS]
#
# Options:
#   --namespace, -n    Kubernetes namespace (default: sentinel-gateway)
#   --since, -s        Time window for logs (default: 30m)
#   --output-dir, -o   Output directory (default: /tmp/sentinel-evidence)
#   --help, -h         Show usage
#
# Output:
#   incident-evidence-<TIMESTAMP>.tar.gz
#   evidence-manifest.sha256
#
# SOC 2 CC7.3: Evidence preservation for incident response
# ============================================================================

set -euo pipefail

# --- Defaults ---
NAMESPACE="sentinel-gateway"
SINCE="30m"
OUTPUT_DIR="/tmp/sentinel-evidence"
TIMESTAMP=$(date -u +%Y%m%d_%H%M%S_UTC)
EVIDENCE_DIR="${OUTPUT_DIR}/evidence-${TIMESTAMP}"
TARBALL_NAME="incident-evidence-${TIMESTAMP}.tar.gz"
MANIFEST_NAME="evidence-manifest-${TIMESTAMP}.sha256"

# --- Colors (if terminal supports) ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Functions ---
usage() {
    cat <<EOF
Sentinel Gateway — Incident Response Evidence Collection

Usage: $(basename "$0") [OPTIONS]

Options:
  --namespace, -n <ns>     Kubernetes namespace (default: sentinel-gateway)
  --since, -s <duration>   Log time window, e.g. 30m, 1h, 2h (default: 30m)
  --output-dir, -o <path>  Output directory (default: /tmp/sentinel-evidence)
  --help, -h               Show this help

Output:
  <output-dir>/incident-evidence-<TIMESTAMP>.tar.gz
  <output-dir>/evidence-manifest-<TIMESTAMP>.sha256

Notes:
  - All operations are READ-ONLY (no state modification)
  - Requires kubectl access to the target namespace
  - Evidence tarball is SHA-256 hashed for chain of custody
  - Suitable for SOC 2 auditor review and legal proceedings

Examples:
  # Collect last 30 minutes (default)
  ./scripts/ir-collect-evidence.sh

  # Collect last 2 hours from custom namespace
  ./scripts/ir-collect-evidence.sh --namespace prod-sentinel --since 2h

  # Custom output directory
  ./scripts/ir-collect-evidence.sh --output-dir ./incident-INC-1234/
EOF
    exit 0
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

collect_step() {
    local description="$1"
    local output_file="$2"
    local command="$3"

    echo -e "${BLUE}[COLLECT]${NC} ${description}..."
    if eval "${command}" > "${EVIDENCE_DIR}/${output_file}" 2>&1; then
        local size
        size=$(wc -c < "${EVIDENCE_DIR}/${output_file}" 2>/dev/null || echo "0")
        log_success "${description} (${size} bytes)"
    else
        log_warn "${description} — command failed (non-fatal, continuing)"
        echo "COLLECTION FAILED: ${command}" > "${EVIDENCE_DIR}/${output_file}"
    fi
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case $1 in
        --namespace|-n)
            NAMESPACE="$2"
            shift 2
            ;;
        --since|-s)
            SINCE="$2"
            shift 2
            ;;
        --output-dir|-o)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --help|-h)
            usage
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

# Update paths after argument parsing
EVIDENCE_DIR="${OUTPUT_DIR}/evidence-${TIMESTAMP}"

# --- Pre-flight Checks ---
echo "=============================================="
echo " Sentinel Gateway — Evidence Collection"
echo " SOC 2 CC7.3 Compliant"
echo "=============================================="
echo ""
echo "  Namespace:  ${NAMESPACE}"
echo "  Time window: --since=${SINCE}"
echo "  Output:     ${OUTPUT_DIR}/"
echo "  Timestamp:  ${TIMESTAMP}"
echo ""
echo "  NOTE: All operations are READ-ONLY"
echo ""
echo "=============================================="
echo ""

# Check kubectl is available
if ! command -v kubectl &> /dev/null; then
    log_error "kubectl not found in PATH. Cannot collect evidence."
    exit 1
fi

# Check namespace exists
if ! kubectl get namespace "${NAMESPACE}" &> /dev/null; then
    log_error "Namespace '${NAMESPACE}' not found. Check --namespace parameter."
    exit 1
fi

# Create evidence directory
mkdir -p "${EVIDENCE_DIR}"
log_info "Evidence directory created: ${EVIDENCE_DIR}"

# --- Metadata ---
log_info "Recording collection metadata..."
cat > "${EVIDENCE_DIR}/00-collection-metadata.txt" <<EOF
============================================
INCIDENT EVIDENCE COLLECTION METADATA
============================================

Collection timestamp (UTC): ${TIMESTAMP}
Collector: $(whoami)@$(hostname)
kubectl context: $(kubectl config current-context 2>/dev/null || echo "unknown")
Kubernetes cluster: $(kubectl cluster-info 2>/dev/null | head -1 || echo "unknown")
Namespace: ${NAMESPACE}
Time window: ${SINCE}
Script version: 1.0.0
Script path: scripts/ir-collect-evidence.sh
Script SHA-256: $(sha256sum "$0" 2>/dev/null | awk '{print $1}' || echo "unknown")

============================================
CHAIN OF CUSTODY
============================================
Collected by: $(whoami)
Collection time: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
Purpose: Incident response evidence preservation
Handling: Evidence must be stored in write-once storage
Access: Requires Incident Commander or Legal approval

============================================
IMPORTANT NOTES
============================================
- All collection operations were READ-ONLY
- No running state was modified during collection
- Tarball integrity can be verified via accompanying .sha256 manifest
- Individual files are timestamped for timeline reconstruction
EOF
log_success "Metadata recorded"

# ============================================================================
# SECTION 1: Pod and Deployment Status
# ============================================================================
log_info "--- Section 1: Kubernetes Resource Status ---"

collect_step "Pod status (all pods in namespace)" \
    "01-pods-status.txt" \
    "kubectl get pods -n ${NAMESPACE} -o wide"

collect_step "Pod descriptions (detailed)" \
    "01-pods-describe.txt" \
    "kubectl describe pods -n ${NAMESPACE}"

collect_step "Deployments" \
    "01-deployments.txt" \
    "kubectl get deployments -n ${NAMESPACE} -o yaml"

collect_step "Services" \
    "01-services.txt" \
    "kubectl get svc -n ${NAMESPACE} -o yaml"

collect_step "Recent Kubernetes events" \
    "01-events.txt" \
    "kubectl get events -n ${NAMESPACE} --sort-by='.lastTimestamp'"

collect_step "HPA status" \
    "01-hpa.txt" \
    "kubectl get hpa -n ${NAMESPACE} -o yaml"

collect_step "PodDisruptionBudgets" \
    "01-pdb.txt" \
    "kubectl get pdb -n ${NAMESPACE} -o yaml"

collect_step "Resource usage (top pods)" \
    "01-resource-usage.txt" \
    "kubectl top pods -n ${NAMESPACE}"

# ============================================================================
# SECTION 2: Application Logs
# ============================================================================
log_info "--- Section 2: Application Logs ---"

collect_step "Proxy logs (current, --since=${SINCE})" \
    "02-proxy-logs.jsonl" \
    "kubectl logs deploy/proxy -n ${NAMESPACE} --since=${SINCE} --all-containers"

collect_step "Proxy logs (previous instance, if crashed)" \
    "02-proxy-logs-previous.jsonl" \
    "kubectl logs deploy/proxy -n ${NAMESPACE} --previous --all-containers --tail=1000"

collect_step "Admin logs (current, --since=${SINCE})" \
    "02-admin-logs.jsonl" \
    "kubectl logs deploy/admin -n ${NAMESPACE} --since=${SINCE} --all-containers"

collect_step "Admin logs (previous instance)" \
    "02-admin-logs-previous.jsonl" \
    "kubectl logs deploy/admin -n ${NAMESPACE} --previous --all-containers --tail=1000"

collect_step "Redis logs" \
    "02-redis-logs.txt" \
    "kubectl logs -l app.kubernetes.io/name=redis -n ${NAMESPACE} --since=${SINCE}"

# ============================================================================
# SECTION 3: Redis State (Security Counters and Recent Blocks)
# ============================================================================
log_info "--- Section 3: Redis State ---"

collect_step "Redis global counters" \
    "03-redis-counters.txt" \
    "kubectl exec deploy/redis -n ${NAMESPACE} -- redis-cli --no-auth-warning MGET sentinel:global:requests_total sentinel:global:block sentinel:global:allow sentinel:global:warn"

collect_step "Redis SIEM stats" \
    "03-redis-siem-stats.txt" \
    "kubectl exec deploy/redis -n ${NAMESPACE} -- redis-cli --no-auth-warning MGET sentinel:siem:batches_sent sentinel:siem:events_exported sentinel:siem:export_errors sentinel:siem:transports sentinel:siem:queue_memory_depth sentinel:siem:updated_at"

collect_step "Redis recent blocks (last 100)" \
    "03-redis-recent-blocks.json" \
    "kubectl exec deploy/redis -n ${NAMESPACE} -- redis-cli --no-auth-warning LRANGE sentinel:recent_blocks 0 99"

collect_step "Redis guardrail version" \
    "03-redis-guardrail-version.txt" \
    "kubectl exec deploy/redis -n ${NAMESPACE} -- redis-cli --no-auth-warning GET sentinel:guardrails:version"

collect_step "Redis disabled patterns" \
    "03-redis-disabled-patterns.txt" \
    "kubectl exec deploy/redis -n ${NAMESPACE} -- redis-cli --no-auth-warning SMEMBERS sentinel:guardrails:disabled"

collect_step "Redis custom patterns" \
    "03-redis-custom-patterns.txt" \
    "kubectl exec deploy/redis -n ${NAMESPACE} -- redis-cli --no-auth-warning HGETALL sentinel:guardrails:custom"

collect_step "Redis rate limit keys" \
    "03-redis-rate-limit-keys.txt" \
    "kubectl exec deploy/redis -n ${NAMESPACE} -- redis-cli --no-auth-warning KEYS 'sentinel:rate_limit:*'"

collect_step "Redis INFO (memory, clients, stats)" \
    "03-redis-info.txt" \
    "kubectl exec deploy/redis -n ${NAMESPACE} -- redis-cli --no-auth-warning INFO"

# ============================================================================
# SECTION 4: Security Configuration State
# ============================================================================
log_info "--- Section 4: Security Configuration ---"

collect_step "Network policies" \
    "04-network-policies.yaml" \
    "kubectl get networkpolicies -n ${NAMESPACE} -o yaml"

collect_step "Secrets metadata (no values)" \
    "04-secrets-metadata.txt" \
    "kubectl get secrets -n ${NAMESPACE} -o custom-columns=NAME:.metadata.name,TYPE:.type,CREATED:.metadata.creationTimestamp"

collect_step "ConfigMaps" \
    "04-configmaps.yaml" \
    "kubectl get configmaps -n ${NAMESPACE} -o yaml"

collect_step "Ingress configuration" \
    "04-ingress.yaml" \
    "kubectl get ingress -n ${NAMESPACE} -o yaml"

collect_step "TLS certificate expiry" \
    "04-tls-certificates.txt" \
    "kubectl get secrets -n ${NAMESPACE} --field-selector type=kubernetes.io/tls -o name | while read s; do echo \"=== \$s ===\"; kubectl get \$s -n ${NAMESPACE} -o jsonpath='{.data.tls\\.crt}' | base64 -d 2>/dev/null | openssl x509 -noout -dates -subject 2>/dev/null || echo 'Failed to decode'; done"

collect_step "Service account permissions" \
    "04-service-accounts.yaml" \
    "kubectl get serviceaccounts -n ${NAMESPACE} -o yaml"

# ============================================================================
# SECTION 5: Prometheus Alert State
# ============================================================================
log_info "--- Section 5: Alert State ---"

# Try to get Prometheus alerts (may fail if not port-forwarded)
collect_step "Prometheus firing alerts" \
    "05-prometheus-alerts.json" \
    "kubectl exec deploy/prometheus -n ${NAMESPACE} -- wget -qO- http://localhost:9090/api/v1/alerts 2>/dev/null || echo 'Prometheus not accessible via kubectl exec'"

collect_step "Prometheus targets" \
    "05-prometheus-targets.json" \
    "kubectl exec deploy/prometheus -n ${NAMESPACE} -- wget -qO- http://localhost:9090/api/v1/targets 2>/dev/null || echo 'Prometheus not accessible via kubectl exec'"

# ============================================================================
# SECTION 6: Proxy Health and Metrics
# ============================================================================
log_info "--- Section 6: Health and Metrics ---"

collect_step "Proxy health check" \
    "06-proxy-health.json" \
    "kubectl exec deploy/proxy -n ${NAMESPACE} -- curl -s http://localhost:8080/health"

collect_step "Proxy health stats" \
    "06-proxy-health-stats.json" \
    "kubectl exec deploy/proxy -n ${NAMESPACE} -- curl -s http://localhost:8080/health/stats"

collect_step "Admin health check" \
    "06-admin-health.json" \
    "kubectl exec deploy/admin -n ${NAMESPACE} -- curl -s http://localhost:8090/admin/health"

# ============================================================================
# SECTION 7: Persistent Volume Status
# ============================================================================
log_info "--- Section 7: Storage ---"

collect_step "PersistentVolumeClaims" \
    "07-pvcs.yaml" \
    "kubectl get pvc -n ${NAMESPACE} -o yaml"

collect_step "Volume usage" \
    "07-volume-usage.txt" \
    "kubectl exec deploy/proxy -n ${NAMESPACE} -- df -h 2>/dev/null || echo 'df not available in container'"

# ============================================================================
# PACKAGE AND HASH
# ============================================================================
log_info "--- Packaging Evidence ---"

# Create file listing
log_info "Creating file inventory..."
find "${EVIDENCE_DIR}" -type f -exec sha256sum {} \; > "${EVIDENCE_DIR}/00-file-inventory.sha256"
log_success "File inventory created ($(wc -l < "${EVIDENCE_DIR}/00-file-inventory.sha256") files)"

# Create tarball
log_info "Creating compressed tarball..."
tar -czf "${OUTPUT_DIR}/${TARBALL_NAME}" -C "${OUTPUT_DIR}" "evidence-${TIMESTAMP}"
log_success "Tarball created: ${OUTPUT_DIR}/${TARBALL_NAME}"

# Generate chain-of-custody hash
log_info "Generating SHA-256 integrity hash..."
sha256sum "${OUTPUT_DIR}/${TARBALL_NAME}" > "${OUTPUT_DIR}/${MANIFEST_NAME}"
log_success "Manifest: ${OUTPUT_DIR}/${MANIFEST_NAME}"

# Display manifest
echo ""
echo "=============================================="
echo " EVIDENCE COLLECTION COMPLETE"
echo "=============================================="
echo ""
echo "  Tarball:  ${OUTPUT_DIR}/${TARBALL_NAME}"
echo "  Manifest: ${OUTPUT_DIR}/${MANIFEST_NAME}"
echo "  SHA-256:  $(cat "${OUTPUT_DIR}/${MANIFEST_NAME}" | awk '{print $1}')"
echo ""
echo "  Total files collected: $(find "${EVIDENCE_DIR}" -type f | wc -l)"
echo "  Tarball size: $(du -h "${OUTPUT_DIR}/${TARBALL_NAME}" | awk '{print $1}')"
echo ""
echo "  Chain of Custody:"
echo "    Collected by: $(whoami)"
echo "    Collected at: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "    From cluster: $(kubectl config current-context 2>/dev/null || echo "unknown")"
echo ""
echo "  NEXT STEPS:"
echo "    1. Store tarball in write-once storage (S3 Object Lock, WORM, etc.)"
echo "    2. Record manifest hash in incident ticket"
echo "    3. Do NOT modify the tarball after collection"
echo "    4. Share only with IC or Legal approval"
echo ""
echo "=============================================="

# Cleanup working directory (keep tarball and manifest only)
rm -rf "${EVIDENCE_DIR}"
log_info "Working directory cleaned (tarball and manifest remain)"
