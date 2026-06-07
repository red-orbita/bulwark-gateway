#!/bin/bash
# ============================================================
# Sentinel Gateway — Kubernetes Deployment Script
#
# Prerequisites:
#   - kubectl configured with target cluster
#   - Docker images built and pushed to registry
#   - secrets/init.sh already run (secrets exist)
#
# Usage:
#   ./k8s/deploy.sh                    # Full deploy
#   ./k8s/deploy.sh --backend-ip IP    # Specify backend IP explicitly
#   ./k8s/deploy.sh --secrets-only     # Only update secrets
#   ./k8s/deploy.sh --dry-run          # Preview manifests
#
# Environment:
#   BACKEND_IP — IP of the LLM backend (auto-detected on minikube)
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err() { echo -e "${RED}[✗]${NC} $1" >&2; }

# --- Parse args ---
DRY_RUN=""
SECRETS_ONLY=false
BACKEND_IP="${BACKEND_IP:-}"
for arg in "$@"; do
    case $arg in
        --dry-run) DRY_RUN="--dry-run=client -o yaml" ;;
        --secrets-only) SECRETS_ONLY=true ;;
        --backend-ip=*) BACKEND_IP="${arg#*=}" ;;
        --backend-ip) NEXT_IS_BACKEND_IP=true ;;
        *)
            if [ "${NEXT_IS_BACKEND_IP:-}" = true ]; then
                BACKEND_IP="$arg"
                NEXT_IS_BACKEND_IP=false
            fi
            ;;
    esac
done

# --- 1. Create namespace ---
log "Creating namespace..."
kubectl apply -f "$SCRIPT_DIR/namespace.yaml" $DRY_RUN

# --- 2. Configure external backends ---
if [ -z "$BACKEND_IP" ]; then
    # Auto-detect minikube gateway IP
    if command -v minikube &>/dev/null && minikube status &>/dev/null; then
        MINIKUBE_IP="$(minikube ip 2>/dev/null)"
        if [ -n "$MINIKUBE_IP" ]; then
            # Gateway is the .1 address on minikube's network
            BACKEND_IP="${MINIKUBE_IP%.*}.1"
            log "Auto-detected minikube gateway: $BACKEND_IP"
        fi
    fi
fi

if [ -z "$BACKEND_IP" ]; then
    err "BACKEND_IP is not set and minikube auto-detection failed."
    echo ""
    echo "  Set the backend IP using one of:"
    echo "    export BACKEND_IP=<your-backend-ip>"
    echo "    ./k8s/deploy.sh --backend-ip <your-backend-ip>"
    echo ""
    echo "  Examples:"
    echo "    export BACKEND_IP=10.0.1.50        # On-prem / cloud VM"
    echo "    export BACKEND_IP=192.168.49.1     # Minikube default gateway"
    echo ""
    exit 1
fi

log "Configuring external backends (BACKEND_IP=$BACKEND_IP)..."
sed "s/\${BACKEND_IP}/$BACKEND_IP/g" "$SCRIPT_DIR/base/external-backends.yaml" \
    | kubectl apply $DRY_RUN -f -

# --- 3. Generate and apply secrets ---
log "Generating Kubernetes secrets from local files..."
if [ ! -f "$PROJECT_DIR/secrets/jwt_secret.txt" ]; then
    err "Secrets not found. Run: ./secrets/init.sh"
    exit 1
fi
bash "$SCRIPT_DIR/secrets/generate-secrets.sh" | kubectl apply $DRY_RUN -f -
log "Secrets applied (encrypted at rest via etcd encryption)"

if [ "$SECRETS_ONLY" = true ]; then
    log "Secrets-only mode. Done."
    exit 0
fi

# --- 4. Create ConfigMap from large config files ---
log "Creating static config ConfigMap..."
kubectl create configmap sentinel-static-config \
    --from-file=iocs.json="$PROJECT_DIR/config/iocs.json" \
    --from-file=agents.yaml="$PROJECT_DIR/config/agents.yaml" \
    -n sentinel-gateway \
    --dry-run=client -o yaml | kubectl apply $DRY_RUN -f -

# --- 5. Apply all manifests via Kustomize ---
log "Applying Kustomize manifests..."
kubectl apply -k "$SCRIPT_DIR" $DRY_RUN

# --- 6. Wait for rollout ---
if [ -z "$DRY_RUN" ]; then
    log "Waiting for Redis..."
    kubectl rollout status deployment/redis -n sentinel-gateway --timeout=120s

    log "Waiting for Proxy..."
    kubectl rollout status deployment/proxy -n sentinel-gateway --timeout=180s

    log "Waiting for Admin..."
    kubectl rollout status deployment/admin -n sentinel-gateway --timeout=120s

    log "Waiting for Wazuh (sentinel-siem namespace)..."
    kubectl rollout status statefulset/wazuh -n sentinel-siem --timeout=300s || warn "Wazuh not ready (may need manual pull of image)"

    echo ""
    log "=========================================="
    log "  Sentinel Gateway deployed successfully!"
    log "=========================================="
    echo ""
    echo "  Proxy:      kubectl port-forward svc/proxy 8080:8080 -n sentinel-gateway"
    echo "  Admin:      kubectl port-forward svc/admin 8090:8090 -n sentinel-gateway"
    echo "  Prometheus: kubectl port-forward svc/prometheus 9090:9090 -n sentinel-gateway"
    echo "  Grafana:    kubectl port-forward svc/grafana 3000:3000 -n sentinel-gateway"
    echo ""
    echo "  Or configure Ingress with your domain (see k8s/base/ingress.yaml)"
    echo ""
fi
