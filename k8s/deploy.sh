#!/bin/bash
# ============================================================
# Sentinel Gateway — Kubernetes Deployment Script
#
# Zero manual steps: builds images, loads into cluster, and deploys.
#
# Usage:
#   ./k8s/deploy.sh                    # Full deploy (build + deploy)
#   ./k8s/deploy.sh --backend-ip IP    # Specify backend IP explicitly
#   ./k8s/deploy.sh --no-build         # Skip image build (use existing)
#   ./k8s/deploy.sh --secrets-only     # Only update secrets
#   ./k8s/deploy.sh --dry-run          # Preview manifests (no build)
#
# Environment:
#   BACKEND_IP    — IP of the LLM backend (auto-detected on minikube)
#   IMAGE_REGISTRY — Registry prefix (default: none, local images)
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err() { echo -e "${RED}[✗]${NC} $1" >&2; }
step() { echo -e "${CYAN}[→]${NC} $1"; }

# --- Version (single source of truth) ---
PROXY_VERSION="0.4.3"
ADMIN_VERSION="0.4.3-sp2"
IMAGE_REGISTRY="${IMAGE_REGISTRY:-}"

PROXY_IMAGE="${IMAGE_REGISTRY}sentinel-gateway-proxy:${PROXY_VERSION}"
ADMIN_IMAGE="${IMAGE_REGISTRY}sentinel-gateway-admin:${ADMIN_VERSION}"

# --- Parse args ---
DRY_RUN=""
SECRETS_ONLY=false
SKIP_BUILD=false
BACKEND_IP="${BACKEND_IP:-}"
NEXT_IS_BACKEND_IP=false

for arg in "$@"; do
    case $arg in
        --dry-run) DRY_RUN="--dry-run=client -o yaml"; SKIP_BUILD=true ;;
        --secrets-only) SECRETS_ONLY=true; SKIP_BUILD=true ;;
        --no-build) SKIP_BUILD=true ;;
        --backend-ip=*) BACKEND_IP="${arg#*=}" ;;
        --backend-ip) NEXT_IS_BACKEND_IP=true ;;
        *)
            if [ "$NEXT_IS_BACKEND_IP" = true ]; then
                BACKEND_IP="$arg"
                NEXT_IS_BACKEND_IP=false
            fi
            ;;
    esac
done

# --- 1. Build Docker images ---
if [ "$SKIP_BUILD" = false ]; then
    step "Building Docker images..."

    log "Building proxy image: $PROXY_IMAGE"
    docker build -t "$PROXY_IMAGE" -f "$PROJECT_DIR/Dockerfile" "$PROJECT_DIR"

    log "Building admin image: $ADMIN_IMAGE"
    docker build -t "$ADMIN_IMAGE" -f "$PROJECT_DIR/docker/Dockerfile.admin" "$PROJECT_DIR"

    # Load images into cluster (minikube)
    if command -v minikube &>/dev/null && minikube status &>/dev/null; then
        step "Loading images into minikube..."
        minikube image load "$PROXY_IMAGE"
        minikube image load "$ADMIN_IMAGE"
        log "Images loaded into minikube"
    elif command -v kind &>/dev/null && kind get clusters &>/dev/null 2>&1; then
        step "Loading images into kind..."
        kind load docker-image "$PROXY_IMAGE"
        kind load docker-image "$ADMIN_IMAGE"
        log "Images loaded into kind"
    elif [ -n "$IMAGE_REGISTRY" ]; then
        step "Pushing images to registry: $IMAGE_REGISTRY"
        docker push "$PROXY_IMAGE"
        docker push "$ADMIN_IMAGE"
        log "Images pushed to registry"
    else
        warn "No cluster runtime detected (minikube/kind) and no IMAGE_REGISTRY set."
        warn "Images built locally. Ensure they are accessible from your cluster."
    fi
else
    log "Skipping image build (--no-build / --dry-run)"
fi

# --- 2. Create namespace ---
step "Creating namespace..."
kubectl apply -f "$SCRIPT_DIR/namespace.yaml" $DRY_RUN

# --- 3. Configure external backends ---
if [ -z "$BACKEND_IP" ]; then
    # Auto-detect minikube gateway IP
    if command -v minikube &>/dev/null && minikube status &>/dev/null; then
        MINIKUBE_IP="$(minikube ip 2>/dev/null)"
        if [ -n "$MINIKUBE_IP" ]; then
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

# --- 4. Generate and apply secrets ---
step "Generating Kubernetes secrets..."
if [ ! -f "$PROJECT_DIR/secrets/jwt_secret.txt" ]; then
    warn "Secrets not found. Running secrets/init.sh..."
    bash "$PROJECT_DIR/secrets/init.sh"
fi
bash "$SCRIPT_DIR/secrets/generate-secrets.sh" | kubectl apply $DRY_RUN -f -
log "Secrets applied (encrypted at rest via etcd encryption)"

if [ "$SECRETS_ONLY" = true ]; then
    log "Secrets-only mode. Done."
    exit 0
fi

# --- 5. Create ConfigMap from large config files ---
step "Creating static config ConfigMap..."
kubectl create configmap sentinel-static-config \
    --from-file=iocs.json="$PROJECT_DIR/config/iocs.json" \
    --from-file=agents.yaml="$PROJECT_DIR/config/agents.yaml" \
    -n sentinel-gateway \
    --dry-run=client -o yaml | kubectl apply $DRY_RUN -f -

# --- 6. Apply all manifests via Kustomize ---
step "Applying Kustomize manifests..."
kubectl apply -k "$SCRIPT_DIR" $DRY_RUN

# --- 7. Wait for rollout ---
if [ -z "$DRY_RUN" ]; then
    step "Waiting for services to be ready..."

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
    echo "  Images:"
    echo "    Proxy: $PROXY_IMAGE"
    echo "    Admin: $ADMIN_IMAGE"
    echo ""
    echo "  Access:"
    echo "    Proxy:        https://sentinel-gateway.local/v1/chat/completions"
    echo "    Admin:        https://admin.sentinel-gateway.local"
    echo "    SkillSpector: https://admin.sentinel-gateway.local/skills"
    echo ""
    echo "  Port-forward (alternative):"
    echo "    kubectl port-forward svc/proxy 8080:8080 -n sentinel-gateway"
    echo "    kubectl port-forward svc/admin 8090:8090 -n sentinel-gateway"
    echo "    kubectl port-forward svc/prometheus 9090:9090 -n sentinel-gateway"
    echo "    kubectl port-forward svc/grafana 3000:3000 -n sentinel-gateway"
    echo ""
fi
