#!/bin/bash
# ============================================================
# Generate SealedSecrets from local secret files
#
# Produces the FULL set of keys the Helm chart / Kustomize manifests expect,
# so the app runs with `secrets.create=false` (GitOps mode) and no credential
# is auto-generated at render time.
#
# Prerequisites:
#   - kubeseal CLI installed
#   - SealedSecrets controller running in the TARGET cluster
#   - secrets/init.sh already run (secret files exist)
#
# IMPORTANT: SealedSecrets are encrypted with the TARGET cluster's public key.
# The output only decrypts in that cluster. Re-run this against each cluster.
#
# Usage:
#   ./k8s/secrets/generate-sealed-secrets.sh                 # namespace bulwark-gateway
#   NAMESPACE=my-ns ./k8s/secrets/generate-sealed-secrets.sh # custom namespace
#
# Output: k8s/secrets/sealed-secrets.yaml (safe to commit to git)
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
SECRETS_DIR="$PROJECT_DIR/secrets"
OUTPUT="$SCRIPT_DIR/sealed-secrets.yaml"
NAMESPACE="${NAMESPACE:-bulwark-gateway}"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log() { echo -e "${GREEN}[✓]${NC} $1"; }
err() { echo -e "${RED}[✗]${NC} $1" >&2; exit 1; }

# Verify prerequisites
command -v kubeseal >/dev/null 2>&1 || err "kubeseal not found. Install: https://github.com/bitnami-labs/sealed-secrets"
[ -f "$SECRETS_DIR/jwt_secret.txt" ] || err "Secrets not found. Run: ./secrets/init.sh"

CERT="$(mktemp)"
trap 'rm -f "$CERT"' EXIT

log "Fetching SealedSecrets public key from cluster (namespace: $NAMESPACE)..."
kubeseal --fetch-cert > "$CERT"

log "Generating sealed secrets..."

# seal <secret-name> <kubectl create secret args...>
# Renders a plain Secret (client-side), pipes it through kubeseal, appends to output.
seal() {
    local name="$1"; shift
    echo "---" >> "$OUTPUT"
    kubectl create secret generic "$name" -n "$NAMESPACE" \
        --dry-run=client -o yaml "$@" \
        | kubeseal --cert "$CERT" --format yaml >> "$OUTPUT"
}

# Clear output file
: > "$OUTPUT"
{
    echo "# Auto-generated SealedSecrets — safe to commit to git"
    echo "# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# Namespace: $NAMESPACE"
    echo "# Re-generate with: ./k8s/secrets/generate-sealed-secrets.sh"
    echo "# NOTE: only decrypts in the cluster whose public key sealed it."
} >> "$OUTPUT"

# --- Proxy secrets (keys consumed by src/config.py via bulwark-proxy-secrets) ---
seal bulwark-proxy-secrets \
    --from-file=jwt-secret="$SECRETS_DIR/jwt_secret.txt" \
    --from-file=api-keys="$SECRETS_DIR/api_keys.txt" \
    --from-file=key-encryption-key="$SECRETS_DIR/key_encryption_key.txt" \
    --from-file=redis-password="$SECRETS_DIR/redis_password.txt" \
    --from-file=urlhaus-key="$SECRETS_DIR/urlhaus_key.txt" \
    --from-file=threatfox-key="$SECRETS_DIR/threatfox_key.txt" \
    --from-file=otx-key="$SECRETS_DIR/otx_key.txt" \
    --from-file=abuseipdb-key="$SECRETS_DIR/abuseipdb_key.txt"

# --- Admin secrets (bulwark-admin-secrets) ---
seal bulwark-admin-secrets \
    --from-file=admin-jwt-secret="$SECRETS_DIR/admin_jwt_secret.txt" \
    --from-file=admin-password="$SECRETS_DIR/admin_password.txt" \
    --from-file=security-password="$SECRETS_DIR/security_password.txt" \
    --from-file=auditor-password="$SECRETS_DIR/auditor_password.txt" \
    --from-file=redis-password="$SECRETS_DIR/redis_password.txt" \
    --from-file=api-keys="$SECRETS_DIR/api_keys.txt" \
    --from-file=db-encryption-key="$SECRETS_DIR/db_encryption_key.txt" \
    --from-file=key-encryption-key="$SECRETS_DIR/key_encryption_key.txt"

# --- Redis secrets (internal Redis) ---
seal bulwark-redis-secrets \
    --from-file=redis-password="$SECRETS_DIR/redis_password.txt"

# --- Monitoring secrets (only if Grafana password exists) ---
if [ -f "$SECRETS_DIR/grafana_password.txt" ]; then
    seal bulwark-monitoring-secrets \
        --from-file=grafana-password="$SECRETS_DIR/grafana_password.txt"
fi

log "SealedSecrets written to: $OUTPUT"
log "Safe to commit (encrypted with the cluster's public key)"
echo ""
echo "  Apply directly:  kubectl apply -f $OUTPUT"
echo "  Or via ArgoCD:   see deploy/argocd/ (bulwark-secrets Application)"
echo "  The controller decrypts and creates the plain Secrets in-cluster."
