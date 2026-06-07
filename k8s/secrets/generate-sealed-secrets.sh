#!/bin/bash
# ============================================================
# Generate SealedSecrets from local secret files
#
# Prerequisites:
#   - kubeseal CLI installed
#   - SealedSecrets controller running in cluster
#   - secrets/init.sh already run (secret files exist)
#
# Output: k8s/secrets/sealed-secrets.yaml (safe to commit to git)
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
OUTPUT="$SCRIPT_DIR/sealed-secrets.yaml"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log() { echo -e "${GREEN}[✓]${NC} $1"; }
err() { echo -e "${RED}[✗]${NC} $1" >&2; exit 1; }

# Verify prerequisites
command -v kubeseal >/dev/null 2>&1 || err "kubeseal not found. Install: https://github.com/bitnami-labs/sealed-secrets"
[ -f "$PROJECT_DIR/secrets/jwt_secret.txt" ] || err "Secrets not found. Run: ./secrets/init.sh"

log "Fetching SealedSecrets public key from cluster..."
kubeseal --fetch-cert > /tmp/sealed-secrets-cert.pem

log "Generating sealed secrets..."

# Clear output file
> "$OUTPUT"
echo "# Auto-generated SealedSecrets — safe to commit to git" >> "$OUTPUT"
echo "# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUTPUT"
echo "# Re-generate with: ./k8s/secrets/generate-sealed-secrets.sh" >> "$OUTPUT"
echo "---" >> "$OUTPUT"

# Proxy secrets
kubectl create secret generic sentinel-proxy-secrets \
    --from-file=jwt-secret="$PROJECT_DIR/secrets/jwt_secret.txt" \
    --from-file=api-keys="$PROJECT_DIR/secrets/api_keys.txt" \
    -n sentinel-gateway \
    --dry-run=client -o yaml | \
    kubeseal --cert /tmp/sealed-secrets-cert.pem --format yaml >> "$OUTPUT"

echo "---" >> "$OUTPUT"

# Admin secrets
kubectl create secret generic sentinel-admin-secrets \
    --from-file=admin-password="$PROJECT_DIR/secrets/admin_password.txt" \
    --from-file=jwt-secret="$PROJECT_DIR/secrets/jwt_secret.txt" \
    -n sentinel-gateway \
    --dry-run=client -o yaml | \
    kubeseal --cert /tmp/sealed-secrets-cert.pem --format yaml >> "$OUTPUT"

echo "---" >> "$OUTPUT"

# Redis secrets
kubectl create secret generic sentinel-redis-secrets \
    --from-file=redis-password="$PROJECT_DIR/secrets/redis_password.txt" \
    -n sentinel-gateway \
    --dry-run=client -o yaml | \
    kubeseal --cert /tmp/sealed-secrets-cert.pem --format yaml >> "$OUTPUT"

echo "---" >> "$OUTPUT"

# Monitoring secrets (if exists)
if [ -f "$PROJECT_DIR/secrets/grafana_password.txt" ]; then
    kubectl create secret generic sentinel-monitoring-secrets \
        --from-file=grafana-password="$PROJECT_DIR/secrets/grafana_password.txt" \
        -n sentinel-gateway \
        --dry-run=client -o yaml | \
        kubeseal --cert /tmp/sealed-secrets-cert.pem --format yaml >> "$OUTPUT"
fi

rm -f /tmp/sealed-secrets-cert.pem

log "SealedSecrets written to: $OUTPUT"
log "This file is safe to commit to git (encrypted with cluster's public key)"
echo ""
echo "  To apply:  kubectl apply -f $OUTPUT"
echo "  The controller will decrypt and create regular Secrets in-cluster."
