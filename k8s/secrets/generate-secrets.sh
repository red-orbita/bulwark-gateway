#!/bin/bash
# Generate Kubernetes Secrets from local secret files.
# Usage: ./generate-secrets.sh | kubectl apply -f -
#
# In production, use SealedSecrets, SOPS, or external-secrets-operator
# to avoid storing plain secrets in manifests.

set -euo pipefail

SECRETS_DIR="$(dirname "$0")/../../secrets"

if [ ! -d "$SECRETS_DIR" ]; then
    echo "ERROR: secrets/ directory not found. Run secrets/init.sh first." >&2
    exit 1
fi

cat <<EOF
---
apiVersion: v1
kind: Secret
metadata:
  name: sentinel-proxy-secrets
  namespace: sentinel-gateway
  labels:
    app.kubernetes.io/part-of: sentinel-gateway
    app.kubernetes.io/component: proxy
type: Opaque
data:
  jwt-secret: $(base64 -w0 < "$SECRETS_DIR/jwt_secret.txt")
  redis-password: $(base64 -w0 < "$SECRETS_DIR/redis_password.txt")
  api-keys: $(base64 -w0 < "$SECRETS_DIR/api_keys.txt")
  urlhaus-key: $(base64 -w0 < "$SECRETS_DIR/urlhaus_key.txt")
  threatfox-key: $(base64 -w0 < "$SECRETS_DIR/threatfox_key.txt")
  otx-key: $(base64 -w0 < "$SECRETS_DIR/otx_key.txt")
  abuseipdb-key: $(base64 -w0 < "$SECRETS_DIR/abuseipdb_key.txt")
---
apiVersion: v1
kind: Secret
metadata:
  name: sentinel-admin-secrets
  namespace: sentinel-gateway
  labels:
    app.kubernetes.io/part-of: sentinel-gateway
    app.kubernetes.io/component: admin
type: Opaque
data:
  admin-jwt-secret: $(base64 -w0 < "$SECRETS_DIR/admin_jwt_secret.txt")
  admin-password: $(base64 -w0 < "$SECRETS_DIR/admin_password.txt")
  security-password: $(base64 -w0 < "$SECRETS_DIR/security_password.txt")
  auditor-password: $(base64 -w0 < "$SECRETS_DIR/auditor_password.txt")
  db-encryption-key: $(base64 -w0 < "$SECRETS_DIR/db_encryption_key.txt")
  redis-password: $(base64 -w0 < "$SECRETS_DIR/redis_password.txt")
  api-keys: $(base64 -w0 < "$SECRETS_DIR/api_keys.txt")
---
apiVersion: v1
kind: Secret
metadata:
  name: sentinel-redis-secrets
  namespace: sentinel-gateway
  labels:
    app.kubernetes.io/part-of: sentinel-gateway
    app.kubernetes.io/component: redis
type: Opaque
data:
  redis-password: $(base64 -w0 < "$SECRETS_DIR/redis_password.txt")
---
apiVersion: v1
kind: Secret
metadata:
  name: sentinel-monitoring-secrets
  namespace: sentinel-gateway
  labels:
    app.kubernetes.io/part-of: sentinel-gateway
    app.kubernetes.io/component: monitoring
type: Opaque
data:
  grafana-password: $(base64 -w0 < "$SECRETS_DIR/grafana_password.txt")
  prometheus-password: $(base64 -w0 < "$SECRETS_DIR/prometheus_password.txt")
EOF
