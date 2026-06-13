#!/usr/bin/env bash
# generate-mtls-certs.sh — Generate mTLS certificates for Sentinel Gateway inter-service communication.
#
# Generates:
#   - Self-signed CA (sentinel-internal-ca)
#   - Server certificate for proxy service
#   - Server certificate for admin service
#   - Client certificate for proxy→admin communication
#   - Client certificate for admin→proxy communication
#
# All certificates use EC P-256 keys (faster than RSA, smaller certs).
# Certificates are valid for 1 year (365 days).
#
# Usage:
#   ./scripts/generate-mtls-certs.sh [output-dir]
#
# Output files:
#   ca.crt, ca.key                         — Internal CA
#   proxy-server.crt, proxy-server.key     — Proxy server cert
#   admin-server.crt, admin-server.key     — Admin server cert
#   proxy-client.crt, proxy-client.key     — Proxy client cert (for proxy→admin calls)
#   admin-client.crt, admin-client.key     — Admin client cert (for admin→proxy calls)
#
# Environment variables:
#   CERT_VALIDITY_DAYS  — Certificate validity (default: 365)
#   NAMESPACE           — Kubernetes namespace (default: sentinel-gateway)
#   CA_CN               — CA Common Name (default: sentinel-internal-ca)

set -euo pipefail

# --- Configuration ---
OUTPUT_DIR="${1:-./certs/mtls}"
VALIDITY_DAYS="${CERT_VALIDITY_DAYS:-365}"
NAMESPACE="${NAMESPACE:-sentinel-gateway}"
CA_CN="${CA_CN:-sentinel-internal-ca}"

# Service DNS names (Kubernetes FQDN pattern)
PROXY_DNS="proxy.${NAMESPACE}.svc.cluster.local"
ADMIN_DNS="admin.${NAMESPACE}.svc.cluster.local"

# --- Functions ---
log() { echo "[mtls-gen] $*"; }
err() { echo "[mtls-gen] ERROR: $*" >&2; exit 1; }

check_openssl() {
    if ! command -v openssl &>/dev/null; then
        err "openssl is required but not found. Install it first."
    fi
    local version
    version=$(openssl version)
    log "Using: $version"
}

generate_ec_key() {
    local keyfile="$1"
    openssl ecparam -genkey -name prime256v1 -noout -out "$keyfile" 2>/dev/null
    chmod 600 "$keyfile"
}

# --- Main ---
log "Generating mTLS certificates for Sentinel Gateway"
log "Output directory: $OUTPUT_DIR"
log "Validity: $VALIDITY_DAYS days"
log "Namespace: $NAMESPACE"

check_openssl

# Create output directory
mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

# ============================================================
# 1. Generate Internal CA
# ============================================================
log ""
log "=== Step 1: Generating Internal CA ==="

generate_ec_key "ca.key"

openssl req -new -x509 \
    -key ca.key \
    -out ca.crt \
    -days "$VALIDITY_DAYS" \
    -subj "/O=Sentinel Gateway/OU=Internal PKI/CN=${CA_CN}" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    2>/dev/null

log "  CA certificate: ca.crt"
log "  CA private key: ca.key (keep secure!)"

# ============================================================
# 2. Generate Proxy Server Certificate
# ============================================================
log ""
log "=== Step 2: Generating Proxy Server Certificate ==="

generate_ec_key "proxy-server.key"

# Create CSR config with SANs
cat > proxy-server.cnf <<EOF
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no

[req_dn]
O = Sentinel Gateway
OU = Proxy Service
CN = ${PROXY_DNS}

[v3_req]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${PROXY_DNS}
DNS.2 = proxy.${NAMESPACE}.svc
DNS.3 = proxy.${NAMESPACE}
DNS.4 = proxy
DNS.5 = localhost
DNS.6 = sentinel-proxy
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

openssl req -new \
    -key proxy-server.key \
    -out proxy-server.csr \
    -config proxy-server.cnf \
    2>/dev/null

openssl x509 -req \
    -in proxy-server.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out proxy-server.crt \
    -days "$VALIDITY_DAYS" \
    -extensions v3_req \
    -extfile proxy-server.cnf \
    2>/dev/null

log "  Server cert: proxy-server.crt"
log "  Server key:  proxy-server.key"

# ============================================================
# 3. Generate Admin Server Certificate
# ============================================================
log ""
log "=== Step 3: Generating Admin Server Certificate ==="

generate_ec_key "admin-server.key"

cat > admin-server.cnf <<EOF
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no

[req_dn]
O = Sentinel Gateway
OU = Admin Service
CN = ${ADMIN_DNS}

[v3_req]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${ADMIN_DNS}
DNS.2 = admin.${NAMESPACE}.svc
DNS.3 = admin.${NAMESPACE}
DNS.4 = admin
DNS.5 = localhost
DNS.6 = sentinel-admin
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

openssl req -new \
    -key admin-server.key \
    -out admin-server.csr \
    -config admin-server.cnf \
    2>/dev/null

openssl x509 -req \
    -in admin-server.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out admin-server.crt \
    -days "$VALIDITY_DAYS" \
    -extensions v3_req \
    -extfile admin-server.cnf \
    2>/dev/null

log "  Server cert: admin-server.crt"
log "  Server key:  admin-server.key"

# ============================================================
# 4. Generate Proxy Client Certificate (for proxy→admin calls)
# ============================================================
log ""
log "=== Step 4: Generating Proxy Client Certificate ==="

generate_ec_key "proxy-client.key"

cat > proxy-client.cnf <<EOF
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no

[req_dn]
O = Sentinel Gateway
OU = Proxy Service
CN = ${PROXY_DNS}

[v3_req]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${PROXY_DNS}
DNS.2 = proxy.${NAMESPACE}
DNS.3 = sentinel-proxy
EOF

openssl req -new \
    -key proxy-client.key \
    -out proxy-client.csr \
    -config proxy-client.cnf \
    2>/dev/null

openssl x509 -req \
    -in proxy-client.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out proxy-client.crt \
    -days "$VALIDITY_DAYS" \
    -extensions v3_req \
    -extfile proxy-client.cnf \
    2>/dev/null

log "  Client cert: proxy-client.crt"
log "  Client key:  proxy-client.key"

# ============================================================
# 5. Generate Admin Client Certificate (for admin→proxy calls)
# ============================================================
log ""
log "=== Step 5: Generating Admin Client Certificate ==="

generate_ec_key "admin-client.key"

cat > admin-client.cnf <<EOF
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no

[req_dn]
O = Sentinel Gateway
OU = Admin Service
CN = ${ADMIN_DNS}

[v3_req]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${ADMIN_DNS}
DNS.2 = admin.${NAMESPACE}
DNS.3 = sentinel-admin
EOF

openssl req -new \
    -key admin-client.key \
    -out admin-client.csr \
    -config admin-client.cnf \
    2>/dev/null

openssl x509 -req \
    -in admin-client.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out admin-client.crt \
    -days "$VALIDITY_DAYS" \
    -extensions v3_req \
    -extfile admin-client.cnf \
    2>/dev/null

log "  Client cert: admin-client.crt"
log "  Client key:  admin-client.key"

# ============================================================
# 6. Cleanup and Summary
# ============================================================
log ""
log "=== Cleanup ==="

# Remove CSR files and configs (not needed after signing)
rm -f *.csr *.cnf *.srl

log "  Removed temporary CSR and config files"

# Set restrictive permissions
chmod 644 *.crt
chmod 600 *.key

log ""
log "=== Certificate Generation Complete ==="
log ""
log "Files generated in: $(pwd)"
log ""
log "  CA:            ca.crt, ca.key"
log "  Proxy Server:  proxy-server.crt, proxy-server.key"
log "  Admin Server:  admin-server.crt, admin-server.key"
log "  Proxy Client:  proxy-client.crt, proxy-client.key"
log "  Admin Client:  admin-client.crt, admin-client.key"
log ""
log "Deployment:"
log "  1. Create K8s secrets:"
log "     kubectl create secret generic sentinel-mtls-ca \\"
log "       --from-file=ca.crt=ca.crt -n $NAMESPACE"
log ""
log "     kubectl create secret tls sentinel-proxy-mtls \\"
log "       --cert=proxy-server.crt --key=proxy-server.key -n $NAMESPACE"
log ""
log "     kubectl create secret tls sentinel-admin-mtls \\"
log "       --cert=admin-server.crt --key=admin-server.key -n $NAMESPACE"
log ""
log "     kubectl create secret tls sentinel-proxy-client-mtls \\"
log "       --cert=proxy-client.crt --key=proxy-client.key -n $NAMESPACE"
log ""
log "     kubectl create secret tls sentinel-admin-client-mtls \\"
log "       --cert=admin-client.crt --key=admin-client.key -n $NAMESPACE"
log ""
log "  2. Or use Helm with existing secrets:"
log "     helm install sentinel ./helm/sentinel-gateway \\"
log "       --set mtls.enabled=true \\"
log "       --set mtls.existingSecrets.ca=sentinel-mtls-ca \\"
log "       --set mtls.existingSecrets.proxyCert=sentinel-proxy-mtls \\"
log "       --set mtls.existingSecrets.adminCert=sentinel-admin-mtls"
log ""
log "  SECURITY: Keep ca.key secure! It can sign new certificates."
log "            Consider storing it in a vault (HashiCorp Vault, AWS KMS, etc.)"

# Verify certificates
log ""
log "=== Verification ==="
openssl verify -CAfile ca.crt proxy-server.crt 2>/dev/null && log "  proxy-server.crt: OK"
openssl verify -CAfile ca.crt admin-server.crt 2>/dev/null && log "  admin-server.crt: OK"
openssl verify -CAfile ca.crt proxy-client.crt 2>/dev/null && log "  proxy-client.crt: OK"
openssl verify -CAfile ca.crt admin-client.crt 2>/dev/null && log "  admin-client.crt: OK"

log ""
log "Done."
