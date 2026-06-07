#!/bin/bash
# ============================================================
# Sentinel Gateway — First-run secrets initialization
#
# This script is called by docker compose on first deploy.
# It generates ALL secrets automatically if they don't exist.
#
# Usage:
#   ./secrets/init.sh          # Generate all missing secrets
#   ./secrets/init.sh --force  # Regenerate all (rotation)
# ============================================================
set -euo pipefail

SECRETS_DIR="$(cd "$(dirname "$0")" && pwd)"
FORCE="${1:-}"

generate_if_missing() {
    local file="$1"
    local generator="$2"
    local path="$SECRETS_DIR/$file"

    if [ "$FORCE" = "--force" ] || [ ! -f "$path" ]; then
        eval "$generator" > "$path"
        chmod 600 "$path"
        echo "  [GENERATED] $file"
    else
        echo "  [EXISTS]    $file"
    fi
}

echo "=== Sentinel Gateway — Secrets Initialization ==="
echo "Directory: $SECRETS_DIR"
echo ""

# Cryptographic secrets (high entropy)
generate_if_missing "jwt_secret.txt"           "openssl rand -base64 32"
generate_if_missing "admin_jwt_secret.txt"     "openssl rand -base64 32"
generate_if_missing "redis_password.txt"       "openssl rand -base64 24"
generate_if_missing "db_encryption_key.txt"    "openssl rand -base64 32"
generate_if_missing "grafana_password.txt"     "openssl rand -base64 24"

# User passwords (readable random, 20 chars)
generate_if_missing "admin_password.txt"       "openssl rand -base64 15 | tr -d '=/+' | head -c 20"
generate_if_missing "security_password.txt"    "openssl rand -base64 15 | tr -d '=/+' | head -c 20"
generate_if_missing "auditor_password.txt"     "openssl rand -base64 15 | tr -d '=/+' | head -c 20"

# API keys (hex, 48 chars)
generate_if_missing "api_keys.txt"             "openssl rand -hex 24"

# Prometheus password + web.yml with bcrypt hash
generate_if_missing "prometheus_password.txt"  "openssl rand -base64 24"

# IOC feed keys (empty by default — user fills in)
generate_if_missing "urlhaus_key.txt"          "echo ''"
generate_if_missing "threatfox_key.txt"        "echo ''"
generate_if_missing "otx_key.txt"              "echo ''"
generate_if_missing "abuseipdb_key.txt"        "echo ''"

echo ""
echo "=== Initialization complete ==="

# Generate Prometheus web.yml with bcrypt hash
PROM_PW="$(cat "$SECRETS_DIR/prometheus_password.txt")"
if command -v python3 &>/dev/null && python3 -c "import bcrypt" 2>/dev/null; then
    # H-08: Pass password via env var to prevent shell injection
    PROM_HASH=$(PROM_PW_ENV="$PROM_PW" python3 -c "import os, bcrypt; print(bcrypt.hashpw(os.environ['PROM_PW_ENV'].encode(), bcrypt.gensalt()).decode())")
    PROM_WEB="$(dirname "$SECRETS_DIR")/prometheus/web.yml"
    mkdir -p "$(dirname "$PROM_WEB")"
    cat > "$PROM_WEB" <<WEBEOF
basic_auth_users:
  admin: "$PROM_HASH"
WEBEOF
    echo "  [GENERATED] prometheus/web.yml (basic_auth)"
else
    echo "  [SKIP]      prometheus/web.yml (install bcrypt: pip install bcrypt)"
fi

echo ""
echo "Admin credentials (first login requires password change):"
echo "  Username: admin"
echo "  Password: stored in $SECRETS_DIR/admin_password.txt"
echo ""
echo "IMPORTANT:"
echo "  - secrets/*.txt are in .gitignore (never committed)"
echo "  - Back up $SECRETS_DIR securely"
echo "  - To rotate: ./secrets/init.sh --force"
echo "  - IOC feed keys (urlhaus, threatfox, otx, abuseipdb) are empty — fill manually if needed"
