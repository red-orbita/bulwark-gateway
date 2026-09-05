#!/bin/bash
# ============================================================
# Bulwark Gateway — First-run secrets initialization
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
        # 0644, not 0600: the distroless proxy/admin containers run as the
        # non-root UID 65532 and read these files as Docker Compose secrets via
        # a read-only bind mount that preserves the host owner (the developer's
        # UID). A 0600 file owned by the host user is therefore unreadable by
        # UID 65532 inside the container, which crash-loops the admin on boot
        # (PermissionError on /run/secrets/*). Group/other read keeps the files
        # loadable regardless of the container UID. These are local deployment
        # secrets in a git-ignored dir; in Kubernetes real secrets are Secret
        # objects, not this file.
        chmod 644 "$path"
        echo "  [GENERATED] $file"
    else
        echo "  [EXISTS]    $file"
    fi
}

echo "=== Bulwark Gateway — Secrets Initialization ==="
echo "Directory: $SECRETS_DIR"
echo ""

# Cryptographic secrets (high entropy)
generate_if_missing "jwt_secret.txt"           "openssl rand -base64 32"
generate_if_missing "admin_jwt_secret.txt"     "openssl rand -base64 32"
generate_if_missing "redis_password.txt"       "openssl rand -base64 24"
# Opt-in PostgreSQL admin backend (docker compose --profile postgres). Only used
# when the `postgres` profile is enabled; the default stack runs on SQLite.
generate_if_missing "postgres_password.txt"    "openssl rand -base64 24"
# db_encryption_key MUST be 64 hex chars (32 bytes) — SQLCipher raw-key mode
# (PRAGMA key = "x'...'"). Non-hex values fail with "file is not a database".
generate_if_missing "db_encryption_key.txt"    "openssl rand -hex 32"
generate_if_missing "key_encryption_key.txt"   "openssl rand -base64 32"
generate_if_missing "grafana_password.txt"     "openssl rand -base64 24"

# User passwords (readable random, 20 chars with guaranteed complexity)
# Generate base alphanumeric + append mandatory special/digit/upper/lower chars
generate_if_missing "admin_password.txt"       "printf '%s%s' \$(openssl rand -base64 15 | tr -d '=/+' | head -c 16) '!A1a' | fold -w1 | shuf | tr -d '\n' | head -c 20"
generate_if_missing "security_password.txt"    "printf '%s%s' \$(openssl rand -base64 15 | tr -d '=/+' | head -c 16) '@B2b' | fold -w1 | shuf | tr -d '\n' | head -c 20"
generate_if_missing "auditor_password.txt"     "printf '%s%s' \$(openssl rand -base64 15 | tr -d '=/+' | head -c 16) '#C3c' | fold -w1 | shuf | tr -d '\n' | head -c 20"

# API keys (hex, 48 chars)
generate_if_missing "api_keys.txt"             "openssl rand -hex 24"

# Prometheus scrape token for /admin/health/metrics (hex, 64 chars)
# Least-privilege static bearer used ONLY by Prometheus to scrape the admin
# metrics endpoint. Verified with hmac.compare_digest; revocable via this file.
generate_if_missing "metrics_scrape_token.txt" "openssl rand -hex 32"

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
