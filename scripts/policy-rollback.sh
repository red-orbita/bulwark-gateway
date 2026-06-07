#!/usr/bin/env bash
# policy-rollback.sh — Restore previous policy version and restart without downtime
# Usage: ./scripts/policy-rollback.sh [policy-version]
#
# If no version specified, restores from the latest .bak file.

set -euo pipefail

POLICIES_DIR="config/policies"
BACKUP_DIR="config/policies/.backups"

echo "[ROLLBACK] Starting policy rollback..."

if [[ "${1:-}" ]]; then
    VERSION="$1"
    BACKUP_FILE="${BACKUP_DIR}/policy-${VERSION}.tar.gz"
    if [[ ! -f "$BACKUP_FILE" ]]; then
        echo "[ERROR] Backup not found: $BACKUP_FILE"
        echo "[INFO] Available backups:"
        ls -la "$BACKUP_DIR"/*.tar.gz 2>/dev/null || echo "  (none)"
        exit 1
    fi
    echo "[ROLLBACK] Restoring from version: $VERSION"
    tar -xzf "$BACKUP_FILE" -C "$POLICIES_DIR"
else
    # Find latest backup
    LATEST=$(ls -t "$BACKUP_DIR"/*.tar.gz 2>/dev/null | head -1)
    if [[ -z "$LATEST" ]]; then
        echo "[ERROR] No backups found in $BACKUP_DIR"
        exit 1
    fi
    echo "[ROLLBACK] Restoring latest backup: $LATEST"
    tar -xzf "$LATEST" -C "$POLICIES_DIR"
fi

# Trigger hot-reload via admin endpoint
echo "[ROLLBACK] Triggering policy hot-reload..."
RELOAD_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8080/admin/policies/reload 2>/dev/null || echo "000")

if [[ "$RELOAD_RESPONSE" == "200" ]]; then
    echo "[ROLLBACK] ✓ Policies reloaded successfully (HTTP 200)"
else
    echo "[ROLLBACK] ⚠ Hot-reload returned HTTP $RELOAD_RESPONSE"
    echo "[ROLLBACK] Policies will auto-reload within 5s via polling"
fi

# Verify health
echo "[ROLLBACK] Verifying health..."
sleep 2
HEALTH=$(curl -s http://localhost:8080/health 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null || echo "unreachable")

if [[ "$HEALTH" == "ok" ]]; then
    echo "[ROLLBACK] ✓ Service healthy after rollback"
else
    echo "[ROLLBACK] ✗ Service unhealthy: $HEALTH"
    echo "[ROLLBACK] Consider restarting: docker-compose restart sentinel-gateway"
    exit 1
fi

echo "[ROLLBACK] Done."
