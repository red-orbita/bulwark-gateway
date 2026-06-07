# Operations Runbook

Day-to-day operational procedures for Sentinel Gateway.

## Table of Contents

- [Scripts Reference](#scripts-reference)
- [Account Management](#account-management)
- [Secret Rotation](#secret-rotation)
- [Policy Management](#policy-management)
- [Service Restarts](#service-restarts)
- [Backup & Restore](#backup--restore)
- [Scaling](#scaling)
- [Log Collection](#log-collection)

---

## Scripts Reference

All operational scripts are located in the `scripts/` directory.

### validate-deployment.sh

Post-deploy infrastructure validation. Checks all critical components (pods, services, Redis, SIEM, ingress, TLS, backends) and reports pass/fail/warn status. Run this after every deployment or upgrade.

```bash
# Basic usage (uses default namespace: sentinel-gateway)
./scripts/validate-deployment.sh

# Custom namespace
./scripts/validate-deployment.sh --namespace my-namespace

# Skip backend checks (useful when LLM backends are external/offline)
./scripts/validate-deployment.sh --skip-backend
```

**Checks performed** (15 total):
- Pod readiness (proxy, admin, Redis)
- Redis connectivity and persistence
- SIEM transport configuration and event export
- Backend DNS resolution and TCP connectivity
- Ingress and TLS certificate validity
- Wazuh decoder/rules injection
- Network policies applied

**Exit codes**: `0` = all critical checks pass, `1` = one or more critical failures.

---

### security-smoke-test.py

End-to-end security validation that fires real requests against the proxy to verify guardrails are operational. Validates both blocking (malicious payloads are rejected) and passthrough (legitimate traffic is allowed).

```bash
# Basic usage (against default localhost:8080)
python scripts/security-smoke-test.py

# Target a specific host
python scripts/security-smoke-test.py --host https://api.mycompany.com

# Multiple rounds for latency confidence
python scripts/security-smoke-test.py --rounds 3

# Verbose output (show all test details)
python scripts/security-smoke-test.py --verbose
```

**Test categories**:
- Input guardrail: prompt injection, jailbreak, multilingual evasion
- Tool policy: unauthorized tool calls, argument validation
- False positive: legitimate traffic must pass through
- Metrics: counters increment correctly

**Exit codes**: `0` = all tests pass, `1` = one or more failures.

**Recommended workflow**:
```bash
# After deployment, run both validation steps in sequence:
./scripts/validate-deployment.sh          # Infrastructure OK?
python scripts/security-smoke-test.py     # Security posture OK?
```

---

### policy-rollback.sh

Restore a previous policy version and trigger hot-reload without downtime. Uses backups stored in `config/policies/.backups/`.

```bash
# Rollback to a specific version
./scripts/policy-rollback.sh 2024-06-01

# Rollback to the latest backup (most recent .tar.gz)
./scripts/policy-rollback.sh
```

**What it does**:
1. Extracts the backup archive into `config/policies/`
2. Triggers hot-reload via `POST /admin/policies/reload`
3. Verifies service health after rollback

**Prerequisites**: Policy backups must exist in `config/policies/.backups/`. Backups are created automatically when policies are updated via the admin API.

---

### build-ui.sh

Downloads and vendors all CDN dependencies (JS/CSS) for the admin dashboard with SRI integrity hashes. Run this when setting up the development environment or updating vendor libraries.

```bash
./scripts/build-ui.sh
```

**What it does**:
- Downloads Alpine.js, Chart.js, and CSS dependencies
- Stores them in `admin/static/js/vendor/` and `admin/static/css/`
- Verifies SHA-384 integrity hashes

This script is idempotent — safe to re-run at any time.

---

## Account Management

### Reset Locked Account

Accounts lock after 3 failed attempts per username (15-minute lockout). The lockout is **in-memory** — restarting the admin pod clears it.

```bash
# Option 1: Wait 15 minutes

# Option 2: Restart admin pod (clears in-memory lockout cache)
kubectl rollout restart deploy/admin -n sentinel-gateway
```

### Reset User Password (DB Reset)

If the user database is corrupted or passwords are unknown:

```bash
# Delete user database (will re-seed from secrets on next startup)
kubectl exec deploy/admin -n sentinel-gateway -- rm -f /app/data/users.db /app/data/users.db-shm /app/data/users.db-wal

# Restart to trigger re-seed
kubectl rollout restart deploy/admin -n sentinel-gateway
```

> **Note**: As of v0.2.0, passwords auto-sync on startup. If you rotate the K8s secret, just restart the pod — no DB deletion needed.

### Password Auto-Sync (v0.2.0+)

The admin service compares the secret file content with stored hashes at every startup. If the secret changed (e.g., you rotated `ADMIN_PASSWORD` in K8s), it automatically updates the hash in the database.

```bash
# Rotate admin password
kubectl create secret generic sentinel-admin-secrets \
  --from-literal=admin-password="new-secure-password" \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart to pick up new password
kubectl rollout restart deploy/admin -n sentinel-gateway
```

### Default Users

| Username | Secret Key | Role | Default Password |
|----------|-----------|------|-----------------|
| `admin` | `ADMIN_PASSWORD` | Admin | `sentinel-admin` |
| `security` | `SECURITY_PASSWORD` | Security | `sentinel-security` |
| `auditor` | `AUDITOR_PASSWORD` | Auditor | `sentinel-auditor` |

---

## Secret Rotation

### JWT Secret Rotation

**Impact**: Invalidates ALL active sessions (users must re-login).

```bash
# Generate new secret
NEW_JWT=$(openssl rand -base64 32)

# Update K8s secret
kubectl create secret generic sentinel-proxy-secrets \
  --from-literal=jwt-secret="$NEW_JWT" \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart both proxy and admin
kubectl rollout restart deploy/proxy deploy/admin -n sentinel-gateway
```

### Redis Password Rotation

**Impact**: Requires simultaneous restart of all pods that connect to Redis.

```bash
NEW_REDIS_PW=$(openssl rand -base64 24)

# Update Redis secret
kubectl create secret generic sentinel-redis-secrets \
  --from-literal=redis-password="$NEW_REDIS_PW" \
  --dry-run=client -o yaml | kubectl apply -f -

# Update admin and proxy secrets too (they reference redis password)
# Then restart ALL pods simultaneously
kubectl rollout restart deploy/redis deploy/proxy deploy/admin -n sentinel-gateway
```

### API Keys Rotation

**Impact**: Old API keys stop working immediately after restart.

```bash
# Update API keys
kubectl create secret generic sentinel-proxy-secrets \
  --from-literal=api-keys="new-key-1,new-key-2" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl rollout restart deploy/proxy -n sentinel-gateway
```

### Using SealedSecrets

```bash
# Edit plaintext secrets
echo "new-value" > secrets/jwt_secret.txt

# Re-generate sealed secrets
./k8s/secrets/generate-sealed-secrets.sh

# Apply and restart
kubectl apply -f k8s/secrets/sealed-secrets.yaml
kubectl rollout restart deploy -n sentinel-gateway
```

---

## Policy Management

### Hot-Reload Policies (No Restart)

```bash
# Via admin API
curl -X POST https://admin.sentinel.corp.com/admin/policies/reload \
  -H "Authorization: Bearer $TOKEN"

# Via kubectl (if admin is port-forwarded)
curl -X POST http://localhost:8090/admin/policies/reload \
  -H "Authorization: Bearer $TOKEN"
```

### Apply Policy from YAML

```bash
# Copy policy file into the policies PVC
kubectl cp config/policies/new-tenant.yaml \
  $(kubectl get pod -l app.kubernetes.io/name=admin -n sentinel-gateway -o name):/app/config/policies/

# Trigger reload
curl -X POST http://localhost:8090/admin/policies/reload \
  -H "Authorization: Bearer $TOKEN"
```

---

## Service Restarts

### Restart Individual Components

```bash
# Proxy only (no downtime if replicas > 1)
kubectl rollout restart deploy/proxy -n sentinel-gateway

# Admin only
kubectl rollout restart deploy/admin -n sentinel-gateway

# Redis (causes brief cache loss)
kubectl rollout restart deploy/redis -n sentinel-gateway

# All components
kubectl rollout restart deploy -n sentinel-gateway
```

### Verify Health After Restart

```bash
# Check all pods are ready
kubectl get pods -n sentinel-gateway

# Check proxy health
curl -s https://sentinel.corp.com/health

# Check admin health
curl -s https://admin.sentinel.corp.com/admin/health
```

---

## Backup & Restore

### Backup User Database

```bash
# Copy user DB from pod
kubectl cp sentinel-gateway/$(kubectl get pod -l app.kubernetes.io/name=admin -n sentinel-gateway -o jsonpath='{.items[0].metadata.name}'):/app/data/users.db ./backup-users.db
```

### Backup Audit Log

```bash
kubectl cp sentinel-gateway/$(kubectl get pod -l app.kubernetes.io/name=admin -n sentinel-gateway -o jsonpath='{.items[0].metadata.name}'):/app/data/audit_log.db ./backup-audit.db
```

### Backup Redis (RDB Snapshot)

```bash
# Trigger save
kubectl exec deploy/redis -n sentinel-gateway -- redis-cli BGSAVE

# Copy RDB file
kubectl cp sentinel-gateway/$(kubectl get pod -l app.kubernetes.io/name=redis -n sentinel-gateway -o jsonpath='{.items[0].metadata.name}'):/data/dump.rdb ./backup-redis.rdb
```

### Restore User Database

```bash
kubectl cp ./backup-users.db sentinel-gateway/$(kubectl get pod -l app.kubernetes.io/name=admin -n sentinel-gateway -o jsonpath='{.items[0].metadata.name}'):/app/data/users.db
kubectl rollout restart deploy/admin -n sentinel-gateway
```

---

## Scaling

### Proxy Horizontal Scaling

```bash
# Scale proxy replicas
kubectl scale deploy/proxy -n sentinel-gateway --replicas=3

# Or use HPA
kubectl autoscale deploy/proxy -n sentinel-gateway --min=2 --max=10 --cpu-percent=70
```

### Admin (Single Replica Only)

The admin portal uses SQLite — it **cannot** be scaled beyond 1 replica without migrating to PostgreSQL.

---

## Log Collection

### View Proxy Logs

```bash
# Real-time logs
kubectl logs -f deploy/proxy -n sentinel-gateway

# Last 100 lines
kubectl logs deploy/proxy -n sentinel-gateway --tail=100

# Filter for blocks only
kubectl logs deploy/proxy -n sentinel-gateway | grep "BLOCK"
```

### View Admin Logs

```bash
kubectl logs -f deploy/admin -n sentinel-gateway
```

### Export Audit Log

```bash
# Via API
curl -s https://admin.sentinel.corp.com/admin/audit/export \
  -H "Authorization: Bearer $TOKEN" > audit-export.json
```

---

## Monitoring

### Check Prometheus Targets

```bash
kubectl port-forward svc/prometheus 9090:9090 -n sentinel-gateway
# Open http://localhost:9090/targets
```

### Grafana Access

```bash
kubectl port-forward svc/grafana 3000:3000 -n sentinel-gateway
# Open http://localhost:3000 (admin / <grafana-password>)
```
