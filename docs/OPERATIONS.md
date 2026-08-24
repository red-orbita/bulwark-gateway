# Operations Runbook

Day-to-day operational procedures for Bulwark Gateway.

## Table of Contents

- [Scripts Reference](#scripts-reference)
- [Account Management](#account-management)
- [Secret Rotation](#secret-rotation)
- [Policy Management](#policy-management)
- [Service Restarts](#service-restarts)
- [Backup & Restore](#backup--restore)
- [Scaling](#scaling)
- [Log Collection](#log-collection)
- [Security Events History & Retention](#security-events-history--retention)
- [Guardrail Allowlist / Exceptions](#guardrail-allowlist--exceptions)

---

## Scripts Reference

All operational scripts are located in the `scripts/` directory.

### validate-deployment.sh

Post-deploy infrastructure validation. Checks all critical components (pods, services, Redis, SIEM, ingress, TLS, backends) and reports pass/fail/warn status. Run this after every deployment or upgrade.

```bash
# Basic usage (uses default namespace: bulwark-gateway)
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
- Downloads Alpine.js, HTMX, Lucide icons, qrcodejs, and Google Fonts (with SRI verification)
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
kubectl rollout restart deploy/admin -n bulwark-gateway
```

### Reset User Password (DB Reset)

If the user database is corrupted or passwords are unknown:

```bash
# Delete user database (will re-seed from secrets on next startup)
kubectl exec deploy/admin -n bulwark-gateway -- rm -f /app/data/users.db /app/data/users.db-shm /app/data/users.db-wal

# Restart to trigger re-seed
kubectl rollout restart deploy/admin -n bulwark-gateway
```

> **Note**: As of v0.2.0, passwords auto-sync on startup. If you rotate the K8s secret, just restart the pod — no DB deletion needed.

### Password Auto-Sync (v0.2.0+)

The admin service compares the secret file content with stored hashes at every startup. If the secret changed (e.g., you rotated `ADMIN_PASSWORD` in K8s), it automatically updates the hash in the database.

```bash
# Rotate admin password
kubectl create secret generic bulwark-admin-secrets \
  --from-literal=admin-password="new-secure-password" \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart to pick up new password
kubectl rollout restart deploy/admin -n bulwark-gateway
```

### Default Users

| Username | Secret Key | Role | Default Password |
|----------|-----------|------|-----------------|
| `admin` | `ADMIN_PASSWORD` | Admin | `bulwark-admin` |
| `security` | `SECURITY_PASSWORD` | Security | `bulwark-security` |
| `auditor` | `AUDITOR_PASSWORD` | Auditor | `bulwark-auditor` |

---

## Secret Rotation

### JWT Secret Rotation

The proxy and admin use **distinct** JWT secrets by design (a leaked proxy token
must not be able to forge an admin session):

- `bulwark-proxy-secrets/jwt-secret` — signs data-plane (proxy) JWTs
- `bulwark-admin-secrets/admin-jwt-secret` — signs admin dashboard sessions

Rotate whichever is affected. Rotating the proxy secret invalidates issued proxy
JWTs; rotating the admin secret forces all admin users to re-login.

```bash
# --- Proxy JWT secret ---
NEW_JWT=$(openssl rand -base64 32)
kubectl create secret generic bulwark-proxy-secrets \
  --from-literal=jwt-secret="$NEW_JWT" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart deploy/proxy -n bulwark-gateway

# --- Admin session secret (invalidates all admin logins) ---
NEW_ADMIN_JWT=$(openssl rand -base64 32)
kubectl create secret generic bulwark-admin-secrets \
  --from-literal=admin-jwt-secret="$NEW_ADMIN_JWT" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart deploy/admin -n bulwark-gateway
```

### Redis Password Rotation

**Impact**: Requires simultaneous restart of all pods that connect to Redis.

```bash
NEW_REDIS_PW=$(openssl rand -base64 24)

# Update Redis secret
kubectl create secret generic bulwark-redis-secrets \
  --from-literal=redis-password="$NEW_REDIS_PW" \
  --dry-run=client -o yaml | kubectl apply -f -

# Update admin and proxy secrets too (they reference redis password)
# Then restart ALL pods simultaneously
kubectl rollout restart deploy/redis deploy/proxy deploy/admin -n bulwark-gateway
```

### API Keys Rotation

**Impact**: Old API keys stop working immediately after restart.

```bash
# Update API keys
kubectl create secret generic bulwark-proxy-secrets \
  --from-literal=api-keys="new-key-1,new-key-2" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl rollout restart deploy/proxy -n bulwark-gateway
```

### Using SealedSecrets

```bash
# Edit plaintext secrets
echo "new-value" > secrets/jwt_secret.txt

# Re-generate sealed secrets
./k8s/secrets/generate-sealed-secrets.sh

# Apply and restart
kubectl apply -f k8s/secrets/sealed-secrets.yaml
kubectl rollout restart deploy -n bulwark-gateway
```

---

## Policy Management

### Hot-Reload Policies (No Restart)

```bash
# Via admin API
curl -X POST https://admin.bulwark.corp.com/admin/policies/reload \
  -H "Authorization: Bearer $TOKEN"

# Via kubectl (if admin is port-forwarded)
curl -X POST http://localhost:8090/admin/policies/reload \
  -H "Authorization: Bearer $TOKEN"
```

### Apply Policy from YAML

```bash
# Copy policy file into the policies PVC
kubectl cp config/policies/new-tenant.yaml \
  $(kubectl get pod -l app.kubernetes.io/name=admin -n bulwark-gateway -o name):/app/config/policies/

# Trigger reload
curl -X POST http://localhost:8090/admin/policies/reload \
  -H "Authorization: Bearer $TOKEN"
```

---

## Service Restarts

### Restart Individual Components

```bash
# Proxy only (no downtime if replicas > 1)
kubectl rollout restart deploy/proxy -n bulwark-gateway

# Admin only
kubectl rollout restart deploy/admin -n bulwark-gateway

# Redis (causes brief cache loss)
kubectl rollout restart deploy/redis -n bulwark-gateway

# All components
kubectl rollout restart deploy -n bulwark-gateway
```

### Verify Health After Restart

```bash
# Check all pods are ready
kubectl get pods -n bulwark-gateway

# Check proxy health
curl -s https://bulwark.corp.com/health

# Check admin health
curl -s https://admin.bulwark.corp.com/admin/health
```

---

## Backup & Restore

### Backup User Database

```bash
# Copy user DB from pod
kubectl cp bulwark-gateway/$(kubectl get pod -l app.kubernetes.io/name=admin -n bulwark-gateway -o jsonpath='{.items[0].metadata.name}'):/app/data/users.db ./backup-users.db
```

### Backup Audit Log

```bash
kubectl cp bulwark-gateway/$(kubectl get pod -l app.kubernetes.io/name=admin -n bulwark-gateway -o jsonpath='{.items[0].metadata.name}'):/app/data/audit_log.db ./backup-audit.db
```

### Backup Redis (RDB Snapshot)

```bash
# Trigger save
kubectl exec deploy/redis -n bulwark-gateway -- redis-cli BGSAVE

# Copy RDB file
kubectl cp bulwark-gateway/$(kubectl get pod -l app.kubernetes.io/name=redis -n bulwark-gateway -o jsonpath='{.items[0].metadata.name}'):/data/dump.rdb ./backup-redis.rdb
```

### Restore User Database

```bash
kubectl cp ./backup-users.db bulwark-gateway/$(kubectl get pod -l app.kubernetes.io/name=admin -n bulwark-gateway -o jsonpath='{.items[0].metadata.name}'):/app/data/users.db
kubectl rollout restart deploy/admin -n bulwark-gateway
```

---

## Scaling

### Proxy Horizontal Scaling

```bash
# Scale proxy replicas
kubectl scale deploy/proxy -n bulwark-gateway --replicas=3

# Or use HPA
kubectl autoscale deploy/proxy -n bulwark-gateway --min=2 --max=10 --cpu-percent=70
```

### Admin (Single Replica Only)

The admin portal uses SQLite — it **cannot** be scaled beyond 1 replica without migrating to PostgreSQL.

---

## Log Collection

### View Proxy Logs

```bash
# Real-time logs
kubectl logs -f deploy/proxy -n bulwark-gateway

# Last 100 lines
kubectl logs deploy/proxy -n bulwark-gateway --tail=100

# Filter for blocks only
kubectl logs deploy/proxy -n bulwark-gateway | grep "BLOCK"
```

### View Admin Logs

```bash
kubectl logs -f deploy/admin -n bulwark-gateway
```

### Export Audit Log

```bash
# Via API
curl -s https://admin.bulwark.corp.com/admin/audit/export \
  -H "Authorization: Bearer $TOKEN" > audit-export.json
```

---

## Security Events History & Retention

The admin portal keeps a **durable history** of security events (blocks and
warnings) in the `security_events` table. This is separate from the proxy's
capped Redis live buffer (`bulwark:recent_blocks:*`): the durable store survives
Redis flushes and pod restarts, and outlives the per-tenant buffer cap, so the
**Security Events** page can show a real, queryable history.

### Default behavior (enabled out of the box)

- **On by default.** The admin lifespan starts the `events_sync` background task
  unconditionally — no feature flag required. It drains the proxy's Redis live
  buffer into the durable store every `sync_interval_seconds` (default **30s**).
- **BLOCK + WARN are recorded** and browsable. Warnings include allow-exception
  events (see [Allowlist / Exceptions](#guardrail-allowlist--exceptions)) tagged
  `allowed_by_exception`.
- **ALLOWED events are opt-in.** Set `BULWARK_LOG_ALLOWED=true` on the proxy to
  also record legitimate/allowed traffic into a **separate** feed, browsable via
  `GET /admin/events?verdict=allowed`. Kept separate so normal traffic doesn't
  drown the security-relevant events.

### Retention model

Retention is resolved with the following precedence (highest wins):

1. **Portal override** (`config` table, set from the UI or API),
2. **Environment variable** (`BULWARK_EVENTS_RETENTION_DAYS`, deploy/Helm bootstrap),
3. **SIEM-aware default** — **90 days** when a SIEM exporter is enabled
   (`BULWARK_TELEMETRY_ENABLED=true`), otherwise **0 = keep forever**.

`retention_days` semantics:

| Value | Meaning |
|-------|---------|
| `-1` / auto | Fall back to env var, else SIEM-aware default |
| `0` | Keep forever (unlimited) |
| `> 0` | Prune events older than N days (max 3650 = 10 years) |

> **Portal wins over env.** The environment variable is only a bootstrap
> fallback; once an operator sets retention from the portal, that value governs
> until it is changed back to *auto*.

Pruning runs periodically inside the sync loop (every ~20 cycles). Changes made
from the portal are applied to the live task immediately (`events_sync.reload()`),
without waiting for the next cycle.

### Configure retention from the portal

Admin UI: **Security Events → Retention** panel. Or via API (requires
`guardrails:write`):

```bash
# Keep events for 30 days
curl -X POST https://admin.bulwark.corp.com/admin/events/settings \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"retention_mode":"custom","retention_days":30}'

# Keep forever
curl -X POST .../admin/events/settings \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"retention_mode":"custom","retention_days":0}'

# Back to automatic (SIEM-aware) default
curl -X POST .../admin/events/settings \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"retention_mode":"auto"}'

# Inspect effective settings and where each value comes from
curl -s .../admin/events/settings -H "Authorization: Bearer $TOKEN" | jq .
```

Other tunables in the same payload:

| Key | Default | Purpose |
|-----|---------|---------|
| `max_per_tenant` | 1000 | Per-tenant cap when draining the Redis buffer each cycle |
| `sync_interval_seconds` | 30 | How often the durable store is refreshed (5–3600) |

Send `null` for either to clear the override and fall back to env/default.

### Related environment variables (bootstrap)

| Variable | Default | Notes |
|----------|---------|-------|
| `BULWARK_EVENTS_RETENTION_DAYS` | (unset → auto) | Bootstrap retention; portal overrides it |
| `BULWARK_EVENTS_MAX_PER_TENANT` | 1000 | Bootstrap per-tenant drain cap |
| `BULWARK_EVENTS_SYNC_INTERVAL` | 30 | Bootstrap sync cadence (seconds) |
| `BULWARK_LOG_ALLOWED` | false | Opt-in: record allowed traffic into the browsable feed |
| `BULWARK_TELEMETRY_ENABLED` | false | When true, the auto retention default becomes 90 days |

---

## Guardrail Allowlist / Exceptions

The **Allowlist** page manages per-tenant/agent **allow-exceptions** for
guardrail detection patterns — a scoped way to reduce false positives **without
disabling a pattern globally** and without losing the audit trail.

### How it works

- An exception is keyed by `pattern_id` and scoped to one or more
  `tenant:agent` strings.
- When a would-be **BLOCK** matches a pattern that has an exception for the
  requesting `tenant:agent`, the verdict is **degraded to WARN** instead of 403.
- The request still emits a fully-auditable security event, tagged
  `allowed_by_exception=true` with the matching `exception_scope`, and it is
  still exported to the SIEM and browsable in the Security Events console.
- The pattern remains **fully active** for every other tenant/agent. An
  exception is *not* the same as disabling a pattern.

Exceptions sync to the proxy via Redis (`bulwark:guardrails:exceptions` HASH), so
they take effect on the hot path without a restart.

### Manage exceptions

Admin UI: **Allowlist** page. Or via API (patterns namespace):

```bash
# List all exceptions ({pattern_id: [scopes]})
curl -s .../admin/guardrails/exceptions -H "Authorization: Bearer $TOKEN"

# List scopes for one pattern
curl -s .../admin/guardrails/patterns/<pattern_id>/exceptions \
  -H "Authorization: Bearer $TOKEN"

# Add an allow-exception for a tenant/agent (BLOCK → WARN for that scope only)
curl -X POST .../admin/guardrails/patterns/<pattern_id>/exceptions \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"scope":"default-corp:support-bot"}'

# Remove an allow-exception
curl -X DELETE .../admin/guardrails/patterns/<pattern_id>/exceptions \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"scope":"default-corp:support-bot"}'
```

> **When to use.** Prefer a scoped allow-exception over disabling a pattern when
> one tenant/agent has a legitimate need that trips an otherwise-valuable rule.
> You keep detection everywhere else and retain full visibility (the event is
> still logged and alertable) for the exempted scope.

---

## Monitoring

### Check Prometheus Targets

```bash
kubectl port-forward svc/prometheus 9090:9090 -n bulwark-gateway
# Open http://localhost:9090/targets
```

### Grafana Access

```bash
kubectl port-forward svc/grafana 3000:3000 -n bulwark-gateway
# Open http://localhost:3000 (admin / <grafana-password>)
```
