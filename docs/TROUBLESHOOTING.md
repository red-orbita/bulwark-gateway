# Troubleshooting Guide

Common issues and their solutions for Sentinel Gateway.

## Table of Contents

- [Authentication Issues](#authentication-issues)
- [Redis Issues](#redis-issues)
- [Pod / Kubernetes Issues](#pod--kubernetes-issues)
- [SIEM Export Issues](#siem-export-issues)
- [Proxy Issues](#proxy-issues)
- [Notification Issues](#notification-issues)
- [Wazuh CrashLoopBackOff](#wazuh-crashloopbackoff)
- [Admin Portal: White Screen / All Forms Visible](#admin-portal-white-screen--all-forms-visible)
- [Admin Portal: "file is not a database"](#admin-portal-file-is-not-a-database)
- [Common Deployment Issues](#common-deployment-issues)

---

## Authentication Issues

### "Account temporarily locked"

**Cause**: 3+ failed login attempts for the same username within 5 minutes.

**Solution**:
```bash
# Option 1: Wait 15 minutes (lockout auto-expires)

# Option 2: Restart admin pod (lockout is in-memory)
kubectl rollout restart deploy/admin -n sentinel-gateway
```

### "Invalid credentials" after secret rotation

**Cause**: The user database was seeded with the OLD password. Prior to v0.2.0, changing the K8s secret did not update the stored password hash.

**Solution (v0.2.0+)**: Simply restart the admin pod — password sync is automatic.

```bash
kubectl rollout restart deploy/admin -n sentinel-gateway
```

**Solution (older versions)**: Delete the user database to force re-seed.

```bash
kubectl exec deploy/admin -n sentinel-gateway -- rm -f /app/data/users.db /app/data/users.db-shm /app/data/users.db-wal
kubectl rollout restart deploy/admin -n sentinel-gateway
```

### "Invalid token or API key" on proxy

**Causes**:
1. JWT secret mismatch between proxy and token issuer
2. API key not in the keys file
3. Token expired

**Solution**:
```bash
# Verify the JWT secret matches
kubectl exec deploy/proxy -n sentinel-gateway -- cat /run/secrets/jwt-secret

# Check API keys file
kubectl exec deploy/proxy -n sentinel-gateway -- cat /run/secrets/api-keys

# Verify token hasn't expired
# Decode JWT at jwt.io or: echo "<token>" | cut -d. -f2 | base64 -d | jq .exp
```

---

## Redis Issues

### Redis shows "unhealthy" in admin Status page

**Cause**: The `/admin/health/detailed` endpoint couldn't connect to Redis. Most common reasons:

1. Redis password mismatch
2. DNS resolution failure
3. NetworkPolicy blocking traffic

**Diagnosis**:
```bash
# Check Redis pod is running
kubectl get pods -l app.kubernetes.io/name=redis -n sentinel-gateway

# Test connectivity from admin pod
kubectl exec deploy/admin -n sentinel-gateway -- env | grep REDIS

# Check if password file is mounted correctly
kubectl exec deploy/admin -n sentinel-gateway -- cat /run/secrets/redis-password

# Test Redis PING directly
kubectl exec deploy/redis -n sentinel-gateway -- redis-cli PING
```

**Solution (password mismatch)**:
```bash
# Ensure all pods use the same Redis password
# Check proxy and admin have the same password file content
kubectl exec deploy/proxy -n sentinel-gateway -- cat /run/secrets/redis-password
kubectl exec deploy/admin -n sentinel-gateway -- cat /run/secrets/redis-password

# If different, update the secrets and restart all
kubectl rollout restart deploy -n sentinel-gateway
```

### Redis "connection refused"

**Cause**: Redis pod not running or service not resolving.

```bash
# Check Redis pod
kubectl get pods -l app.kubernetes.io/name=redis -n sentinel-gateway

# Check service exists
kubectl get svc redis -n sentinel-gateway

# Test DNS resolution from another pod
kubectl exec deploy/admin -n sentinel-gateway -- nslookup redis.sentinel-gateway.svc.cluster.local
```

### Redis high memory usage

```bash
# Check memory
kubectl exec deploy/redis -n sentinel-gateway -- redis-cli INFO memory

# Flush non-essential caches (rate limit counters)
kubectl exec deploy/redis -n sentinel-gateway -- redis-cli DEL sentinel:rate_limits
```

---

## Pod / Kubernetes Issues

### Pods stuck in CrashLoopBackOff

```bash
# Check pod logs
kubectl logs <pod-name> -n sentinel-gateway --previous

# Common causes:
# 1. Missing secrets (FATAL: ADMIN_JWT_SECRET is insecure)
# 2. Redis connection timeout
# 3. PVC not mounted (permission errors)
```

**Fix for missing secrets**:
```bash
# Verify secrets exist
kubectl get secrets -n sentinel-gateway

# Re-generate if needed
./k8s/secrets/generate-sealed-secrets.sh
kubectl apply -f k8s/secrets/sealed-secrets.yaml
```

### Pods stuck in Pending

```bash
# Check events
kubectl describe pod <pod-name> -n sentinel-gateway

# Common causes:
# 1. PVC not bound (no StorageClass provisioner)
# 2. Resource limits too high for node
# 3. Node selector/affinity mismatch
```

### "read-only file system" errors

**Cause**: `readOnlyRootFilesystem: true` in security context. The application must write to `/tmp` or mounted volumes only.

**Solution**: Ensure writable paths are mounted:
- `/tmp` → emptyDir
- `/app/data` → PVC
- `/app/shared` → PVC

---

## SIEM Export Issues

### Stats show 0 events exported

**Causes**:
1. No SIEM transport configured
2. Transport disabled or circuit breaker open
3. Shared volume not mounted correctly

**Diagnosis**:
```bash
# Check transport configuration
kubectl exec deploy/admin -n sentinel-gateway -- cat /app/shared/siem/siem_transports.json

# Check proxy can read the transport file
kubectl exec deploy/proxy -n sentinel-gateway -- cat /app/shared/siem/siem_transports.json

# Check SIEM stats
kubectl exec deploy/proxy -n sentinel-gateway -- cat /app/shared/siem/siem_stats.json
```

### Transport shows "circuit_breaker: open"

**Cause**: Too many consecutive failures. The circuit breaker opens to prevent overwhelming a down endpoint.

**Solution**:
1. Fix the underlying connectivity issue
2. Wait for half-open state (automatic, 60s)
3. Or restart proxy to reset circuit breaker

### Wazuh transport not receiving events

```bash
# Check Wazuh API connectivity from proxy pod
kubectl exec deploy/proxy -n sentinel-gateway -- curl -sk https://wazuh-manager:55000/security/user/authenticate -u admin:password

# Verify log file path exists
kubectl exec deploy/proxy -n sentinel-gateway -- ls -la /var/ossec/logs/
```

---

## Proxy Issues

### High latency (>100ms per request)

**Causes**:
1. Regex guardrail patterns too complex (ReDoS risk)
2. Too many IOC patterns loaded
3. Redis connection timeouts
4. Backend (LLM) slow response

**Diagnosis**:
```bash
# Check Prometheus metrics
# sentinel_request_duration_seconds histogram

# Check guardrail pattern count
curl -s http://localhost:8080/health/stats -H "X-Tenant-ID: ..." -H "Authorization: ..."
```

### Proxy returns 403 for valid tenant

**Cause**: Tenant not registered in `config/agents.yaml` or policy file missing.

```bash
# Check agent registry
kubectl exec deploy/proxy -n sentinel-gateway -- cat /app/config/agents.yaml

# Check policy exists
kubectl exec deploy/proxy -n sentinel-gateway -- ls /app/config/policies/
```

---

## Notification Issues

### Notifications not sending

**Causes**:
1. No channels configured
2. Channel disabled
3. Severity threshold too high (e.g., min_severity=critical but event is high)
4. Dedup window active (same alert sent recently)

**Diagnosis**:
```bash
# Check configured channels
curl -s http://localhost:8090/admin/notifications/channels \
  -H "Authorization: Bearer $TOKEN"

# Test a specific channel
curl -X POST http://localhost:8090/admin/notifications/channels/<id>/test \
  -H "Authorization: Bearer $TOKEN"
```

### Email notifications failing

**Common issues**:
- Gmail: Must use App Password (not account password), enable "Less secure apps" or use OAuth
- Office 365: SMTP AUTH must be enabled in Exchange admin center
- SendGrid: Username is literally `apikey`, password is your API key

```bash
# Check admin logs for SMTP errors
kubectl logs deploy/admin -n sentinel-gateway | grep "SMTP"
```

### Slack webhook returns 404

**Cause**: Webhook URL expired or was revoked in Slack workspace settings.

**Solution**: Generate a new Incoming Webhook URL in Slack App settings and update the channel.

---

## General Debugging

### Enable debug logging

```bash
# Set log level via environment
kubectl set env deploy/proxy -n sentinel-gateway SENTINEL_LOG_LEVEL=DEBUG
kubectl set env deploy/admin -n sentinel-gateway ADMIN_DEBUG=true

# Don't forget to disable after debugging
kubectl set env deploy/proxy -n sentinel-gateway SENTINEL_LOG_LEVEL=INFO
kubectl set env deploy/admin -n sentinel-gateway ADMIN_DEBUG=false
```

### Port-forward for local debugging

```bash
# Proxy
kubectl port-forward svc/proxy 8080:8080 -n sentinel-gateway

# Admin
kubectl port-forward svc/admin 8090:8090 -n sentinel-gateway

# Redis
kubectl port-forward svc/redis 6379:6379 -n sentinel-gateway

# Grafana
kubectl port-forward svc/grafana 3000:3000 -n sentinel-gateway
```

---

## Wazuh CrashLoopBackOff

### Filebeat crash: "No outputs are defined" or segfault

**Cause**: The `wazuh/wazuh-manager` image ships with Filebeat configured to send to `wazuh.indexer:9200`. Without a Wazuh Indexer deployment, Filebeat crashes and kills the entire container (s6 process supervisor exits on any service failure).

**Solution**: The deployment uses an initContainer that replaces the Filebeat binary with a no-op (`sleep infinity`). If you see this issue after updating the Wazuh manifest:

```bash
# Verify the initContainer is present
kubectl get pod wazuh-0 -n sentinel-siem -o jsonpath='{.spec.initContainers[*].name}'
# Expected: init-filebeat

# If Filebeat is still crashing, delete the PVC and recreate
kubectl delete statefulset wazuh -n sentinel-siem
kubectl delete pvc wazuh-data-wazuh-0 -n sentinel-siem
kubectl apply -f k8s/monitoring/wazuh.yaml
```

### Filebeat crash: "sed: cannot rename ... Device or resource busy"

**Cause**: Wazuh init scripts try to modify `/etc/filebeat/filebeat.yml` which is mounted as a read-only ConfigMap.

**Solution**: Mount `/etc/filebeat` as an emptyDir and use an initContainer to populate it. This is the current approach in `k8s/monitoring/wazuh.yaml`.

### Wazuh API connection refused (port 55000)

**Cause**: Wazuh Manager takes 60-90 seconds to fully start all daemons (analysisd, remoted, logcollector, apid).

**Solution**: Wait for readiness probe to pass:
```bash
kubectl wait --for=condition=ready pod/wazuh-0 -n sentinel-siem --timeout=180s
```

---

## Admin Portal: White Screen / All Forms Visible

### Login page shows MFA, Reset Password, and Change Password simultaneously

**Cause**: The Content-Security-Policy (CSP) blocks inline scripts and styles. Alpine.js requires `'unsafe-inline'` and `'unsafe-eval'` in `script-src` to process `x-data`, `x-show`, and `@click` directives. Without them, Alpine never initializes and all `x-show` blocks render as visible.

**Symptoms**:
- White background (gradient animation CSS blocked)
- All form sections visible (MFA, forgot password, change password)
- No interactivity (buttons don't work)

**Solution**: The CSP in `admin/main.py` must include:
```python
"script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; "
"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
```

**Verify** (check response headers):
```bash
curl -sk -I https://admin.sentinel-gateway.local/login | grep content-security
```

---

## Admin Portal: "file is not a database"

### SQLCipher fails on startup

**Cause**: The `DB_ENCRYPTION_KEY` is not valid hexadecimal. SQLCipher uses `PRAGMA key = "x'<hex>'"` which requires a strict hex string (characters 0-9, a-f, A-F only).

**Symptoms**:
```
pysqlcipher3.dbapi2.DatabaseError: file is not a database
ERROR: Application startup failed. Exiting.
```

**Solutions**:

1. **Wrong key format**: Regenerate with `openssl rand -hex 32` (NOT `-base64`)
2. **Key changed after DB creation**: Delete the admin-data PVC to recreate the database:
   ```bash
   kubectl scale deployment admin -n sentinel-gateway --replicas=0
   kubectl delete pvc admin-data -n sentinel-gateway
   kubectl apply -f k8s/base/volumes.yaml
   kubectl scale deployment admin -n sentinel-gateway --replicas=1
   ```
3. **Key contains invalid characters**: Only `[a-zA-Z0-9+/=\-_]` are accepted

---

## Common Deployment Issues

Issues commonly encountered during first-time deployments and upgrades.

### SIEM Dashboard Shows All Zeros

**Symptom**: Events Exported = 0, Batches Sent = 0 in the Admin SIEM dashboard.

**Causes**:
1. `siem-stats` volume mounted as read-only
2. `siem_transports.json` doesn't exist (no SIEM transport configured)
3. Telemetry disabled in environment

**Diagnosis**:
```bash
# Check telemetry is enabled
kubectl exec deploy/proxy -n sentinel-gateway -- env | grep SENTINEL_TELEMETRY

# Check volume is writable
kubectl exec deploy/proxy -n sentinel-gateway -- touch /app/shared/siem/test && echo "writable" || echo "READ-ONLY"

# Check proxy logs for transport errors
kubectl logs deploy/proxy -n sentinel-gateway | grep -E "transport_load_error|telemetry_no_transports"
```

**Solution**:
1. Ensure `SENTINEL_TELEMETRY_ENABLED=true` is set in the proxy deployment
2. Verify the shared volume mount is **read-write** (not `readOnly: true`)
3. Configure at least one SIEM transport via Admin UI > SIEM or the API
4. If you see `transport_load_error` in logs, the `siem_transports.json` file is missing or malformed

---

### Bypass Rate Shows 14-25%

**Symptom**: Dashboard bypass rate is high (14-25%) even when all known attacks are being blocked.

**Root Cause**: Older versions (< v0.4.3) calculated bypass rate as `allowed_requests / total_requests`, which counted legitimate traffic as "bypasses". This made the metric misleading since legitimate requests passing through are expected behavior, not bypasses.

**Solution**: Update to v0.4.3+ where bypass rate is calculated exclusively from red-team test reports. The new formula is:

```
bypass_rate = undetected_attacks / total_attack_attempts
```

This requires running the security smoke test (`python scripts/security-smoke-test.py`) to produce meaningful bypass metrics.

---

### Notifications Not Sending (Telegram)

**Symptom**: No Telegram alerts received, no errors visible in admin logs.

**Causes**:
1. `channels.json` is empty or has no Telegram channel configured
2. Bot token is invalid or bot was removed from the chat
3. `parse_mode` incompatibility (Markdown vs MarkdownV2)

**Diagnosis**:
```bash
# Check channel config
kubectl exec deploy/admin -n sentinel-gateway -- cat /app/data/channels.json

# Test Telegram API directly
BOT_TOKEN="<your-token>"
CHAT_ID="<your-chat-id>"
curl -s "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
  -d "chat_id=${CHAT_ID}" \
  -d "text=Test from sentinel-gateway" \
  -d "parse_mode=HTML"
```

**Solution**:
1. Configure Telegram via Admin UI > Notifications > Add Channel
2. Verify bot token with `https://api.telegram.org/bot<TOKEN>/getMe`
3. Ensure the bot is added to the target chat/group
4. If messages with special characters fail, switch `parse_mode` to `HTML` (more forgiving than MarkdownV2)

---

### Dashboard Metrics Reset on Refresh

**Symptom**: KPI values (total events, blocks, etc.) drop to 0 when refreshing the admin dashboard page.

**Cause**: In versions < v0.4.3, counters were stored in-memory only. Each page refresh re-read from volatile state, and pod restarts lost all metrics.

**Solution**: Update to v0.4.3+ which persists counters in Redis. Verify Redis is connected:

```bash
# Check Redis connectivity from admin
kubectl exec deploy/admin -n sentinel-gateway -- python -c "
import redis, os
r = redis.Redis(host='redis', port=6379, password=open('/run/secrets/redis-password').read().strip())
print('PING:', r.ping())
print('Keys:', r.keys('sentinel:metrics:*'))
"
```

If Redis is connected but counters are still zero, the migration from in-memory to Redis may not have carried over old data. Counters will accumulate from new events going forward.

---

### Proxy Returns 502/Timeout for Legitimate Requests

**Symptom**: Guardrail blocks work correctly (fast 403 responses), but legitimate requests that should pass through timeout or return 502 Bad Gateway.

**Causes**:
1. `backend.ip` in values.yaml is incorrect or unreachable
2. LLM backend (Ollama/vLLM) is not running
3. SSRF guardrail is blocking requests to the trusted backend IP
4. NetworkPolicy blocking egress to backend

**Diagnosis**:
```bash
# Test backend reachability from proxy pod
kubectl exec deploy/proxy -n sentinel-gateway -- curl -s -o /dev/null -w "%{http_code}" http://ollama:11434/

# Check if SSRF pattern is matching backend IP
kubectl logs deploy/proxy -n sentinel-gateway | grep -i "ssrf"

# Verify backend IP in config
kubectl exec deploy/proxy -n sentinel-gateway -- env | grep -i BACKEND
```

**Solution**:
1. Verify `backend.ip` matches your actual LLM endpoint
2. Test the backend is accepting connections: `curl -s http://<backend-ip>:<port>/`
3. Add your backend IP to the SSRF allowlist in the guardrail configuration
4. If using NetworkPolicy, ensure egress to the backend CIDR is permitted

---

### Wazuh Not Receiving Events

**Symptom**: Wazuh `alerts.json` has no sentinel-gateway entries despite events being generated.

**Causes**:
1. Missing decoders/rules for sentinel-gateway log format
2. Fetch script not configured or not running
3. ServiceAccount missing RBAC permissions to read proxy logs

**Diagnosis**:
```bash
# Check if Wazuh decoders are loaded
kubectl exec -n sentinel-siem wazuh-0 -- cat /var/ossec/etc/decoders/sentinel-gateway.xml

# Check rules
kubectl exec -n sentinel-siem wazuh-0 -- cat /var/ossec/etc/rules/sentinel-gateway-rules.xml

# Check init-container logs for fetch script
kubectl logs wazuh-0 -n sentinel-siem -c init-fetch-script

# Test the fetch script manually
kubectl exec -n sentinel-siem wazuh-0 -- /var/ossec/integrations/sentinel-fetch.sh
```

**Solution**:
1. Verify ConfigMaps with decoders and rules are mounted into the Wazuh pod
2. Check init-container completed successfully (`kubectl describe pod wazuh-0 -n sentinel-siem`)
3. Ensure the ServiceAccount has `get`/`list` permissions on pods/logs in the `sentinel-gateway` namespace
4. Restart Wazuh after applying decoder/rule changes: `kubectl exec -n sentinel-siem wazuh-0 -- /var/ossec/bin/wazuh-control restart`

---

### Pod CrashLoopBackOff

**Symptom**: Proxy or admin pods restart repeatedly, never reaching Ready state.

**Causes**:
1. Missing required secrets (JWT secret, API keys, Redis password)
2. JWT secret too short (must be >= 32 characters)
3. `readOnlyRootFilesystem` blocking writes to paths the app needs
4. Redis not available at startup (connection timeout → exit)

**Diagnosis**:
```bash
# Run the validation script first
./scripts/validate-deployment.sh

# Check pod events
kubectl describe pod -l app=proxy -n sentinel-gateway | tail -20

# Check previous container logs
kubectl logs -l app=proxy -n sentinel-gateway --previous

# Verify all secrets exist
kubectl get secrets -n sentinel-gateway -o name | sort
```

**Solution**:
1. Re-run `./secrets/init.sh` and redeploy secrets if any are missing
2. Ensure JWT secret is at least 32 characters: `openssl rand -base64 48`
3. Verify emptyDir mounts exist for `/tmp` and any other writable paths
4. Add `initialDelaySeconds: 10` to readiness probes if Redis takes time to start

---

### `transport_load_error` / `telemetry_no_transports` in Logs

**Symptom**: Proxy starts and handles requests, but SIEM export doesn't work. Logs contain `transport_load_error` or `telemetry_no_transports` entries.

**Cause**: The SIEM output directory (`/app/shared/siem/`) doesn't exist, isn't writable, or `siem_transports.json` is missing/empty.

**Diagnosis**:
```bash
# Check if shared volume is mounted
kubectl exec deploy/proxy -n sentinel-gateway -- df -h /app/shared/siem/

# Check file exists and has content
kubectl exec deploy/proxy -n sentinel-gateway -- cat /app/shared/siem/siem_transports.json

# Check permissions
kubectl exec deploy/proxy -n sentinel-gateway -- ls -la /app/shared/siem/
```

**Solution**:
1. Verify the `siem-stats` PVC (or shared volume) is mounted at `/app/shared/siem/` in **both** proxy and admin deployments
2. Ensure the volume mount is **read-write** (remove any `readOnly: true` from the volumeMount)
3. Configure at least one transport via Admin UI > SIEM (this creates `siem_transports.json`)
4. If the file exists but is empty `[]`, add a transport endpoint:
   ```bash
   curl -X POST http://localhost:8090/admin/siem/transports \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"type":"file","path":"/app/shared/siem/events.ndjson","enabled":true}'
   ```
