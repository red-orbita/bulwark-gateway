# Runbook: BulwarkCertificateExpiringSoon

## Alert Details

- **Severity**: Critical
- **Alert rule**: `BulwarkCertificateExpiringSoon`
- **Prometheus expression**:
  ```promql
  (probe_ssl_earliest_cert_expiry - time()) / 86400 < 7
  ```
- **Fires when**: TLS certificate expires in less than 7 days (evaluated for 1 hour)
- **Team**: Platform
- **Compliance**: SOC 2 CC6.1 (Logical and Physical Access Controls — encryption)

## Impact Assessment

- **Who is affected**: All users/tenants if ingress certificate expires; specific backends if internal certs expire
- **What degrades**: TLS handshake failures → complete service outage for HTTPS clients
- **What still works**: Nothing if the ingress cert expires (clients will reject the connection)
- **Business impact**: Complete service unavailability for all HTTPS clients, compliance violation

## Immediate Actions (First 5 Minutes)

1. **Acknowledge the alert** in PagerDuty
2. **Identify which certificate is expiring**:
   ```bash
   # Check ingress TLS secret
   kubectl get secret -n bulwark-gateway -l cert-manager.io/certificate-name | \
     xargs -I{} kubectl get secret {} -n bulwark-gateway -o jsonpath='{.data.tls\.crt}' | \
     base64 -d | openssl x509 -noout -dates -subject

   # Check all TLS secrets in namespace
   kubectl get secrets -n bulwark-gateway --field-selector type=kubernetes.io/tls -o name | \
     while read secret; do
       echo "=== $secret ==="
       kubectl get $secret -n bulwark-gateway -o jsonpath='{.data.tls\.crt}' | \
         base64 -d | openssl x509 -noout -enddate -subject 2>/dev/null
     done
   ```
3. **Check cert-manager status** (if using cert-manager):
   ```bash
   kubectl get certificates -n bulwark-gateway
   kubectl get certificaterequests -n bulwark-gateway
   kubectl describe certificate bulwark-tls -n bulwark-gateway
   ```
4. **Decision point**: Is cert-manager renewal failing, or is this a manually-managed cert?

## Investigation Steps

```bash
# 1. Cert-manager certificate status
kubectl get certificates -n bulwark-gateway -o wide

# 2. Cert-manager events (renewal failures)
kubectl get events -n bulwark-gateway --field-selector reason=Failed --sort-by='.lastTimestamp' | grep -i cert

# 3. CertificateRequest details (why renewal failed)
kubectl get certificaterequests -n bulwark-gateway -o yaml | grep -A5 "status:"

# 4. Cert-manager logs
kubectl logs deploy/cert-manager -n cert-manager --since=1h | grep -i "bulwark\|error\|fail"

# 5. Check ACME challenge completion (if Let's Encrypt)
kubectl get challenges -n bulwark-gateway
kubectl describe challenge -n bulwark-gateway

# 6. Verify DNS for ACME DNS-01 challenge
kubectl exec deploy/proxy -n bulwark-gateway -- nslookup _acme-challenge.bulwark-gateway.yourdomain.com

# 7. Check ingress annotation for cert-manager
kubectl get ingress -n bulwark-gateway -o yaml | grep -A3 "cert-manager"

# 8. Direct certificate inspection
echo | openssl s_client -connect bulwark-gateway.yourdomain.com:443 -servername bulwark-gateway.yourdomain.com 2>/dev/null | \
  openssl x509 -noout -dates -issuer
```

### Common Causes

| Cause | Indicator | Fix |
|-------|-----------|-----|
| Cert-manager not renewing | Certificate status "False", events show failures | Fix issuer config or DNS challenge |
| DNS challenge failing | Challenge stuck in "pending" | Fix DNS provider credentials or zone access |
| HTTP challenge failing | 404 on `.well-known/acme-challenge` | Ensure ingress routes challenge path |
| Issuer misconfigured | ClusterIssuer/Issuer shows errors | Fix issuer secret or API credentials |
| Rate limited by CA | Let's Encrypt rate limit hit | Wait or use staging issuer, check limits |
| Manual cert (no automation) | No Certificate resource exists | Renew manually and automate going forward |
| Cloud provider issue | Managed cert shows provisioning failure | Check cloud DNS/cert service status |

## Remediation

### Cert-Manager Automated Renewal (Normal Path)

```bash
# 1. Force renewal attempt
kubectl cert-manager renew bulwark-tls -n bulwark-gateway

# 2. Watch for completion
kubectl get certificate bulwark-tls -n bulwark-gateway -w

# 3. If challenge is stuck, delete and recreate
kubectl delete certificaterequest -n bulwark-gateway --all
# cert-manager will create a new request

# 4. If issuer credentials expired (e.g., DNS provider API key)
kubectl get secret cert-manager-dns-credentials -n cert-manager -o yaml
# Update with valid credentials
```

### Manual Certificate Renewal (Emergency)

```bash
# 1. Generate CSR or use existing private key
openssl req -new -key server.key -out server.csr -subj "/CN=bulwark-gateway.yourdomain.com"

# 2. Submit to CA (internal or public) and receive signed cert

# 3. Update the TLS secret directly
kubectl create secret tls bulwark-tls \
  --cert=server.crt \
  --key=server.key \
  --namespace bulwark-gateway \
  --dry-run=client -o yaml | kubectl apply -f -

# 4. Restart ingress controller to pick up new cert
kubectl rollout restart deploy/ingress-nginx-controller -n ingress-nginx

# 5. Verify
echo | openssl s_client -connect bulwark-gateway.yourdomain.com:443 2>/dev/null | \
  openssl x509 -noout -dates
```

### Self-Signed Certificate (Development/Internal)

```bash
# 1. Generate new self-signed cert (90 days)
openssl req -x509 -nodes -days 90 \
  -newkey rsa:2048 \
  -keyout /tmp/tls.key \
  -out /tmp/tls.crt \
  -subj "/CN=bulwark-gateway.internal"

# 2. Update secret
kubectl create secret tls bulwark-tls \
  --cert=/tmp/tls.crt \
  --key=/tmp/tls.key \
  --namespace bulwark-gateway \
  --dry-run=client -o yaml | kubectl apply -f -

# 3. Clean up temp files
rm /tmp/tls.key /tmp/tls.crt
```

### Mutual TLS (mTLS) Certificates

```bash
# If using mTLS between proxy<->backend, check those certs too
# Our mTLS cert generation script:
./scripts/generate-mtls-certs.sh

# Verify mTLS connectivity
kubectl exec deploy/proxy -n bulwark-gateway -- \
  curl --cert /etc/bulwark/tls/client.crt --key /etc/bulwark/tls/client.key \
  https://backend:443/health
```

## Escalation

- If cert expires within 24 hours and automated renewal is failing → P1 escalation to platform lead
- If cert has already expired (users seeing TLS errors) → Immediate P1, all hands
- If CA is rate limiting → Contact CA support, consider alternative issuer
- If wildcard cert used across services → Notify all dependent teams

## Related Alerts

- [`BulwarkProxyTargetDown`](alert-certificate-expiry.md) — expired cert causes scrape failures
- [`BulwarkBackendErrorRateHigh`](alert-backend-errors.md) — mTLS cert expiry can cause backend connection failures
- [`BulwarkAuditLogFailures`](alert-certificate-expiry.md) — TLS cert failure to SIEM can break audit export

## Post-Incident

- [ ] Implement cert-manager if not already in use
- [ ] Set alert threshold earlier (14 days instead of 7)
- [ ] Add certificate expiry to `validate-deployment.sh` checks
- [ ] Document certificate renewal procedure for this specific cert
- [ ] Verify all other certificates in the namespace
- [ ] Create Jira ticket for root cause (why didn't auto-renewal work?)
- [ ] Update this runbook with lessons learned
