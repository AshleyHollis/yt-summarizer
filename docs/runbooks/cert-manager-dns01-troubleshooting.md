# cert-manager DNS-01 Certificate Management Runbook

## Overview

This runbook covers the management and troubleshooting of wildcard TLS certificates issued by cert-manager using Cloudflare DNS-01 challenges.

**Certificate Details:**
- **Name:** `yt-summarizer-wildcard`
- **Namespace:** `gateway-system`
- **Domains:** `*.yt-summarizer.apps.ashleyhollis.com`, `yt-summarizer.apps.ashleyhollis.com`
- **Issuer:** ClusterIssuer `letsencrypt-cloudflare`
- **Challenge Type:** DNS-01 (Cloudflare)
- **Duration:** 90 days
- **Renewal Window:** 30 days before expiration
- **Secret:** `yt-summarizer-wildcard-tls`

## Normal Operations

### Checking Certificate Status

```bash
# Check certificate status
kubectl get certificate -n gateway-system

# Expected output:
# NAME                     READY   SECRET                       AGE
# yt-summarizer-wildcard   True    yt-summarizer-wildcard-tls   1d

# Get detailed certificate information
kubectl describe certificate yt-summarizer-wildcard -n gateway-system

# Check validity dates and renewal time
kubectl get certificate yt-summarizer-wildcard -n gateway-system -o yaml | grep -E "notAfter|notBefore|renewalTime"
```

### Automatic Renewal Process

cert-manager automatically renews certificates 30 days before expiration:

1. **30 days before expiry:** cert-manager creates a new CertificateRequest
2. **DNS-01 challenge:** Creates TXT records in Cloudflare via API
3. **Let's Encrypt validation:** Verifies DNS records propagation
4. **Certificate issuance:** New certificate replaces old one in Secret
5. **Gateway pickup:** NGINX Gateway Fabric automatically reloads certificate

**No manual intervention required for renewal.**

### Monitoring Renewal Status

```bash
# Check if renewal is in progress (30-60 days after issuance)
kubectl get certificaterequest -n gateway-system

# Check DNS-01 challenges
kubectl get challenges -n gateway-system

# Check ACME orders
kubectl get order -n gateway-system

# Monitor cert-manager logs during renewal
kubectl logs -n cert-manager -l app=cert-manager --tail=50 -f
```

## Troubleshooting

### Certificate Not Ready

**Symptom:** `kubectl get certificate` shows `READY=False`

**Diagnosis:**

```bash
# Check certificate status
kubectl describe certificate yt-summarizer-wildcard -n gateway-system

# Look for conditions:
# - Issuing: True → Certificate is being issued
# - Ready: False → Not yet complete
```

**Common Causes:**

1. **Initial issuance in progress** → Wait 2-5 minutes for DNS propagation
2. **Cloudflare API errors** → Check challenges and cert-manager logs
3. **DNS propagation delays** → Check challenge status

### Challenge Stuck in Pending State

**Symptom:** Challenge exists but shows no STATE or stays in `pending`

**Diagnosis:**

```bash
# List challenges
kubectl get challenges -n gateway-system

# Check challenge details
kubectl describe challenge <challenge-name> -n gateway-system

# Check cert-manager logs for errors
kubectl logs -n cert-manager -l app=cert-manager --tail=100 | grep -i error
```

**Common Errors:**

1. **"DNS record not yet propagated"**
   - **Cause:** DNS changes haven't reached all nameservers
   - **Solution:** Wait 1-2 minutes, challenge will retry automatically

2. **"Cloudflare API Error... Could not route to /zones//dns_records"**
   - **Cause:** Zone ID missing in DELETE request (cleanup phase)
   - **Solution:** Delete stuck challenge, cert-manager will recreate:

   ```bash
   kubectl delete challenge <challenge-name> -n gateway-system
   ```

3. **"Actor requires permission to list zones"**
   - **Cause:** Cloudflare API token lacks `Zone - Zone - Read` permission
   - **Solution:** Update API token permissions in Cloudflare dashboard

### Certificate Stuck in Issuing State

**Symptom:** Certificate shows `Issuing: True` for >10 minutes

**Diagnosis:**

```bash
# Check order status
kubectl describe order -n gateway-system

# Check all challenges
kubectl get challenges -n gateway-system -o wide

# Check cert-manager logs
kubectl logs -n cert-manager -l app=cert-manager --tail=50
```

**Resolution:**

If challenges are valid but order is still pending, try recreating the certificate:

```bash
# Delete certificate (Secret will be preserved)
kubectl delete certificate yt-summarizer-wildcard -n gateway-system

# Delete pending orders and challenges
kubectl delete order --all -n gateway-system
kubectl delete challenge --all -n gateway-system

# Certificate will be automatically recreated by ArgoCD
# Or manually recreate:
kubectl apply -f k8s/argocd/certificates/yt-summarizer-wildcard.yaml

# Wait for issuance (usually 1-3 minutes)
kubectl get certificate -n gateway-system -w
```

### Cloudflare API Token Issues

**Symptom:** Challenges fail with "API token invalid" or permission errors

**Diagnosis:**

```bash
# Check ExternalSecret status
kubectl get externalsecret cloudflare-api-token -n gateway-system

# Expected output:
# NAME                  STORE                       REFRESH   STATUS
# cloudflare-api-token  azure-keyvault-cluster      1h        SecretSynced

# Check secret exists
kubectl get secret cloudflare-api-token -n gateway-system
kubectl get secret cloudflare-api-token -n cert-manager
```

**Resolution:**

1. **Verify API token in Cloudflare:**
   - Login to Cloudflare → My Profile → API Tokens
   - Check `yt-summarizer-cert-manager` token permissions:
     - `Zone - DNS - Edit`
     - `Zone - Zone - Read`
   - Zone Resources: `Include - All Zones`

2. **Regenerate token if needed:**

   ```bash
   # Update token in Azure Key Vault
   az keyvault secret set \
     --vault-name <keyvault-name> \
     --name cloudflare-api-token \
     --value "<new-token>"

   # Force ExternalSecret refresh
   kubectl delete secret cloudflare-api-token -n gateway-system
   kubectl delete secret cloudflare-api-token -n cert-manager

   # Secrets will be recreated automatically within 1 minute
   ```

### DNS Propagation Delays

**Symptom:** Challenges show "DNS record not yet propagated" for >5 minutes

**Diagnosis:**

```bash
# Check if TXT record was created
dig _acme-challenge.yt-summarizer.apps.ashleyhollis.com TXT

# Check challenge status
kubectl get challenge -n gateway-system -o yaml
```

**Resolution:**

1. **Check Cloudflare DNS:**
   - Login to Cloudflare → Domain → DNS Records
   - Look for `_acme-challenge` TXT records
   - Verify records exist and match challenge tokens

2. **Manual propagation check:**

   ```bash
   # Query Cloudflare nameservers directly
   dig @ns1.cloudflare.com _acme-challenge.yt-summarizer.apps.ashleyhollis.com TXT
   dig @ns2.cloudflare.com _acme-challenge.yt-summarizer.apps.ashleyhollis.com TXT
   ```

3. **If records are missing:**
   - Check cert-manager logs for API errors
   - Verify Cloudflare API token has DNS Edit permission
   - Delete challenge to force recreation

### Certificate Expiration

**Symptom:** Certificate expired or will expire soon

**Diagnosis:**

```bash
# Check certificate expiry
kubectl get certificate yt-summarizer-wildcard -n gateway-system -o yaml | grep notAfter

# Check renewal time
kubectl get certificate yt-summarizer-wildcard -n gateway-system -o yaml | grep renewalTime
```

**Prevention:**

cert-manager should automatically renew 30 days before expiry. If renewal failed:

1. **Check cert-manager logs:**

   ```bash
   kubectl logs -n cert-manager -l app=cert-manager --tail=200 | grep -i renew
   ```

2. **Force renewal:**

   ```bash
   # Delete certificate to trigger immediate renewal
   kubectl delete certificate yt-summarizer-wildcard -n gateway-system

   # Certificate will be recreated by ArgoCD
   # Or manually apply:
   kubectl apply -f k8s/argocd/certificates/yt-summarizer-wildcard.yaml
   ```

### TLS Not Working on Gateway

**Symptom:** HTTPS connections fail with certificate errors

**Diagnosis:**

```bash
# Check Gateway TLS configuration
kubectl get gateway main-gateway -n gateway-system -o yaml

# Verify certificateRef points to correct secret
# Expected: secretName: yt-summarizer-wildcard-tls

# Check secret in gateway-system namespace
kubectl get secret yt-summarizer-wildcard-tls -n gateway-system

# Test TLS with curl
curl -v https://api.yt-summarizer.apps.ashleyhollis.com
```

**Resolution:**

1. **Verify Gateway listener configuration:**

   ```yaml
   listeners:
   - name: https
     hostname: "*.yt-summarizer.apps.ashleyhollis.com"
     port: 443
     protocol: HTTPS
     tls:
       mode: Terminate
       certificateRefs:
       - kind: Secret
         name: yt-summarizer-wildcard-tls
   ```

2. **Restart NGINX Gateway Fabric if needed:**

   ```bash
   kubectl rollout restart deployment nginx-gateway -n gateway-system
   ```

3. **Check NGINX Gateway logs:**

   ```bash
   kubectl logs -n gateway-system -l app.kubernetes.io/name=nginx-gateway-fabric
   ```

## Emergency Procedures

### Immediate Certificate Replacement

If the certificate is critically broken and needs immediate replacement:

```bash
# 1. Delete everything
kubectl delete certificate yt-summarizer-wildcard -n gateway-system
kubectl delete certificaterequest --all -n gateway-system
kubectl delete order --all -n gateway-system
kubectl delete challenge --all -n gateway-system

# 2. Recreate certificate
kubectl apply -f k8s/argocd/certificates/yt-summarizer-wildcard.yaml

# 3. Monitor issuance (usually 2-3 minutes)
watch kubectl get certificate -n gateway-system

# 4. Verify TLS secret was created
kubectl get secret yt-summarizer-wildcard-tls -n gateway-system
```

### Rollback to Self-Signed Certificate

If Let's Encrypt is unavailable, create a temporary self-signed certificate:

```bash
# Create self-signed certificate
openssl req -x509 -nodes -days 30 -newkey rsa:2048 \
  -keyout /tmp/tls.key -out /tmp/tls.crt \
  -subj "/CN=*.yt-summarizer.apps.ashleyhollis.com"

# Create temporary secret
kubectl create secret tls yt-summarizer-wildcard-tls-temp \
  --cert=/tmp/tls.crt --key=/tmp/tls.key \
  -n gateway-system

# Update Gateway to use temporary secret
kubectl patch gateway main-gateway -n gateway-system --type=json \
  -p='[{"op": "replace", "path": "/spec/listeners/0/tls/certificateRefs/0/name", "value": "yt-summarizer-wildcard-tls-temp"}]'

# Clean up temp files
rm /tmp/tls.key /tmp/tls.crt
```

**Note:** Browsers will show security warnings for self-signed certificates.

## Maintenance

### Updating Certificate Domains

To add or remove domains from the certificate:

1. **Edit certificate manifest:**

   ```yaml
   # k8s/argocd/certificates/yt-summarizer-wildcard.yaml
   spec:
     dnsNames:
     - "*.yt-summarizer.apps.ashleyhollis.com"
     - "yt-summarizer.apps.ashleyhollis.com"
     - "newdomain.apps.ashleyhollis.com"  # Add new domain
   ```

2. **Apply changes:**

   ```bash
   kubectl apply -f k8s/argocd/certificates/yt-summarizer-wildcard.yaml
   ```

3. **Monitor re-issuance:**

   ```bash
   kubectl get certificate -n gateway-system -w
   ```

### Rotating Cloudflare API Token

1. **Create new token in Cloudflare dashboard**
2. **Update Azure Key Vault:**

   ```bash
   az keyvault secret set \
     --vault-name <keyvault-name> \
     --name cloudflare-api-token \
     --value "<new-token>"
   ```

3. **Force secret refresh:**

   ```bash
   kubectl delete secret cloudflare-api-token -n gateway-system
   kubectl delete secret cloudflare-api-token -n cert-manager
   ```

4. **Verify secrets recreated:**

   ```bash
   kubectl get externalsecret cloudflare-api-token -n gateway-system
   kubectl get secret cloudflare-api-token -n gateway-system
   kubectl get secret cloudflare-api-token -n cert-manager
   ```

## Monitoring and Alerts

### Key Metrics to Monitor

1. **Certificate expiry:** Alert 40 days before expiration
2. **Renewal failures:** Alert if renewal fails
3. **Challenge duration:** Alert if challenge takes >10 minutes
4. **Secret sync status:** Alert if ExternalSecret not synced

### Prometheus Queries

```promql
# Certificate expiry in days
(cert_manager_certificate_expiry_timestamp_seconds{name="yt-summarizer-wildcard"} - time()) / 86400

# Certificate ready status
cert_manager_certificate_ready_status{name="yt-summarizer-wildcard"}

# Challenge failures
rate(cert_manager_controller_sync_call_count{controller="challenges", result="error"}[5m])
```

## References

- [cert-manager Cloudflare DNS-01 Documentation](https://cert-manager.io/docs/configuration/acme/dns01/cloudflare/)
- [cert-manager Troubleshooting Guide](https://cert-manager.io/docs/troubleshooting/)
- [Let's Encrypt Rate Limits](https://letsencrypt.org/docs/rate-limits/)
- [Cloudflare API Documentation](https://developers.cloudflare.com/api/)

## Change Log

- **2026-01-11:** Initial documentation - wildcard certificate issued successfully
