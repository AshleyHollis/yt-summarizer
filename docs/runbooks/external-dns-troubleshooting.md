# ExternalDNS Troubleshooting and Verification Runbook

## Overview

This runbook covers troubleshooting and verifying ExternalDNS operations with Gateway API HTTPRoutes, specifically for the preview environment cleanup process.

**ExternalDNS Configuration:**
- **Version:** v0.14.0
- **Source:** `gateway-httproute`
- **Provider:** Cloudflare
- **Domain Filter:** `apps.ashleyhollis.com`
- **Namespace:** `external-dns`
- **Watched Resources:** HTTPRoute resources across all namespaces

## How ExternalDNS Works with HTTPRoutes

### DNS Record Creation

When an HTTPRoute is created with the `external-dns.alpha.kubernetes.io/hostname` annotation:

1. **HTTPRoute Created:**
   ```yaml
   apiVersion: gateway.networking.k8s.io/v1
   kind: HTTPRoute
   metadata:
     name: api-httproute
     namespace: preview-pr-123
     annotations:
       external-dns.alpha.kubernetes.io/hostname: api-pr-123.yt-summarizer.apps.ashleyhollis.com
   spec:
     hostnames:
     - "api-pr-123.yt-summarizer.apps.ashleyhollis.com"
   ```

2. **ExternalDNS watches the HTTPRoute** and detects the annotation

3. **Resolves Gateway LoadBalancer IP** from the HTTPRoute's parentRef

4. **Creates DNS record in Cloudflare:**
   - Type: A
   - Name: `api-pr-123.yt-summarizer.apps`
   - Value: `20.187.186.135` (Gateway LoadBalancer IP)
   - TTL: 300 (5 minutes)

5. **Record appears in Cloudflare within 30-60 seconds**

### DNS Record Deletion

When an HTTPRoute is deleted (e.g., PR closed, namespace deleted):

1. **HTTPRoute Deleted:** Kubernetes removes the HTTPRoute resource
2. **ExternalDNS detects deletion** via watch mechanism
3. **Deletes DNS record from Cloudflare** within 30-60 seconds
4. **DNS propagation:** Record removal propagates globally within 5 minutes (TTL)

**Important:** ExternalDNS manages DNS records via Kubernetes ownership. When a resource is deleted, ExternalDNS automatically removes the corresponding DNS records.

## Verification Procedures

### Verify ExternalDNS is Running

```bash
# Check ExternalDNS pod status
kubectl get pods -n external-dns

# Expected output:
# NAME                            READY   STATUS    RESTARTS   AGE
# external-dns-xxxxxxxxxx-xxxxx   1/1     Running   0          1d

# Check logs for errors
kubectl logs -n external-dns -l app.kubernetes.io/name=external-dns --tail=50
```

### Verify DNS Record Creation (Preview Deployment)

**After a preview deployment:**

```bash
# 1. Check HTTPRoute was created
kubectl get httproute -n preview-pr-<NUMBER>

# Expected output:
# NAME            HOSTNAMES                                              AGE
# api-httproute   ["api-pr-<NUMBER>.yt-summarizer.apps.ashleyhollis.com"]   1m

# 2. Verify HTTPRoute annotation
kubectl get httproute api-httproute -n preview-pr-<NUMBER> -o yaml | grep external-dns

# Expected output:
# external-dns.alpha.kubernetes.io/hostname: api-pr-<NUMBER>.yt-summarizer.apps.ashleyhollis.com

# 3. Check ExternalDNS logs for record creation
kubectl logs -n external-dns -l app.kubernetes.io/name=external-dns --tail=100 | grep "api-pr-<NUMBER>"

# Expected log entries:
# level=info msg="Desired change: CREATE api-pr-<NUMBER>.yt-summarizer.apps.ashleyhollis.com A [endpoint=20.187.186.135]"
# level=info msg="Record successfully created" zone="ashleyhollis.com" record="api-pr-<NUMBER>.yt-summarizer.apps"

# 4. Verify DNS resolution (may take 30-60 seconds)
nslookup api-pr-<NUMBER>.yt-summarizer.apps.ashleyhollis.com

# Expected output:
# Name:    api-pr-<NUMBER>.yt-summarizer.apps.ashleyhollis.com
# Address: 20.187.186.135
```

### Verify DNS Record Deletion (Preview Cleanup)

**After closing a PR:**

```bash
# 1. Verify namespace is deleted or being deleted
kubectl get namespace preview-pr-<NUMBER>

# Expected output (after cleanup):
# Error from server (NotFound): namespaces "preview-pr-<NUMBER>" not found

# OR (during cleanup):
# NAME                STATUS        AGE
# preview-pr-<NUMBER>   Terminating   5m

# 2. Verify HTTPRoute is deleted
kubectl get httproute -n preview-pr-<NUMBER> 2>&1

# Expected output:
# Error from server (NotFound): namespaces "preview-pr-<NUMBER>" not found

# 3. Check ExternalDNS logs for deletion
kubectl logs -n external-dns -l app.kubernetes.io/name=external-dns --tail=100 | grep "api-pr-<NUMBER>"

# Expected log entries:
# level=info msg="Desired change: DELETE api-pr-<NUMBER>.yt-summarizer.apps.ashleyhollis.com A"
# level=info msg="Record successfully deleted" zone="ashleyhollis.com" record="api-pr-<NUMBER>.yt-summarizer.apps"

# 4. Verify DNS record is removed (check after 5-10 minutes for propagation)
nslookup api-pr-<NUMBER>.yt-summarizer.apps.ashleyhollis.com

# Expected output:
# ** server can't find api-pr-<NUMBER>.yt-summarizer.apps.ashleyhollis.com: NXDOMAIN
```

### Verify via Cloudflare Dashboard

1. **Login to Cloudflare Dashboard** → Select `ashleyhollis.com` domain
2. **Navigate to DNS → Records**
3. **Search for** `api-pr-<NUMBER>`

**Expected Results:**
- **After deployment:** Record exists with value `20.187.186.135`
- **After cleanup (5-10 min):** Record does not exist

## Troubleshooting

### DNS Record Not Created After HTTPRoute Deployment

**Symptoms:**
- HTTPRoute exists but DNS record not in Cloudflare
- `nslookup` fails with NXDOMAIN

**Diagnosis:**

```bash
# 1. Check HTTPRoute has correct annotation
kubectl describe httproute api-httproute -n preview-pr-<NUMBER>

# Look for:
# Annotations: external-dns.alpha.kubernetes.io/hostname: api-pr-<NUMBER>.yt-summarizer.apps.ashleyhollis.com

# 2. Check ExternalDNS logs for errors
kubectl logs -n external-dns -l app.kubernetes.io/name=external-dns --tail=200 | grep -i error

# Common errors:
# - "zone not found" → Domain filter issue
# - "permission denied" → Cloudflare API token lacks permissions
# - "no endpoints found" → HTTPRoute not referencing valid Gateway
```

**Common Causes & Solutions:**

1. **Missing or incorrect annotation:**
   
   ```bash
   # Add annotation to HTTPRoute
   kubectl annotate httproute api-httproute -n preview-pr-<NUMBER> \
     external-dns.alpha.kubernetes.io/hostname="api-pr-<NUMBER>.yt-summarizer.apps.ashleyhollis.com"
   ```

2. **HTTPRoute not referencing Gateway:**
   
   ```bash
   # Verify HTTPRoute has parentRef to main-gateway
   kubectl get httproute api-httproute -n preview-pr-<NUMBER> -o yaml | grep -A5 parentRefs
   
   # Expected:
   # parentRefs:
   # - name: main-gateway
   #   namespace: gateway-system
   #   sectionName: https
   ```

3. **Gateway not PROGRAMMED:**
   
   ```bash
   # Check Gateway status
   kubectl get gateway main-gateway -n gateway-system
   
   # Expected:
   # NAME           CLASS   ADDRESS           PROGRAMMED   AGE
   # main-gateway   nginx   20.187.186.135    True         1d
   ```

4. **Cloudflare API token issues:**
   
   ```bash
   # Check ExternalSecret for Cloudflare token
   kubectl get externalsecret cloudflare-api-token -n external-dns
   
   # Expected:
   # NAME                   STORE                       REFRESH   STATUS
   # cloudflare-api-token   azure-keyvault-cluster      1h        SecretSynced
   
   # If not synced, force refresh:
   kubectl delete secret cloudflare-api-token -n external-dns
   # Secret will be recreated automatically within 1 minute
   ```

5. **Domain filter mismatch:**
   
   ```bash
   # Check ExternalDNS deployment args
   kubectl get deployment external-dns -n external-dns -o yaml | grep domain-filter
   
   # Expected:
   # - --domain-filter=apps.ashleyhollis.com
   
   # Hostname must match: *.yt-summarizer.apps.ashleyhollis.com
   ```

### DNS Record Not Deleted After Namespace Cleanup

**Symptoms:**
- Namespace deleted but DNS record still in Cloudflare
- `nslookup` still resolves after 10+ minutes

**Diagnosis:**

```bash
# 1. Check if ExternalDNS saw the deletion
kubectl logs -n external-dns -l app.kubernetes.io/name=external-dns --tail=500 | grep "api-pr-<NUMBER>" | grep DELETE

# Expected:
# level=info msg="Desired change: DELETE api-pr-<NUMBER>.yt-summarizer.apps.ashleyhollis.com A"

# 2. Check for Cloudflare API errors
kubectl logs -n external-dns -l app.kubernetes.io/name=external-dns --tail=200 | grep -i "cloudflare.*error"
```

**Common Causes & Solutions:**

1. **ExternalDNS didn't detect deletion:**
   
   ```bash
   # Restart ExternalDNS to force re-sync
   kubectl rollout restart deployment external-dns -n external-dns
   
   # ExternalDNS will re-sync all records and delete orphaned ones
   ```

2. **Cloudflare API rate limiting:**
   
   ```bash
   # Check logs for rate limit errors
   kubectl logs -n external-dns -l app.kubernetes.io/name=external-dns | grep -i "rate limit"
   
   # Solution: Wait 5-10 minutes, ExternalDNS will retry
   ```

3. **Manual cleanup required:**
   
   If record persists after 15+ minutes:
   
   ```bash
   # Option 1: Delete via Cloudflare Dashboard
   # Login → DNS → Records → Delete the specific record
   
   # Option 2: Use Cloudflare API (if you have API token)
   # First get zone ID and record ID, then delete via API
   ```

### ExternalDNS Pod CrashLooping

**Symptoms:**
- ExternalDNS pod not running
- DNS records not being created or deleted

**Diagnosis:**

```bash
# Check pod status
kubectl get pods -n external-dns

# Check pod logs
kubectl logs -n external-dns -l app.kubernetes.io/name=external-dns --previous

# Common errors:
# - "invalid Cloudflare API token" → Token issue
# - "connection refused" → Network issue
# - "no such file or directory" → Secret mounting issue
```

**Solutions:**

1. **Verify Cloudflare secret exists:**
   
   ```bash
   kubectl get secret cloudflare-api-token -n external-dns
   
   # If missing, check ExternalSecret
   kubectl describe externalsecret cloudflare-api-token -n external-dns
   ```

2. **Check deployment configuration:**
   
   ```bash
   kubectl describe deployment external-dns -n external-dns
   
   # Look for:
   # - Correct image version
   # - Secret volume mount
   # - Environment variables
   ```

3. **Restart deployment:**
   
   ```bash
   kubectl rollout restart deployment external-dns -n external-dns
   kubectl rollout status deployment external-dns -n external-dns
   ```

### Stale DNS Records After Multiple PR Cycles

**Symptoms:**
- Old preview DNS records still exist for closed PRs
- Cloudflare has orphaned records

**Diagnosis:**

```bash
# 1. List all HTTPRoutes across namespaces
kubectl get httproute -A | grep yt-summarizer

# 2. Compare with DNS records in Cloudflare
# Login to Cloudflare → DNS → Records → Filter for "api-pr-"

# 3. Identify orphaned records (no matching HTTPRoute)
```

**Cleanup:**

```bash
# Force ExternalDNS to re-sync and clean up orphaned records
kubectl annotate deployment external-dns -n external-dns \
  force-sync="$(date +%s)" --overwrite

# Or restart ExternalDNS
kubectl rollout restart deployment external-dns -n external-dns

# ExternalDNS will:
# 1. List all HTTPRoutes
# 2. List all DNS records it manages
# 3. Delete records without matching HTTPRoutes
```

## Preview Cleanup Verification Checklist

Use this checklist when verifying preview cleanup works correctly:

### Before Closing PR

- [ ] Preview namespace exists: `kubectl get namespace preview-pr-<NUMBER>`
- [ ] HTTPRoute exists: `kubectl get httproute -n preview-pr-<NUMBER>`
- [ ] DNS resolves: `nslookup api-pr-<NUMBER>.yt-summarizer.apps.ashleyhollis.com`
- [ ] Record in Cloudflare dashboard

### Immediately After Closing PR (0-2 minutes)

- [ ] GitHub Actions workflow triggers
- [ ] Cleanup comment posted to PR
- [ ] ArgoCD Application begins deletion

### 3-5 Minutes After Closing

- [ ] Namespace status: `Terminating` or deleted
- [ ] ArgoCD Application deleted
- [ ] ExternalDNS logs show DELETE operation
- [ ] DNS record removed from Cloudflare dashboard

### 5-10 Minutes After Closing

- [ ] Namespace fully deleted: `kubectl get namespace preview-pr-<NUMBER>` → NotFound
- [ ] DNS no longer resolves: `nslookup` → NXDOMAIN
- [ ] No orphaned resources in cluster

### Cleanup Timing Expectations

| Event | Expected Timing |
|-------|----------------|
| PR closed → ArgoCD detects | 30-60 seconds |
| ArgoCD deletes Application | 1-2 minutes |
| Namespace deletion starts | 2-3 minutes |
| HTTPRoute deleted | 2-3 minutes (with namespace) |
| ExternalDNS detects deletion | 30-60 seconds after HTTPRoute deleted |
| DNS record removed from Cloudflare | 30-60 seconds after ExternalDNS detects |
| **Total cleanup time** | **5-10 minutes** |

## Monitoring and Alerts

### Key Metrics to Monitor

1. **ExternalDNS pod health:**
   ```promql
   up{job="external-dns"} == 0
   ```

2. **DNS record creation lag:**
   ```promql
   (time() - kube_httproute_created{namespace=~"preview-pr-.*"}) > 300
   ```

3. **Orphaned DNS records:**
   - Monitor Cloudflare for `api-pr-*` records without matching namespace

### Recommended Alerts

1. **ExternalDNS Down:**
   - Alert if pod not ready for 5+ minutes
   - Impact: New previews won't get DNS records

2. **Stale DNS Records:**
   - Alert if DNS records exist for closed PRs (>24 hours old)
   - Impact: Unnecessary Cloudflare records, potential confusion

3. **DNS Creation Failures:**
   - Alert if HTTPRoute exists >5 minutes without DNS record
   - Impact: Preview URL not accessible

## References

- [ExternalDNS Gateway API Documentation](https://github.com/kubernetes-sigs/external-dns/blob/master/docs/tutorials/gateway-api.md)
- [ExternalDNS Cloudflare Provider](https://github.com/kubernetes-sigs/external-dns/blob/master/docs/tutorials/cloudflare.md)
- [cert-manager DNS-01 Troubleshooting](./cert-manager-dns01-troubleshooting.md)
- [Argo CD ApplicationSet Pull Request Generator](https://argo-cd.readthedocs.io/en/stable/operator-manual/applicationset/Generators-Pull-Request/)

## Change Log

- **2026-01-12:** Initial documentation - ExternalDNS with Gateway API HTTPRoutes
