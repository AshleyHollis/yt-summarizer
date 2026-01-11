# Quickstart: Preview DNS/TLS Migration Validation

**Feature**: 003-preview-dns-cloudflare  
**Date**: January 11, 2026  
**Status**: Draft

---

## Prerequisites

Before starting validation, ensure:

1. ✅ Wildcard DNS record created in Cloudflare zone `ashleyhollis.com` (e.g., `*.yt-summarizer.apps` → Gateway IP)
2. ✅ Cloudflare API token stored in Azure Key Vault
3. ✅ Gateway API CRDs installed
4. ✅ NGINX Gateway Fabric deployed
5. ✅ ExternalDNS deployed
6. ✅ ClusterIssuer configured
7. ✅ Wildcard certificate issued

---

## Validation Checklist

### 1. DNS Record Verification

**Test**: Verify wildcard DNS record resolves to Gateway IP.

```bash
# Check that ashleyhollis.com zone uses Cloudflare nameservers
dig NS ashleyhollis.com +short

# Expected output (Cloudflare nameservers):
# something.ns.cloudflare.com.
# something.ns.cloudflare.com.

# Verify wildcard record resolves to Gateway IP
dig api.yt-summarizer.apps.ashleyhollis.com +short
# Expected output: <Gateway public IP>
```

**Pass Criteria**: Parent domain uses Cloudflare nameservers; wildcard subdomains resolve to Gateway IP.

---

### 2. Wildcard Certificate

**Test**: Verify wildcard certificate is issued and Ready.

```bash
# Check certificate status
kubectl get certificate -n gateway-system

# Expected output:
# NAME                     READY   SECRET                       AGE
# yt-summarizer-wildcard   True    yt-summarizer-wildcard-tls   5m

# Check certificate details
kubectl describe certificate yt-summarizer-wildcard -n gateway-system

# Verify secret exists
kubectl get secret yt-summarizer-wildcard-tls -n gateway-system
```

**Pass Criteria**: 
- Certificate shows `READY: True`
- Secret exists with `tls.crt` and `tls.key`

---

### 3. Gateway Status

**Test**: Verify Gateway is programmed and has an external IP.

```bash
# Check Gateway status
kubectl get gateway -n gateway-system

# Expected output:
# NAME           CLASS   ADDRESS        PROGRAMMED   AGE
# main-gateway   nginx   20.255.x.x     True         10m

# Check Gateway details
kubectl describe gateway main-gateway -n gateway-system
```

**Pass Criteria**:
- Gateway shows `PROGRAMMED: True`
- Gateway has an external IP address

---

### 4. ExternalDNS

**Test**: Verify ExternalDNS is running and detecting routes.

```bash
# Check ExternalDNS pods
kubectl get pods -n gateway-system -l app=external-dns

# Check ExternalDNS logs
kubectl logs -n gateway-system -l app=external-dns --tail=50

# Look for log lines like:
# "Desired change: CREATE api-pr-42.yt-summarizer.apps.ashleyhollis.com A"
```

**Pass Criteria**:
- Pod is Running
- Logs show Cloudflare API calls succeeding

---

### 5. Production Route

**Test**: Verify production API is reachable via new hostname.

```bash
# DNS resolution
dig api.yt-summarizer.apps.ashleyhollis.com +short
# Should return Gateway external IP

# HTTPS request
curl -v https://api.yt-summarizer.apps.ashleyhollis.com/health/live

# Expected:
# * SSL certificate verify ok.
# * subject: CN=*.yt-summarizer.apps.ashleyhollis.com
# {"status":"ok"}
```

**Pass Criteria**:
- DNS resolves to Gateway IP
- TLS certificate is valid (no warnings)
- Health endpoint returns 200

---

### 6. Preview Route (End-to-End)

**Test**: Create a PR and verify full preview flow.

1. **Open a PR** against `main` branch

2. **Wait for preview workflow** to complete

3. **Check PR comment** for preview URLs:
   - API: `https://api-pr-<N>.yt-summarizer.apps.ashleyhollis.com`
   - SWA: `https://<id>.azurestaticapps.net`

4. **Verify DNS record created**:
```bash
dig api-pr-<N>.yt-summarizer.apps.ashleyhollis.com +short
# Should return Gateway IP
```

5. **Verify HTTPS works**:
```bash
curl -v https://api-pr-<N>.yt-summarizer.apps.ashleyhollis.com/health/live
# Should return 200 with valid TLS
```

6. **Verify SWA can call API**:
   - Open SWA preview URL in browser
   - Check browser console for CORS errors
   - Verify API calls succeed

**Pass Criteria**:
- DNS record created within 2 minutes
- HTTPS works with wildcard certificate
- SWA preview can call API without CORS errors

---

### 7. Preview Cleanup

**Test**: Close PR and verify cleanup.

1. **Close the PR**

2. **Wait for cleanup workflow** (up to 5 minutes)

3. **Verify namespace deleted**:
```bash
kubectl get namespace preview-pr-<N>
# Should return: Error from server (NotFound)
```

4. **Verify DNS record removed** (up to 10 minutes):
```bash
dig api-pr-<N>.yt-summarizer.apps.ashleyhollis.com +short
# Should return empty (NXDOMAIN)
```

5. **Check Cloudflare dashboard**:
   - Record should no longer exist

**Pass Criteria**:
- Namespace deleted
- DNS record removed
- No orphaned resources

---

### 8. Auth0 BFF Flow

**Test**: Verify authentication works with new hostnames.

1. **Initiate login**:
```bash
# Open in browser (will redirect to Auth0)
open "https://api-pr-<N>.yt-summarizer.apps.ashleyhollis.com/api/auth/login?returnTo=https://<swa-preview>.azurestaticapps.net"
```

2. **Complete Auth0 login**

3. **Verify redirect** back to SWA preview

4. **Check session cookie**:
   - Open browser DevTools → Application → Cookies
   - Verify `session` cookie exists on API domain
   - Verify cookie attributes: `HttpOnly`, `Secure`, `SameSite=None`

5. **Call protected endpoint**:
```bash
# From SWA preview, make authenticated request
# Should receive user data, not 401
```

**Pass Criteria**:
- Login redirects to Auth0
- Callback sets session cookie
- SWA preview can make authenticated API calls

---

### 9. No nip.io/sslip.io References

**Test**: Verify no legacy DNS references remain.

```bash
# Search codebase
cd /path/to/yt-summarizer
grep -r "nip\.io\|sslip\.io\|xip\.io" . \
  --include="*.yaml" \
  --include="*.yml" \
  --include="*.ts" \
  --include="*.py" \
  --include="*.md" \
  | grep -v "specs/003-preview-dns-cloudflare"

# Should return empty (no matches outside the spec)
```

**Pass Criteria**: No matches in workflows, manifests, or code.

---

## Troubleshooting Commands

### Certificate Issues

```bash
# Check cert-manager logs
kubectl logs -n cert-manager deploy/cert-manager -f

# Check certificate events
kubectl describe certificate yt-summarizer-wildcard -n gateway-system

# Check challenge status
kubectl get challenges -A
kubectl describe challenge <name> -n gateway-system
```

### DNS Issues

```bash
# Check ExternalDNS logs
kubectl logs -n gateway-system -l app=external-dns -f

# Check what ExternalDNS sees
kubectl get httproute -A

# Verify Cloudflare API access
kubectl exec -n gateway-system deploy/external-dns -- \
  curl -H "Authorization: Bearer $CF_API_TOKEN" \
  https://api.cloudflare.com/client/v4/zones
```

### Gateway Issues

```bash
# Check NGINX Gateway Fabric logs
kubectl logs -n gateway-system deploy/ngf-nginx-gateway-fabric -f

# Check Gateway status
kubectl describe gateway main-gateway -n gateway-system

# Check HTTPRoute attachment
kubectl describe httproute api-route -n preview-pr-<N>
```

### CORS Issues

```bash
# Check CORS headers
curl -v -X OPTIONS \
  -H "Origin: https://example.azurestaticapps.net" \
  -H "Access-Control-Request-Method: GET" \
  https://api-pr-<N>.yt-summarizer.apps.ashleyhollis.com/api/auth/me

# Look for:
# Access-Control-Allow-Origin: https://example.azurestaticapps.net
# Access-Control-Allow-Credentials: true
```

---

## Success Summary

| Check | Status | Notes |
|-------|--------|-------|
| DNS delegation | ⬜ | |
| Wildcard certificate | ⬜ | |
| Gateway programmed | ⬜ | |
| ExternalDNS running | ⬜ | |
| Production route | ⬜ | |
| Preview route E2E | ⬜ | |
| Preview cleanup | ⬜ | |
| Auth0 BFF flow | ⬜ | |
| No legacy DNS refs | ⬜ | |

**All checks must pass before feature is considered complete.**
