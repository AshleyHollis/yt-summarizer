# Research: Preview DNS/TLS Migration to Cloudflare

**Feature**: 003-preview-dns-cloudflare  
**Date**: January 11, 2026  
**Status**: Complete

---

## Research Summary

This document captures research findings for migrating from nip.io/sslip.io to apps.ashleyhollis.com with Cloudflare, Gateway API, and per-app wildcard certificates.

---

## 1. Gateway API Controller Selection

### Decision: NGINX Gateway Fabric

**Rationale**:
- Official F5/NGINX implementation with strong community support
- Mature and production-ready (v1.5.x as of Jan 2026)
- Comprehensive Gateway API v1.2.0 support
- Easy migration path from existing NGINX Ingress Controller
- Helm chart available: `nginx-gateway-fabric/nginx-gateway-fabric`

**Alternatives Considered**:

| Controller | Rejected Because |
|------------|-----------------|
| Envoy Gateway | Newer project, less documentation, smaller community |
| Contour | Different operational model, less familiar |
| Istio Gateway | Overkill for single-app cluster, complex |
| Traefik | Less Gateway API feature coverage |

**Installation Method**:
```bash
helm repo add nginx-gateway-fabric https://nginx.github.io/nginx-gateway-fabric
helm install ngf nginx-gateway-fabric/nginx-gateway-fabric \
  --namespace gateway-system \
  --create-namespace
```

---

## 2. Gateway API CRD Version

### Decision: v1.2.0 (Standard Channel)

**Rationale**:
- Latest stable release with full HTTPRoute support
- Includes ReferenceGrant for cross-namespace certificate references
- Compatible with cert-manager and ExternalDNS

**CRD Installation**:
```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.0/standard-install.yaml
```

---

## 3. ExternalDNS Gateway API Support

### Decision: Use `--source=gateway-httproute`

**Rationale**:
- ExternalDNS v0.14.0+ natively supports Gateway API HTTPRoute as a source
- Automatically creates DNS records based on HTTPRoute hostnames
- Works with Cloudflare provider out of the box

**Configuration**:
```yaml
args:
  - --source=gateway-httproute
  - --provider=cloudflare
  - --domain-filter=apps.ashleyhollis.com
  - --policy=sync
  - --registry=txt
  - --txt-owner-id=yt-summarizer-aks
```

**Key Flags**:
- `--policy=sync`: Deletes records when HTTPRoutes are removed
- `--registry=txt`: Uses TXT records to track ownership
- `--txt-owner-id`: Prevents conflicts with other ExternalDNS instances
- `--domain-filter`: Limits management to `apps.ashleyhollis.com`

---

## 4. Cloudflare API Token Scopes

### Decision: Minimal Scopes for DNS Management

**Required Permissions**:

| Permission | Scope | Used By |
|------------|-------|---------|
| Zone:Read | `apps.ashleyhollis.com` | cert-manager (DNS-01), ExternalDNS |
| DNS:Edit | `apps.ashleyhollis.com` | cert-manager (DNS-01), ExternalDNS |

**Token Creation Steps**:
1. Cloudflare Dashboard → My Profile → API Tokens
2. Create Token → Custom Token
3. Permissions:
   - Zone / Zone / Read
   - Zone / DNS / Edit
4. Zone Resources: Include → Specific zone → `ashleyhollis.com`
5. Copy token and store in Azure Key Vault

**Kubernetes Secret**:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cloudflare-api-token
  namespace: gateway-system
type: Opaque
stringData:
  api-token: <CF_API_TOKEN>
```

In production, this secret is populated via ExternalSecret from Azure Key Vault.

---

## 5. cert-manager DNS-01 with Cloudflare

### Decision: ClusterIssuer with Cloudflare DNS-01 Solver

**Rationale**:
- DNS-01 is required for wildcard certificates
- HTTP-01 cannot issue wildcards
- Cloudflare integration is well-documented and stable

**ClusterIssuer Configuration**:
```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-cloudflare
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: ops@ashleyhollis.com
    privateKeySecretRef:
      name: letsencrypt-cloudflare-key
    solvers:
      - dns01:
          cloudflare:
            apiTokenSecretRef:
              name: cloudflare-api-token
              key: api-token
        selector:
          dnsZones:
            - "apps.ashleyhollis.com"
```

**Wildcard Certificate**:
```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: yt-summarizer-wildcard
  namespace: gateway-system
spec:
  secretName: yt-summarizer-wildcard-tls
  issuerRef:
    name: letsencrypt-cloudflare
    kind: ClusterIssuer
  dnsNames:
    - "*.yt-summarizer.apps.ashleyhollis.com"
    - "yt-summarizer.apps.ashleyhollis.com"
```

**Why Include Base Domain**:
Including `yt-summarizer.apps.ashleyhollis.com` alongside the wildcard allows the Gateway to handle both `api.yt-summarizer.apps.ashleyhollis.com` and potential future bare-domain use.

---

## 6. Auth0 Wildcard Callback URLs

### Decision: Auth0 Supports Wildcards in Allowed Callback URLs

**Findings**:
- Auth0 allows wildcard patterns in "Allowed Callback URLs" for non-production tenants
- Pattern: `https://api-pr-*.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0`
- For production tenants, may need to enumerate specific URLs or use tenant-level wildcard

**Recommended Configuration**:
```
# Allowed Callback URLs
https://api.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0
https://api-stg.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0
https://api-pr-*.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0

# Allowed Web Origins
https://web.yt-summarizer.apps.ashleyhollis.com
https://*.azurestaticapps.net
```

**Fallback** (if wildcards not supported):
- GitHub Action adds callback URL on preview creation
- GitHub Action removes callback URL on preview cleanup
- Requires Auth0 Management API token

---

## 7. SWA Preview URL Format

### Decision: Use SWA-Generated Preview URLs

**Findings**:
- Azure Static Web Apps generates preview URLs automatically for PR deployments
- Format: `https://<random>-<environment>.azurestaticapps.net`
- The exact URL is returned by the SWA deploy action output

**CORS Implications**:
- Cannot predict exact SWA preview hostname in advance
- Must use regex pattern: `https://.*\.azurestaticapps\.net`
- Or retrieve from deploy action and configure dynamically

**Recommendation**:
- Accept `*.azurestaticapps.net` in CORS for development/preview
- For production, pin to the specific production SWA domain

---

## 8. Gateway Certificate Cross-Namespace Reference

### Decision: Use ReferenceGrant for Certificate Access

**Problem**:
Gateway in `gateway-system` needs to reference HTTPRoutes in app namespaces.

**Solution**:
Gateway API v1.2.0 includes ReferenceGrant CRD. However, for our use case:
- Certificate Secret is in `gateway-system` (same as Gateway) → no ReferenceGrant needed
- HTTPRoutes in app namespaces reference the Gateway → allowed by default with `allowedRoutes.namespaces.from: All`

**No ReferenceGrant Required** for our architecture.

---

## 9. DNS Propagation Timing

### Findings

| Operation | Expected Time |
|-----------|---------------|
| ExternalDNS sync interval | 1 minute (default) |
| Cloudflare DNS propagation | < 5 minutes (typical) |
| cert-manager DNS-01 verification | 1-2 minutes |
| Total preview availability | < 5 minutes |

**Optimization**:
- Set ExternalDNS `--interval=30s` for faster preview creation
- Cloudflare's global anycast network ensures fast propagation

---

## 10. Rollback Strategy

### Decision: Parallel Running Before Cutover

**Phase 1**: Deploy new infrastructure alongside existing
- Both Ingress and HTTPRoute serve traffic
- Existing nip.io/sslip.io hostnames continue working

**Phase 2**: Migrate previews first
- Lower risk, higher iteration velocity
- Easy to switch back if issues

**Phase 3**: Migrate production last
- Validate with staging first
- Keep old Ingress for quick rollback

**Phase 4**: Cleanup
- Remove old resources after 1 week of stable operation

---

## References

1. [Gateway API Documentation](https://gateway-api.sigs.k8s.io/)
2. [NGINX Gateway Fabric Installation](https://docs.nginx.com/nginx-gateway-fabric/installation/)
3. [ExternalDNS Gateway API Tutorial](https://kubernetes-sigs.github.io/external-dns/latest/tutorials/gateway-api/)
4. [cert-manager Cloudflare DNS-01](https://cert-manager.io/docs/configuration/acme/dns01/cloudflare/)
5. [Auth0 Allowed Callback URLs](https://auth0.com/docs/get-started/applications/application-settings#allowed-callback-urls)
