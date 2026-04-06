# Research: Preview DNS / Cloudflare / cert-manager

> **Feature ID**: F003 | **Status**: Complete | **Research Date**: 2026-01-11

---

## Executive Summary

Migrating from nip.io/sslip.io to `apps.ashleyhollis.com` with Cloudflare delegation, NGINX Gateway Fabric (Gateway API), per-app wildcard certificates (DNS-01), and ExternalDNS for automatic record management is fully viable on a single AKS cluster with Cloudflare Free tier. The approach eliminates Let's Encrypt rate limit risk and provides professional, predictable hostnames for all preview environments.

---

## External Research

### Best Practices

| Topic | Decision | Key Finding |
|-------|----------|-------------|
| Gateway API CRD version | v1.2.0 experimental channel | Required for BackendTLSPolicy; standard channel lacks it |
| Gateway controller | NGINX Gateway Fabric v2.3.0 | Official F5/NGINX implementation, Helm chart available |
| ExternalDNS source | `--source=gateway-httproute` | Native Gateway API support in v0.14.0+; `--policy=sync` handles deletion |
| Cloudflare API token scopes | Zone:Read + DNS:Edit on `ashleyhollis.com` | Minimal scopes; both needed by cert-manager and ExternalDNS |
| cert-manager DNS-01 | Cloudflare solver | Only validation method that supports wildcard certificates |
| Auth0 wildcard callbacks | Wildcards supported | `https://api-pr-*.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0` works |
| SWA preview URL | `*.azurestaticapps.net` | Cannot predict exact domain; CORS regex required |

### Prior Art

The team already operates:
- cert-manager with HTTP-01 (existing, being extended to DNS-01)
- NGINX Ingress Controller (being replaced by NGINX Gateway Fabric)
- Argo CD ApplicationSet for preview lifecycle management (preserved)

### Pitfalls to Avoid

| Pitfall | Mitigation |
|---------|------------|
| `--cloudflare-proxied=false` flag syntax crash | Remove `=false` — boolean flags don't use `=value` syntax |
| ExternalSecret references wrong ClusterSecretStore | Use `azure-keyvault-cluster` (not `azure-secret-store`) |
| Standard CRDs missing BackendTLSPolicy | Install experimental CRDs: `experimental-install.yaml` |
| Multiple ExternalDNS instances fighting over records | Set unique `--txt-owner-id=yt-summarizer-aks` |
| ReferenceGrant needed for cross-namespace cert access | Not needed: cert Secret and Gateway are both in `gateway-system` |
| Certificate stuck in Issuing (stale Cloudflare challenge) | Delete cert + certificaterequest + order + challenges; recreate |

---

## Codebase Analysis

### Existing Patterns

| Pattern | File | Notes |
|---------|------|-------|
| Argo CD ApplicationSet for preview lifecycle | `k8s/argocd/preview-appset.yaml` | Preserved; drives namespace creation/deletion |
| ExternalSecret → Azure Key Vault | `k8s/argocd/cert-manager/` | ClusterSecretStore: `azure-keyvault-cluster` |
| Kustomize overlays (base / base-preview / overlays) | `k8s/` | HTTPRoute patches follow same pattern as old Ingress patches |
| GitHub Action: compute-preview-urls | `.github/actions/compute-preview-urls/action.yml` | Updated hostname scheme only |
| CI preview workflow | `.github/workflows/preview.yml` | Removed `get-aks-ingress-ip` step (no longer needed) |

### Dependencies

| Tool | Version | Purpose |
|------|---------|---------|
| cert-manager | Existing | Extended with DNS-01 ClusterIssuer |
| NGINX Gateway Fabric | v2.3.0 | Replaces NGINX Ingress Controller |
| ExternalDNS | v0.14.0 | Automatic DNS record management |
| Gateway API CRDs | v1.2.0 experimental | HTTPRoute, GatewayClass, Gateway resources |
| Argo CD | Existing | GitOps sync for new applications |

### Constraints

- Single LoadBalancer IP: `20.187.186.135` (Azure assigned; differs from existing nginx-ingress IP)
- Cloudflare Free tier: sufficient for Zone:Read + DNS:Edit API
- Let's Encrypt: rate limit on cert issuance is the primary driver for wildcard strategy

---

## Quality Commands

| Type | Command | Source |
|------|---------|--------|
| Manifest validation | `kubectl kustomize k8s/overlays/prod` | k8s/ structure |
| Cert status | `kubectl get certificate -n gateway-system` | Live cluster |
| DNS check | `nslookup api-pr-N.yt-summarizer.apps.ashleyhollis.com` | Terminal |
| TLS check | `curl -vI https://api-pr-N.yt-summarizer.apps.ashleyhollis.com` | Terminal |
| ExternalDNS logs | `kubectl logs -n gateway-system deployment/external-dns --tail=50` | Live cluster |

---

## Verification Tooling

| Tool | Command/Value | Detected From |
|------|--------------|---------------|
| Manifest dry-run | `kubectl kustomize {overlay-path}` | k8s/ directory |
| Gateway status | `kubectl get gateway -n gateway-system main-gateway` | Cluster |
| Health endpoint | `/health/live`, `/health/ready` | API service |
| Browser automation | Playwright | apps/web tests |

**Project Type**: Infrastructure + API  
**Verification Strategy**: kubectl/curl checks against live cluster; create real PR to exercise full end-to-end flow

---

## Related Specs

| Spec | Relationship | May Need Update |
|------|-------------|----------------|
| F001 (if exists) | Preview infrastructure base | Possible hostname reference updates |
| F002 (if exists) | CI/CD pipeline | Hostname scheme change affects workflow outputs |

---

## Feasibility Assessment

| Aspect | Assessment | Notes |
|--------|-----------|-------|
| Technical Viability | High | All components production-ready; implemented and validated |
| Effort Estimate | L | 77 tasks across 8 phases; completed in ~1 day |
| Risk Level | Low (post-implementation) | Six issues encountered and resolved; documented in IMPLEMENTATION_COMPLETE.md |

---

## Sources

1. [Gateway API Documentation](https://gateway-api.sigs.k8s.io/)
2. [NGINX Gateway Fabric Installation](https://docs.nginx.com/nginx-gateway-fabric/installation/)
3. [ExternalDNS Gateway API Tutorial](https://kubernetes-sigs.github.io/external-dns/latest/tutorials/gateway-api/)
4. [cert-manager Cloudflare DNS-01](https://cert-manager.io/docs/configuration/acme/dns01/cloudflare/)
5. [Auth0 Allowed Callback URLs](https://auth0.com/docs/get-started/applications/application-settings#allowed-callback-urls)
6. Source spec: `specs/003-preview-dns-cloudflare/research.md`
