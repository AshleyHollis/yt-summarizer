# Design: Preview DNS / Cloudflare / cert-manager

> **Feature ID**: F003 | **Status**: Complete | **Milestone**: M2

---

## Overview

Replace NGINX Ingress + HTTP-01 certificates + nip.io DNS with a Gateway API stack: NGINX Gateway Fabric (v2.3.0) handles TLS termination using a single per-app wildcard certificate issued by cert-manager DNS-01 via Cloudflare. ExternalDNS watches HTTPRoutes and manages Cloudflare A records automatically. All environments (prod, staging, every PR preview) share one Gateway in `gateway-system` with no per-environment infrastructure duplication.

---

## Architecture

```
Cloudflare DNS zone: ashleyhollis.com
  └── apps.ashleyhollis.com (delegated)
       └── *.yt-summarizer.apps.ashleyhollis.com → 20.187.186.135 (Gateway LB IP)

AKS Cluster
  gateway-system namespace
  ├── GatewayClass: nginx (controller: gateway.nginx.org/nginx-gateway-controller)
  ├── Gateway: main-gateway
  │     listeners:
  │       HTTPS :443  hostname *.yt-summarizer.apps.ashleyhollis.com  → Secret yt-summarizer-wildcard-tls
  │       HTTP  :80   hostname *.yt-summarizer.apps.ashleyhollis.com  → redirect to HTTPS
  ├── Certificate: yt-summarizer-wildcard  (cert-manager → Let's Encrypt DNS-01 via Cloudflare)
  │     dnsNames: [*.yt-summarizer.apps.ashleyhollis.com, yt-summarizer.apps.ashleyhollis.com]
  │     Secret: yt-summarizer-wildcard-tls
  ├── ExternalDNS deployment
  │     --source=gateway-httproute
  │     --provider=cloudflare
  │     --domain-filter=apps.ashleyhollis.com
  │     --policy=sync  (deletes records when HTTPRoute removed)
  │     --registry=txt  --txt-owner-id=yt-summarizer-aks
  └── ExternalSecret: cloudflare-api-token  (from azure-keyvault-cluster)

App namespaces (e.g. yt-summarizer, yt-summarizer-stg, preview-pr-42)
  └── HTTPRoute: api-route
        parentRef: gateway-system/main-gateway
        hostname: api[-pr-N|-stg].yt-summarizer.apps.ashleyhollis.com
        backendRef: api:80
```

---

### Component Responsibilities

| Component | Responsibility |
|-----------|---------------|
| NGINX Gateway Fabric | TLS termination, HTTP→HTTPS redirect, hostname-based routing to backend services |
| ExternalDNS | Creates/deletes Cloudflare A records when HTTPRoutes are created/deleted |
| cert-manager (DNS-01) | Issues and auto-renews `*.yt-summarizer.apps.ashleyhollis.com` wildcard certificate |
| Argo CD ApplicationSet | Creates/deletes preview namespace + resources on PR open/close |
| GitHub Actions (compute-preview-urls) | Outputs the new hostname pattern for use in PR comments and kustomize patches |

---

## Data Flow

### PR Preview Creation

```
Developer opens PR
  → GitHub Actions: preview.yml
  → compute-preview-urls: outputs api-pr-N.yt-summarizer.apps.ashleyhollis.com
  → update-preview-overlay: generates HTTPRoute patch with PR hostname
  → git push overlay to main
  → Argo CD detects overlay change
  → Creates namespace preview-pr-N + HTTPRoute api-route
  → ExternalDNS detects new HTTPRoute
  → Creates Cloudflare A record api-pr-N.yt-summarizer.apps.ashleyhollis.com → 20.187.186.135
  → DNS propagates (<5 min)
  → HTTPS accessible using existing wildcard cert (no cert issuance)
  → post-preview-comment: posts PR comment with URLs
```

### PR Cleanup

```
Developer closes/merges PR
  → GitHub Actions: preview-cleanup.yml
  → Argo CD ApplicationSet: deletes preview-pr-N Application
  → Namespace preview-pr-N deleted (including HTTPRoute)
  → ExternalDNS detects HTTPRoute deletion
  → Deletes Cloudflare A record (<10 min)
```

---

## Technical Decisions

| Decision | Options Considered | Choice | Rationale |
|----------|-------------------|--------|-----------|
| Gateway controller | Envoy Gateway, Contour, Istio, Traefik, NGINX GF | **NGINX Gateway Fabric v2.3.0** | Official F5/NGINX; mature Helm chart; migration path from NGINX Ingress |
| Certificate scope | Per-environment cert, Per-app wildcard | **Per-app wildcard** `*.yt-summarizer.apps.ashleyhollis.com` | Single cert eliminates rate limit risk; covers all current and future envs |
| DNS challenge | HTTP-01, DNS-01 | **DNS-01** | Required for wildcard; HTTP-01 cannot issue wildcards |
| ExternalDNS source | `--source=ingress`, `--source=gateway-httproute` | **`gateway-httproute`** | Direct Gateway API integration; no annotations needed |
| DNS record type | A record, CNAME | **A record** | Simplest; works with Cloudflare Free; direct IP assignment |
| Gateway API CRDs | Standard channel v1.2.0, Experimental channel v1.2.0 | **Experimental v1.2.0** | NGINX GF v2.3.0 requires BackendTLSPolicy (experimental CRD) |
| Namespace for shared resources | `kube-system`, `default`, `gateway-system` | **`gateway-system`** | Clean separation of platform infra from app workloads |
| Auth CORS | Wildcard `*`, regex allowlist, enumerated origins | **Regex allowlist** | Allows `*.azurestaticapps.net` SWA previews while blocking others |

---

## File Structure

| File | Action | Purpose |
|------|--------|---------|
| `k8s/argocd/gateway-api/namespace.yaml` | Create | `gateway-system` namespace |
| `k8s/argocd/gateway-api/gateway-crds.yaml` | Create | Gateway API experimental CRDs v1.2.0 |
| `k8s/argocd/gateway-api/nginx-gateway-fabric.yaml` | Create | NGINX GF Helm chart Argo CD Application |
| `k8s/argocd/gateway-api/gatewayclass.yaml` | Create | GatewayClass `nginx` |
| `k8s/argocd/gateway-api/gateway.yaml` | Create | Gateway `main-gateway` with HTTPS+HTTP listeners |
| `k8s/argocd/gateway-api/externalsecret-cloudflare.yaml` | Create | ExternalSecret for Cloudflare API token |
| `k8s/argocd/gateway-api/kustomization.yaml` | Create | Kustomize manifest for gateway-api app |
| `k8s/argocd/cert-manager/clusterissuer-cloudflare.yaml` | Create | DNS-01 ClusterIssuer using Cloudflare |
| `k8s/argocd/cert-manager/kustomization.yaml` | Update | Include new ClusterIssuer |
| `k8s/argocd/external-dns/rbac.yaml` | Create | ServiceAccount + RBAC for ExternalDNS |
| `k8s/argocd/external-dns/deployment.yaml` | Create | ExternalDNS Deployment |
| `k8s/argocd/external-dns/kustomization.yaml` | Create | Kustomize manifest for external-dns app |
| `k8s/argocd/certificates/yt-summarizer-wildcard.yaml` | Create | Wildcard Certificate resource |
| `k8s/argocd/certificates/kustomization.yaml` | Create | Kustomize manifest for certificates app |
| `k8s/argocd/infra-apps.yaml` | Update | Add gateway-api, external-dns, certificates apps |
| `k8s/base/api-httproute.yaml` | Create | Production HTTPRoute template |
| `k8s/base/kustomization.yaml` | Update | Include HTTPRoute, remove Ingress |
| `k8s/base-preview/api-httproute.yaml` | Create | Preview HTTPRoute template |
| `k8s/base-preview/kustomization.yaml` | Update | Include HTTPRoute, remove Ingress |
| `k8s/overlays/prod/patches/httproute-patch.yaml` | Create | Production hostname patch |
| `k8s/overlays/prod/kustomization.yaml` | Update | Include HTTPRoute patch |
| `k8s/overlays/preview/patches/httproute-patch.yaml` | Create | Preview hostname patch template |
| `.github/actions/compute-preview-urls/action.yml` | Update | New hostname scheme; remove sslip.io logic |
| `.github/workflows/preview.yml` | Update | Remove `get-aks-ingress-ip` step |
| `services/api/src/api/routes/auth.py` | Create | Auth0 BFF endpoints |
| `services/api/src/api/main.py` | Update | Register auth routes; CORS with regex allowlist |
| `infra/terraform/modules/auth0/main.tf` | Create | Auth0 Terraform module |
| `docs/runbooks/cloudflare-setup.md` | Create | Cloudflare setup runbook |
| `docs/runbooks/cert-manager-dns01-troubleshooting.md` | Create | cert-manager DNS-01 runbook |
| `docs/runbooks/external-dns-troubleshooting.md` | Create | ExternalDNS troubleshooting runbook |
| `docs/runbooks/gateway-troubleshooting.md` | Create | Gateway/HTTPRoute troubleshooting runbook |

---

## Interfaces

### Auth0 BFF API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/login` | GET | Initiates Auth0 login; accepts `returnTo` query param |
| `/api/auth/callback/auth0` | GET | Handles Auth0 callback; sets session cookie |
| `/api/auth/logout` | POST | Clears session cookie (local logout) |
| `/api/auth/me` | GET | Returns current user info if authenticated |

### CORS Configuration

```python
ALLOWED_ORIGINS = [
    "https://web.yt-summarizer.apps.ashleyhollis.com",  # Production web
    r"https://.*\.azurestaticapps\.net",                # SWA previews (regex)
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)
```

### Hostname Scheme

| Environment | Hostname |
|-------------|---------|
| Production | `api.yt-summarizer.apps.ashleyhollis.com` |
| Staging | `api-stg.yt-summarizer.apps.ashleyhollis.com` |
| PR Preview | `api-pr-<N>.yt-summarizer.apps.ashleyhollis.com` |

---

## Error Handling

| Scenario | Strategy | Impact |
|----------|----------|--------|
| Cloudflare API unavailable | ExternalDNS retries; existing records remain functional | DNS creation/deletion delayed; no outage |
| cert-manager DNS-01 challenge stale | Delete cert + order + challenges; recreate Certificate | <5 min cert re-issuance; no traffic impact |
| ExternalDNS CrashLoopBackOff | Fix flag syntax; redeploy | DNS not managed until pod healthy |
| Gateway LoadBalancer IP mismatch | Update Cloudflare wildcard A record to new IP | Update DNS manually; propagation <5 min |
| Two PRs opened simultaneously | Independent HTTPRoutes + DNS records; same wildcard cert | No conflict |

---

## Edge Cases

- **Concurrent PRs**: Each gets independent HTTPRoute + DNS A record; wildcard cert shared without conflict
- **Cloudflare API unavailable**: ExternalDNS retries with backoff; cert-manager DNS-01 retries; existing records intact
- **HTTPRoute deleted before namespace**: ExternalDNS still removes DNS via TXT ownership registry (`--policy=sync`)
- **Certificate expiry/renewal**: cert-manager auto-renews 30 days before expiry; HTTPRoutes unaffected during renewal
- **ExternalSecret missing ClusterSecretStore**: Use `azure-keyvault-cluster` (not `azure-secret-store`)

---

## Security Considerations

- Cloudflare API token: stored in Azure Key Vault; fetched via ExternalSecret; never committed to repo
- CORS: strict origin allowlist with regex for `*.azurestaticapps.net`; wildcard `*` never used for credentialed requests
- Session cookies: HttpOnly, Secure, SameSite=None for cross-origin preview support
- ExternalDNS scope: `--domain-filter=apps.ashleyhollis.com` prevents modification of other zones
- Cloudflare token scope: Zone:Read + DNS:Edit on `ashleyhollis.com` only (least privilege)

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| NGINX Gateway Fabric | v2.3.0 | Gateway API controller |
| ExternalDNS | v0.14.0 | Automatic DNS record management |
| cert-manager | Existing | Certificate issuance and renewal |
| Gateway API CRDs | v1.2.0 experimental | HTTPRoute, Gateway, GatewayClass resources |
| Argo CD | Existing | GitOps sync |
