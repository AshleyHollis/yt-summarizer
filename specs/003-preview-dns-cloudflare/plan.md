# Implementation Plan: Preview DNS/TLS Migration to Cloudflare

**Branch**: `003-preview-dns-cloudflare` | **Date**: January 11, 2026 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/003-preview-dns-cloudflare/spec.md`

---

## Summary

Migrate preview DNS/TLS infrastructure from nip.io/sslip.io to `apps.ashleyhollis.com` using Cloudflare delegation, Gateway API (NGINX Gateway Fabric), per-app wildcard certificates (DNS-01), and ExternalDNS for automatic DNS record management. This eliminates Let's Encrypt rate limit issues and provides a professional hostname scheme.

---

## Technical Context

**Language/Version**: Python 3.11 (API), YAML (Kubernetes manifests), TypeScript (GitHub Actions)  
**Primary Dependencies**: cert-manager, NGINX Gateway Fabric, ExternalDNS, Kustomize, ArgoCD  
**Storage**: Azure SQL (existing), Cloudflare DNS API  
**Testing**: Playwright (E2E), pytest (API), curl/kubectl (infrastructure validation)  
**Target Platform**: AKS (single-node, cost-optimized)  
**Project Type**: Infrastructure/DevOps + minor API changes  
**Performance Goals**: Preview environments accessible within 5 minutes of PR creation  
**Constraints**: Single AKS cluster, Cloudflare Free tier, Let's Encrypt rate limits  
**Scale/Scope**: One app (`yt-summarizer`), extensible to multiple apps

---

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| IV.4 GitOps deployments | ✅ PASS | All manifests in `k8s/`; Argo CD syncs from overlays |
| V.1 No secrets in repo | ✅ PASS | Cloudflare API token stored in ExternalSecret/KeyVault |
| VI.1 Simplicity first | ✅ PASS | Using standard Gateway API + ExternalDNS patterns |
| VI.4 Aspire for dev only | ✅ N/A | No Aspire changes required |
| VI.6 Migration-driven schema | ✅ N/A | No database schema changes |
| VII.2 Feature compliance | ✅ PASS | Constitution referenced; complexity justified |

**No violations.** Proceeding to Phase 0.

---

## Project Structure

### Documentation (this feature)

```text
specs/003-preview-dns-cloudflare/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output (Kubernetes resources)
├── quickstart.md        # Phase 1 output (validation steps)
├── contracts/           # Phase 1 output (API auth endpoints)
└── tasks.md             # Phase 2 output (/speckit.tasks command)
```

### Source Code (repository root)

```text
# Infrastructure changes
k8s/
├── argocd/
│   ├── cert-manager/
│   │   ├── clusterissuer-cloudflare.yaml   # NEW: DNS-01 issuer
│   │   └── kustomization.yaml              # Updated
│   ├── gateway-api/                         # NEW: Gateway controller
│   │   ├── gateway-crds.yaml
│   │   ├── nginx-gateway-fabric.yaml
│   │   ├── gateway.yaml
│   │   ├── gatewayclass.yaml
│   │   └── kustomization.yaml
│   ├── external-dns/                        # NEW: ExternalDNS
│   │   ├── deployment.yaml
│   │   ├── rbac.yaml
│   │   └── kustomization.yaml
│   └── certificates/                        # NEW: Per-app wildcard certs
│       ├── yt-summarizer-wildcard.yaml
│       └── kustomization.yaml
├── base/
│   └── api-httproute.yaml                   # NEW: HTTPRoute (replaces Ingress)
├── base-preview/
│   └── api-httproute.yaml                   # NEW: Preview HTTPRoute template
├── overlays/
│   ├── prod/
│   │   └── patches/httproute-patch.yaml     # NEW: Prod hostname
│   └── preview/
│       └── patches/httproute-patch.yaml     # NEW: Preview hostname (generated)

# Workflow changes
.github/
├── actions/
│   └── compute-preview-urls/
│       └── action.yml                       # Updated: new hostname scheme
├── workflows/
│   └── preview.yml                          # Updated: compute and deploy

# API changes (Auth0 BFF)
services/api/
└── src/api/
    ├── routes/
    │   └── auth.py                          # NEW: Auth routes
    └── main.py                              # Updated: CORS config

# Runbooks
docs/runbooks/
├── cloudflare-setup.md                      # NEW
├── gateway-troubleshooting.md               # NEW
├── cert-manager-dns01-troubleshooting.md    # NEW
└── external-dns-troubleshooting.md          # NEW
```

**Structure Decision**: Infrastructure-focused with minimal API changes. Follows existing `k8s/` conventions with new subdirectories for Gateway API and ExternalDNS components.

---

## Phase 0: Research

### Research Topics

| Topic | Status | Key Finding |
|-------|--------|-------------|
| Gateway API CRD versions | ✅ | Use v1.2.0 (stable channel) |
| NGINX Gateway Fabric installation | ✅ | Helm chart `nginx-gateway-fabric/nginx-gateway-fabric` |
| ExternalDNS Gateway API support | ✅ | Supported via `--source=gateway-httproute` |
| Cloudflare API token scopes | ✅ | Zone:Read, DNS:Edit on `apps.ashleyhollis.com` |
| cert-manager DNS-01 Cloudflare | ✅ | Use `cloudflare` solver with API token secret |
| Auth0 wildcard callback URLs | ✅ | Auth0 supports wildcards in callback URLs |
| SWA preview URL format | ✅ | `https://<deployment-token>-<environment>.azurestaticapps.net` |

### Key Decisions

1. **Gateway Controller**: NGINX Gateway Fabric (Helm chart v1.5.x)
   - Rationale: Official F5/NGINX support, mature, widely adopted
   - Alternatives rejected: Envoy Gateway (newer, less documentation), Contour (different paradigm)

2. **Wildcard Certificate Scope**: `*.yt-summarizer.apps.ashleyhollis.com`
   - Rationale: Single cert covers all environments (prod, staging, previews)
   - Alternative rejected: Separate cert per environment (unnecessary complexity)

3. **ExternalDNS Source**: `gateway-httproute`
   - Rationale: Direct integration with Gateway API, no annotation parsing
   - Alternative rejected: Ingress source (we're migrating away from Ingress)

4. **DNS Record Type**: A records pointing to Gateway external IP
   - Rationale: Simplest approach, works with Cloudflare Free
   - Alternative rejected: CNAME (requires additional DNS setup)

5. **Namespace for Shared Resources**: `gateway-system`
   - Rationale: Separates platform infrastructure from app workloads
   - Contains: Gateway, GatewayClass, wildcard certificates, ExternalDNS

---

## Phase 1: Design

### Component Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Cloudflare DNS                                │
│                   apps.ashleyhollis.com zone                         │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ *.yt-summarizer.apps.ashleyhollis.com → Gateway External IP  │   │
│  │ (A records managed by ExternalDNS)                           │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        AKS Cluster                                   │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │               gateway-system namespace                        │   │
│  │  ┌─────────────┐  ┌─────────────────┐  ┌──────────────────┐  │   │
│  │  │ NGINX       │  │ ExternalDNS     │  │ Wildcard Cert    │  │   │
│  │  │ Gateway     │◄─┤ (watches        │  │ *.yt-summarizer  │  │   │
│  │  │ Fabric      │  │  HTTPRoutes)    │  │ .apps.ashley...  │  │   │
│  │  └──────┬──────┘  └─────────────────┘  └──────────────────┘  │   │
│  │         │                                                     │   │
│  │         │ Gateway (TLS termination using wildcard cert)       │   │
│  │         ▼                                                     │   │
│  │  ┌─────────────────────────────────────────────────────────┐ │   │
│  │  │                     HTTPRoutes                           │ │   │
│  │  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐    │ │   │
│  │  │  │ api.yt-...  │ │ api-stg...  │ │ api-pr-N.yt-... │    │ │   │
│  │  │  │ (prod)      │ │ (staging)   │ │ (preview)       │    │ │   │
│  │  │  └──────┬──────┘ └──────┬──────┘ └────────┬────────┘    │ │   │
│  │  │         │               │                 │              │ │   │
│  └──────────────────────────────────────────────────────────────┘   │
│           │               │                 │                        │
│           ▼               ▼                 ▼                        │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────────────┐    │
│  │ yt-summ    │ │ yt-summ-stg │ │ preview-pr-N namespace      │    │
│  │ namespace  │ │ namespace   │ │  ┌─────────┐ ┌───────────┐  │    │
│  │ (prod)     │ │ (staging)   │ │  │ API svc │ │ Workers   │  │    │
│  └─────────────┘ └─────────────┘ │  └─────────┘ └───────────┘  │    │
│                                  └─────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

### Hostname Scheme

| Environment | Hostname Pattern | Example |
|-------------|-----------------|---------|
| Production | `api.yt-summarizer.apps.ashleyhollis.com` | `https://api.yt-summarizer.apps.ashleyhollis.com` |
| Staging | `api-stg.yt-summarizer.apps.ashleyhollis.com` | `https://api-stg.yt-summarizer.apps.ashleyhollis.com` |
| Preview | `api-pr-<N>.yt-summarizer.apps.ashleyhollis.com` | `https://api-pr-42.yt-summarizer.apps.ashleyhollis.com` |

### Kubernetes Resources

#### 1. GatewayClass

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: nginx
spec:
  controllerName: gateway.nginx.org/nginx-gateway-controller
```

#### 2. Gateway

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: main-gateway
  namespace: gateway-system
spec:
  gatewayClassName: nginx
  listeners:
    - name: https
      port: 443
      protocol: HTTPS
      hostname: "*.yt-summarizer.apps.ashleyhollis.com"
      tls:
        mode: Terminate
        certificateRefs:
          - name: yt-summarizer-wildcard-tls
            kind: Secret
      allowedRoutes:
        namespaces:
          from: All
    - name: http
      port: 80
      protocol: HTTP
      hostname: "*.yt-summarizer.apps.ashleyhollis.com"
      allowedRoutes:
        namespaces:
          from: All
```

#### 3. HTTPRoute (Preview Template)

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: api-route
  namespace: preview-pr-<N>
spec:
  parentRefs:
    - name: main-gateway
      namespace: gateway-system
  hostnames:
    - "api-pr-<N>.yt-summarizer.apps.ashleyhollis.com"
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
      backendRefs:
        - name: api
          port: 80
```

#### 4. ClusterIssuer (DNS-01 Cloudflare)

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

#### 5. Wildcard Certificate

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

#### 6. ExternalDNS Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: external-dns
  namespace: gateway-system
spec:
  template:
    spec:
      containers:
        - name: external-dns
          image: registry.k8s.io/external-dns/external-dns:v0.14.0
          args:
            - --source=gateway-httproute
            - --provider=cloudflare
            - --cloudflare-proxied=false
            - --domain-filter=apps.ashleyhollis.com
            - --policy=sync
            - --registry=txt
            - --txt-owner-id=yt-summarizer-aks
          env:
            - name: CF_API_TOKEN
              valueFrom:
                secretKeyRef:
                  name: cloudflare-api-token
                  key: api-token
```

### Auth0 BFF Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/login` | GET | Initiates Auth0 login, accepts `returnTo` query param |
| `/api/auth/callback/auth0` | GET | Handles Auth0 callback, sets session cookie |
| `/api/auth/logout` | POST | Clears session cookie (local logout) |
| `/api/auth/me` | GET | Returns current user info if authenticated |

### CORS Configuration

```python
# Dynamic origin allowlist
ALLOWED_ORIGINS = [
    "https://web.yt-summarizer.apps.ashleyhollis.com",  # Production web
    r"https://.*\.azurestaticapps\.net",                # SWA previews (regex)
]

# CORS settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)
```

---

## Migration Plan

### Phase A: Infrastructure Setup (No Traffic Cutover)

1. Create DNS records in existing Cloudflare zone `ashleyhollis.com` for `apps.ashleyhollis.com` (wildcard A record `*.yt-summarizer.apps` → Gateway IP)
2. Create Cloudflare API token and store in Key Vault
3. Deploy Gateway API CRDs
4. Deploy NGINX Gateway Fabric
5. Deploy ExternalDNS
6. Deploy ClusterIssuer (DNS-01)
7. Issue wildcard certificate

### Phase B: Parallel Running

1. Deploy prod HTTPRoute alongside existing Ingress
2. Verify prod hostname resolves and TLS works
3. Deploy staging HTTPRoute
4. Verify staging works

### Phase C: Preview Migration

1. Update `compute-preview-urls` action
2. Update `update-preview-overlay` action
3. Create new preview HTTPRoute template
4. Test with a single PR
5. Verify DNS creation and TLS

### Phase D: Cleanup

1. Remove all nip.io/sslip.io references
2. Remove old Ingress resources
3. Remove HTTP-01 ClusterIssuer (keep for rollback initially)
4. Update documentation

### Validation Checklist

- [ ] DNS: `dig api-pr-42.yt-summarizer.apps.ashleyhollis.com` returns Gateway IP
- [ ] TLS: `curl -v https://api-pr-42.yt-summarizer.apps.ashleyhollis.com/health/live` shows valid cert
- [ ] Cert: `kubectl get certificate -n gateway-system` shows Ready=True
- [ ] Route: `kubectl get httproute -A` shows all routes attached
- [ ] ExternalDNS: Cloudflare dashboard shows auto-created records
- [ ] Cleanup: Closing PR removes DNS record within 10 minutes

---

## Complexity Tracking

> No constitution violations requiring justification.

---

## Next Steps

1. Run `/speckit.tasks` to generate detailed implementation tasks
2. Create DNS records in Cloudflare (manual step: wildcard A record for Gateway IP)
3. Implement infrastructure manifests
4. Update GitHub Actions
5. Implement Auth0 BFF endpoints
6. Create runbooks
