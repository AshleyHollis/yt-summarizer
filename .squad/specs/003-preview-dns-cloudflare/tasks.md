# Tasks: Preview DNS / Cloudflare / cert-manager

> **Feature ID**: F003 | **Status**: Complete | **All tasks implemented and validated**

## Overview
- **Total Tasks**: 77
- **Completed**: 77
- **Workflow**: poc
- **Intent**: GREENFIELD

### Phase Distribution
| Phase | Tasks | Status |
|-------|-------|--------|
| 1. Setup (Manual Prerequisites) | 5 | ✅ Complete |
| 2. Foundational (Gateway API Infrastructure) | 17 | ✅ Complete |
| 3. US3: Per-App Wildcard Certificates | 5 | ✅ Complete |
| 4. US1: Developer Creates PR Preview | 15 | ✅ Complete |
| 5. US2: Developer Closes/Merges PR | 5 | ✅ Complete |
| 6. US4: Authenticated User via SWA Frontend | 15 | ✅ Complete |
| 7. US5: Platform Team Debugging | 7 | ✅ Complete |
| 8. Cleanup & Migration Completion | 9 | ✅ Complete |

---

## Phase 1: Setup (Manual Prerequisites)

- [x] T001 Get current nginx-ingress LoadBalancer IP
  - **Agent**: Parker
  - **Do**: `kubectl get svc -n ingress-nginx ingress-nginx-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}'`
  - **Files**: none (read-only)
  - **Done when**: LoadBalancer IP known (result: 20.255.113.149)
  - **Verify**: IP returned by kubectl command

- [x] T002 Create wildcard DNS A record in Cloudflare
  - **Agent**: Parker
  - **Do**: Create `*.yt-summarizer.apps` A record in Cloudflare zone `ashleyhollis.com` pointing to LoadBalancer IP from T001
  - **Files**: Cloudflare Dashboard
  - **Done when**: DNS record visible in Cloudflare dashboard
  - **Verify**: `nslookup anything.yt-summarizer.apps.ashleyhollis.com`

- [x] T003 Create Cloudflare API token
  - **Agent**: Parker
  - **Do**: Cloudflare Dashboard → My Profile → API Tokens → Create Token with Zone:Read + DNS:Edit on `ashleyhollis.com`
  - **Files**: Cloudflare Dashboard
  - **Done when**: Token generated with correct scopes
  - **Verify**: Token has Zone:Read and DNS:Edit permissions only

- [x] T004 Store Cloudflare API token in Azure Key Vault
  - **Agent**: Parker
  - **Do**: Store token as secret `cloudflare-api-token` in the project Key Vault
  - **Files**: Azure Key Vault
  - **Done when**: Secret accessible from cluster via ExternalSecret
  - **Verify**: ExternalSecret syncs successfully in `gateway-system` and `cert-manager` namespaces

- [x] T005 Verify DNS resolution baseline
  - **Agent**: Parker
  - **Do**: `dig ashleyhollis.com` — confirm Cloudflare nameservers are authoritative
  - **Files**: none
  - **Done when**: Cloudflare nameservers returned
  - **Verify**: `dig NS ashleyhollis.com` shows Cloudflare NS records

---

## Phase 2: Foundational (Gateway API Infrastructure)

- [x] T006 Create `gateway-system` namespace manifest
  - **Agent**: Parker
  - **Files**: `k8s/argocd/gateway-api/namespace.yaml`
  - **Done when**: Namespace manifest exists and syncs via Argo CD
  - **Verify**: `kubectl get ns gateway-system`

- [x] T007 Create Gateway API CRDs install manifest [P]
  - **Agent**: Parker
  - **Files**: `k8s/argocd/gateway-api/gateway-crds.yaml`
  - **Done when**: Experimental CRDs v1.2.0 installed (includes BackendTLSPolicy)
  - **Verify**: `kubectl get crd gateways.gateway.networking.k8s.io`

- [x] T008 Create NGINX Gateway Fabric Helm chart manifest [P]
  - **Agent**: Parker
  - **Files**: `k8s/argocd/gateway-api/nginx-gateway-fabric.yaml`
  - **Done when**: Argo CD Application for NGINX GF v2.3.0 created
  - **Verify**: `kubectl get pods -n gateway-system -l app.kubernetes.io/name=nginx-gateway`

- [x] T009 Create GatewayClass manifest
  - **Agent**: Parker
  - **Files**: `k8s/argocd/gateway-api/gatewayclass.yaml`
  - **Done when**: GatewayClass `nginx` with `controllerName: gateway.nginx.org/nginx-gateway-controller`
  - **Verify**: `kubectl get gatewayclass nginx`

- [x] T010 Create kustomization.yaml for gateway-api
  - **Agent**: Parker
  - **Files**: `k8s/argocd/gateway-api/kustomization.yaml`
  - **Done when**: All gateway-api resources included
  - **Verify**: `kubectl kustomize k8s/argocd/gateway-api` exits 0

- [x] T011 Create ClusterIssuer for DNS-01 Cloudflare
  - **Agent**: Parker
  - **Files**: `k8s/argocd/cert-manager/clusterissuer-cloudflare.yaml`
  - **Done when**: ClusterIssuer `letsencrypt-cloudflare` with DNS-01 Cloudflare solver
  - **Verify**: `kubectl get clusterissuer letsencrypt-cloudflare`

- [x] T012 Create ExternalSecret for Cloudflare API token
  - **Agent**: Parker
  - **Files**: `k8s/argocd/gateway-api/externalsecret-cloudflare.yaml`
  - **Done when**: ExternalSecret references `azure-keyvault-cluster` ClusterSecretStore
  - **Verify**: `kubectl get externalsecret -n gateway-system cloudflare-api-token`

- [x] T013 Update cert-manager kustomization to include new ClusterIssuer
  - **Agent**: Parker
  - **Files**: `k8s/argocd/cert-manager/kustomization.yaml`
  - **Done when**: ClusterIssuer included in kustomization
  - **Verify**: `kubectl kustomize k8s/argocd/cert-manager` exits 0

- [x] T014 Create ExternalDNS ServiceAccount and RBAC
  - **Agent**: Parker
  - **Files**: `k8s/argocd/external-dns/rbac.yaml`
  - **Done when**: ServiceAccount + ClusterRole + ClusterRoleBinding for ExternalDNS
  - **Verify**: `kubectl get serviceaccount -n gateway-system external-dns`

- [x] T015 Create ExternalDNS Deployment manifest [P]
  - **Agent**: Parker
  - **Files**: `k8s/argocd/external-dns/deployment.yaml`
  - **Done when**: Deployment with `--source=gateway-httproute --provider=cloudflare --domain-filter=apps.ashleyhollis.com --policy=sync --registry=txt --txt-owner-id=yt-summarizer-aks` (no `=false` boolean syntax)
  - **Verify**: `kubectl get pods -n gateway-system -l app=external-dns`

- [x] T016 Create ExternalDNS kustomization
  - **Agent**: Parker
  - **Files**: `k8s/argocd/external-dns/kustomization.yaml`
  - **Done when**: All ExternalDNS resources included
  - **Verify**: `kubectl kustomize k8s/argocd/external-dns` exits 0

- [x] T017 Create wildcard Certificate manifest
  - **Agent**: Parker
  - **Files**: `k8s/argocd/certificates/yt-summarizer-wildcard.yaml`
  - **Done when**: Certificate `yt-summarizer-wildcard` in `gateway-system`, dnsNames: `[*.yt-summarizer.apps.ashleyhollis.com, yt-summarizer.apps.ashleyhollis.com]`
  - **Verify**: `kubectl get certificate -n gateway-system yt-summarizer-wildcard`

- [x] T018 Create certificates kustomization
  - **Agent**: Parker
  - **Files**: `k8s/argocd/certificates/kustomization.yaml`
  - **Done when**: Certificate included in kustomization
  - **Verify**: `kubectl kustomize k8s/argocd/certificates` exits 0

- [x] T019 Create Gateway manifest
  - **Agent**: Parker
  - **Files**: `k8s/argocd/gateway-api/gateway.yaml`
  - **Done when**: Gateway `main-gateway` with HTTPS:443 and HTTP:80 listeners for `*.yt-summarizer.apps.ashleyhollis.com`; HTTPS listener references `yt-summarizer-wildcard-tls` Secret
  - **Verify**: `kubectl get gateway -n gateway-system main-gateway`

- [x] T019a Configure Gateway to request same LoadBalancer IP
  - **Agent**: Parker
  - **Files**: `k8s/argocd/gateway-api/gateway.yaml`
  - **Done when**: Gateway service annotation `service.beta.kubernetes.io/azure-load-balancer-ipv4` set (result: Azure assigned 20.187.186.135)
  - **Verify**: `kubectl get svc -n gateway-system -o wide`

- [x] T020 Update Argo CD infra-apps.yaml for new components
  - **Agent**: Parker
  - **Files**: `k8s/argocd/infra-apps.yaml`
  - **Done when**: gateway-api, external-dns, certificates Argo CD Applications defined
  - **Verify**: `kubectl get applications -n argocd | grep -E "gateway-api|external-dns|certificates"`

- [x] T021 Apply foundational manifests and verify Gateway has external IP
  - **Agent**: Parker
  - **Do**: Sync Argo CD; verify Gateway PROGRAMMED=True and LoadBalancer IP = 20.187.186.135
  - **Files**: none (operational)
  - **Done when**: Gateway `PROGRAMMED=True`, LB IP assigned
  - **Verify**: `kubectl get gateway -n gateway-system main-gateway -o jsonpath='{.status.conditions[?(@.type=="Programmed")].status}'`

- [x] T022 Verify wildcard certificate is Ready
  - **Agent**: Kane
  - **Do**: `kubectl get certificate -n gateway-system`
  - **Files**: none (validation)
  - **Done when**: READY=True, TLS secret `yt-summarizer-wildcard-tls` exists (Valid: 2026-01-11 to 2026-04-11)
  - **Verify**: `kubectl get certificate -n gateway-system yt-summarizer-wildcard -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}'`

---

## Phase 3: US3 — Per-App Wildcard Certificates

- [x] T023 Verify Certificate READY=True with valid dates
  - **Agent**: Kane
  - **Done when**: `READY=True`, not before 2026-01-11, not after 2026-04-11
  - **Verify**: `kubectl describe certificate -n gateway-system yt-summarizer-wildcard`

- [x] T024 Verify TLS secret contents
  - **Agent**: Kane
  - **Done when**: Secret `yt-summarizer-wildcard-tls` has `tls.crt` and `tls.key` (Type: kubernetes.io/tls)
  - **Verify**: `kubectl get secret -n gateway-system yt-summarizer-wildcard-tls -o jsonpath='{.type}'`

- [x] T025a Update Cloudflare DNS wildcard A record to Gateway IP
  - **Agent**: Parker
  - **Do**: Update `*.yt-summarizer.apps.ashleyhollis.com` from 20.255.113.149 → 20.187.186.135
  - **Files**: Cloudflare Dashboard
  - **Done when**: DNS resolves to 20.187.186.135
  - **Verify**: `nslookup test.yt-summarizer.apps.ashleyhollis.com` → 20.187.186.135

- [x] T025 Test TLS termination
  - **Agent**: Kane
  - **Done when**: `curl -v https://api.yt-summarizer.apps.ashleyhollis.com` shows cert CN=*.yt-summarizer.apps.ashleyhollis.com, Issuer=Let's Encrypt R12
  - **Verify**: `curl -vI https://api.yt-summarizer.apps.ashleyhollis.com 2>&1 | grep -E "(subject:|issuer:)"`

- [x] T026 Document certificate renewal process
  - **Agent**: Dallas
  - **Files**: `docs/runbooks/cert-manager-dns01-troubleshooting.md`
  - **Done when**: Runbook covers normal cert lifecycle, renewal, troubleshooting stuck challenges, emergency replacement
  - **Verify**: File exists and covers all sections

---

## Phase 4: US1 — Developer Creates PR Preview

- [x] T027 Create base HTTPRoute template
  - **Agent**: Parker
  - **Files**: `k8s/base-preview/api-httproute.yaml`
  - **Done when**: HTTPRoute template with placeholder hostname; references `gateway-system/main-gateway`
  - **Verify**: `kubectl kustomize k8s/base-preview` exits 0

- [x] T028 Update base-preview kustomization to include HTTPRoute
  - **Agent**: Parker
  - **Files**: `k8s/base-preview/kustomization.yaml`
  - **Done when**: HTTPRoute included; Ingress removed
  - **Verify**: `kubectl kustomize k8s/base-preview` exits 0

- [x] T029 Create HTTPRoute patch template for preview overlay
  - **Agent**: Parker
  - **Files**: `k8s/overlays/preview/patches/httproute-patch.yaml`
  - **Done when**: Patch sets hostname to `api-pr-<N>.yt-summarizer.apps.ashleyhollis.com`
  - **Verify**: `kubectl kustomize k8s/overlays/preview` exits 0

- [x] T030 Update compute-preview-urls action to use new hostname scheme
  - **Agent**: Parker
  - **Files**: `.github/actions/compute-preview-urls/action.yml`
  - **Done when**: Outputs `api-pr-{number}.yt-summarizer.apps.ashleyhollis.com`; sslip.io logic removed
  - **Verify**: Action output matches new hostname pattern

- [x] T031 Verify generate_preview_kustomization.py supports HTTPRoute
  - **Agent**: Parker
  - **Files**: `scripts/ci/generate_preview_kustomization.py`
  - **Done when**: Script generates HTTPRoute patch with correct hostname
  - **Verify**: Run script for PR #99 and inspect output

- [x] T032 Update preview-kustomization-template.yaml to include HTTPRoute patch [P]
  - **Agent**: Parker
  - **Files**: `scripts/ci/templates/preview-kustomization-template.yaml`
  - **Done when**: Template includes HTTPRoute patch reference
  - **Verify**: `kubectl kustomize` on generated overlay exits 0

- [x] T033 Verify update-preview-overlay action generates HTTPRoute patch
  - **Agent**: Parker
  - **Files**: `.github/actions/update-preview-overlay/action.yml`
  - **Done when**: Action generates correct HTTPRoute patch for given PR number
  - **Verify**: Action produces valid kustomize overlay

- [x] T034 Update preview.yml workflow to remove Ingress IP lookups
  - **Agent**: Parker
  - **Files**: `.github/workflows/preview.yml`
  - **Done when**: `get-aks-ingress-ip` step removed; hostname-based URLs used throughout
  - **Verify**: Workflow lint passes; no references to nginx-ingress IP lookup

- [x] T035 Verify post-preview-comment action URL format
  - **Agent**: Parker
  - **Files**: `.github/actions/post-preview-comment/action.yml`
  - **Done when**: Action posts new hostname-based URLs correctly (action was already URL-agnostic)
  - **Verify**: PR comment contains `yt-summarizer.apps.ashleyhollis.com` URLs

- [x] T036 Create production HTTPRoute [P]
  - **Agent**: Parker
  - **Files**: `k8s/base/api-httproute.yaml`
  - **Done when**: HTTPRoute template for production; references `gateway-system/main-gateway`
  - **Verify**: `kubectl kustomize k8s/base` exits 0

- [x] T037 Create production HTTPRoute hostname patch [P]
  - **Agent**: Parker
  - **Files**: `k8s/overlays/prod/patches/httproute-patch.yaml`
  - **Done when**: Patch sets hostname to `api.yt-summarizer.apps.ashleyhollis.com`
  - **Verify**: `kubectl kustomize k8s/overlays/prod` exits 0

- [x] T038 Update prod overlay kustomization to include HTTPRoute
  - **Agent**: Parker
  - **Files**: `k8s/overlays/prod/kustomization.yaml`
  - **Done when**: HTTPRoute included; old Ingress removed
  - **Verify**: `kubectl kustomize k8s/overlays/prod` exits 0

- [x] T039 Test preview creation with real PR — verify DNS record created
  - **Agent**: Kane
  - **Do**: Create test PR; observe GitHub Actions run; verify HTTPRoute and DNS A record created
  - **Files**: none (validation)
  - **Done when**: `kubectl get httproute -n preview-pr-5` shows route with correct hostname
  - **Verify**: `nslookup api-pr-5.yt-summarizer.apps.ashleyhollis.com` → 20.187.186.135 ✅ PR #5 validated

- [x] T040 Verify HTTPS works on preview URL with valid certificate
  - **Agent**: Kane
  - **Done when**: `curl -vI https://api-pr-5.yt-summarizer.apps.ashleyhollis.com` shows CN=*.yt-summarizer.apps.ashleyhollis.com, Issuer=Let's Encrypt R12
  - **Verify**: `curl -vI https://api-pr-5.yt-summarizer.apps.ashleyhollis.com 2>&1 | grep -E "(subject:|issuer:)"` ✅ Validated

- [x] T041 Verify PR comment contains correct API and SWA preview URLs
  - **Agent**: Kane
  - **Done when**: PR #5 comment contains `api-pr-5.yt-summarizer.apps.ashleyhollis.com` and SWA URL
  - **Verify**: `gh pr view 5 --json body` shows preview URLs ✅ Validated

---

## Phase 5: US2 — Developer Closes/Merges PR

- [x] T042 Verify preview-cleanup.yml workflow deletes namespace on PR close
  - **Agent**: Parker
  - **Do**: Review `.github/workflows/preview-cleanup.yml`; confirm Argo CD ApplicationSet deletion is triggered
  - **Files**: `.github/workflows/preview-cleanup.yml`
  - **Done when**: Workflow confirmed to delete Argo CD Application on PR close
  - **Verify**: Workflow file contains correct cleanup trigger

- [x] T043 Verify ExternalDNS removes DNS record when HTTPRoute is deleted
  - **Agent**: Parker
  - **Do**: Confirm `--policy=sync` in ExternalDNS deployment ensures record deletion
  - **Files**: `k8s/argocd/external-dns/deployment.yaml`
  - **Done when**: `--policy=sync` confirmed in deployment args
  - **Verify**: `kubectl get deployment -n gateway-system external-dns -o yaml | grep policy`

- [x] T044 Test cleanup with real PR — verify namespace deleted
  - **Agent**: Kane
  - **Do**: Close PR #5; verify namespace gone within 5 minutes
  - **Files**: none (validation)
  - **Done when**: `kubectl get namespace preview-pr-5` returns NotFound ✅ Deleted within 2 minutes
  - **Verify**: `kubectl get namespace preview-pr-5` exits with NotFound

- [x] T045 Verify DNS record removed from Cloudflare within 10 minutes
  - **Agent**: Kane
  - **Do**: After PR #5 close, verify Cloudflare A record deleted within 10 minutes
  - **Files**: none (validation)
  - **Done when**: `nslookup api-pr-5.yt-summarizer.apps.ashleyhollis.com` no longer resolves ✅ Verified
  - **Verify**: DNS propagation confirmed via runbook procedures

- [x] T046 Document cleanup verification steps
  - **Agent**: Dallas
  - **Files**: `docs/runbooks/external-dns-troubleshooting.md`
  - **Done when**: Runbook covers DNS lifecycle with HTTPRoutes, cleanup timing, orphaned record detection
  - **Verify**: File exists and is ≥100 lines covering all scenarios

---

## Phase 6: US4 — Authenticated User via SWA Frontend

- [x] T047 Create auth routes module
  - **Agent**: Ripley
  - **Files**: `services/api/src/api/routes/auth.py`
  - **Done when**: Module file exists with imports and router setup
  - **Verify**: `python -c "from api.routes.auth import router"` exits 0

- [x] T048 Implement GET /api/auth/login endpoint
  - **Agent**: Ripley
  - **Files**: `services/api/src/api/routes/auth.py`
  - **Done when**: Endpoint redirects to Auth0 authorize URL; accepts optional `returnTo` query param
  - **Verify**: `curl -I http://localhost:8000/api/auth/login` returns 302 with Auth0 URL

- [x] T049 Implement GET /api/auth/callback/auth0 endpoint
  - **Agent**: Ripley
  - **Files**: `services/api/src/api/routes/auth.py`
  - **Done when**: Endpoint completes Auth0 code exchange; sets session cookie
  - **Verify**: Auth0 redirect lands at endpoint and sets `Set-Cookie` header

- [x] T050 Implement POST /api/auth/logout endpoint
  - **Agent**: Ripley
  - **Files**: `services/api/src/api/routes/auth.py`
  - **Done when**: Endpoint clears session cookie (local logout only)
  - **Verify**: `curl -X POST http://localhost:8000/api/auth/logout` clears cookie

- [x] T051 Implement GET /api/auth/me endpoint
  - **Agent**: Ripley
  - **Files**: `services/api/src/api/routes/auth.py`
  - **Done when**: Returns current user info if authenticated; 401 if not
  - **Verify**: `curl http://localhost:8000/api/auth/me` returns 401 without session

- [x] T052 Register auth routes in main.py
  - **Agent**: Ripley
  - **Files**: `services/api/src/api/main.py`
  - **Done when**: `auth.router` included in FastAPI app
  - **Verify**: `curl http://localhost:8000/openapi.json | grep auth`

- [x] T053 Update CORS configuration with new allowed origins
  - **Agent**: Ripley
  - **Files**: `services/api/src/api/main.py`
  - **Done when**: CORS middleware includes `https://web.yt-summarizer.apps.ashleyhollis.com` and `*.azurestaticapps.net` regex
  - **Verify**: CORS headers on OPTIONS request from SWA origin

- [x] T054 Add regex pattern for *.azurestaticapps.net origins
  - **Agent**: Ripley
  - **Files**: `services/api/src/api/main.py`
  - **Done when**: Regex `r"https://.*\.azurestaticapps\.net"` in allowed origins
  - **Verify**: SWA preview origin receives correct `Access-Control-Allow-Origin` header

- [x] T055 Ensure allow_credentials=True with origin reflection
  - **Agent**: Ripley
  - **Files**: `services/api/src/api/main.py`
  - **Done when**: `allow_credentials=True` set; specific origin reflected (not `*`)
  - **Verify**: `Access-Control-Allow-Credentials: true` in CORS response

- [x] T056 Add wildcard callback URL pattern in Auth0 Dashboard via Terraform
  - **Agent**: Parker
  - **Files**: `infra/terraform/modules/auth0/main.tf`
  - **Done when**: `https://api-pr-*.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0` in Allowed Callback URLs
  - **Verify**: Terraform plan shows Auth0 app configuration

- [x] T057 Add production and staging callback URLs via Terraform
  - **Agent**: Parker
  - **Files**: `infra/terraform/modules/auth0/main.tf`
  - **Done when**: Prod and staging callback URLs included
  - **Verify**: Terraform plan includes all callback URLs

- [x] T058 Add allowed web origins for production and *.azurestaticapps.net via Terraform
  - **Agent**: Parker
  - **Files**: `infra/terraform/modules/auth0/main.tf`
  - **Done when**: `https://web.yt-summarizer.apps.ashleyhollis.com` and `https://*.azurestaticapps.net` in Allowed Web Origins
  - **Verify**: Terraform plan shows web origins configuration

- [x] T058a Create Auth0 Terraform module and wire into prod environment
  - **Agent**: Parker
  - **Files**: `infra/terraform/modules/auth0/main.tf`, `infra/terraform/environments/prod`
  - **Done when**: Module deployable; manages Auth0 application settings via Terraform
  - **Verify**: `terraform plan` in prod environment exits 0

- [x] T058b Create ExternalSecrets for Auth0 credentials
  - **Agent**: Parker
  - **Files**: `k8s/base/externalsecret-auth0.yaml`, `k8s/base-preview/externalsecret-auth0.yaml`
  - **Done when**: API deployment gets Auth0 env vars from Key Vault via ExternalSecret
  - **Verify**: `kubectl get externalsecret -n yt-summarizer externalsecret-auth0`

- [x] T058c Update API deployment manifests with Auth0 environment variables
  - **Agent**: Parker
  - **Files**: API deployment manifests
  - **Done when**: AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET env vars injected
  - **Verify**: `kubectl get deployment -n yt-summarizer api -o yaml | grep AUTH0`

- [x] T058d Create Auth0 setup runbook
  - **Agent**: Dallas
  - **Files**: `docs/runbooks/auth0-setup.md`
  - **Done when**: Runbook covers Auth0 app creation, callback URL configuration, token setup
  - **Verify**: File exists and covers all setup steps

- [x] T059 Test login flow from preview API endpoint
  - **Agent**: Kane
  - **Done when**: `GET /api/auth/login` on preview API redirects to Auth0 (auth endpoints deployed and accessible)
  - **Verify**: `curl -I https://api-pr-N.yt-summarizer.apps.ashleyhollis.com/api/auth/login` returns 302

- [x] T060 Test cross-origin credentialed request from SWA preview to API preview
  - **Agent**: Kane
  - **Done when**: CORS allows `*.azurestaticapps.net` with credentials; credentialed request returns 200
  - **Verify**: OPTIONS preflight returns `Access-Control-Allow-Credentials: true` and SWA origin

- [x] T061 Verify session cookie attributes
  - **Agent**: Kane
  - **Done when**: Session cookie has HttpOnly, Secure, SameSite=None, no Domain attribute (per `services/api/src/api/routes/auth.py:311-318`)
  - **Verify**: `curl -vI .../api/auth/callback/auth0 2>&1 | grep Set-Cookie`

---

## Phase 7: US5 — Platform Team Debugging

- [x] T062 Create Cloudflare setup runbook [P]
  - **Agent**: Dallas
  - **Files**: `docs/runbooks/cloudflare-setup.md`
  - **Done when**: Runbook covers: API token creation, Key Vault storage, ExternalSecret setup, DNS zone delegation
  - **Verify**: File exists

- [x] T063 Create cert-manager DNS-01 troubleshooting runbook [P]
  - **Agent**: Dallas
  - **Files**: `docs/runbooks/cert-manager-dns01-troubleshooting.md`
  - **Done when**: Runbook covers certificate lifecycle, renewal, stuck challenges, emergency replacement (460 lines)
  - **Verify**: `wc -l docs/runbooks/cert-manager-dns01-troubleshooting.md` ≥ 200

- [x] T064 Create ExternalDNS troubleshooting runbook [P]
  - **Agent**: Dallas
  - **Files**: `docs/runbooks/external-dns-troubleshooting.md`
  - **Done when**: Runbook covers DNS lifecycle with HTTPRoutes, cleanup timing, orphaned record detection, monitoring (463 lines)
  - **Verify**: `wc -l docs/runbooks/external-dns-troubleshooting.md` ≥ 200

- [x] T065 Create Gateway/HTTPRoute troubleshooting runbook [P]
  - **Agent**: Dallas
  - **Files**: `docs/runbooks/gateway-troubleshooting.md`
  - **Done when**: Runbook covers Gateway status checks, HTTPRoute attachment verification, routing debugging
  - **Verify**: File exists with Gateway and HTTPRoute status commands

- [x] T066 Verify cert-manager runbook with simulated DNS-01 failure
  - **Agent**: Kane
  - **Do**: Use runbook to inspect certificate status and challenge state after simulated failure
  - **Files**: none (validation)
  - **Done when**: Certificate status commands work; challenge inspection documented and verified
  - **Verify**: Runbook steps produce expected kubectl output

- [x] T067 Verify ExternalDNS runbook with simulated record creation failure
  - **Agent**: Kane
  - **Do**: Use runbook to inspect ExternalDNS logs and HTTPRoute watch mechanism
  - **Files**: none (validation)
  - **Done when**: Log inspection and HTTPRoute watch mechanism documented and validated
  - **Verify**: `kubectl logs -n gateway-system deployment/external-dns` matches runbook guidance

- [x] T068 Verify Gateway runbook with simulated HTTPRoute attachment issue
  - **Agent**: Kane
  - **Do**: Use runbook to check Gateway/HTTPRoute status
  - **Files**: none (validation)
  - **Done when**: Status checks documented and verified against live cluster
  - **Verify**: `kubectl describe httproute` output matches runbook guidance

---

## Phase 8: Cleanup & Migration Completion

- [x] T069 Remove sslip.io hostname logic from compute-preview-urls action
  - **Agent**: Parker
  - **Files**: `.github/actions/compute-preview-urls/action.yml`
  - **Done when**: No references to sslip.io, nip.io, or xip.io in the action
  - **Verify**: `grep -r "sslip.io\|nip.io\|xip.io" .github/` returns nothing

- [x] T070 Remove old ingress-patch.yaml from preview overlay
  - **Agent**: Parker
  - **Files**: `k8s/overlays/preview/patches/ingress-patch.yaml` (deleted)
  - **Done when**: File removed; kustomization updated
  - **Verify**: File no longer exists

- [x] T071 Remove api-ingress.yaml from base [P]
  - **Agent**: Parker
  - **Files**: `k8s/base/api-ingress.yaml` (deleted)
  - **Done when**: File removed
  - **Verify**: File no longer exists

- [x] T072 Remove api-ingress.yaml from base-preview [P]
  - **Agent**: Parker
  - **Files**: `k8s/base-preview/api-ingress.yaml` (deleted)
  - **Done when**: File removed
  - **Verify**: File no longer exists

- [x] T073 Update base kustomization to remove Ingress reference
  - **Agent**: Parker
  - **Files**: `k8s/base/kustomization.yaml`
  - **Done when**: No Ingress resource reference; HTTPRoute included
  - **Verify**: `kubectl kustomize k8s/base` exits 0

- [x] T074 Update base-preview kustomization to remove Ingress reference
  - **Agent**: Parker
  - **Files**: `k8s/base-preview/kustomization.yaml`
  - **Done when**: No Ingress resource reference; HTTPRoute included
  - **Verify**: `kubectl kustomize k8s/base-preview` exits 0

- [x] T075 Search codebase for remaining nip.io/sslip.io/xip.io references and remove
  - **Agent**: Parker
  - **Done when**: `grep -r "nip.io\|sslip.io\|xip.io" .` returns nothing
  - **Verify**: `grep -r "nip.io\|sslip.io\|xip.io" .` exits with no matches

- [x] T076 Update architecture documentation
  - **Agent**: Dallas
  - **Files**: `docs/architecture.md`
  - **Done when**: Architecture doc reflects Gateway API, ExternalDNS, wildcard cert setup
  - **Verify**: Doc mentions NGINX Gateway Fabric, ExternalDNS, cert-manager DNS-01

- [x] T077 Final validation: all quickstart.md checks pass
  - **Agent**: Kane
  - **Do**: Run all 9 validation checks from `specs/003-preview-dns-cloudflare/quickstart.md`
  - **Files**: none (validation)
  - **Done when**: All 9 checks completed successfully ✅ Validated 2026-01-12
  - **Verify**: See validation summary in IMPLEMENTATION_COMPLETE.md
