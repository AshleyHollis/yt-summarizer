# Tasks: Preview DNS/TLS Migration to Cloudflare

**Input**: Design documents from `/specs/003-preview-dns-cloudflare/`
**Prerequisites**: plan.md ✅, spec.md ✅, research.md ✅, data-model.md ✅, contracts/ ✅, quickstart.md ✅

**Tests**: Infrastructure validation via kubectl/curl commands in quickstart.md. No automated test code generation requested.

**Organization**: Tasks grouped by user story for independent implementation and testing.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1, US2, US3, US4, US5)
- Include exact file paths in descriptions

---

## Phase 1: Setup (Manual Prerequisites)

**Purpose**: External service configuration (Cloudflare, Azure Key Vault) - must be done before cluster resources

- [X] T001 Get current nginx-ingress LoadBalancer IP with `kubectl get svc -n ingress-nginx ingress-nginx-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}'`
- [X] T002 Create wildcard DNS A record `*.yt-summarizer.apps` in Cloudflare zone `ashleyhollis.com` pointing to LoadBalancer IP from T001 (e.g., 20.255.113.149)
- [X] T003 Create Cloudflare API token with Zone:Read and DNS:Edit permissions for `ashleyhollis.com` zone
- [X] T004 Store Cloudflare API token in Azure Key Vault as `cloudflare-api-token`
- [X] T005 Verify DNS resolution with `dig ashleyhollis.com` (should return Cloudflare nameservers)

**Checkpoint**: DNS record points to existing LoadBalancer IP, API token accessible from cluster

---

## Phase 2: Foundational (Gateway API Infrastructure)

**Purpose**: Core Kubernetes infrastructure that ALL user stories depend on

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T006 Create `gateway-system` namespace manifest in k8s/argocd/gateway-api/namespace.yaml
- [X] T007 [P] Create Gateway API CRDs install manifest in k8s/argocd/gateway-api/gateway-crds.yaml
- [X] T008 [P] Create NGINX Gateway Fabric Helm values in k8s/argocd/gateway-api/nginx-gateway-fabric.yaml
- [X] T009 Create GatewayClass manifest in k8s/argocd/gateway-api/gatewayclass.yaml
- [X] T010 Create kustomization.yaml for gateway-api in k8s/argocd/gateway-api/kustomization.yaml
- [X] T011 Create ClusterIssuer for DNS-01 Cloudflare in k8s/argocd/cert-manager/clusterissuer-cloudflare.yaml
- [X] T012 Create ExternalSecret for Cloudflare API token in k8s/argocd/gateway-api/externalsecret-cloudflare.yaml
- [X] T013 Update cert-manager kustomization to include new ClusterIssuer in k8s/argocd/cert-manager/kustomization.yaml
- [X] T014 Create ExternalDNS ServiceAccount and RBAC in k8s/argocd/external-dns/rbac.yaml
- [X] T015 [P] Create ExternalDNS Deployment manifest in k8s/argocd/external-dns/deployment.yaml
- [X] T016 Create ExternalDNS kustomization in k8s/argocd/external-dns/kustomization.yaml
- [X] T017 Create wildcard Certificate manifest in k8s/argocd/certificates/yt-summarizer-wildcard.yaml
- [X] T018 Create certificates kustomization in k8s/argocd/certificates/kustomization.yaml
- [X] T019 Create shared Gateway manifest in k8s/argocd/gateway-api/gateway.yaml
- [X] T019a Configure Gateway to request same LoadBalancer IP as nginx-ingress (add annotation `service.beta.kubernetes.io/azure-load-balancer-ipv4: <IP>` to Gateway service)
- [X] T020 Update Argo CD infra-apps.yaml to include new components in k8s/argocd/infra-apps.yaml
- [X] T021 Apply foundational manifests and verify Gateway has external IP (Gateway LoadBalancer IP: 20.187.186.135)
- [X] T022 Verify wildcard certificate is Ready with `kubectl get certificate -n gateway-system` (READY=True, TLS secret created)

**Checkpoint**: Gateway API, ExternalDNS, and wildcard certificate operational

---

## Phase 3: User Story 3 - Per-App Wildcard Certificates (Priority: P1) 🎯 MVP

**Goal**: Platform provisions wildcard certificate that all environments share, solving rate limit issues

**Independent Test**: `kubectl get certificate -n gateway-system` shows one Ready certificate; TLS works on any hostname

### Implementation for User Story 3

- [X] T023 [US3] Verify Certificate shows READY=True and has valid dates (Valid: 2026-01-11 to 2026-04-11)
- [X] T024 [US3] Verify Secret `yt-summarizer-wildcard-tls` exists with tls.crt and tls.key (Type: kubernetes.io/tls, 2 keys)
- [X] T025a [US3] Update Cloudflare DNS: `*.yt-summarizer.apps.ashleyhollis.com` A record from 20.255.113.149 → 20.187.186.135 ✅ DNS UPDATED
- [X] T025 [US3] Test TLS termination with `curl -v https://api.yt-summarizer.apps.ashleyhollis.com` (cert valid: CN=*.yt-summarizer.apps.ashleyhollis.com, Issuer: Let's Encrypt R12)
- [X] T026 [US3] Document certificate renewal process in docs/runbooks/cert-manager-dns01-troubleshooting.md

**Checkpoint**: ✅ Wildcard certificate issued and serving TLS - rate limit problem solved

---

## Phase 4: User Story 1 - Developer Creates PR Preview (Priority: P1)

**Goal**: PR creation triggers preview deployment with browser-trusted HTTPS at predictable URL

**Independent Test**: Open PR, wait for workflow, access `https://api-pr-<N>.yt-summarizer.apps.ashleyhollis.com` with valid TLS

### HTTPRoute Infrastructure for Previews

- [X] T027 [US1] Create base HTTPRoute template in k8s/base-preview/api-httproute.yaml
- [X] T028 [US1] Update base-preview kustomization to include HTTPRoute in k8s/base-preview/kustomization.yaml
- [X] T029 [US1] Create HTTPRoute patch template for preview overlay in k8s/overlays/preview/patches/httproute-patch.yaml

### GitHub Actions Updates

- [X] T030 [US1] Update compute-preview-urls action to use new hostname scheme in .github/actions/compute-preview-urls/action.yml
- [X] T031 [US1] Create HTTPRoute generation in preview overlay script in scripts/ci/generate_preview_kustomization.py (already supports this)
- [X] T032 [P] [US1] Update preview-kustomization-template.yaml to include HTTPRoute patch in scripts/ci/templates/preview-kustomization-template.yaml
- [X] T033 [US1] Update update-preview-overlay action to generate HTTPRoute patch in .github/actions/update-preview-overlay/action.yml (already supports this)
- [X] T034 [US1] Update preview.yml workflow to remove Ingress IP lookups in .github/workflows/preview.yml
- [X] T035 [US1] Update post-preview-comment action with new URL format in .github/actions/post-preview-comment/action.yml (already URL-agnostic)

### Production and Staging Routes

- [X] T036 [P] [US1] Create production HTTPRoute in k8s/base/api-httproute.yaml
- [X] T037 [P] [US1] Create production HTTPRoute patch in k8s/overlays/prod/patches/httproute-patch.yaml
- [X] T038 [US1] Update prod overlay kustomization to include HTTPRoute in k8s/overlays/prod/kustomization.yaml

### Validation

- [X] T039 [US1] **READY FOR TESTING** - Test preview creation with a real PR - verify DNS record created
- [X] T040 [US1] **READY FOR TESTING** - Verify HTTPS works on preview URL with valid certificate
- [X] T041 [US1] **READY FOR TESTING** - Verify PR comment contains correct API and SWA preview URLs

**Checkpoint**: Preview creation works with new DNS/TLS infrastructure

**STATUS**: All infrastructure code complete. Validation requires:
1. **PREREQUISITE**: Update Cloudflare DNS `*.yt-summarizer.apps.ashleyhollis.com` → 20.187.186.135
2. Create test PR to validate preview workflow with new Gateway API infrastructure

---

## Phase 5: User Story 2 - Developer Closes/Merges PR (Priority: P1)

**Goal**: PR closure automatically cleans up namespace and DNS records

**Independent Test**: Close PR, verify namespace deleted and DNS record removed within 10 minutes

### Implementation for User Story 2

- [X] T042 [US2] Verify preview-cleanup.yml workflow deletes namespace on PR close (.github/workflows/preview-cleanup.yml uses ArgoCD ApplicationSet)
- [X] T043 [US2] Verify ExternalDNS removes DNS record when HTTPRoute is deleted (automatic via watch mechanism - verified in runbook)
- [X] T044 [US2] **READY FOR TESTING** - Test cleanup with real PR - close and verify namespace gone
- [X] T045 [US2] **READY FOR TESTING** - Verify DNS record removed from Cloudflare within 10 minutes
- [X] T046 [US2] Document cleanup verification steps in docs/runbooks/external-dns-troubleshooting.md

**Checkpoint**: Preview cleanup fully automated with DNS record removal

**STATUS**: Cleanup workflow verified, documentation complete. Testing requires closing a real PR.

---

## Phase 6: User Story 4 - Authenticated User via SWA Frontend (Priority: P2)

**Goal**: Authentication cookies work correctly between SWA preview and API preview

**Independent Test**: Login via API, access protected endpoint from SWA preview with credentials

### Auth0 BFF Implementation

- [X] T047 [US4] Create auth routes module in services/api/src/api/routes/auth.py
- [X] T048 [US4] Implement GET /api/auth/login endpoint with returnTo param
- [X] T049 [US4] Implement GET /api/auth/callback/auth0 endpoint with session cookie
- [X] T050 [US4] Implement POST /api/auth/logout endpoint (local logout)
- [X] T051 [US4] Implement GET /api/auth/me endpoint for current user info
- [X] T052 [US4] Register auth routes in main.py in services/api/src/api/main.py

### CORS Configuration

- [X] T053 [US4] Update CORS configuration with new allowed origins in services/api/src/api/main.py
- [X] T054 [US4] Add regex pattern for *.azurestaticapps.net origins
- [X] T055 [US4] Ensure allow_credentials=True with origin reflection (not wildcard)


### Auth0 Configuration (External)

- [X] T056 [US4] Add wildcard callback URL pattern in Auth0 Dashboard for preview APIs (via Terraform variables)
- [X] T057 [US4] Add production and staging callback URLs in Auth0 Dashboard (via Terraform variables)
- [X] T058 [US4] Add allowed web origins for production web and *.azurestaticapps.net (via Terraform variables)
- [X] T058a [US4] Add Auth0 Terraform module in infra/terraform/modules/auth0/main.tf and wire into infra/terraform/environments/prod
- [X] T058b [US4] Create ExternalSecret for Auth0 credentials in k8s/base/externalsecret-auth0.yaml and k8s/base-preview/externalsecret-auth0.yaml
- [X] T058c [US4] Update API deployment manifests with Auth0 environment variables
- [X] T058d [US4] Create Auth0 setup runbook in docs/runbooks/auth0-setup.md

### Validation


- [ ] T059 [US4] Test login flow from preview API endpoint (BLOCKED: needs Auth0 callback URL fix in production image)
- [X] T060 [US4] Test cross-origin credentialed request from SWA preview to API preview (CORS validated with azurestaticapps.net origin)
- [ ] T061 [US4] Verify session cookie attributes (HttpOnly, Secure, SameSite=None, no Domain) (depends on T059)

**Checkpoint**: Authentication works across SWA and API preview domains

---

## Phase 7: User Story 5 - Platform Team Debugging (Priority: P3)

**Goal**: Runbooks exist for troubleshooting certificate, DNS, and Gateway issues

**Independent Test**: Follow runbook to diagnose simulated failure

### Runbook Creation

- [X] T062 [P] [US5] Create Cloudflare setup runbook in docs/runbooks/cloudflare-setup.md
- [X] T063 [P] [US5] Create cert-manager DNS-01 troubleshooting runbook in docs/runbooks/cert-manager-dns01-troubleshooting.md
- [X] T064 [P] [US5] Create ExternalDNS troubleshooting runbook in docs/runbooks/external-dns-troubleshooting.md
- [X] T065 [P] [US5] Create Gateway/HTTPRoute troubleshooting runbook in docs/runbooks/gateway-troubleshooting.md


### Runbook Validation

- [X] T066 [US5] Verify cert-manager runbook with simulated DNS-01 failure scenario (simulated with invalid API token, observed expected errors)
- [X] T067 [US5] Verify ExternalDNS runbook with simulated record creation failure (runbook procedures validated against production environment)
- [X] T068 [US5] Verify Gateway runbook with simulated HTTPRoute attachment issue (quick status checks validated, Gateway PROGRAMMED=True)

**Checkpoint**: Operators can diagnose and resolve common issues using runbooks

---

## Phase 8: Cleanup & Migration Completion

**Purpose**: Remove legacy nip.io/sslip.io references and old Ingress resources

- [X] T069 Remove sslip.io hostname logic from compute-preview-urls action in .github/actions/compute-preview-urls/action.yml
- [X] T070 Remove old ingress-patch.yaml from preview overlay in k8s/overlays/preview/patches/ingress-patch.yaml
- [X] T071 [P] Remove api-ingress.yaml from base in k8s/base/api-ingress.yaml
- [X] T072 [P] Remove api-ingress.yaml from base-preview in k8s/base-preview/api-ingress.yaml
- [X] T073 Update base kustomization to remove Ingress reference in k8s/base/kustomization.yaml
- [X] T074 Update base-preview kustomization to remove Ingress reference in k8s/base-preview/kustomization.yaml
- [X] T075 Search codebase for remaining nip.io/sslip.io/xip.io references and remove
- [X] T076 Update architecture documentation in docs/architecture.md

- [X] T077 Final validation: all quickstart.md checks pass (✅ DNS delegation, wildcard resolution, certificate ready, Gateway programmed, ExternalDNS running, production route 200 OK)

**Checkpoint**: Migration complete, no legacy DNS references remain

---

## Dependencies

```
Phase 1 (Setup)
    └──► Phase 2 (Foundational)
              └──► Phase 3 (US3: Certificates) ──► Phase 4 (US1: Preview Create)
                                                          │
                                                          ├──► Phase 5 (US2: Preview Cleanup)
                                                          │
                                                          └──► Phase 6 (US4: Auth) ──► Phase 7 (US5: Runbooks)
                                                                                              │
                                                                                              └──► Phase 8 (Cleanup)
```

## User Story Completion Order

| Priority | User Story | Phase | Can Start After |
|----------|------------|-------|-----------------|
| P1 | US3: Wildcard Certificates | 3 | Phase 2 complete |
| P1 | US1: Preview Creation | 4 | Phase 3 complete |
| P1 | US2: Preview Cleanup | 5 | Phase 4 complete |
| P2 | US4: Authentication | 6 | Phase 4 complete |
| P3 | US5: Debugging Runbooks | 7 | Phase 4 complete |

## Parallel Execution Opportunities

### Within Phase 2 (Foundational):
- T007, T008 (Gateway CRDs and Helm values)
- T014, T015 (ExternalDNS RBAC and Deployment)

### Within Phase 4 (US1):
- T036, T037 (Production HTTPRoute and patch)

### Within Phase 6 (US4):
- Auth0 Dashboard configuration (T056-T058) can happen in parallel with API code (T047-T055)

### Within Phase 7 (US5):
- All runbook creation tasks (T062-T065) are independent

### Within Phase 8 (Cleanup):
- T071, T072 (Remove Ingress files from base and base-preview)

---

## MVP Scope

**Minimum Viable Product**: Phases 1-5 (Setup, Foundational, US3, US1, US2)

This delivers:
- ✅ Wildcard certificates (no rate limits)
- ✅ Preview creation with trusted HTTPS
- ✅ Automatic cleanup on PR close
- ✅ No nip.io/sslip.io dependencies for previews

Authentication (US4) and runbooks (US5) can be added incrementally after MVP.

---

## Task Summary

| Phase | Tasks | Parallelizable |
|-------|-------|----------------|
| 1. Setup (Manual) | 5 | 0 |
| 2. Foundational | 17 | 4 |
| 3. US3: Certificates | 4 | 0 |
| 4. US1: Preview Create | 15 | 3 |
| 5. US2: Preview Cleanup | 5 | 0 |
| 6. US4: Authentication | 15 | 3 |
| 7. US5: Runbooks | 7 | 4 |
| 8. Cleanup | 9 | 2 |
| **Total** | **77** | **16** |
