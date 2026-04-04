# Requirements: Preview DNS / Cloudflare / cert-manager

> **Feature ID**: F003 | **Status**: Complete | **Milestone**: M2

---

## Goal

Replace nip.io/sslip.io-based preview DNS with dedicated, team-owned hostnames under `apps.ashleyhollis.com`, backed by automated DNS management (Cloudflare + ExternalDNS), per-app wildcard TLS certificates (cert-manager DNS-01), and NGINX Gateway Fabric — eliminating Let's Encrypt rate limit risk and providing professional, predictable URLs for every environment.

---

## User Stories

### US-1: Developer Creates a PR Preview
**As a** developer  
**I want to** open a pull request and automatically get a browser-trusted HTTPS preview environment  
**So that** I can test my changes at a predictable URL without certificate warnings

**Acceptance Criteria:**
- [x] AC-1.1: When PR #N is opened and the workflow completes, `https://api-pr-N.yt-summarizer.apps.ashleyhollis.com` is reachable with a browser-trusted TLS certificate
- [x] AC-1.2: The PR receives an automated comment containing both the API preview URL and the SWA preview URL
- [x] AC-1.3: Authenticated API calls from the SWA preview domain succeed with cookies/credentials intact

---

### US-2: Developer Closes/Merges a PR
**As a** developer  
**I want to** close or merge a PR and have the preview environment automatically cleaned up  
**So that** no orphaned resources accumulate and DNS records don't conflict with future PRs

**Acceptance Criteria:**
- [x] AC-2.1: When PR #N is closed/merged, namespace `preview-pr-N` is deleted within 5 minutes
- [x] AC-2.2: When PR #N is closed/merged, DNS records for `api-pr-N.yt-summarizer.apps.ashleyhollis.com` are removed within 10 minutes

---

### US-3: Platform Team Provisions Per-App Wildcard Certificates
**As a** platform engineer  
**I want to** configure one wildcard TLS certificate per application  
**So that** no new certificate is ever issued for an individual PR preview, eliminating rate limit risk

**Acceptance Criteria:**
- [x] AC-3.1: Only one Certificate resource exists for `*.yt-summarizer.apps.ashleyhollis.com` in `gateway-system` namespace
- [x] AC-3.2: When PR #N preview is created, no new Certificate resource is created; the existing wildcard is used
- [x] AC-3.3: Certificate auto-renews at least 30 days before expiry without service disruption

---

### US-4: Authenticated User Accesses Preview via SWA Frontend
**As an** authenticated end user  
**I want to** use the SWA preview frontend to access protected API resources  
**So that** I can test authenticated features in preview environments

**Acceptance Criteria:**
- [x] AC-4.1: A user can log in via `https://api-pr-N.yt-summarizer.apps.ashleyhollis.com/api/auth/login` and receive a session cookie
- [x] AC-4.2: The SWA preview can make credentialed cross-origin requests to the API preview and receive a 200 response
- [x] AC-4.3: API responds with correct `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` headers for SWA preview origins
- [x] AC-4.4: Session cookie attributes: HttpOnly, Secure, SameSite=None (for cross-origin preview scenarios)

---

### US-5: Platform Team Debugs Certificate or DNS Issues
**As a** platform engineer  
**I want to** have runbooks for diagnosing certificate and DNS failures  
**So that** I can resolve issues quickly without trial-and-error

**Acceptance Criteria:**
- [x] AC-5.1: A runbook exists for cert-manager DNS-01 challenge failures and is verified against a simulated failure
- [x] AC-5.2: A runbook exists for ExternalDNS record creation failures and is verified against simulated scenarios
- [x] AC-5.3: A runbook exists for Gateway/HTTPRoute attachment issues
- [x] AC-5.4: A runbook exists for Cloudflare API setup and token management

---

## Functional Requirements

| ID | Requirement | Priority | Verify |
|----|------------|----------|--------|
| FR-001 | Platform MUST provide dedicated DNS hostnames under `apps.ashleyhollis.com` for every environment | Must | `nslookup api.yt-summarizer.apps.ashleyhollis.com` returns Gateway IP |
| FR-002 | DNS records MUST be created automatically on environment provisioning and removed on teardown | Must | Create PR → DNS A record appears; close PR → DNS record removed |
| FR-003 | Automated DNS management MUST be scoped exclusively to `apps.ashleyhollis.com` | Must | ExternalDNS `--domain-filter=apps.ashleyhollis.com` |
| FR-004 | Credentials for DNS management MUST follow least-privilege | Must | Cloudflare token: Zone:Read + DNS:Edit only |
| FR-005 | All HTTP traffic to application hostnames MUST redirect to HTTPS | Must | `curl -I http://api.yt-summarizer.apps.ashleyhollis.com` returns 301 |
| FR-006 | Platform MUST route each incoming hostname to the correct application service | Must | HTTPRoute per hostname verified via `kubectl get httproute -A` |
| FR-007 | All environments MUST be served through the same shared routing layer | Must | Single Gateway in `gateway-system`; all HTTPRoutes attach to it |
| FR-008 | Platform MUST provision browser-trusted TLS certificates | Must | `curl -vI https://api.yt-summarizer.apps.ashleyhollis.com` shows Let's Encrypt cert |
| FR-009 | One certificate per app MUST cover every environment for that app | Must | `kubectl get certificate -n gateway-system` shows exactly one cert |
| FR-010 | Platform MUST NOT request a new cert when a PR preview is created | Must | No new Certificate resource after PR open |
| FR-011 | Certificates MUST auto-renew at least 30 days before expiry | Must | cert-manager default renewBefore behavior |
| FR-012 | Preview URLs MUST follow pattern `api-pr-<N>.<app>.apps.ashleyhollis.com` | Must | PR comment URL matches pattern |
| FR-013 | Preview environments MUST be ready within 5 minutes of PR opened | Must | Time from PR open to HTTPS accessible |
| FR-014 | Preview environments MUST be removed automatically on PR close/merge | Must | Namespace gone within 5 min of close |
| FR-015 | DNS records for removed previews MUST be cleaned up within 10 minutes | Must | Cloudflare dashboard / nslookup no longer resolves |
| FR-016 | System MUST NOT depend on nip.io, sslip.io, xip.io, or equivalent | Must | `grep -r "nip.io\|sslip.io\|xip.io" .` returns nothing |
| FR-017 | CI/CD pipeline MUST post a PR comment with SWA and API preview URLs | Must | PR comment appears after workflow run |
| FR-018 | API MUST provide `/api/auth/login` endpoint accepting optional `returnTo` param | Must | `GET /api/auth/login?returnTo=...` redirects to Auth0 |
| FR-019 | API MUST provide `/api/auth/callback/auth0` endpoint to complete Auth0 flow | Must | Auth0 redirect lands and sets session cookie |
| FR-020 | API MUST provide `/api/auth/logout` endpoint that clears session | Must | `POST /api/auth/logout` removes session cookie |
| FR-021 | Session credentials MUST be delivered as secure HttpOnly cookies | Must | Response headers contain `Set-Cookie` with HttpOnly;Secure |
| FR-022 | API MUST enforce strict origin allowlist for credentialed requests | Must | Origins outside allowlist receive CORS rejection |
| FR-023 | API MUST NOT permit `*` for credentialed cross-origin requests | Must | No wildcard in `Access-Control-Allow-Origin` for credentialed requests |
| FR-024 | Identity provider MUST permit callbacks from all app hostnames | Must | Auth0 Allowed Callback URLs include wildcard pattern |
| FR-025 | Identity provider MUST permit cross-origin requests from prod and SWA preview domains | Must | Auth0 Allowed Web Origins includes `*.azurestaticapps.net` |

---

## Non-Functional Requirements

| ID | Requirement | Metric | Target |
|----|------------|--------|--------|
| NFR-1 | Preview environment availability | Time from PR open to HTTPS accessible | < 5 minutes |
| NFR-2 | DNS cleanup after PR close | Time for DNS record removal | < 10 minutes |
| NFR-3 | Certificate renewal | Days before expiry renewal begins | ≥ 30 days |
| NFR-4 | Rate limit incidents | Cert authority rate limit errors per month | 0 |
| NFR-5 | Orphaned resource cleanup | Resources remaining after PR close | 0 |

---

## Glossary

| Term | Definition |
|------|-----------|
| Application Environment | A running instance of the application (production, staging, or PR preview) with its own hostname and routing configuration |
| Per-App Wildcard Certificate | A single TLS certificate covering every environment for one application, shared across all current and future previews |
| Preview Environment | An ephemeral, isolated deployment created for a pull request, auto-removed on PR closure |
| DNS Ownership Record | A TXT companion record tracking which automation system owns a DNS entry, preventing record collisions |
| Gateway API | Kubernetes-native API for traffic routing (HTTPRoute, GatewayClass, Gateway CRDs) |
| ExternalDNS | Kubernetes controller that creates/deletes Cloudflare DNS records based on HTTPRoute hostnames |
| DNS-01 Challenge | ACME validation method that proves domain ownership via DNS TXT records; required for wildcard certs |

---

## Out of Scope

- Global identity provider logout
- Multi-app support beyond `yt-summarizer`
- Custom domains for SWA preview environments
- IPv6 support
- Mutual TLS
- WAF/rate limiting at routing layer

---

## Dependencies

- Cloudflare account with `ashleyhollis.com` zone (team-owned)
- Azure Key Vault for Cloudflare API token storage
- ExternalSecret operator (ClusterSecretStore: `azure-keyvault-cluster`)
- Existing Argo CD ApplicationSet for preview lifecycle
- Auth0 tenant with wildcard callback URL support

---

## Success Criteria

See `goals.md` — SC-001 through SC-009. All criteria verified live with PR #5 on 2026-01-12.
