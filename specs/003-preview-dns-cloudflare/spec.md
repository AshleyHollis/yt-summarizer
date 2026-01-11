# Feature Specification: Migrate Preview DNS/TLS from nip.io to apps.ashleyhollis.com

**Feature Branch**: `003-preview-dns-cloudflare`  
**Created**: January 11, 2026  
**Status**: Draft  
**Input**: User description: "Migrate Preview DNS/TLS from nip.io to apps.ashleyhollis.com (Cloudflare Delegation + Gateway API + Per-App Wildcard Certs)"

---

## Problem Statement

The current preview platform on AKS uses wildcard DNS services (nip.io/sslip.io) combined with cert-manager and Let's Encrypt for TLS in preview environments. This approach is hitting Let's Encrypt rate limits due to:

1. Shared domains (nip.io) causing rate limit collisions with other users
2. Per-preview certificate issuance creating excessive certificate requests

Preview environments must remain fast to create, provide browser-trusted TLS, and eliminate dependency on external wildcard DNS services.

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Developer Creates a PR Preview (Priority: P1)

A developer opens a pull request on GitHub. The CI/CD pipeline automatically creates a preview environment with browser-trusted HTTPS endpoints. The developer can immediately access the API at a predictable URL without certificate warnings.

**Why this priority**: This is the core use case—developers need fast, trusted preview environments for every PR to test changes before merging.

**Independent Test**: Create a PR, wait for deployment to complete, and access `https://api-pr-<PR>.yt-summarizer.apps.ashleyhollis.com` in a browser. The connection must be secure with a valid certificate.

**Acceptance Scenarios**:

1. **Given** a developer opens PR #42, **When** the preview workflow completes, **Then** `https://api-pr-42.yt-summarizer.apps.ashleyhollis.com` is reachable with a browser-trusted TLS certificate.

2. **Given** a developer opens PR #42, **When** the preview workflow completes, **Then** the PR receives a comment containing the API preview URL and SWA preview URL.

3. **Given** the SWA preview is deployed, **When** the frontend makes authenticated API calls to the preview API, **Then** the requests succeed with cookies/credentials intact.

---

### User Story 2 - Developer Closes/Merges a PR (Priority: P1)

When a developer closes or merges a PR, the preview environment is automatically cleaned up. DNS records are removed, and the namespace is deleted. No orphaned resources remain.

**Why this priority**: Cleanup is essential to prevent resource leakage and DNS record accumulation that could cause conflicts.

**Independent Test**: Close a PR that had a preview environment, then verify the namespace `preview-pr-<PR>` no longer exists and DNS records for `api-pr-<PR>.yt-summarizer.apps.ashleyhollis.com` are removed.

**Acceptance Scenarios**:

1. **Given** PR #42 has an active preview environment, **When** the PR is closed/merged, **Then** the namespace `preview-pr-42` is deleted within 5 minutes.

2. **Given** PR #42 has an active preview environment, **When** the PR is closed/merged, **Then** DNS records for `api-pr-42.yt-summarizer.apps.ashleyhollis.com` are removed within 10 minutes.

---

### User Story 3 - Platform Team Provisions Per-App Wildcard Certificates (Priority: P1)

The platform team configures cert-manager to issue one wildcard certificate per application (e.g., `*.yt-summarizer.apps.ashleyhollis.com`). This certificate is shared across all environments (prod, staging, previews) for that app, eliminating per-PR certificate issuance.

**Why this priority**: This directly solves the Let's Encrypt rate limit problem and must be in place before previews can use the new DNS scheme.

**Independent Test**: Check that only one Certificate resource exists per app in the `gateway-system` namespace, and that all HTTPRoutes for that app's hostnames use TLS successfully.

**Acceptance Scenarios**:

1. **Given** the platform is configured for app `yt-summarizer`, **When** I list Certificate resources, **Then** only one certificate exists for `*.yt-summarizer.apps.ashleyhollis.com`.

2. **Given** the wildcard certificate is issued, **When** a new preview is created for PR #99, **Then** no new Certificate resource is created; the existing wildcard is used.

---

### User Story 4 - Authenticated User Accesses Preview via SWA Frontend (Priority: P2)

An authenticated user accesses a preview SWA frontend and performs actions that require API calls. The authentication cookies flow correctly from the SWA preview domain to the API preview endpoint.

**Why this priority**: Authentication across domains is critical for testing user-facing features in previews, but can be implemented after the core infrastructure.

**Independent Test**: Log in via the preview API's `/api/auth/login` endpoint, then access a protected resource from the SWA preview. The request should succeed with credentials.

**Acceptance Scenarios**:

1. **Given** a user logs in via `https://api-pr-42.yt-summarizer.apps.ashleyhollis.com/api/auth/login`, **When** the SWA preview calls a protected API endpoint with credentials, **Then** the API accepts the session cookie and returns data.

2. **Given** CORS is configured, **When** the SWA preview origin makes a credentialed request, **Then** the API responds with correct `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` headers.

---

### User Story 5 - Platform Team Debugs Certificate or DNS Issues (Priority: P3)

When certificate issuance fails or DNS records aren't created, the platform team has runbooks and observability to diagnose and resolve the issue quickly.

**Why this priority**: Operational reliability is important but can be documented after core functionality works.

**Independent Test**: Simulate a DNS-01 challenge failure, then follow the runbook to diagnose and remediate.

**Acceptance Scenarios**:

1. **Given** a cert-manager DNS-01 challenge fails, **When** the operator follows the troubleshooting runbook, **Then** the operator can identify the root cause (Cloudflare API token permissions, DNS propagation, etc.).

2. **Given** ExternalDNS fails to create a record, **When** the operator checks ExternalDNS logs, **Then** the logs clearly indicate the failure reason.

---

### Edge Cases

- What happens when two PRs are created simultaneously? Both should get independent DNS records and use the same wildcard certificate without conflict.
- What happens when Cloudflare API is temporarily unavailable? DNS record creation should retry; existing records and certificates remain functional.
- What happens when an HTTPRoute is deleted before the namespace? ExternalDNS should still remove the DNS record via TXT ownership registry.
- What happens when the wildcard certificate expires or needs renewal? cert-manager should auto-renew 30 days before expiry without impacting existing routes.

---

## Requirements *(mandatory)*

### Functional Requirements

#### DNS & Cloudflare

- **FR-001**: System MUST create DNS records within the existing Cloudflare zone `ashleyhollis.com` for hostnames under `apps.ashleyhollis.com` (e.g., wildcard record `*.yt-summarizer.apps` for routing, plus automated TXT records for DNS-01 challenges).
- **FR-002**: System MUST use a Cloudflare API token with least-privilege permissions for cert-manager (TXT records for DNS-01) and ExternalDNS (A/CNAME record management).
- **FR-003**: All DNS records under `apps.ashleyhollis.com` MUST be managed exclusively through automation (ExternalDNS) or documented manual procedures.

#### Gateway API & Routing

- **FR-004**: System MUST install Gateway API CRDs (standard channel) in the AKS cluster.
- **FR-005**: System MUST deploy a Gateway API controller (NGINX Gateway Fabric) in the cluster.
- **FR-006**: System MUST configure a shared `Gateway` resource in `gateway-system` namespace that terminates TLS for all `*.apps.ashleyhollis.com` traffic.
- **FR-007**: System MUST define a `GatewayClass` resource for the NGINX Gateway Fabric controller.
- **FR-008**: Each environment (prod, staging, preview) MUST have an `HTTPRoute` that routes traffic from its hostname to the appropriate backend service.

#### Certificates & TLS

- **FR-009**: System MUST configure a cert-manager `ClusterIssuer` using Let's Encrypt production with DNS-01 challenge via Cloudflare.
- **FR-010**: System MUST issue one wildcard `Certificate` per app (e.g., `*.yt-summarizer.apps.ashleyhollis.com`) stored in `gateway-system` namespace.
- **FR-011**: System MUST NOT issue per-preview certificates; all previews MUST use the app's wildcard certificate.
- **FR-012**: Gateway listeners MUST reference the per-app wildcard certificate secrets for TLS termination.
- **FR-013**: Certificates MUST auto-renew at least 30 days before expiry.

#### ExternalDNS

- **FR-014**: System MUST deploy ExternalDNS configured to watch Gateway API `HTTPRoute` resources.
- **FR-015**: ExternalDNS MUST create A/CNAME records in Cloudflare when HTTPRoutes are created.
- **FR-016**: ExternalDNS MUST delete DNS records when HTTPRoutes are deleted or namespaces are removed.
- **FR-017**: ExternalDNS MUST use TXT registry ownership to prevent record collisions.
- **FR-018**: ExternalDNS MUST be domain-filtered to only manage records under `apps.ashleyhollis.com`.

#### Preview Workflow

- **FR-019**: GitHub Actions MUST compute preview hostnames using pattern `api-pr-<PR>.{app}.apps.ashleyhollis.com`.
- **FR-020**: GitHub Actions MUST deploy preview resources: namespace, deployment, service, and HTTPRoute.
- **FR-021**: GitHub Actions MUST pass `API_BASE_URL` to SWA build pointing to the preview API hostname.
- **FR-022**: GitHub Actions MUST post a PR comment with both SWA preview URL and API preview URL.
- **FR-023**: On PR close, GitHub Actions MUST delete the preview namespace, triggering cascade deletion of HTTPRoute and DNS records.
- **FR-024**: System MUST NOT use nip.io, sslip.io, xip.io, or any similar wildcard DNS service.

#### Authentication (Auth0 BFF)

- **FR-025**: API MUST implement `/api/auth/login?returnTo=<web-url>` endpoint that initiates Auth0 authorization flow.
- **FR-026**: API MUST implement `/api/auth/callback/auth0` endpoint that handles Auth0 callback and sets session cookie.
- **FR-027**: API MUST implement `POST /api/auth/logout` endpoint that clears the session cookie (local logout only initially).
- **FR-028**: Session cookies MUST be configured with: `HttpOnly`, `Secure`, `Path=/`, `SameSite=None` (for cross-origin SWA requests).
- **FR-029**: Cookies MUST NOT set a `Domain` attribute (host-only cookies).
- **FR-030**: API MUST implement strict CORS origin allowlist supporting credentialed requests from production web domain and `*.azurestaticapps.net` SWA previews.
- **FR-031**: API MUST NOT use `Access-Control-Allow-Origin: *` with credentials.

#### Auth0 Configuration

- **FR-032**: Auth0 application MUST have allowed callback URLs for prod, staging, and preview API hostnames.
- **FR-033**: Auth0 application MUST have allowed web origins for production web domain and SWA preview domains.

### Key Entities

- **Gateway**: Shared Kubernetes resource that terminates TLS and routes traffic to HTTPRoutes. Lives in `gateway-system` namespace.
- **HTTPRoute**: Per-environment routing rule that maps a hostname to a backend service. Created in each environment's namespace.
- **Certificate**: Per-app wildcard TLS certificate issued by cert-manager. Referenced by Gateway listeners.
- **ClusterIssuer**: Cluster-wide cert-manager configuration for Let's Encrypt DNS-01 via Cloudflare.
- **Preview Namespace**: Ephemeral namespace (`preview-pr-<PR>`) containing all preview resources for a PR.

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Preview environments are accessible via browser-trusted HTTPS within 5 minutes of PR creation.
- **SC-002**: No certificate warnings or errors appear when accessing any preview URL in modern browsers.
- **SC-003**: Zero Let's Encrypt rate limit errors occur during normal operation (no per-preview certificate issuance).
- **SC-004**: Only one Certificate resource exists per app, regardless of the number of active preview environments.
- **SC-005**: DNS records for closed PRs are removed within 10 minutes of PR closure.
- **SC-006**: Preview cleanup completes without orphaned resources (namespaces, DNS records, or secrets).
- **SC-007**: Zero references to nip.io, sslip.io, or xip.io remain in code, workflows, or manifests.
- **SC-008**: Authenticated SWA preview users can successfully call protected API preview endpoints.
- **SC-009**: Runbooks exist and are verified for: cert-manager DNS-01 failures, ExternalDNS record creation failures, and Gateway/HTTPRoute attachment issues.

---

## Assumptions

1. **App naming**: The primary application is named `yt-summarizer`. Hostname patterns use this app name (e.g., `api-pr-42.yt-summarizer.apps.ashleyhollis.com`).
2. **Cloudflare Free tier**: Cloudflare Free tier is sufficient for the required DNS and API features.
3. **NGINX Gateway Fabric**: NGINX Gateway Fabric is the chosen Gateway API controller unless the platform already uses a different controller.
4. **Let's Encrypt production**: Using Let's Encrypt production (not staging) for trusted certificates.
5. **Single Gateway**: A single shared Gateway in `gateway-system` handles all app traffic; multi-gateway is not required initially.
6. **Auth0 wildcard support**: Auth0 supports wildcard patterns in allowed callback URLs (e.g., `https://api-pr-*.yt-summarizer.apps.ashleyhollis.com/...`) or requires enumeration of allowed URLs.
7. **SWA preview URL format**: Azure Static Web Apps preview URLs follow a predictable pattern under `*.azurestaticapps.net`.

---

## Out of Scope

- Global Auth0 logout (initially implementing local logout only)
- Multi-app support beyond `yt-summarizer` (can be added later using the same patterns)
- Custom domains for SWA preview environments (SWA previews use `azurestaticapps.net`)
- IPv6 (AAAA records) support
- mTLS or client certificate authentication
- Rate limiting or WAF rules at the Gateway level
