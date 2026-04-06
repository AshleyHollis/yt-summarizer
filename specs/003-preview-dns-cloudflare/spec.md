# Feature Specification: Migrate Preview DNS/TLS from nip.io to apps.ashleyhollis.com

**Feature Branch**: `003-preview-dns-cloudflare`  
**Created**: January 11, 2026  
**Completed**: January 12, 2026  
**Status**: Complete  
**Input**: User description: "Migrate Preview DNS/TLS from nip.io to apps.ashleyhollis.com (Cloudflare Delegation + Gateway API + Per-App Wildcard Certs)"

---

## Context

The preview platform was using third-party wildcard DNS services (nip.io/sslip.io) together with individually-issued TLS certificates for each preview environment. This approach hit certificate authority rate limits because:

1. Shared third-party domains caused rate limit collisions with other users on those services
2. Issuing a fresh certificate per pull request consumed the weekly quota quickly

This feature replaces that approach with a dedicated subdomain under the team's own domain (`apps.ashleyhollis.com`), automated DNS record management, and a single wildcard certificate per application that covers every environment — eliminating both the rate limit risk and the dependency on external DNS services.

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

#### DNS Management

- **FR-001**: The platform MUST provide dedicated, human-readable DNS hostnames under `apps.ashleyhollis.com` for every application environment (production, staging, and each pull request preview).
- **FR-002**: DNS records MUST be created automatically when a new environment is provisioned and removed automatically when that environment is torn down — no manual DNS changes required.
- **FR-003**: Automated DNS management MUST be scoped exclusively to `apps.ashleyhollis.com`; records in any other zone MUST NOT be modified automatically.
- **FR-004**: The credentials used for automated DNS management MUST follow least-privilege — granting only the minimum permissions necessary and nothing broader.

#### Traffic Routing

- **FR-005**: All plain HTTP traffic to application hostnames MUST be automatically redirected to HTTPS.
- **FR-006**: The platform MUST route each incoming hostname to the correct application service without additional manual configuration per environment.
- **FR-007**: Production, staging, and all preview environments MUST be served through the same shared routing layer with no per-environment infrastructure duplication.

#### Certificates & TLS

- **FR-008**: The platform MUST provision browser-trusted TLS certificates covering all hostnames under `apps.ashleyhollis.com`.
- **FR-009**: A single certificate per application MUST cover every environment for that application, including all current and future pull request previews.
- **FR-010**: The platform MUST NOT request a new certificate when a pull request preview environment is created; the existing per-application certificate MUST be reused.
- **FR-011**: Certificates MUST auto-renew at least 30 days before expiry without any service disruption or manual intervention.

#### Preview Workflow

- **FR-012**: Pull request preview environments MUST be accessible at the URL pattern `api-pr-<PR_NUMBER>.<app>.apps.ashleyhollis.com`.
- **FR-013**: Preview environments MUST be provisioned automatically when a pull request is opened and must be ready within 5 minutes.
- **FR-014**: Preview environments MUST be fully removed automatically when their pull request is closed or merged.
- **FR-015**: DNS records for a removed preview environment MUST be cleaned up within 10 minutes of the environment teardown.
- **FR-016**: The system MUST NOT depend on any third-party wildcard DNS service (nip.io, sslip.io, xip.io, or equivalent).
- **FR-017**: The CI/CD pipeline MUST post a comment on each pull request containing both the SWA preview URL and the API preview URL.

#### Authentication (Auth0 BFF)

- **FR-018**: The API MUST provide an authentication initiation endpoint (`/api/auth/login`) that redirects users to the identity provider and accepts an optional post-login return URL.
- **FR-019**: The API MUST provide an authentication callback endpoint that completes the identity provider flow and establishes a user session.
- **FR-020**: The API MUST provide a logout endpoint that clears the user's session.
- **FR-021**: Session credentials MUST be delivered as secure, HTTP-only cookies that work correctly for credentialed cross-origin requests from SWA preview domains.
- **FR-022**: The API MUST enforce a strict allowlist of permitted cross-origin origins for all credentialed requests.
- **FR-023**: The API MUST NOT permit unrestricted cross-origin access (`*`) for credentialed requests.

#### Identity Provider Configuration

- **FR-024**: The identity provider application MUST permit authentication callbacks from all application hostnames (production, staging, and preview).
- **FR-025**: The identity provider application MUST permit cross-origin requests from the production web domain and SWA preview domains.

### Key Entities

- **Application Environment**: A running instance of the application (production, staging, or pull-request preview) with its own hostname and routing configuration.
- **Per-App Wildcard Certificate**: A single TLS certificate that covers every environment for one application, shared across all current and future previews to avoid certificate authority rate limits.
- **Preview Environment**: An ephemeral, isolated deployment created for a pull request, identified by its PR number, and automatically removed on PR closure.
- **DNS Ownership Record**: A companion record created alongside each DNS entry to track which automation system owns it, preventing record collisions when multiple tools are running.

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Pull request preview environments are accessible via browser-trusted HTTPS within 5 minutes of the PR being opened.
- **SC-002**: No certificate warnings or errors appear when accessing any preview URL in any modern browser.
- **SC-003**: Zero certificate authority rate limit errors occur during normal operation, regardless of how many simultaneous preview environments exist.
- **SC-004**: Exactly one certificate exists per application at all times, regardless of the number of active pull request previews.
- **SC-005**: DNS records for closed pull requests are removed within 10 minutes of PR closure.
- **SC-006**: Preview cleanup leaves no orphaned resources — no dangling namespaces, DNS records, or credentials remain after a PR is closed.
- **SC-007**: Zero references to third-party wildcard DNS services (nip.io, sslip.io, xip.io) remain anywhere in code, workflows, or configuration.
- **SC-008**: Authenticated SWA preview users can successfully call protected API preview endpoints with their credentials intact.
- **SC-009**: Runbooks exist and are verified for all foreseeable failure modes: certificate issuance failures, DNS record creation failures, and routing attachment issues.

---

## Assumptions

1. **App naming**: The primary application is named `yt-summarizer`. Hostname patterns use this app name (e.g., `api-pr-42.yt-summarizer.apps.ashleyhollis.com`).
2. **DNS zone ownership**: The team owns and controls the `ashleyhollis.com` DNS zone and can delegate `apps.ashleyhollis.com` records to automated management.
3. **Certificate authority**: The certificate authority (Let's Encrypt) supports DNS-based validation for wildcard certificates via a DNS provider API.
4. **Single routing layer**: A single shared routing component in the cluster handles all application traffic; multi-instance routing is not required initially.
5. **Identity provider wildcard support**: The identity provider supports wildcard patterns in allowed callback URLs (e.g., `https://api-pr-*.yt-summarizer.apps.ashleyhollis.com/...`) or enumeration of specific preview URLs.
6. **SWA preview URL format**: Azure Static Web Apps preview URLs follow a predictable pattern under `*.azurestaticapps.net`.
7. **Cloudflare Free tier**: The Cloudflare Free tier is sufficient for the required DNS management API features.

---

## Out of Scope

- Global identity provider logout (local session logout only — invalidating the session at the identity provider is a separate feature)
- Multi-app support beyond `yt-summarizer` (the same patterns apply and can be extended, but configuration is out of scope here)
- Custom domains for SWA preview environments (SWA previews use `azurestaticapps.net` managed by Azure)
- IPv6 address record support
- Mutual TLS or client certificate authentication
- Rate limiting or web application firewall rules at the routing layer
