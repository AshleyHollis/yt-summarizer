# Requirements: Auth0 BFF Authentication + RBAC

**Feature ID**: F004  
**Status**: Implementing  
**Milestone**: M3

---

## Goal

Integrate Auth0 authentication end-to-end in the Next.js UI with session management and role-based access control, enabling end users to sign in via social providers and giving admins protected access to administrative features, while automated tests authenticate reliably via test accounts.

---

## User Stories

### US-1: Social Login Authentication
**As an** end user  
**I want to** sign in with my Google or GitHub account  
**So that** I can access the application without creating new credentials

**Acceptance Criteria:**
- [ ] AC-1.1: Given an unauthenticated user on the login page, when they click "Sign in with Google", they are redirected to Google's OAuth consent screen
- [ ] AC-1.2: Given a user completes Google OAuth consent, when Google redirects back to the app, the user is authenticated and sees their role-appropriate dashboard
- [ ] AC-1.3: Given an authenticated user, when they refresh the page, they remain logged in (session persists)
- [ ] AC-1.4: Given an authenticated user, when they click "Sign Out", they are logged out and redirected to the login page
- [ ] AC-1.5: Given a user who previously signed in, when they return before session expiry, they are automatically authenticated

---

### US-2: Role-Based Access Control
**As an** admin user  
**I want to** access administrative features that are unavailable to normal users  
**So that** privileged operations are protected from unauthorized access

**Acceptance Criteria:**
- [ ] AC-2.1: Given an admin user is authenticated, when they navigate to `/admin`, they can access all administrative features
- [ ] AC-2.2: Given a normal user is authenticated, when they navigate to `/admin` directly, they are redirected to an access-denied page
- [ ] AC-2.3: Given an admin user views the navigation menu, admin-specific menu items are visible
- [ ] AC-2.4: Given a normal user views the navigation menu, admin-specific menu items are hidden
- [ ] AC-2.5: Given an unauthenticated user, when they attempt to access any protected page, they are redirected to the login page

---

### US-3: Username/Password Authentication for Testing
**As a** QA tester or automated test system  
**I want to** authenticate via username/password without depending on social providers  
**So that** tests run reliably in CI/CD without external OAuth dependencies

**Acceptance Criteria:**
- [ ] AC-3.1: Given a tester retrieves admin test credentials from Key Vault, when they log in with username/password, they authenticate successfully as an admin user
- [ ] AC-3.2: Given an automated test suite uses stored username/password credentials, when it runs, it completes the authentication flow without social provider interaction
- [ ] AC-3.3: Given test accounts exist, when they authenticate, they have appropriate role assignments (admin or normal)
- [ ] AC-3.4: Given multiple testers work simultaneously, they can all authenticate using different test accounts without conflicts
- [ ] AC-3.5: Given the login page is displayed, users see both social login buttons AND a username/password form
- [ ] AC-3.6: Given Terraform is applied, all test accounts are automatically created with credentials stored in Azure Key Vault
- [ ] AC-3.7: Given Terraform destroy + apply is executed, all test accounts are recreated with the same credentials from Key Vault

---

### US-4: Test Suite Continuity
**As a** developer  
**I want** all existing and new automated tests to work after authentication is added  
**So that** CI/CD continues to pass and we can detect regressions safely

**Acceptance Criteria:**
- [ ] AC-4.1: Given authentication is implemented, when unit tests run in CI, all pass without modification
- [ ] AC-4.2: Given authentication is implemented, when integration tests run in CI, all pass with credentials from Key Vault
- [ ] AC-4.3: Given E2E tests run in CI, they can authenticate as different user roles and verify role-specific behaviour
- [ ] AC-4.4: Given CI pipeline is running, test credentials are retrieved from Key Vault automatically (no manual intervention)
- [ ] AC-4.5: Given E2E tests test unauthenticated flows, they can verify redirect to login page
- [ ] AC-4.6: Given E2E tests test authenticated flows, they can log in, perform actions, and log out
- [ ] AC-4.7: Given CI pipeline completes, test execution time is ≤ 20% above pre-auth baseline

---

## Functional Requirements

| ID | Requirement | Priority | Story |
|----|------------|----------|-------|
| FR-001 | System MUST integrate third-party authentication in the UI with redirect-based OAuth flow | Must | US-1 |
| FR-002 | System MUST support Google and GitHub social login providers | Must | US-1 |
| FR-003 | System MUST support username/password authentication for test accounts | Must | US-3 |
| FR-004 | Login page MUST present both social login options AND a username/password form | Must | US-3 |
| FR-005 | System MUST distinguish between "admin" and "normal user" roles | Must | US-2 |
| FR-006 | User role MUST be stored in authentication provider user metadata | Must | US-2 |
| FR-007 | Admin-only routes and components MUST be protected from unauthorized access | Must | US-2 |
| FR-008 | UI elements MUST be shown or hidden based on user role | Must | US-2 |
| FR-009 | User session state MUST persist across page refreshes and navigation | Must | US-1 |
| FR-010 | System MUST provide a sign-out mechanism that clears session and tokens | Must | US-1 |
| FR-011 | Unauthenticated users MUST be redirected to login when accessing protected routes | Must | US-2 |
| FR-012 | System MUST create username/password test accounts for QA and automated testing | Must | US-3 |
| FR-013 | Test account credentials MUST be stored in Azure Key Vault | Must | US-3 |
| FR-014 | Test credentials MUST include both admin and normal user accounts | Must | US-3 |
| FR-015 | Authentication errors MUST be handled gracefully with user-friendly messages | Must | US-1 |
| FR-015a | On session expiry, system MUST redirect to login with "Session expired" message and preserve destination URL | Must | US-1 |
| FR-015b | On OAuth failure, system MUST display inline error with retry button and alternate provider option | Must | US-1 |
| FR-016 | Authentication tokens MUST be validated on protected API requests | Must | US-4 |
| FR-017 | System MUST sync user authentication state between UI and API layers | Must | US-4 |
| FR-018 | Automated tests MUST be able to authenticate via username/password without social providers | Must | US-4 |
| FR-019 | All authentication infrastructure MUST be deployable via IaC with zero manual steps | Must | All |
| FR-021 | All existing automated tests MUST continue to pass after authentication is implemented | Must | US-4 |
| FR-022 | CI/CD pipelines MUST execute all test suites with authentication enabled | Must | US-4 |
| FR-023 | Test suites MUST authenticate programmatically without manual intervention | Must | US-4 |
| FR-024 | E2E tests MUST cover both authenticated and unauthenticated user flows | Must | US-4 |
| FR-025 | Auth functionality MUST be contained in a clearly bounded, self-contained module | Must | All |
| FR-026 | Non-auth areas MUST interact with auth only through a defined public interface | Must | All |
| FR-027 | All auth functions MUST be independently verifiable via automated tests without external services | Must | All |
| FR-028 | Auth module MUST support simulated external provider calls in test environments | Must | All |
| FR-029 | RBAC logic MUST be extensible to additional roles without modifying core auth logic | Should | US-2 |
| FR-030 | Auth provider configuration MUST be configuration-driven, not hardcoded conditionals | Should | US-2 |
| FR-031 | Auth module MUST include developer documentation: setup, usage examples, architecture overview | Should | All |
| FR-032 | Public auth interface MUST be documented with usage examples and defined contracts | Should | All |
| FR-033 | Auth module MUST expose a single public interface; internals remain private | Must | All |
| FR-034 | Each distinct auth failure mode MUST produce a distinct, self-describing error state | Must | US-1 |
| FR-035 | System MUST log security-critical auth events with correlation IDs | Should | All |

---

## Non-Functional Requirements

| ID | Requirement | Metric | Target |
|----|------------|--------|--------|
| NFR-001 | Social login completion time | Time from "Sign In" click to dashboard | < 30 s (SC-001) |
| NFR-002 | RBAC enforcement | Unauthorized admin access attempts blocked | 100% (SC-002) |
| NFR-003 | Session duration | Session persistence without re-auth | ≥ 24 h (SC-003) |
| NFR-004 | Test reliability | Authentication success rate in CI | ≥ 95% on first try (SC-007) |
| NFR-005 | CI test time delta | Increase over pre-auth baseline | ≤ 20% (SC-014) |
| NFR-006 | IaC coverage | Auth infrastructure deployed via Terraform | 100% (SC-011) |
| NFR-007 | Password storage | User passwords in app database | Zero (SC-005) |
| NFR-008 | Test pass rate | Existing tests after auth implementation | 100% (SC-013) |

---

## Glossary

| Term | Definition |
|------|-----------|
| BFF | Backend-for-Frontend — server-side session management proxied through Next.js |
| `app_metadata` | Auth0 user field for server-managed data (not user-editable); used to store role |
| Custom claim | JWT claim with namespaced key (`https://yt-summarizer.com/role`) added via Auth0 Action |
| Auth0 Action | JavaScript function triggered at login to enrich tokens with custom claims |
| Storage state | Playwright mechanism to save/restore browser cookies and localStorage between tests |
| ROPG | Resource Owner Password Grant — OAuth grant type (rejected for Free tier violation of FR-019) |

---

## Dependencies

- Auth0 tenant already configured and integrated with API backend
- Terraform Auth0 provider configured with Management API credentials
- Azure Key Vault provisioned and accessible from CI/CD (OIDC already configured)
- Social provider OAuth apps (Google, GitHub) registered externally; credentials in Key Vault
- Auth0 database connection enabled via Terraform

---

## Out of Scope

- Multi-factor authentication (requires paid Auth0 tier)
- Custom registration forms beyond Auth0 Universal Login
- User profile editing, password reset UI
- Fine-grained permissions beyond admin/normal
- User invitation flows, account linking
- Custom OAuth providers beyond Google and GitHub
- Self-service username/password registration

---

## Success Criteria

See `goals.md` § Success Criteria. Measurable outcomes: SC-001 through SC-023 as defined in the original spec.
