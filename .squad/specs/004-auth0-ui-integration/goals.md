# Goals: Auth0 BFF Authentication + RBAC

**Feature ID**: F004  
**Status**: Implementing  
**Milestone**: M3  
**Phase**: execution  
**Created**: 2026-01-19  
**Updated**: 2026-06-01

---

## Problem Statement

The application has Auth0 integrated at the API layer but users have no way to sign in via the UI. There is no session management, no role-based UI, and no way for automated tests or QA testers to authenticate reliably. End users cannot access the application without a working login flow, and administrators cannot perform privileged operations because admin-gated pages do not yet exist.

---

## Success Criteria

1. A user can click "Sign in with Google" or "Sign in with GitHub" on the login page, complete the OAuth consent flow, and land on their dashboard — all in under 30 seconds.
2. An admin user can navigate to `/admin` and use all administrative features; a normal user who visits the same URL is redirected to an access-denied page.
3. Sessions survive page refreshes and tab re-opens for at least 24 hours without requiring re-authentication.
4. A tester can run `./scripts/run-tests.ps1` against a freshly deployed environment and every test (unit, integration, E2E) passes at 100% — credentials are fetched automatically from Azure Key Vault.
5. The full CI/CD test run takes no more than 20% longer than the pre-auth baseline.
6. Zero user passwords exist in the application database or repository.

---

## In Scope

- `@auth0/nextjs-auth0` SDK integration in the Next.js App Router frontend
- Cookie-based BFF session management via `proxy.ts` (Next.js 16 middleware)
- Auth0 API route handlers (`/api/auth/[auth0]`)
- Login page with Google, GitHub, and username/password options
- `AuthContext` + `useAuth()` hook as the single public auth interface
- Role-based route protection: admin vs. normal user
- Admin dashboard page and access-denied page
- Role-based navigation menu rendering
- Auth0 Action injecting `app_metadata.role` into token custom claims
- Terraform: database connection, Google/GitHub social connections, Auth0 Actions, trigger bindings
- Terraform: admin + normal test user provisioning with credentials stored in Azure Key Vault
- Playwright programmatic authentication with storage-state reuse
- GitHub Actions step to retrieve test credentials from Azure Key Vault
- Auth event logging with correlation IDs
- Auth module documentation (README, quickstart, JSDoc)

---

## Out of Scope

- Multi-factor authentication (MFA) — requires Auth0 paid tier
- Custom user registration forms beyond Auth0 Universal Login
- User profile editing
- Password reset flows (Auth0 built-in handles this)
- Fine-grained permissions beyond admin/normal
- User invitation flows
- Account linking (social ↔ username/password for same email)
- Custom OAuth providers beyond Google and GitHub
- Self-service user registration via username/password

---

## Constraints

- Auth0 **Free tier**: 25 K MAU, no native RBAC — roles must use `app_metadata`
- Zero manual Auth0 dashboard operations — 100% Terraform IaC (FR-019, SC-011)
- No secrets in repository — all credentials via Azure Key Vault
- All existing automated tests must continue to pass (SC-013)
- CI/CD test execution time increase ≤ 20% (SC-014)
- `@auth0/nextjs-auth0` is the only new direct dependency (pinned version)

---

## Users

| User Type | Description |
|-----------|-------------|
| End user (normal) | Authenticated via Google or GitHub; accesses video submission and summaries |
| Admin user | Authenticated via any method; accesses admin dashboard and user management |
| QA tester / CI | Authenticates via username/password test accounts stored in Key Vault |
| AI agent (E2E) | Same as QA tester — programmatic auth using storage-state reuse |

---

## Testing Expectations

- **Unit tests** (Vitest): `useAuth` hook, `hasRole` utility, all auth components — mocked Auth0 SDK, no network calls
- **Integration tests** (pytest): API token validation, existing API tests updated with auth headers
- **E2E tests** (Playwright): Social login flow, session persistence, sign-out, RBAC admin/normal access, unauthenticated redirect, programmatic auth setup
- **100% pass rate required** before marking feature complete (Constitution VI.10)
- TDD order: unit tests written and failing before implementation
