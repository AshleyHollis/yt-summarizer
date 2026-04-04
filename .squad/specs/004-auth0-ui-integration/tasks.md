# Tasks: Auth0 BFF Authentication + RBAC

**Feature ID**: F004  
**Status**: Implementing (~50% complete)

## Overview
- **Total Tasks**: 75
- **Completed**: 38
- **Remaining**: 37
- **Workflow**: TDD Red-Green-Yellow
- **Intent**: GREENFIELD

### Phase Distribution
| Phase | Tasks | Completed | Remaining |
|-------|-------|-----------|-----------|
| Phase 1 — Setup | 4 | 4 | 0 |
| Phase 2 — Foundation | 8 | 8 | 0 |
| Phase 3 — US-1 Social Login | 16 | 16 | 0 |
| Phase 4 — US-2 RBAC | 11 | 11 | 0 |
| Phase 5 — US-3 Username/Password | 10 | 10 | 0 |
| Phase 6 — US-4 Test Continuity | 12 | 12 | 0 |
| Phase 7 — Documentation | 6 | 6 | 0 |
| Phase 8 — Polish & Validation | 8 | 8 | 0 |

> ⚠️ All tasks marked `[x]` were completed per the source tasks.md. The 50% implementation note
> in the original spec referred to production deployment status, not task completion status.
> Several tasks (e.g., T044–T047 test account Terraform) and E2E tests (T026–T028, T037–T039,
> T048–T059) may need validation against running infrastructure. See `.progress.md` for detail.

## Completion Criteria
- [x] All tasks checked off
- [ ] All tests passing in CI (100% — SC-013)
- [ ] CI green with auth enabled
- [ ] PR created and reviewed
- [ ] All review comments resolved

---

## Phase 1: Setup

- [x] T001 Install `@auth0/nextjs-auth0` package [P]
  - **Agent**: Lambert
  - **Do**: Add `@auth0/nextjs-auth0` (pinned version) to `apps/web/package.json`; run `npm install`
  - **Files**: `apps/web/package.json`, `apps/web/package-lock.json`
  - **Done when**: Package installed, no peer-dep warnings
  - **Verify**: `cd apps/web && npm ls @auth0/nextjs-auth0`
  - _Requirements: FR-001_

- [x] T002 Add Auth0 env var stubs to `.env.example` [P]
  - **Agent**: Lambert
  - **Do**: Add `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`, `AUTH0_SECRET`, `APP_BASE_URL` to `apps/web/.env.example`
  - **Files**: `apps/web/.env.example`
  - **Done when**: All 5 env vars documented with placeholder values
  - **Verify**: `grep -E "AUTH0_|APP_BASE_URL" apps/web/.env.example`
  - _Requirements: FR-001_

- [x] T003 Configure Vitest mock setup [P]
  - **Agent**: Kane
  - **Do**: Add `vi.mock('@auth0/nextjs-auth0', ...)` global mock in `apps/web/src/__tests__/setup.ts`
  - **Files**: `apps/web/src/__tests__/setup.ts`
  - **Done when**: Mock stubs `getSession`, `withPageAuthRequired`, `withApiAuthRequired`
  - **Verify**: `cd apps/web && npm run test -- --passWithNoTests`

- [x] T004 Create Playwright auth directory [P]
  - **Agent**: Kane
  - **Do**: Create `apps/web/playwright/.auth/` with `.gitkeep`
  - **Files**: `apps/web/playwright/.auth/.gitkeep`
  - **Done when**: Directory exists and is tracked by git
  - **Verify**: `Test-Path apps/web/playwright/.auth`

---

## Phase 2: Foundation

- [x] T005 Create `AuthContext.tsx` with TypeScript interfaces
  - **Agent**: Lambert
  - **Do**: Define `User`, `Session`, `AuthContextValue` interfaces; create `AuthContext` with `AuthProvider` skeleton
  - **Files**: `apps/web/src/contexts/AuthContext.tsx`
  - **Done when**: Context exports `AuthProvider` and `AuthContext`; interfaces match contracts/auth-types.d.ts
  - **Verify**: `cd apps/web && npm run typecheck`
  - _Requirements: FR-025, FR-033_

- [x] T006 Create `useAuth` hook with JSDoc
  - **Agent**: Lambert
  - **Do**: Implement `useAuth()` hook consuming `AuthContext`; add JSDoc with usage example
  - **Files**: `apps/web/src/hooks/useAuth.ts`
  - **Done when**: `useAuth()` returns `AuthContextValue`; throws if used outside `AuthProvider`
  - **Verify**: `cd apps/web && npm run typecheck`
  - _Requirements: FR-026, FR-032_

- [x] T007 Define auth error types [P]
  - **Agent**: Lambert
  - **Do**: Create `AuthError`, `SessionExpiredError`, `UnauthorizedError`, `OAuthError` classes
  - **Files**: `apps/web/src/types/auth.ts`
  - **Done when**: All 4 error types exported; extend `AuthError` base class
  - **Verify**: `cd apps/web && npm run typecheck`
  - _Requirements: FR-034_

- [x] T008 Create `hasRole` pure utility [P]
  - **Agent**: Lambert
  - **Do**: Implement `hasRole(user, role)`, `getAuthMethod(sub)`, `getProvider(sub)` in `auth-utils.ts`
  - **Files**: `apps/web/src/lib/auth-utils.ts`
  - **Done when**: All 3 functions are pure, exported, typed
  - **Verify**: `cd apps/web && npm run test -- auth-utils`
  - _Requirements: FR-027, SC-017_

- [x] T009 Extend Terraform module — connections
  - **Agent**: Parker
  - **Do**: Add `auth0_connection` resources (database, google-oauth2, github) to `infra/terraform/modules/auth0/main.tf`
  - **Files**: `infra/terraform/modules/auth0/main.tf`
  - **Done when**: `terraform plan` shows 3 new connection resources
  - **Verify**: `terraform -chdir=infra/terraform/environments/prod plan -out=tfplan`
  - _Requirements: FR-019, SC-011_

- [x] T010 Extend Terraform module — users
  - **Agent**: Parker
  - **Do**: Add `auth0_user` + `random_password` resources for test accounts
  - **Files**: `infra/terraform/modules/auth0/main.tf`
  - **Done when**: `terraform plan` shows user resources
  - **Verify**: `terraform -chdir=infra/terraform/environments/prod plan`
  - _Requirements: FR-012, FR-019_

- [x] T011 Extend Terraform module — Actions
  - **Agent**: Parker
  - **Do**: Add `auth0_action` (post-login role-claims JS) + `auth0_trigger_actions` binding
  - **Files**: `infra/terraform/modules/auth0/main.tf`
  - **Done when**: Action JS injects `https://yt-summarizer.com/role` claim
  - **Verify**: `terraform -chdir=infra/terraform/environments/prod plan`
  - _Requirements: FR-006, FR-019_

- [x] T012 Add Auth0 connection variables [P]
  - **Agent**: Parker
  - **Do**: Add `google_oauth_client_id`, `google_oauth_client_secret`, `github_oauth_client_id`, `github_oauth_client_secret` to `variables.tf`
  - **Files**: `infra/terraform/environments/prod/variables.tf`
  - **Done when**: All 4 variables declared with descriptions
  - **Verify**: `terraform -chdir=infra/terraform/environments/prod validate`
  - _Requirements: FR-019_

---

## Phase 3: US-1 — Social Login

### Unit Tests

- [x] T013 Unit test — `useAuth` hook [P]
  - **Agent**: Kane
  - **Files**: `apps/web/src/__tests__/hooks/useAuth.test.tsx`
  - **Done when**: Tests cover loading, authenticated, unauthenticated, and error states
  - **Verify**: `cd apps/web && npm run test -- useAuth`
  - _Requirements: FR-027, AC-1.1–AC-1.5_

- [x] T014 Unit test — `hasRole` utility [P]
  - **Agent**: Kane
  - **Files**: `apps/web/src/__tests__/lib/auth-utils.test.ts`
  - **Done when**: Tests cover admin/normal role checks, null user, all provider sub formats
  - **Verify**: `cd apps/web && npm run test -- auth-utils`

- [x] T015 Unit test — `LoginButton` component [P]
  - **Agent**: Kane
  - **Files**: `apps/web/src/__tests__/components/auth/LoginButton.test.tsx`
  - **Done when**: Tests render provider buttons, trigger redirect on click

- [x] T016 Unit test — `UserProfile` component [P]
  - **Agent**: Kane
  - **Files**: `apps/web/src/__tests__/components/auth/UserProfile.test.tsx`
  - **Done when**: Tests render user name/email/avatar, handle null user

### Implementation

- [x] T017 Implement `AuthProvider` with Auth0 SDK
  - **Agent**: Lambert
  - **Files**: `apps/web/src/contexts/AuthContext.tsx`
  - **Done when**: Provider fetches session, exposes `user`, `isLoading`, `error`, `isAuthenticated`, `hasRole`
  - **Verify**: `cd apps/web && npm run test -- AuthContext`
  - _Requirements: FR-009, FR-017_

- [x] T018 Create Auth0 API route handlers
  - **Agent**: Lambert
  - **Files**: `apps/web/src/app/api/auth/[auth0]/route.ts`
  - **Done when**: `/api/auth/login`, `/api/auth/logout`, `/api/auth/callback`, `/api/auth/me` all respond
  - **Verify**: `cd apps/web && npm run build`

- [x] T019 Create `LoginButton` component [P]
  - **Agent**: Lambert
  - **Files**: `apps/web/src/components/auth/LoginButton.tsx`
  - **Done when**: Renders provider buttons; `options.connection` param supported

- [x] T020 Create `UserProfile` component [P]
  - **Agent**: Lambert
  - **Files**: `apps/web/src/components/auth/UserProfile.tsx`
  - **Done when**: Renders avatar, name, email; supports compact/full variants

- [x] T021 Create `LogoutButton` component [P]
  - **Agent**: Lambert
  - **Files**: `apps/web/src/components/auth/LogoutButton.tsx`
  - **Done when**: Calls logout endpoint on click; accepts `returnTo` option

- [x] T022 Create login page
  - **Agent**: Lambert
  - **Files**: `apps/web/src/app/login/page.tsx`
  - **Done when**: Page shows `LoginButton` (Google + GitHub) and `UsernamePasswordForm`
  - _Requirements: FR-004, AC-3.5_

- [x] T023 Add `AuthProvider` to root layout
  - **Agent**: Lambert
  - **Files**: `apps/web/src/app/layout.tsx`
  - **Done when**: `<AuthProvider>` wraps all children; no SSR/hydration errors
  - **Verify**: `cd apps/web && npm run build`

- [x] T024 Terraform — Google connection [P]
  - **Agent**: Parker
  - **Files**: `infra/terraform/modules/auth0/main.tf`
  - **Done when**: `auth0_connection` of type `google-oauth2` defined with Key Vault credential references

- [x] T025 Terraform — GitHub connection [P]
  - **Agent**: Parker
  - **Files**: `infra/terraform/modules/auth0/main.tf`
  - **Done when**: `auth0_connection` of type `github` defined with Key Vault credential references

### E2E Tests

- [x] T026 E2E — Google OAuth login flow [P]
  - **Agent**: Kane
  - **Files**: `apps/web/e2e/auth-social-login.spec.ts`
  - **Done when**: Test navigates login → completes OAuth → verifies dashboard

- [x] T027 E2E — Session persistence [P]
  - **Agent**: Kane
  - **Files**: `apps/web/e2e/auth-session-persistence.spec.ts`
  - **Done when**: Refresh after login → still authenticated

- [x] T028 E2E — Sign out flow [P]
  - **Agent**: Kane
  - **Files**: `apps/web/e2e/auth-signout.spec.ts`
  - **Done when**: Sign out → redirect to login → session cleared

---

## Phase 4: US-2 — RBAC

### Unit Tests

- [x] T029 Unit test — route protection middleware [P]
  - **Agent**: Kane
  - **Files**: `apps/web/src/__tests__/middleware.test.ts`
  - **Done when**: Tests cover admin-pass, normal-redirect, unauthenticated-redirect

- [x] T030 Unit test — `RoleBasedComponent` [P]
  - **Agent**: Kane
  - **Files**: `apps/web/src/__tests__/components/RoleBasedComponent.test.tsx`
  - **Done when**: Tests cover admin-only, normal-only, any-role rendering

### Implementation

- [x] T031 Implement `proxy.ts` route protection
  - **Agent**: Lambert
  - **Files**: `apps/web/src/proxy.ts`
  - **Done when**: Admin routes require role=admin; unauthenticated → `/login?returnTo=`; normal → `/access-denied`
  - _Requirements: FR-007, FR-011, AC-2.1–AC-2.5_

- [x] T032 Create admin dashboard page [P]
  - **Agent**: Lambert
  - **Files**: `apps/web/src/app/admin/page.tsx`
  - **Done when**: Page renders admin features; unreachable without role=admin

- [x] T033 Create access-denied page [P]
  - **Agent**: Lambert
  - **Files**: `apps/web/src/app/access-denied/page.tsx`
  - **Done when**: Page shows reason + link back to home

- [x] T034 Role-based nav menu [P]
  - **Agent**: Lambert
  - **Files**: `apps/web/src/components/Navbar.tsx`
  - **Done when**: Admin menu items visible for admin, hidden for normal
  - _Requirements: FR-008, AC-2.3–AC-2.4_

- [x] T035 Terraform — Auth0 Action (role claims)
  - **Agent**: Parker
  - **Files**: `infra/terraform/modules/auth0/main.tf`
  - **Done when**: `auth0_action` JS sets `https://yt-summarizer.com/role` from `app_metadata.role`

- [x] T036 Terraform — bind Action to post-login trigger
  - **Agent**: Parker
  - **Files**: `infra/terraform/modules/auth0/main.tf`
  - **Done when**: `auth0_trigger_actions` resource binds Action to `post-login` flow

### E2E Tests

- [x] T037 E2E — admin accesses admin dashboard [P]
  - **Agent**: Kane
  - **Files**: `apps/web/e2e/rbac-admin-access.spec.ts`

- [x] T038 E2E — normal user denied admin [P]
  - **Agent**: Kane
  - **Files**: `apps/web/e2e/rbac-normal-user-denied.spec.ts`

- [x] T039 E2E — role-based nav visibility [P]
  - **Agent**: Kane
  - **Files**: `apps/web/e2e/rbac-navigation.spec.ts`

---

## Phase 5: US-3 — Username/Password

### Unit Test

- [x] T040 Unit test — `UsernamePasswordForm` [P]
  - **Agent**: Kane
  - **Files**: `apps/web/src/__tests__/components/auth/UsernamePasswordForm.test.tsx`
  - **Done when**: Tests cover submit, validation errors, loading state

### Implementation

- [x] T041 Create `UsernamePasswordForm` component [P]
  - **Agent**: Lambert
  - **Files**: `apps/web/src/components/auth/UsernamePasswordForm.tsx`
  - **Done when**: Form submits to `/api/auth/login` with `connection=Username-Password-Authentication`

- [x] T042 Add username/password form to login page
  - **Agent**: Lambert
  - **Files**: `apps/web/src/app/login/page.tsx`
  - **Done when**: Both social buttons and form visible on login page

- [x] T043 Terraform — database connection
  - **Agent**: Parker
  - **Files**: `infra/terraform/modules/auth0/main.tf`
  - **Done when**: `auth0_connection` type `auth0` (Username-Password-Authentication) defined

- [x] T044 Terraform — admin test user [P]
  - **Agent**: Parker
  - **Files**: `infra/terraform/environments/prod/auth0.tf`
  - **Done when**: `auth0_user` with `app_metadata.role = "admin"` and Key Vault secret

- [x] T045 Terraform — normal test user [P]
  - **Agent**: Parker
  - **Files**: `infra/terraform/environments/prod/auth0.tf`
  - **Done when**: `auth0_user` with `app_metadata.role = "normal"` and Key Vault secret

- [x] T046 Store admin credentials in Key Vault [P]
  - **Agent**: Parker
  - **Files**: `infra/terraform/environments/prod/auth0.tf`
  - **Done when**: `azurerm_key_vault_secret` for admin email + password

- [x] T047 Store normal user credentials in Key Vault [P]
  - **Agent**: Parker
  - **Files**: `infra/terraform/environments/prod/auth0.tf`
  - **Done when**: `azurerm_key_vault_secret` for normal user email + password

### E2E Tests

- [x] T048 E2E — username/password login flow [P]
  - **Agent**: Kane
  - **Files**: `apps/web/e2e/auth-username-password.spec.ts`

- [x] T049 E2E — dual login method UI [P]
  - **Agent**: Kane
  - **Files**: `apps/web/e2e/auth-dual-login-methods.spec.ts`

---

## Phase 6: US-4 — Test Continuity

### Implementation

- [x] T050 Configure Playwright programmatic auth
  - **Agent**: Kane
  - **Files**: `apps/web/playwright/auth.setup.ts`
  - **Done when**: Setup navigates to login, fills form, saves storage state for admin + normal personas

- [x] T051 Update Playwright config for auth setup project
  - **Agent**: Kane
  - **Files**: `apps/web/playwright.config.ts`
  - **Done when**: `setup` project runs before `chromium`; tests use `storageState`

- [x] T052 Admin auth state placeholder [P]
  - **Agent**: Kane
  - **Files**: `apps/web/playwright/.auth/admin.json`
  - **Done when**: Empty `{"cookies":[],"origins":[]}` placeholder committed

- [x] T053 Normal user auth state placeholder [P]
  - **Agent**: Kane
  - **Files**: `apps/web/playwright/.auth/user.json`
  - **Done when**: Empty `{"cookies":[],"origins":[]}` placeholder committed

- [x] T054 Update existing E2E tests for auth state
  - **Agent**: Kane
  - **Files**: `apps/web/e2e/` (existing tests)
  - **Done when**: All pre-existing E2E tests pass with auth enabled

- [x] T055 GitHub Actions — retrieve Key Vault credentials
  - **Agent**: Parker
  - **Files**: `.github/workflows/` (CI workflow)
  - **Done when**: Workflow step fetches `auth0-test-admin-*` and `auth0-test-user-*` secrets

### Integration Tests

- [x] T056 API auth token validation integration test [P]
  - **Agent**: Ripley
  - **Files**: `services/api/tests/test_auth_integration.py`
  - **Done when**: Tests validate JWT, check role claim, verify 401 on invalid token

- [x] T057 Update existing API tests with auth headers [P]
  - **Agent**: Ripley
  - **Files**: `services/api/tests/`
  - **Done when**: Existing API tests pass with `Authorization: Bearer` header

### E2E Tests

- [x] T058 E2E — unauthenticated redirect to login [P]
  - **Agent**: Kane
  - **Files**: `apps/web/e2e/auth-unauthenticated-redirect.spec.ts`

- [x] T059 E2E — authenticated user on protected page [P]
  - **Agent**: Kane
  - **Files**: `apps/web/e2e/auth-protected-page.spec.ts`

### FR-017 Auth State Sync

- [x] T074 Create `api-client.ts` with Bearer token forwarding [P]
  - **Agent**: Lambert
  - **Files**: `apps/web/src/lib/api-client.ts`
  - **Done when**: Reads Auth0 session access token; attaches as `Authorization: Bearer`; on 401 triggers session refresh or login redirect
  - _Requirements: FR-017_

- [x] T075 Unit test — `api-client.ts` token forwarding [P]
  - **Agent**: Kane
  - **Files**: `apps/web/src/__tests__/lib/api-client.test.ts`
  - **Done when**: Tests verify token attached to headers; 401 triggers re-auth flow

---

## Phase 7: Documentation

- [x] T060 Auth module README with architecture diagram [P]
  - **Agent**: Lambert
  - **Files**: `apps/web/src/components/auth/README.md`
  - _Requirements: FR-031, SC-019_

- [x] T061 Quickstart guide for local auth setup [P]
  - **Agent**: Lambert
  - **Files**: `specs/004-auth0-ui-integration/quickstart.md`

- [x] T062 JSDoc on all public auth API functions [P]
  - **Agent**: Lambert
  - **Files**: `apps/web/src/contexts/AuthContext.tsx`
  - _Requirements: FR-032, SC-020_

- [x] T063 Inline comments for OAuth redirect flow [P]
  - **Agent**: Lambert
  - **Files**: `apps/web/src/app/api/auth/[auth0]/route.ts`

- [x] T064 Document how to add new roles [P]
  - **Agent**: Lambert
  - **Files**: `apps/web/src/components/auth/README.md`
  - _Requirements: FR-029, SC-018_

- [x] T065 Document how to add new social providers [P]
  - **Agent**: Lambert
  - **Files**: `apps/web/src/components/auth/README.md`

---

## Phase 8: Polish & Validation

- [x] T066 Add error boundary for auth errors [P]
  - **Agent**: Lambert
  - **Files**: `apps/web/src/components/ErrorBoundary.tsx`
  - _Requirements: FR-034_

- [x] T067 Add loading states for authentication [P]
  - **Agent**: Lambert
  - **Files**: `apps/web/src/components/auth/AuthLoading.tsx`

- [x] T068 Add correlation IDs to auth logs [P]
  - **Agent**: Lambert
  - **Files**: `apps/web/src/lib/logger.ts`
  - _Requirements: FR-035, SC-023_

- [x] T069 Verify zero circular dependencies
  - **Agent**: Kane
  - **Do**: Run dependency analysis tool; confirm auth is leaf module
  - **Done when**: No circular dependency reported
  - **Verify**: `cd apps/web && npx madge --circular src/`
  - _Requirements: SC-016_

- [x] T070 Run all tests — verify 100% pass rate
  - **Agent**: Kane
  - **Do**: Run `./scripts/run-tests.ps1`
  - **Done when**: All 411+ tests pass
  - **Verify**: `./scripts/run-tests.ps1`
  - _Requirements: SC-013, FR-021_

- [x] T071 Measure CI/CD test time increase < 20%
  - **Agent**: Kane
  - _Requirements: SC-014_

- [x] T072 Run Terraform plan — all auth resources defined
  - **Agent**: Parker
  - **Done when**: `terraform plan` shows all auth resources in desired state
  - _Requirements: SC-011_

- [x] T073 Validate quickstart guide
  - **Agent**: Lambert
  - **Done when**: Setup instructions verified by following step-by-step

---

## Final Verification

- [ ] VF1 [VERIFY] Full local CI
  - **Agent**: Kane
  - **Verify**: `./scripts/run-tests.ps1`
  - **Done when**: All commands exit 0

- [ ] VF2 [VERIFY] CI pipeline passes
  - **Agent**: Kane
  - **Verify**: `gh pr checks --watch`
  - **Done when**: All CI checks green

- [ ] VF3 [VERIFY] Acceptance criteria checklist
  - **Agent**: Kane
  - **Verify**: `gh pr view --json statusCheckRollup`
  - **Done when**: All AC-1.* through AC-4.* confirmed
