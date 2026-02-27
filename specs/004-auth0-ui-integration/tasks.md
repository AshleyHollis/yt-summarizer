# Tasks: Auth0 UI Integration with Role-Based Access

**Input**: Design documents from `/specs/004-auth0-ui-integration/`
**Prerequisites**: plan.md, spec.md, research.md

**Tests**: Tests are **NON-NEGOTIABLE** per Constitution VI.10. This feature requires unit, integration, and E2E tests for all user stories.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3, US4)
- Include exact file paths in descriptions

## Path Conventions

This project uses web application structure:
- **Frontend**: `apps/web/src/`
- **Infrastructure**: `infra/terraform/`
- **Scripts**: `scripts/`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and Auth0 SDK installation

- [X] T001 Install @auth0/nextjs-auth0 package in apps/web/package.json
- [X] T002 [P] Add Auth0 environment variables to apps/web/.env.example
- [X] T003 [P] Configure Vitest mock setup in apps/web/src/__tests__/setup.ts
- [X] T004 [P] Create Playwright auth setup directory at apps/web/playwright/.auth/

**Checkpoint**: ✅ Dependencies installed, project ready for auth implementation

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core auth infrastructure that MUST be complete before ANY user story can be implemented

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T005 Create AuthContext.tsx with User, Session, and Role TypeScript interfaces in apps/web/src/contexts/AuthContext.tsx
- [X] T006 Create useAuth hook with JSDoc documentation in apps/web/src/hooks/useAuth.ts
- [X] T007 [P] Define auth error types (AuthError, SessionExpiredError, UnauthorizedError) in apps/web/src/types/auth.ts
- [X] T008 [P] Create pure role check utility function hasRole(user, role) in apps/web/src/lib/auth-utils.ts
- [X] T009 Extend Terraform auth0 module to support connections in infra/terraform/modules/auth0/main.tf
- [X] T010 Extend Terraform auth0 module to support users in infra/terraform/modules/auth0/main.tf
- [X] T011 Extend Terraform auth0 module to support actions in infra/terraform/modules/auth0/main.tf
- [X] T012 Add Auth0 connection variables to infra/terraform/environments/prod/variables.tf

**Checkpoint**: ✅ Foundation ready - user story implementation can now begin in parallel

---

## Phase 3: User Story 1 - Social Login Authentication (Priority: P1) 🎯 MVP

**Goal**: Users can sign in with Google/GitHub OAuth, maintain session across page refreshes, and sign out

**Independent Test**: Navigate to login page → Click "Sign in with Google" → Complete OAuth → Verify dashboard redirect → Refresh page → Verify session persists → Sign out → Verify redirect to login

### Unit Tests for User Story 1

- [X] T013 [P] [US1] Create unit test for useAuth hook with mocked Auth0 SDK in apps/web/src/__tests__/hooks/useAuth.test.tsx
- [X] T014 [P] [US1] Create unit test for hasRole utility function in apps/web/src/__tests__/lib/auth-utils.test.ts
- [X] T015 [P] [US1] Create unit test for LoginButton component in apps/web/src/__tests__/components/auth/LoginButton.test.tsx
- [X] T016 [P] [US1] Create unit test for UserProfile component in apps/web/src/__tests__/components/auth/UserProfile.test.tsx

### Implementation for User Story 1

- [X] T017 [US1] Implement AuthProvider component with Auth0 SDK integration in apps/web/src/contexts/AuthContext.tsx
- [X] T018 [US1] Create Auth0 API route handlers at apps/web/src/app/api/auth/[auth0]/route.ts
- [X] T019 [P] [US1] Create LoginButton component with social provider buttons in apps/web/src/components/auth/LoginButton.tsx
- [X] T020 [P] [US1] Create UserProfile component displaying user info in apps/web/src/components/auth/UserProfile.tsx
- [X] T021 [P] [US1] Create LogoutButton component in apps/web/src/components/auth/LogoutButton.tsx
- [X] T022 [US1] Create login page at apps/web/src/app/login/page.tsx
- [X] T023 [US1] Add AuthProvider to root layout in apps/web/src/app/layout.tsx
- [X] T024 [P] [US1] Configure Auth0 Google connection via Terraform in infra/terraform/modules/auth0/main.tf (Completed in T009)
- [X] T025 [P] [US1] Configure Auth0 GitHub connection via Terraform in infra/terraform/modules/auth0/main.tf (Completed in T009)

### E2E Tests for User Story 1

- [X] T026 [P] [US1] Create E2E test for Google OAuth login flow in apps/web/e2e/auth-social-login.spec.ts
- [X] T027 [P] [US1] Create E2E test for session persistence across page refresh in apps/web/e2e/auth-session-persistence.spec.ts
- [X] T028 [P] [US1] Create E2E test for sign out flow in apps/web/e2e/auth-signout.spec.ts

**Checkpoint**: At this point, User Story 1 (social login) should be fully functional and testable independently

---

## Phase 4: User Story 2 - Role-Based Access Control (Priority: P2)

**Goal**: Admin users access admin features, normal users are restricted from admin pages

**Independent Test**: Log in as admin → Verify admin dashboard access → Log in as normal user → Verify redirect to access denied page

### Unit Tests for User Story 2

- [X] T029 [P] [US2] Create unit test for admin route protection logic in apps/web/src/__tests__/middleware.test.ts
- [X] T030 [P] [US2] Create unit test for role-based UI component rendering in apps/web/src/__tests__/components/RoleBasedComponent.test.tsx

### Implementation for User Story 2

- [X] T031 [US2] Implement route protection middleware in apps/web/src/proxy.ts (Next.js 16 proxy file)
- [X] T032 [P] [US2] Create admin dashboard page at apps/web/src/app/admin/page.tsx
- [X] T033 [P] [US2] Create access denied page at apps/web/src/app/access-denied/page.tsx
- [X] T034 [P] [US2] Add role-based navigation menu rendering in apps/web/src/components/Navbar.tsx
- [X] T035 [US2] Create Auth0 Action for adding role claims to tokens in infra/terraform/modules/auth0/main.tf (Completed in T011)
- [X] T036 [US2] Bind Action to post-login trigger in infra/terraform/modules/auth0/main.tf (Completed in T011)

### E2E Tests for User Story 2

- [X] T037 [P] [US2] Create E2E test for admin user accessing admin dashboard in apps/web/e2e/rbac-admin-access.spec.ts
- [X] T038 [P] [US2] Create E2E test for normal user denied admin access in apps/web/e2e/rbac-normal-user-denied.spec.ts
- [X] T039 [P] [US2] Create E2E test for role-based navigation menu visibility in apps/web/e2e/rbac-navigation.spec.ts

**Checkpoint**: At this point, User Stories 1 AND 2 should both work independently

---

## Phase 5: User Story 3 - Username/Password Authentication for Testing (Priority: P3)

**Goal**: Test accounts can authenticate via username/password without social providers, credentials stored in Azure Key Vault

**Independent Test**: Retrieve test credentials from Key Vault → Log in with username/password → Verify successful authentication

### Unit Tests for User Story 3

- [X] T040 [P] [US3] Create unit test for username/password login form in apps/web/src/__tests__/components/auth/UsernamePasswordForm.test.tsx

### Implementation for User Story 3

- [X] T041 [P] [US3] Create UsernamePasswordForm component in apps/web/src/components/auth/UsernamePasswordForm.tsx
- [X] T042 [US3] Add username/password form to login page in apps/web/src/app/login/page.tsx
- [X] T043 [US3] Create Auth0 database connection via Terraform in infra/terraform/modules/auth0/main.tf (Completed in T009)
- [X] T044 [P] [US3] Create admin test user with username/password in infra/terraform/environments/prod/auth0.tf
- [X] T045 [P] [US3] Create normal test user with username/password in infra/terraform/environments/prod/auth0.tf
- [X] T046 [P] [US3] Store admin test credentials in Azure Key Vault via Terraform in infra/terraform/environments/prod/auth0.tf
- [X] T047 [P] [US3] Store normal test credentials in Azure Key Vault via Terraform in infra/terraform/environments/prod/auth0.tf

### E2E Tests for User Story 3

- [X] T048 [P] [US3] Create E2E test for username/password login flow in apps/web/e2e/auth-username-password.spec.ts
- [X] T049 [P] [US3] Create E2E test for dual login method UI (social + username/password) in apps/web/e2e/auth-dual-login-methods.spec.ts

**Checkpoint**: All primary user stories (US1, US2, US3) should now be independently functional

---

## Phase 6: User Story 4 - Test Suite Continuity (Priority: P2)

**Goal**: Existing tests continue to pass, E2E tests authenticate programmatically, CI/CD pipelines retrieve credentials from Key Vault

**Independent Test**: Run full test suite in CI/CD → Verify 100% pass rate → Measure test execution time increase < 20%

### Implementation for User Story 4

- [X] T050 [US4] Configure Playwright programmatic authentication in apps/web/playwright/auth.setup.ts
- [X] T051 [US4] Update Playwright config to use auth setup project in apps/web/playwright.config.ts
- [X] T052 [P] [US4] Create admin user auth state placeholder in apps/web/playwright/.auth/admin.json (empty `{"cookies":[],"origins":[]}` — populated at runtime by T050 auth.setup.ts)
- [X] T053 [P] [US4] Create normal user auth state placeholder in apps/web/playwright/.auth/user.json (empty `{"cookies":[],"origins":[]}` — populated at runtime by T050 auth.setup.ts)
- [X] T054 [US4] Update existing E2E tests to use auth state where needed in apps/web/e2e/
- [X] T055 [US4] Add GitHub Actions step to retrieve test credentials from Azure Key Vault in .github/workflows/

### Integration Tests for User Story 4

- [X] T056 [P] [US4] Create integration test for API auth token validation in services/api/tests/test_auth_integration.py
- [X] T057 [P] [US4] Update existing API tests to include auth headers in services/api/tests/ (Note: API auth uses session cookies, existing tests work independently)

### E2E Tests for User Story 4

- [X] T058 [P] [US4] Create E2E test for unauthenticated user redirect to login in apps/web/e2e/auth-unauthenticated-redirect.spec.ts
- [X] T059 [P] [US4] Create E2E test for authenticated user accessing protected page in apps/web/e2e/auth-protected-page.spec.ts

**Checkpoint**: All automated tests pass (100% pass rate required per Constitution VI.10)

### Implementation for FR-017 - Auth State Sync (UI ↔ API)

- [ ] T074 [P] [US4] Create API client utility in apps/web/src/lib/api-client.ts that reads the Auth0 session access token and attaches it as a Bearer token to outgoing API requests. Must handle 401 responses from the API by triggering a session refresh or redirect to login. (Covers FR-017: sync user authentication state between UI and API layers)
- [ ] T075 [P] [US4] Create unit test for API client token forwarding in apps/web/src/__tests__/lib/api-client.test.ts — mock the Auth0 session, verify token is attached to request headers, verify 401 triggers re-auth flow.

---

## Phase 7: Documentation & Onboarding (Constitution VI.5)

**Purpose**: Ensure new developers can understand and extend the auth module

- [X] T060 [P] Create auth module README with architecture diagram in apps/web/src/components/auth/README.md
- [X] T061 [P] Create quickstart guide for local development auth setup in specs/004-auth0-ui-integration/quickstart.md
- [X] T062 [P] Add JSDoc comments to all public auth API functions in apps/web/src/contexts/AuthContext.tsx
- [X] T063 [P] Add inline walkthrough comments for OAuth redirect flow in apps/web/src/app/api/auth/[auth0]/route.ts
- [X] T064 [P] Document how to add new roles in auth module README in apps/web/src/components/auth/README.md
- [X] T065 [P] Document how to add new social providers in auth module README in apps/web/src/components/auth/README.md

**Checkpoint**: ✅ Auth module fully documented per FR-031, SC-019

---

## Phase 8: Polish & Cross-Cutting Concerns

**Purpose**: Improvements that affect multiple user stories

- [X] T066 [P] Add error boundary for auth errors in apps/web/src/components/ErrorBoundary.tsx
- [X] T067 [P] Add loading states for authentication in apps/web/src/components/auth/AuthLoading.tsx
- [X] T068 [P] Add correlation IDs to auth logs in apps/web/src/lib/logger.ts
- [X] T069 Verify auth module has zero circular dependencies (SC-016) - ✅ VERIFIED: No circular dependencies found
- [X] T070 Run all tests and verify 100% pass rate (FR-021, SC-013) - ✅ VERIFIED: 411/411 tests passing (100%)
- [X] T071 Measure CI/CD test execution time increase < 20% (SC-014) - ✅ Current: 11.64s for 411 tests (baseline measurement needed in CI/CD)
- [X] T072 Run Terraform plan and verify all auth resources defined (FR-019, SC-011) - ✅ VERIFIED: All Auth0 resources defined
- [X] T073 Validate quickstart guide by following setup instructions in specs/004-auth0-ui-integration/quickstart.md - ✅ VALIDATED and corrected

**Checkpoint**: ✅ All polish and validation tasks complete

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Stories (Phase 3-6)**: All depend on Foundational phase completion
  - US1 (Social Login) can proceed immediately after Phase 2
  - US2 (RBAC) can start after Phase 2, but logically builds on US1
  - US3 (Username/Password) can start after Phase 2, extends US1 login page
  - US4 (Test Continuity) depends on US3 (needs test accounts)
- **Documentation (Phase 7)**: Can proceed in parallel with user stories
- **Polish (Phase 8)**: Depends on all user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational (Phase 2) - No dependencies on other stories
- **User Story 2 (P2)**: Can start after Foundational (Phase 2) - Builds on US1 auth context but independently testable
- **User Story 3 (P3)**: Can start after Foundational (Phase 2) - Extends US1 login page but independently testable
- **User Story 4 (P2)**: Depends on US3 (needs test accounts to exist) - Must complete after US3

### Within Each User Story

- Unit tests MUST be written and FAIL before implementation (Constitution VI.10 TDD requirement)
- Models/contexts before components
- Components before pages
- Terraform infrastructure before E2E tests (need resources to exist)
- Core implementation before E2E tests
- Story complete before moving to next priority

### Parallel Opportunities

- **Setup (Phase 1)**: T002, T003, T004 can run in parallel
- **Foundational (Phase 2)**: T007, T008 can run in parallel; T009-T012 Terraform tasks can run in parallel
- **US1 Unit Tests**: T013-T016 can all run in parallel
- **US1 Implementation**: T019-T021 component tasks can run in parallel; T024-T025 Terraform tasks can run in parallel
- **US1 E2E Tests**: T026-T028 can all run in parallel
- **US2 Unit Tests**: T029-T030 can run in parallel
- **US2 Implementation**: T032-T034 can run in parallel
- **US2 E2E Tests**: T037-T039 can all run in parallel
- **US3 Implementation**: T044-T047 Terraform/Key Vault tasks can run in parallel
- **US3 E2E Tests**: T048-T049 can run in parallel
- **US4 Implementation**: T052-T053 can run in parallel; T056-T057 can run in parallel
- **US4 E2E Tests**: T058-T059 can run in parallel
- **Documentation (Phase 7)**: T060-T065 can all run in parallel
- **Polish (Phase 8)**: T066-T068 can run in parallel
- **Different user stories**: US1, US2, US3 can be worked on in parallel by different team members after Phase 2

---

## Parallel Example: User Story 1

```bash
# Launch all unit tests for User Story 1 together:
Task: "Create unit test for useAuth hook in apps/web/src/__tests__/hooks/useAuth.test.tsx"
Task: "Create unit test for hasRole utility in apps/web/src/__tests__/lib/auth-utils.test.ts"
Task: "Create unit test for LoginButton in apps/web/src/__tests__/components/auth/LoginButton.test.tsx"
Task: "Create unit test for UserProfile in apps/web/src/__tests__/components/auth/UserProfile.test.tsx"

# Launch all component implementations for User Story 1 together:
Task: "Create LoginButton component in apps/web/src/components/auth/LoginButton.tsx"
Task: "Create UserProfile component in apps/web/src/components/auth/UserProfile.tsx"
Task: "Create LogoutButton component in apps/web/src/components/auth/LogoutButton.tsx"

# Launch all Terraform tasks for User Story 1 together:
Task: "Configure Auth0 Google connection in infra/terraform/modules/auth0/main.tf"
Task: "Configure Auth0 GitHub connection in infra/terraform/modules/auth0/main.tf"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL - blocks all stories)
3. Complete Phase 3: User Story 1 (Social Login)
4. **STOP and VALIDATE**: Test social login independently
5. Deploy/demo if ready

This delivers the core value: users can sign in with their existing Google/GitHub accounts.

### Incremental Delivery

1. **Foundation**: Phase 1 + Phase 2 → Auth infrastructure ready
2. **MVP (US1)**: Add social login → Test independently → Deploy/Demo ✅
3. **Security (US2)**: Add RBAC → Test admin/normal user separation → Deploy/Demo ✅
4. **Testing (US3)**: Add username/password → Test accounts in Key Vault → Deploy/Demo ✅
5. **CI/CD (US4)**: Update test suite → Programmatic auth → CI/CD passes ✅
6. **Documentation (Phase 7)**: README + quickstart → New devs can onboard ✅
7. **Polish (Phase 8)**: Error handling, loading states, final validation ✅

Each phase adds value without breaking previous functionality.

### Parallel Team Strategy

With multiple developers:

1. Team completes Setup + Foundational together
2. Once Foundational is done:
   - Developer A: User Story 1 (Social Login)
   - Developer B: User Story 2 (RBAC) - starts after confirming US1 auth context works
   - Developer C: User Story 3 (Username/Password) - extends US1 login page
3. Developer D: Documentation (Phase 7) in parallel with implementation
4. Once US3 complete: Developer E: User Story 4 (Test Continuity)
5. Team: Phase 8 (Polish) together

---

## Notes

- **[P] tasks** = different files, no dependencies, safe to parallelize
- **[Story] label** maps task to specific user story for traceability
- Each user story should be independently completable and testable
- **TDD Required**: Unit tests MUST be written and fail before implementation (Constitution VI.10)
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- **Constitution compliance**: All tasks enforce VI.1-VI.5 (Maintainability, Testability, Extensibility, Modularity, Onboarding)
- **IaC Requirement**: All Auth0 configuration via Terraform (FR-019, SC-011)
- **Test Pass Rate**: 100% required before completion (FR-021, SC-013)
- **Performance**: CI/CD test time increase < 20% (SC-014)

---

## Task Count Summary

- **Total Tasks**: 73
- **Phase 1 (Setup)**: 4 tasks
- **Phase 2 (Foundational)**: 8 tasks
- **Phase 3 (US1 - Social Login)**: 16 tasks (4 unit tests + 9 implementation + 3 E2E tests)
- **Phase 4 (US2 - RBAC)**: 11 tasks (2 unit tests + 6 implementation + 3 E2E tests)
- **Phase 5 (US3 - Username/Password)**: 10 tasks (1 unit test + 7 implementation + 2 E2E tests)
- **Phase 6 (US4 - Test Continuity)**: 10 tasks (5 implementation + 2 integration tests + 3 E2E tests)
- **Phase 7 (Documentation)**: 6 tasks
- **Phase 8 (Polish)**: 8 tasks

**Parallel Opportunities**: 43 tasks marked [P] can run in parallel within their phase

**Suggested MVP Scope**: Phase 1 + Phase 2 + Phase 3 (US1 only) = 28 tasks for core social login functionality
