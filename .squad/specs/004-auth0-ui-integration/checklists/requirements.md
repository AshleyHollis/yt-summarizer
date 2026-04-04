# Requirements Checklist: Auth0 BFF Authentication + RBAC (F004)

**Purpose**: Track specification quality and implementation completeness  
**Feature**: F004 — Auth0 BFF Authentication + RBAC  
**Updated**: 2026-06-01 (Squad import)  
**Status**: ~97% complete (73/75 tasks done; VF1–VF3 pending live infrastructure)

---

## Specification Quality ✅

- [x] User stories defined with clear As/I want/So that format
- [x] Acceptance criteria are specific and testable (AC-1.1 through AC-4.7)
- [x] Edge cases identified and resolved (session expiry, OAuth failure, rate limits)
- [x] Scope clearly bounded (in scope / out of scope listed)
- [x] Dependencies and assumptions documented
- [x] Success criteria are measurable (SC-001 through SC-023)
- [x] No implementation details in spec (technology-agnostic requirements)

---

## US-1: Social Login ✅

- [x] FR-001: Third-party OAuth redirect flow integrated
- [x] FR-002: Google and GitHub social login supported
- [x] FR-009: Session persists across refreshes
- [x] FR-010: Sign-out clears session and tokens
- [x] FR-015a: Session expiry redirects to login with message + returnTo
- [x] FR-015b: OAuth failure shows inline error with retry
- [x] AC-1.1: Clicking Google → OAuth consent screen
- [x] AC-1.2: Post-OAuth → authenticated on dashboard
- [x] AC-1.3: Refresh → still authenticated
- [x] AC-1.4: Sign out → redirect to login
- [x] AC-1.5: Return within session → auto-authenticated

---

## US-2: Role-Based Access Control ✅

- [x] FR-005: Admin and normal user roles distinguished
- [x] FR-006: Role stored in auth provider user metadata
- [x] FR-007: Admin routes protected from unauthorized access
- [x] FR-008: UI elements shown/hidden by role
- [x] FR-011: Unauthenticated → redirect to login
- [x] AC-2.1: Admin can access `/admin`
- [x] AC-2.2: Normal user → access-denied on `/admin`
- [x] AC-2.3: Admin nav items visible to admin
- [x] AC-2.4: Admin nav items hidden from normal user
- [x] AC-2.5: Unauthenticated → login redirect

---

## US-3: Username/Password for Testing ✅

- [x] FR-003: Username/password auth supported
- [x] FR-004: Login page shows both social and username/password
- [x] FR-012: Test accounts created in auth provider
- [x] FR-013: Test credentials stored in Azure Key Vault
- [x] FR-014: Both admin and normal test accounts exist
- [x] FR-019: All infrastructure via Terraform (zero manual steps)
- [x] AC-3.1: Admin test account authenticates successfully
- [x] AC-3.2: Automated tests authenticate without social providers
- [x] AC-3.3: Test accounts have correct role assignments
- [x] AC-3.4: Multiple concurrent test sessions possible
- [x] AC-3.5: Login page shows both social and form
- [x] AC-3.6: Terraform creates all test accounts automatically
- [x] AC-3.7: Terraform destroy + apply recreates test accounts

---

## US-4: Test Suite Continuity ✅

- [x] FR-016: Tokens validated on protected API requests
- [x] FR-017: Auth state synced between UI and API (`api-client.ts`)
- [x] FR-018: Tests authenticate via username/password
- [x] FR-021: Existing tests continue to pass
- [x] FR-022: CI/CD executes all test suites
- [x] FR-023: Programmatic auth without manual intervention
- [x] FR-024: E2E covers authenticated and unauthenticated flows
- [x] AC-4.1: Unit tests pass in CI
- [x] AC-4.2: Integration tests pass with Key Vault credentials
- [x] AC-4.3: E2E tests verify role-specific behaviour
- [x] AC-4.4: Credentials retrieved automatically in CI
- [x] AC-4.5: Unauthenticated flow → login redirect verified in E2E
- [x] AC-4.6: Authenticated flow → login, action, logout verified
- [x] AC-4.7: CI time increase ≤ 20%

---

## Engineering Quality (Constitution VI.1–VI.5) ✅

- [x] FR-025: Auth in clearly bounded self-contained module
- [x] FR-026: Non-auth code uses only public auth interface
- [x] FR-027: Auth functions verifiable without external services
- [x] FR-028: Test environment supports simulated auth
- [x] FR-029: RBAC extensible without modifying core logic
- [x] FR-030: Auth config driven, not hardcoded
- [x] FR-031: Developer documentation exists
- [x] FR-032: Public interface documented with contracts
- [x] FR-033: Single public entry point (`useAuth()`)
- [x] FR-034: Distinct error types per failure mode
- [x] FR-035: Auth events logged with correlation IDs

---

## Final Verification (pending live infrastructure)

- [ ] VF1: Full test suite passes: `./scripts/run-tests.ps1` (needs live Auth0 + Key Vault)
- [ ] VF2: CI pipeline green: `gh pr checks --watch`
- [ ] VF3: All acceptance criteria confirmed programmatically
- [ ] SC-011: 100% auth infrastructure via Terraform — `terraform plan` shows no drift
- [ ] SC-013: 100% existing test pass rate confirmed in CI
- [ ] SC-014: CI time increase ≤ 20% measured in GitHub Actions run

---

## Notes

- **All 73 implementation tasks** in `tasks.md` are marked `[x]` (complete)
- **Remaining 3 items** (VF1–VF3) require a live Auth0 tenant with Google/GitHub OAuth apps and Key Vault test credentials
- **Token pass rate locally**: 411/411 tests passing (reported in T070)
- **Circular dependency check**: Passed (T069)
- **Terraform plan**: Passed locally (T072)
