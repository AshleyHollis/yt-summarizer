# Implementation Plan: Auth0 UI Integration with Role-Based Access

**Branch**: `004-auth0-ui-integration` | **Date**: 2026-01-19 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/004-auth0-ui-integration/spec.md`

## Summary

Integrate Auth0 authentication into the Next.js UI with role-based access control (admin vs normal users). Users will primarily authenticate via social login (Google, GitHub), with username/password available for test accounts and automated testing. All Auth0 configuration will be managed via Terraform Infrastructure as Code.

**Technical Approach**: Use `@auth0/nextjs-auth0` SDK with Next.js 16 `proxy.ts` middleware pattern for session management and route protection. Implement RBAC using Auth0 `app_metadata` (Free tier compatible) with custom claims injected via Auth0 Actions. Provision test accounts and social connections via Terraform with credentials stored in Azure Key Vault. E2E tests use programmatic authentication with storage state reuse for performance.

## Technical Context

**Language/Version**: TypeScript 5.x (Next.js frontend), Python 3.11 (API backend via existing integration)  
**Primary Dependencies**: `@auth0/nextjs-auth0` (Auth0 SDK), Next.js 16 (App Router with proxy.ts), React 18, Vitest (unit tests), Playwright (E2E tests)  
**Storage**: Auth0 user store (managed service), Azure Key Vault (test credentials), Azure SQL (existing - user sessions referenced but not duplicated)  
**Testing**: Vitest for unit tests (mocked Auth0 SDK), Playwright for E2E (programmatic auth with storage state), pytest for API integration  
**Target Platform**: Web browsers (Chrome, Firefox, Safari), deployed to Azure Static Web Apps (frontend) + AKS (backend)  
**Project Type**: Web application (frontend + backend with existing API integration)  
**Performance Goals**: <30s social login flow (SC-001), <20% test execution time increase (SC-014), <1s programmatic auth for E2E tests  
**Constraints**: Auth0 Free tier (25K MAU, no native RBAC), zero manual configuration (100% IaC), existing tests must pass (SC-013)  
**Scale/Scope**: 2 user roles (admin, normal), 4 auth methods (Google, GitHub, username/password, test accounts), ~15 new components/pages, ~73 tasks

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

### I. Product & UX Principles ✅

**I.1 Simplicity over magic**: Auth flow is explicit OAuth redirect (user clicks button, sees consent screen, returns to app). No hidden authentication.

**I.2 Cross-content queries**: Not applicable (auth is infrastructure, not content feature).

**I.3 Transparent scope**: Users see clear login options (Google, GitHub, username/password). Error messages are explicit (e.g., "Session expired").

**I.4 Citation-first answers**: Not applicable (auth doesn't produce answers).

**I.5 Graceful degradation**: Unauthenticated users see clear "Please log in" message and are redirected to login page. Auth failures show retry options (FR-015b).

**Result**: ✅ PASS - Auth UX is transparent and predictable.

---

### II. AI/Copilot Boundaries ✅

**II.1 Read-only chat**: Not applicable (auth is infrastructure; copilot already read-only per existing constitution).

**II.2 Grounded claims only**: Not applicable (auth doesn't make claims about content).

**II.3 Library-scoped knowledge**: Not applicable (auth controls access, not knowledge retrieval).

**Result**: ✅ PASS - Auth does not affect copilot boundaries.

---

### III. Data & Provenance ✅

**III.1 Azure SQL as source of truth**: User identities stored in Auth0 (managed service), not duplicated in Azure SQL. Session references may be logged but Auth0 is authoritative for auth state.

**III.2 One artifact per source**: Each user has one Auth0 profile with one role in `app_metadata`.

**III.3 Video relationships**: Not applicable (auth feature).

**III.4 Traceability metadata**: Auth events logged with correlation IDs (FR-035, SC-023).

**Result**: ✅ PASS - Auth0 is single source of truth for identity; provenance via logging.

---

### IV. Reliability & Operations ✅

**IV.1 Automated service management**: Aspire orchestration unchanged. Auth0 is external managed service (no local background process).

**IV.2 Async-first background processing**: Auth flow is synchronous (OAuth redirect), but test account provisioning is via Terraform (declarative). No background job queue needed.

**IV.3 Serverless wake-up resilience**: Auth0 is always-on managed service. API layer already handles Azure SQL wake-up.

**IV.4 Observability**: Auth events logged with structured logs and correlation IDs (FR-035).

**IV.5 GitOps deployments**: Auth0 configuration deployed via Terraform in GitOps workflow (FR-019, SC-011, SC-012).

**Result**: ✅ PASS - Auth integrates with existing observability and GitOps practices.

---

### V. Security ✅

**V.1 No secrets in repo**: OAuth credentials and test account passwords stored in Azure Key Vault (FR-013, FR-019). Auth0 secrets in environment variables populated from Key Vault.

**V.2 Least-privilege access**: Auth0 application has minimum scopes (openid, profile, email). Test accounts restricted to test environments.

**Result**: ✅ PASS - Zero secrets in code/config; all via Key Vault.

---

### VI. Engineering Quality ✅ (Constitution v1.2.0)

**VI.1 Maintainability** (NON-NEGOTIABLE):
- **Module isolation**: Auth components in `apps/web/src/components/auth/`, context in `apps/web/src/contexts/AuthContext.tsx` (FR-025) ✅
- **Self-documenting code**: TypeScript interfaces for User, Session, Role; JSDoc on public API (FR-032) ✅
- **Single responsibility**: AuthContext provides state, proxy.ts handles routes, components display UI ✅
- **DRY principle**: Role check utility function `hasRole(user, role)` (FR-027) ✅
- **Error handling**: Dedicated error types (AuthError, SessionExpiredError, UnauthorizedError) (FR-034) ✅

**VI.2 Testability** (NON-NEGOTIABLE):
- **Pure functions**: `hasRole(user, role)` is pure, deterministic (FR-027) ✅
- **Dependency injection**: AuthContext injectable via `<AuthProvider>`; tests provide mock context (FR-027) ✅
- **Testable interfaces**: Auth0 SDK mockable in Vitest (FR-028, research.md §5) ✅
- **No hidden state**: All auth state in React context; no singletons (FR-028) ✅
- **Facilities available**: Playwright auth fixtures (research.md §4), Vitest mock setup (research.md §5) ✅

**VI.3 Extensibility** (NON-NEGOTIABLE):
- **Plugin-like architecture**: New social providers via Terraform `auth0_connection` resources (FR-029, SC-018) ✅
- **Strategy pattern**: Auth providers abstracted behind Auth0 SDK interface (research.md §6) ✅
- **Configuration-driven**: Roles in `app_metadata`; adding "moderator" requires config only (FR-030, SC-018) ✅
- **Open-closed principle**: Core auth logic closed; providers/roles added via Terraform config (FR-029) ✅
- **Extension points documented**: README explains adding roles (FR-031, research.md §9) ✅

**VI.4 Modularity** (NON-NEGOTIABLE):
- **Package/module boundaries**: Auth at `src/components/auth/` and `src/contexts/`; non-auth never imports Auth0 SDK (FR-026, SC-016) ✅
- **Internal vs public API**: Only `AuthProvider`, `useAuth`, auth components exported; SDK internal (FR-033) ✅
- **Import dependency graph**: Auth is leaf module; components → useAuth → AuthContext → SDK (no circular deps) (SC-016) ✅
- **Single entry point**: `useAuth()` hook is public API (FR-033) ✅
- **Cross-cutting concerns**: Route protection in proxy.ts middleware (not scattered) ✅

**VI.5 Onboarding** (CLARITY TARGET):
- **README per module**: `quickstart.md` serves as auth module README (FR-031, SC-019) ✅
- **Clear examples**: Login component usage, `useAuth` hook examples (FR-032, research.md §9) ✅
- **Architecture diagrams**: OAuth flow, token claims, session management (FR-031, SC-019) ✅
- **Walkthrough comments**: OAuth redirects, refresh tokens, role extraction (research.md §9) ✅
- **Naming conventions**: `useAuth`, `AuthContext`, `AuthProvider` (React patterns) ✅

**VI.6 Simplicity first**: Auth0 SDK handles complexity (tokens, refresh, sessions). Custom code is minimal. ✅

**VI.7 Bounded queries**: Not applicable (auth feature).

**VI.8 Cost-aware defaults**: Auth0 Free tier used (25K MAU, $0/month). ✅

**VI.9 Development environment**: Aspire orchestration unchanged; Auth0 is external service. ✅

**VI.10 Testing** (NON-NEGOTIABLE):
- **Unit tests**: Cover `useAuth` hook, role utilities, auth components (FR-021, tasks.md T013-T016, T029-T030, T038-T039, T046-T047) ✅
- **Integration tests**: Cover auth token validation in API (FR-022, tasks.md T056-T057) ✅
- **E2E tests**: Cover social login, RBAC, username/password, session flows (FR-024, tasks.md T026-T028, T033-T035, T042-T044, T050-T052) ✅
- **Test-driven development**: Tasks specify tests BEFORE implementation (Phase 3/4/5/6 structure) ✅
- **100% pass rate required**: Per repository AGENTS.md (run ./scripts/run-tests.ps1 before marking complete) ✅
- **No skipping allowed**: Final validation includes E2E (no -SkipE2E) ✅
- **Smoke tests**: Existing smoke-test.ps1 will verify auth endpoints ✅

**VI.11 Migration-driven schema changes**: Not applicable (Auth0 schema managed by service; no database migrations).

**VI.12 Small, reviewable PRs**: Tasks grouped by user story for incremental PRs (tasks.md Phases 3-6).

**VI.13 Dependency discipline**: Single new dependency (`@auth0/nextjs-auth0`), pinned version.

**VI.14 Documentation separation**: Spec (WHAT/WHY), plan (HOW), tasks (concrete steps) - all present.

**Result**: ✅ PASS - All VI.1-VI.5 engineering quality principles satisfied (Constitution v1.2.0). VI.10 testing is comprehensive and NON-NEGOTIABLE.

---

### VII. Change Management ✅

**VII.1 Constitution amendments**: Not applicable (this feature implements constitution, doesn't amend it).

**VII.2 Feature compliance**: This plan includes Constitution Check (this section).

**VII.3 Pre-merge checks**: Tasks include test execution (./scripts/run-tests.ps1) before completion.

**Result**: ✅ PASS - Compliance verified.

---

### GATE RESULT: ✅ PASSED

All constitutional principles satisfied. Proceed to Phase 1 design.

**Engineering Quality Focus**: This feature demonstrates Constitution v1.2.0 engineering quality principles (VI.1-VI.5) as first-class requirements (FR-025 through FR-034).

## Project Structure

### Documentation (this feature)

```text
specs/[###-feature]/
├── plan.md              # This file (/speckit.plan command output)
├── research.md          # Phase 0 output (/speckit.plan command)
├── data-model.md        # Phase 1 output (/speckit.plan command)
├── quickstart.md        # Phase 1 output (/speckit.plan command)
├── contracts/           # Phase 1 output (/speckit.plan command)
└── tasks.md             # Phase 2 output (/speckit.tasks command - NOT created by /speckit.plan)
```

### Source Code (repository root)

```text
apps/web/ (Next.js frontend)
├── src/
│   ├── components/
│   │   └── auth/                  # Auth UI components (LoginButton, UserProfile, etc.)
│   ├── contexts/
│   │   └── AuthContext.tsx        # Auth state management
│   ├── hooks/
│   │   └── useAuth.ts             # Auth hook (public API)
│   ├── lib/
│   │   ├── auth0.ts               # Auth0 SDK initialization
│   │   └── auth-utils.ts          # Pure utility functions (hasRole, etc.)
│   ├── types/
│   │   └── auth.ts                # Auth error types, interfaces
│   ├── app/
│   │   ├── api/auth/[auth0]/      # Auth0 route handlers
│   │   ├── login/                 # Login page
│   │   └── layout.tsx             # Root layout (AuthProvider integration)
│   ├── proxy.ts                   # Next.js 16 auth middleware
│   └── __tests__/
│       ├── hooks/useAuth.test.tsx
│       ├── lib/auth-utils.test.ts
│       ├── components/auth/       # Auth component tests
│       └── middleware.test.ts
├── e2e/
│   ├── auth-social-login.spec.ts
│   ├── auth-session-persistence.spec.ts
│   ├── auth-rbac.spec.ts
│   └── playwright/.auth/          # Auth storage state files
└── playwright.config.ts

services/api/ (Python backend - existing, no auth changes)
└── tests/
    └── integration/
        └── test_auth_token_validation.py  # Existing API auth tests

infra/terraform/
├── modules/auth0/
│   └── main.tf                    # Extended with connections, users, actions
└── environments/prod/
    └── variables.tf               # Auth0 variables (social OAuth credentials)
```

**Structure Decision**: Web application structure (frontend + backend). Auth is frontend-focused with Terraform infrastructure extensions. Backend API already has Auth0 JWT validation (no changes needed for this feature).

## Notes

- **Phase 0 (Research)**: COMPLETE - See [research.md](./research.md) for technology decisions
- **Phase 1 (Design)**: Next step - Generate data-model.md, contracts/, quickstart.md
- **Phase 2 (Tasks)**: Already generated - See [tasks.md](./tasks.md) for 73 implementation tasks
- **Agent Context**: After Phase 1, run `.specify/scripts/powershell/update-agent-context.ps1 -AgentType opencode` to add `@auth0/nextjs-auth0` to AI context

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

(Empty - No constitutional violations. All complexity justified by Auth0 Free tier constraints and existing architecture.)
