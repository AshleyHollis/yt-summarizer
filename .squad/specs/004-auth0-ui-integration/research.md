# Research: Auth0 BFF Authentication + RBAC

**Feature ID**: F004  
**Date**: 2026-01-19  
**Status**: Complete  
**Agent**: Dallas (Architecture)

---

## 1. Auth SDK — `@auth0/nextjs-auth0`

**Decision**: Use `@auth0/nextjs-auth0` with the Next.js 16 `proxy.ts` BFF pattern.

**Rationale**: Official Auth0 SDK for Next.js. Handles session management, token refresh, and route protection out of the box. Next.js 16 replaces `middleware.ts` with `proxy.ts` for auth middleware. Supports App Router server components and client components. Compatible with existing Terraform Auth0 configuration.

**Key configuration**:
- Env vars: `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`, `AUTH0_SECRET`, `APP_BASE_URL`
- Rolling sessions (24 h), refresh token rotation enabled
- Encrypted HTTP-only cookies (SameSite=Lax)

**Alternatives rejected**:
- NextAuth.js — generic, requires custom Auth0 provider config
- Custom OAuth — too much boilerplate
- Auth0 SPA SDK — client-side only, no BFF support

---

## 2. Role-Based Access Control

**Decision**: Store roles in `app_metadata` (Auth0 Free tier compatible), inject via Auth0 Actions as namespaced custom claims.

**Claim namespace**: `https://yt-summarizer.com/role`

**Why not native RBAC**: Auth0 native roles/permissions API requires Professional tier ($240/month). `app_metadata` achieves the same result for a two-role system at zero cost and is fully extensible.

**Pattern**:
```
Auth0 Action (post-login) → reads user.app_metadata.role
  → sets idToken["https://yt-summarizer.com/role"]
  → sets accessToken["https://yt-summarizer.com/role"]
Frontend: user['https://yt-summarizer.com/role'] === 'admin'
Backend: token.get('https://yt-summarizer.com/role') === 'admin'
```

**Extending roles** (no code changes needed):
1. Update Terraform user `app_metadata.role`
2. Update Auth0 Action JS (add new role to allowed set)
3. Add constant to frontend `Role` type

---

## 3. Terraform Auth0 Provider

**Decision**: Extend existing `infra/terraform/modules/auth0/` module.

**Resources to add**:
- `auth0_connection` — database + Google + GitHub
- `auth0_user` — admin + normal test accounts
- `auth0_action` — role-claims post-login action
- `auth0_trigger_actions` — bind action to post-login trigger
- `azurerm_key_vault_secret` — store test account passwords
- `random_password` — generate secure test passwords

**Alternatives rejected**: Manual Auth0 Dashboard (violates FR-019), Management API scripts (less declarative), Pulumi (not in repo).

---

## 4. E2E Testing — Playwright

**Decision**: Programmatic authentication via Auth0 login form + Playwright storage-state reuse.

**Why not Resource Owner Password Grant (ROPG)**: ROPG requires enabling a non-default grant in Auth0 Dashboard — a manual step violating FR-019. Auth0 Free tier doesn't support passwordless ROPG. Rejected.

**Pattern**:
- `auth.setup.ts` global setup: navigates to login page, fills username/password form, saves storage state to `playwright/.auth/`
- Two personas: `admin.json` and `user.json`
- Tests depend on `setup` project — auth runs once per worker
- Auth state cached between runs for performance
- Unauthenticated flow tests use separate browser context (no storage state)

**Performance**: Authenticate once per worker vs per test → stays within 20% CI time increase (SC-014).

---

## 5. Unit Testing — Vitest

**Decision**: Mock `@auth0/nextjs-auth0` at the module level; inject auth context via React Context.

**Key mock targets**:
- `getSession` → returns mock user object with role claim
- `withPageAuthRequired` → passes component through
- `withApiAuthRequired` → passes handler through

**Pure functions** (`hasRole`, `getAuthMethod`, `getProvider`) tested without mocks — no Auth0 dependency.

---

## 6. Social Provider Configuration

**Decision**: Configure Google and GitHub via Terraform `auth0_connection` resources. Credentials stored in Azure Key Vault.

**One-time prerequisite** (manual): Register OAuth apps in Google Cloud Console and GitHub Settings → store Client ID/Secret in Key Vault → reference in Terraform variables.

---

## 7. CI/CD Integration

**Decision**: Retrieve test credentials from Azure Key Vault in GitHub Actions using OIDC (already configured).

**Flow**:
```
Terraform deploy → creates Key Vault secrets
CI run → azure/get-keyvault-secrets@v1 → env vars
Playwright setup → reads env vars → logs in → saves storage state
E2E tests → use storage state (no more auth calls)
```

---

## 8. Auth0 Free Tier Constraints

| Capability | Free Tier | Impact |
|---|---|---|
| MAU | 25 K | Sufficient |
| Native RBAC | ❌ | Use `app_metadata` workaround |
| MFA | Limited | Out of scope |
| Social connections | ✅ | Google + GitHub ✅ |
| Database connections | ✅ | Username/password ✅ |
| `app_metadata` | ✅ | Role storage ✅ |
| Actions | Limited executions | Sufficient for login flow |
| Custom domain | Requires CC | Not required |

---

## 9. Engineering Quality (Constitution VI.1–VI.5)

| Principle | Decision | Outcome |
|---|---|---|
| Maintainability | Isolated auth module `src/components/auth/` + `src/contexts/` | Auth changes don't ripple into non-auth code |
| Testability | Mocked SDK + injectable React Context | 100% unit testable without Auth0 API |
| Extensibility | Config-driven roles via `app_metadata` | Add "moderator" via config only |
| Modularity | Single public entry point `useAuth()` hook | No circular deps, clear API boundary |
| Onboarding | `quickstart.md` + README with architecture diagrams | New devs can integrate auth correctly |

---

## Technology Decision Summary

| Component | Choice | Reason |
|---|---|---|
| Auth SDK | `@auth0/nextjs-auth0` | Official Next.js SDK, handles sessions/tokens |
| Middleware | `proxy.ts` (Next.js 16) | New convention for auth in Next.js 16 |
| RBAC | `app_metadata` + Actions | Free tier compatible, 2-role system |
| IaC | Terraform Auth0 provider | Extends existing module, required by repo |
| E2E auth | Storage-state reuse | Fast, meets perf constraint |
| Unit tests | Mocked SDK | Isolated, no network |
| Social login | Google + GitHub via Terraform | Meets spec, IaC managed |
| Test credentials | Azure Key Vault | Repo standard, secure |
| Session storage | Encrypted httpOnly cookies | SDK default, secure |
| Token refresh | Automatic (refresh_token grant) | SDK built-in |
