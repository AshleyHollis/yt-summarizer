# Kane — History

## Project Context
- **Project**: YT Summarizer — YouTube video knowledge library
- **Stack**: Playwright, pytest, Vitest, GitHub Actions CI
- **User**: Ashley Hollis

## Key Knowledge
- Auth0 test users: admin@test.yt-summarizer.internal, user@test.yt-summarizer.internal
- Passwords stored in Key Vault: auth0-admin-test-password, auth0-user-test-password
- E2E auth setup navigates to API URL directly (not SWA) due to SWA /api/* interception
- Cross-domain cookie issue affects all auth-dependent E2E tests in CI
- Many auth E2E tests have `test.fixme(!!process.env.CI, 'Cross-domain cookie issue...')`
- 5 failing tests in library.spec.ts — all redirecting to Auth0 login when they shouldn't

## Learnings
<!-- Append learnings below -->

### 2026-03-04 — Production Smoke Test

**Frontend (Azure Static Web App)**
- `https://white-meadow-0b8e2e000.6.azurestaticapps.net` returns Azure SWA native 404 — the app bundle is NOT deployed to this slot.
- Console error: `Failed to load resource: 404` on the root path — not an app error, Azure itself is serving the 404 page.
- The SWA resource exists but has no deployed content. **Users cannot access the application.**

**API (AKS Backend)**
- `/health/ready` → ✅ all checks pass: `api`, `database_init`, `database_connection`, `database_connection_cached` all `true`.
- `/docs` (Swagger UI) → ❌ 404 with structured error JSON `{"error":{"code":404,"message":"Not Found",...}}`. Swagger docs are disabled in production (likely intentional for security).
- `/api/auth/session` → ✅ responds correctly with `{"user":null,"isAuthenticated":false}`. No console errors. Auth endpoint is live and responding.

**Summary**: API backend is fully healthy. Frontend is broken — either the deployment pipeline has not pushed the frontend build to the SWA, or the SWA URL has changed.

**Cross-agent findings:**
- transcribe-worker in CrashLoopBackOff (Parker) — transcription jobs blocked.
- Deploy pipeline broken, line 127 (Parker) — production deployments failing.
- CORS broken, security headers missing (Ripley) — browser-side API calls will fail.
