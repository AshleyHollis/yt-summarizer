# Kane — History

## Project Context
- **Project**: YT Summarizer — YouTube video knowledge library
- **Stack**: Playwright, pytest, Vitest, GitHub Actions CI
- **User**: Ashley Hollis

## Key Knowledge
- Auth0 test users: [email scrubbed], [email scrubbed]
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

### 2026-06-02 — PR #177 Preview Auth0 Config Audit

**Auth0 Env Vars in Preview Pod (namespace: preview-pr-177)**
- ✅ `AUTH0_DOMAIN` — set
- ✅ `AUTH0_CLIENT_ID` — set
- ✅ `AUTH0_CLIENT_SECRET` — set
- ✅ `AUTH0_SESSION_SECRET` — set
- ✅ `AUTH0_DEFAULT_RETURN_TO` — set (value: `https://red-grass-06d413100-177.eastasia.6.azurestaticapps.net`)
- ✅ `API__CORS_ORIGINS` — set (value: `["https://red-grass-06d413100-177.eastasia.6.azurestaticapps.net","http://localhost:3000"]`)

**Auth Login Flow**
- `GET /api/auth/login` → 302 redirect to `https://dev-gvli0bfdrue0h8po.us.auth0.com/authorize` ✅
- `redirect_uri` in redirect = `https://api-pr-177.yt-summarizer.apps.ashleyhollis.com/api/auth/callback` ✅
- State `returnTo` decodes to `https://red-grass-06d413100-177.eastasia.6.azurestaticapps.net` ⚠️ (wrong SWA URL — see issue below)

**Terraform Auth0 Config**
- ✅ `auth0_allowed_callback_urls` includes wildcard: `https://api-pr-*.yt-summarizer.apps.ashleyhollis.com/api/auth/callback`
- ✅ `auth0_allowed_logout_urls` includes: `https://*.azurestaticapps.net`
- ✅ `auth0_allowed_web_origins` includes: `https://*.azurestaticapps.net`
- ✅ Preview-specific variables also have wildcard coverage

**CORS Mismatch — ⚠️ BUG FOUND**
- Actual SWA URL for PR 177 (task-provided): `https://proud-hill-0940e7300-177.eastasia.6.azurestaticapps.net`
- CORS configured in API pod: `red-grass-06d413100-177.eastasia.6.azurestaticapps.net`
- Root cause: `scripts/ci/generate_preview_kustomization.sh` line 65 hardcodes `red-grass-06d413100-${PR_NUMBER}` as the SWA URL fallback when `--swa-url` is not passed. The `update-k8s-overlay` workflow runs before SWA deployment and cannot pass the actual SWA URL, so the wrong fallback is baked into CORS and `AUTH0_DEFAULT_RETURN_TO`.

**Frontend API URL Config**
- SWA `staticwebapp.config.json` contains only platform/routing config — no hardcoded API URL
- `api-url` is injected at deploy time via the `deploy-frontend-swa.yml` workflow → `NEXT_PUBLIC_API_URL` / `API_URL` set to `https://api-pr-177.yt-summarizer.apps.ashleyhollis.com` ✅

**Key Learning**: The k8s overlay CORS/returnTo is set from a hardcoded fallback SWA hostname (`red-grass`) because the overlay is committed before SWA deployment runs. A post-SWA-deploy patch step to update CORS/returnTo with the actual SWA URL would fix this. Auth0 wildcard origins cover the Auth0 side, but the API's own CORS header will reject browser requests from `proud-hill`.
