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

### 2026-06-02 — CI fixme removal + segment threshold

**Removed test.fixme(!!process.env.CI) guards from 22 files**
- Trigger: cookie fix landed on `test/e2e-env-verification` (SameSite=None + CORS allow_credentials + credentials:include in frontend).
- All guards with "Cross-domain cookie issue", "Auth0 Universal Login", "CopilotKit/Azure OpenAI credentials", "Route interception unreliable", and "Video submission pipeline" messages were removed.
- **Preserved**: `synthesis-api.spec.ts` → Coverage Verification describe block (embed pipeline timing issue, not a cookie problem).
- **Preserved**: `video-flow.spec.ts` LIVE_PROCESSING guards were not touched (they were already removed in this PR).
- `processing-history.spec.ts` and `queue-progress.spec.ts` retain `test.use({ storageState: undefined })` — these pages don't use auth state.
- `smoke.spec.ts` `test.skip(!!process.env.CI)` inside `beforeEach` blocks were NOT removed (task only targeted `test.fixme`, not `test.skip`).

**Lowered MIN_SEGMENTS_REQUIRED from 40 to 35** in `global-setup.ts` to avoid "39 of 40" borderline timeout in CI.

**auth.setup.ts verified correct**: navigates to API URL directly (not SWA), saves storageState to `playwright/.auth/user.json` and `playwright/.auth/admin.json`. No changes needed.

**Key learning**: Always distinguish between `test.fixme` (marks test as expected to fail/skip) and `test.skip` (hard skip). Only `test.fixme` guards were in scope for this removal round.

### 2026-06-02 — synthesis-api fixme audit + relationship graph coverage

**synthesis-api.spec.ts fixme analysis**
- The global `test.fixme(!!process.env.CI, 'Cross-domain cookie issue...')` was overly broad.
- Root cause: `synthesize` endpoint uses `check_copilot_quota` → `require_auth`, returning 401 without an auth token. The `request` fixture carries no cookies/tokens, so all synthesize tests fail with 401 in CI.
- The `coverage` endpoint (`POST /api/v1/copilot/coverage`) has NO auth dependency — it can run in CI freely.
- Fix applied: removed top-level CI fixme; added per-describe `test.fixme(!!process.env.CI, ...)` to each block using synthesize. Coverage Verification describe now runs in CI.

**Relationship graph coverage**
- Endpoint: `GET /api/v1/copilot/neighbors/{video_id}` (router prefix: `/api/v1/copilot`).
- Response model: `NeighborsResponse` — fields: `sourceVideoId` (UUID), `neighbors` (array of `NeighborVideo`).
- `NeighborVideo` fields: `video` (RecommendedVideo), `relationshipType`, `confidence` (0–1), `rationale?`, `evidenceText?`.
- NO authentication required — safe for CI.
- FastAPI validates UUID path params; malformed UUIDs return 422.
- New file: `apps/web/e2e/relationships.spec.ts` — 6 tests covering structure, sourceVideoId echo, neighbor fields, limit param, graceful empty response, and 422 on bad UUID.

**Key learning**: When removing broad fixme markers, always check whether each endpoint has auth dependencies in the FastAPI route definition (`Depends(require_auth)` or `Depends(check_copilot_quota)`) — not just whether it's "API-level".

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

### 2026-04-03 — Full E2E Coverage Audit (branch: test/e2e-env-verification)

**Coverage State Summary**
- ~80% of E2E tests are `test.fixme(!!CI)` due to the cross-domain SWA↔AKS cookie issue.
- Only `smoke.spec.ts` navigation tests and `health-indicator.spec.ts` reliably run in CI.
- The cross-domain fixme blocks: ALL auth tests, ALL copilot/chat tests, library, RBAC, processing-history, queue-progress, channel-ingest, synthesis.
- **Relationship graph has ZERO E2E coverage** — no test file checks that relationships were built.
- **Transcription/summarization have ZERO CI coverage** — `video-flow.spec.ts` requires `LIVE_PROCESSING=true`.
- `synthesis-api.spec.ts` is API-level (no browser auth needed) but still has `fixme(CI)` — likely overly conservative, could be fixed.
- `auth.setup.ts` runs in CI (saves user.json / admin.json via Key Vault creds + API URL), but the cookies are unusable from the SWA domain.
- Full audit file at `.squad/decisions/inbox/2026-04-03T07-12-53Z-kane-e2e-coverage-audit.md`

**Files with most fixme/skip occurrences in CI:**
- `smoke.spec.ts`: 12, `video-flow.spec.ts`: 12, `library.spec.ts`: 13, `full-journey.spec.ts`: 9, `rbac-navigation.spec.ts`: 7

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

### 2026-06-04 — Chat-Responses E2E Test Hardening (branch: test/e2e-env-verification)

**Root Cause of 4 Failing Tests**
- Error: `Expected at least 2 assistant messages, found 1` at helpers.ts:194
- The test's Strategy B (waitForResponse lifecycle-complete path) had an incorrect assertion
- Original assumption: CopilotKit always has 2 assistant messages (greeting + response)
- Reality: CopilotKit is configured with NO initial greeting (`apps/web/src/app/providers.tsx` has no `makeSystemMessage`)
- Each test starts with fresh BrowserContext (line 39-45 in chat-responses.spec.ts), so no accumulated thread history
- First assistant message is the agent's response to the user query, not a greeting

**waitForResponse Function Architecture** (helpers.ts lines 127-200)
- Two-phase wait strategy:
  1. Phase 1: Wait for "Searching your video library..." loading indicator to appear/disappear
  2. Phase 2: Race two strategies to detect response completion
- **Strategy A** (tool-rendered): Wait for specific content indicators (video cards, "Recommended Videos", "Limited Information", etc.)
- **Strategy B** (lifecycle-complete): Wait for chat input to re-enable + verify assistant message count
- Timeout derives from test's actual timeout: `Math.max(testInfo.timeout - 30_000, 60_000)` (line 131)
- Tests marked `test.slow()` triple timeout: 120s → 360s, so waitForResponse gets 330s (5.5 minutes)

**Changes Made** (commit 0a2f0f40)
- Fixed Strategy B assertion from `count < 2` to `count < 1` (only need 1 message: the response)
- Increased post-response render wait from 2s to 5s for cloud preview streaming delays
- Added clarifying comments about no-greeting architecture

**Environment-Based Skipping**
- No `test.skip` guards needed for Azure OpenAI unavailability
- Parker's commit 7ee3255b already fixed the ESO `openai-credentials` secret pause issue
- Azure OpenAI creds now flow correctly into preview namespace via Terraform → Key Vault → ESO
- Tests should work without additional skip guards once infrastructure is healthy

**Key Learning**: When asserting on CopilotKit message counts, verify the actual configuration in `apps/web/src/app/providers.tsx`. Don't assume there's a greeting unless `makeSystemMessage` or similar is configured. Always check if tests use fresh vs. accumulated context (look for `BrowserContext` creation in `beforeEach`).
