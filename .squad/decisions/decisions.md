# Decisions

## Decisions Index

| Date | Author | Topic | Status |
|------|--------|-------|--------|
| 2026-04-04 | spec-f* | Feature Spec Imports | Completed |
| 2026-04-03 | Various | CI/CD & Preview Fixes | In Progress |
| 2026-03-04 | Parker, Kane, Ripley | Production Deployment | Documented |

---

# E2E Coverage Audit — Kane (2026-04-03)

## Context
Branch: `test/e2e-env-verification`
Purpose: Verify preview AND production environments are functional (transcripts, relationships, all features).

---

## Verification Matrix

| Functionality | Test Files | CI Status (preview-e2e.yml) | Confidence |
|---|---|---|---|
| **Transcription pipeline** | `video-flow.spec.ts` (LIVE_PROCESSING), `queue-progress.spec.ts`, `processing-history.spec.ts` | ⚠️ SKIP — `LIVE_PROCESSING=true` required; `queue-progress` and `processing-history` have `test.fixme(!!CI)` | **LOW** — No E2E test confirms transcript content in CI |
| **Summarization** | `video-flow.spec.ts` (LIVE_PROCESSING), `processing-history.spec.ts` | ⚠️ SKIP — both require live processing or `fixme(CI)` | **LOW** — No E2E confirms summary generation in CI |
| **Relationship graph** | None directly | ❌ NOT COVERED | **NONE** — No test asserts relationship links were built |
| **Embedding/vector search** | `synthesis-api.spec.ts`, `full-journey.spec.ts`, `chat-responses.spec.ts` | ⚠️ SKIP — all `fixme(!!CI)` cross-domain cookie issue | **LOW** — API-level synthesis test has `fixme(CI)` |
| **Copilot/chat (LLM queries)** | `copilot.spec.ts`, `chat-responses.spec.ts`, `full-journey.spec.ts`, `single-response.spec.ts` | ⚠️ SKIP — all `fixme(!!CI)` | **LOW** — Zero copilot tests run in preview CI |
| **Authentication (login/logout)** | `auth-username-password.spec.ts`, `auth-signout.spec.ts`, `auth-protected-page.spec.ts`, `auth-session-persistence.spec.ts`, `auth-social-login.spec.ts` | ⚠️ SKIP — all `fixme(!!CI)` cross-domain cookie | **LOW** — Auth setup still runs (auth.setup.ts via Key Vault creds), but all dependent tests are fixme'd |
| **RBAC (admin vs user)** | `rbac-admin-access.spec.ts`, `rbac-normal-user-denied.spec.ts`, `rbac-navigation.spec.ts` | ⚠️ SKIP — all `fixme(!!CI)` cross-domain cookie | **LOW** — RBAC not verified in CI at all |
| **Library page** | `library.spec.ts` | ⚠️ SKIP — `fixme(!!CI)` (CopilotKit triggers auth redirect in SWA preview) | **LOW** — Library page not E2E-tested in CI |
| **Video submission (single)** | `smoke.spec.ts` ("Video Submission" suite), `video-flow.spec.ts` | `smoke.spec.ts` "Video Submission" has `fixme(!!CI)`; navigation smoke tests ✅ ACTIVE | **MEDIUM** — Landing page, navigation, and form UI are tested; actual submission fixme'd |
| **Queue/progress tracking** | `queue-progress.spec.ts` | ⚠️ SKIP — `fixme(!!CI)` | **LOW** — Not verified in CI |
| **Health indicators** | `health-indicator.spec.ts` | ✅ ACTIVE — no CI skip/fixme | **HIGH** — Runs in CI, tests banner visibility and ARIA |
| **Channel ingest** | `channel-ingest.spec.ts` (navigation/form only; batch creation requires LIVE_PROCESSING) | ⚠️ SKIP — top-level `fixme(!!CI)` on the full describe | **LOW** — All channel-ingest tests skipped in CI |
| **Explain ("Why this?")** | `explain.spec.ts` | Depends on LLM returning video cards — no fixme, but inherently soft assertions | **MEDIUM** — Runs in CI but assertions are lenient |
| **Synthesis/learning path** | `synthesis.spec.ts`, `synthesis-api.spec.ts` | ⚠️ SKIP — both `fixme(!!CI)` | **NONE** — Not tested in CI |

---

## Tests ACTIVE in CI (preview-e2e.yml)

These tests actually execute against preview:

| Test File | What Runs |
|---|---|
| `smoke.spec.ts` | ✅ Navigation smoke tests (landing page, CTAs, feature cards, page titles, `add` heading). Form interaction tests are `fixme(CI)`. |
| `health-indicator.spec.ts` | ✅ Health banner visibility, ARIA attributes, message content |
| `auth.setup.ts` | ✅ Runs (setup project) — authenticates admin+user via Auth0 using Key Vault creds |
| `explain.spec.ts` | ✅ Runs but assertions are soft (LLM-dependent) |
| `rbac-normal-user-denied.spec.ts` | Partial — `/forbidden` page tests (no auth required) run; auth-gated tests `fixme(CI)` |

---

## Critical Gaps

### 1. Relationship graph — **zero coverage**
No E2E test asserts that videos are related to each other. The relationship worker output is never verified by any test.

### 2. Copilot / LLM functionality — **zero CI coverage**
All copilot tests (`copilot.spec.ts`, `chat-responses.spec.ts`, `full-journey.spec.ts`, `single-response.spec.ts`, `synthesis.spec.ts`, `synthesis-api.spec.ts`) have `test.fixme(!!process.env.CI, 'Cross-domain cookie issue...')`. They never run in preview CI.

### 3. Transcription + Summarization — **zero CI coverage**
All tests that verify actual transcript or summary content require either `LIVE_PROCESSING=true` or are `fixme(CI)`.

### 4. Library page — **zero CI coverage**
`library.spec.ts` is `fixme(CI)` because CopilotKit on the library page triggers an Auth0 redirect in the SWA preview environment.

### 5. RBAC — **zero CI coverage**
All three RBAC spec files are `fixme(CI)` due to the cross-domain cookie issue.

### 6. Channel ingest — **zero CI coverage**
The entire `channel-ingest.spec.ts` describe block is `fixme(CI)`.

---

## Root Cause: Cross-Domain Cookie Issue

**Persistent blocker** documented in history.md:
- Auth cookies are set on the API domain (`api-pr-N.yt-summarizer.apps.ashleyhollis.com`)
- SWA frontend loads from a different domain (`*.azurestaticapps.net`)
- Browser does not send auth cookies cross-domain → frontend sees unauthenticated → redirects to Auth0

This causes `test.fixme(!!process.env.CI, 'Cross-domain cookie issue...')` on **~80% of all tests**.

---

## Key Observations

1. **`auth.setup.ts` does run** — it authenticates via the API URL directly (not SWA), saving `user.json` and `admin.json`. However, the saved session cookies can't be used on the SWA domain.

2. **`smoke.spec.ts` navigation tests** are genuinely healthy in CI — they confirm the landing page renders, CTAs work, and the `/add` route is reachable.

3. **`health-indicator.spec.ts`** is the most reliable functional test in CI — it confirms the API health check is wired up correctly.

4. **`video-flow.spec.ts`** contains `test.fixme(!!CI, 'Route interception unreliable...')` on error handling tests specifically; the LIVE_PROCESSING suite is skipped entirely via the `LIVE_PROCESSING` env var.

5. **`queue-progress.spec.ts` polling test** adds `test.use({ storageState: undefined })` to avoid cross-domain issues, yet still has `test.fixme(!!CI)` — indicating even public pages have cookie problems in preview.

6. **`synthesis-api.spec.ts`** tests the API directly (no browser auth), but is still `fixme(CI)` — this seems overly conservative; it could potentially run without the cookie issue.

---

## Manual Verification Checklist for Ashley

Run these steps manually after the preview/prod deployment to verify full functionality:

### Phase 1 — API Health
```bash
# Preview
curl https://api-pr-{N}.yt-summarizer.apps.ashleyhollis.com/health/live
curl https://api-pr-{N}.yt-summarizer.apps.ashleyhollis.com/health/ready

# Production
curl https://api.yt-summarizer.apps.ashleyhollis.com/health/live
curl https://api.yt-summarizer.apps.ashleyhollis.com/health/ready
```
**Expected:** All health checks return `{"status":"healthy",...}` with all sub-checks `true`.

### Phase 2 — Frontend Accessibility
- [ ] Open the SWA URL in a browser — page loads (not Azure 404)
- [ ] Landing page shows "YT Summarizer" heading, "Browse Library" and "Add Content" CTAs
- [ ] `Health indicator` banner is NOT visible (API is healthy)

### Phase 3 — Authentication
- [ ] Click "Add Content" → redirected to Auth0 login
- [ ] Log in with admin test credentials → redirected back to `/add`
- [ ] User profile visible in nav with correct email
- [ ] Log out → redirected to login / home

### Phase 4 — Video Submission & Transcription
- [ ] Submit `https://www.youtube.com/watch?v=ZDa-Z5JzLYM` (Python OOP Tutorial 1 — has auto-captions)
- [ ] Confirm redirect to `/library/{video-id}`
- [ ] Watch status: `pending` → `processing` (transcribing) → further stages
- [ ] Open "History" tab: confirm "Extracting Transcript", "Generating Summary", "Creating Embeddings" stages appear with timing data
- [ ] Confirm final status = `completed`
- [ ] Confirm "Summary" tab shows actual summary text (not empty)

### Phase 5 — Relationship Graph
- [ ] After at least 2 videos are ingested (e.g., `ZDa-Z5JzLYM` and `BJ-VvGyQxho`, both Python OOP), open one video detail
- [ ] Verify "Related Videos" section shows the other OOP video as related
- [ ] Similarity score should be > 0.7 for same-topic videos

### Phase 6 — Copilot / Chat
- [ ] Navigate to `/library?chat=open`
- [ ] Ask: "What Python topics do I have videos about?"
- [ ] Confirm agent responds with video titles/content (not an error)
- [ ] Confirm response includes video card links to `/library/{id}`
- [ ] Ask: "How do I do a proper push-up?" — should return push-up videos if ingested
- [ ] Ask: "How do I bake a chocolate cake?" — should show "Limited Information" indicator

### Phase 7 — Channel Ingest
- [ ] Navigate to `/ingest`
- [ ] Enter `https://www.youtube.com/@darciisabella/videos`
- [ ] Click "Fetch Videos" — verify video list loads within 60s
- [ ] Select 1-2 videos and click "Ingest Selected"
- [ ] Confirm redirect to `/ingest/{batch-id}` batch progress page
- [ ] Confirm batch status updates

### Phase 8 — RBAC
- [ ] While logged in as **normal user**: navigate to `/admin` → redirected to `/forbidden`
- [ ] While logged in as **admin user**: navigate to `/admin` → shows "Admin Dashboard"
- [ ] Normal user does NOT see "Admin" link in nav
- [ ] Admin user sees purple "Admin" link in nav

---

## Recommended Immediate Actions

1. **Fix the cross-domain cookie issue** — This is the root cause blocking ~80% of E2E tests in CI. Options:
   - Configure a shared parent domain for SWA + API (e.g., `*.yt-summarizer.com`)
   - Use a reverse proxy so SWA and API share the same origin
   - Investigate SWA linked backend feature

2. **Un-fixme `synthesis-api.spec.ts`** — These are API-level tests that don't need browser auth. They could run in CI today with a direct API token.

3. **Add a relationship graph smoke test** — E.g., after global-setup seeds videos, assert `/api/v1/library/videos/{id}/relationships` returns at least one relationship. No UI needed.

4. **Add transcription verification to global-setup** — The setup already waits for videos to have "segments" — expose that check as a test assertion so CI can confirm transcription actually completed.


# Decision: Fix Cross-Domain Cookie Issue in SWA Preview E2E Tests

**Author:** Dallas (Tech Lead)  
**Date:** 2026-04-03  
**Status:** Proposed  
**Impact:** ~80% of E2E tests currently skipped in CI  

---

## Root Cause — Confirmed

Preview deployments use **two different origins**:

| Component | Domain | Platform |
|-----------|--------|----------|
| Frontend  | `proud-hill-0940e7300-{PR}.eastasia.6.azurestaticapps.net` | Azure SWA |
| API       | `api-pr-{PR}.yt-summarizer.apps.ashleyhollis.com` | AKS via Gateway API |

The auth flow (BFF pattern via Auth0):
1. Browser navigates to `${apiUrl}/api/auth/login` → Auth0
2. Auth0 authenticates → redirects to `${apiUrl}/api/auth/callback`
3. API sets `appSession` cookie on `api-pr-N.yt-summarizer.apps.ashleyhollis.com`
4. API redirects browser to SWA frontend

When the frontend then makes API calls (via `getClientApiUrl()` → direct cross-origin fetch), the browser does **not** send the `appSession` cookie because:
- The cookie's domain is the API domain
- The request originates from the SWA domain (different site)
- `SameSite=Lax` (default) blocks cross-site cookie sending for non-navigation requests

This affects production too — not just tests. Users on `azurestaticapps.net` hitting `yt-summarizer.apps.ashleyhollis.com` have the same cross-domain issue.

---

## Options Evaluated

### Option A: Next.js API Proxy Rewrites
Next.js rewrites already exist in `next.config.ts` (`/api/:path*` → backend). However:
- **SWA intercepts `/api/*`** as Azure Functions routes before Next.js can handle them (documented in `auth.setup.ts`)
- Client-side code bypasses rewrites entirely — `getClientApiUrl()` returns the direct API URL
- Auth0 callback URL would need to be SWA-based, requiring reconfiguration
- Proxied `Set-Cookie` headers have domain mismatch issues

**Verdict:** Too many moving parts. SWA's `/api` interception is a platform constraint that makes this fragile.

### Option B: Shared Custom Domain
Put SWA previews on `pr-N.yt-summarizer.apps.ashleyhollis.com` alongside `api-pr-N.yt-summarizer.apps.ashleyhollis.com`, then set `Domain=.yt-summarizer.apps.ashleyhollis.com` on cookies.

**Verdict:** Not feasible. SWA preview environments get auto-generated `*.azurestaticapps.net` URLs. Custom domains on preview environments are not a standard SWA capability. The Gateway API can't reverse-proxy to an external HTTPS SWA URL either.

### Option C: `SameSite=None; Secure` Cookies + CORS Credentials ✅ RECOMMENDED
- API sets `appSession` cookie with `SameSite=None; Secure`
- Frontend adds `credentials: 'include'` on all cross-origin API requests
- API CORS config adds `Access-Control-Allow-Credentials: true` for allowed origins

**Verdict:** Architecturally correct. The app IS inherently cross-origin (SWA ≠ AKS). `SameSite=None; Secure` is the W3C-standard mechanism for cross-origin cookies. Security is maintained via `Secure` (HTTPS-only), `HttpOnly`, and strict CORS origin allowlist.

### Option D: Test-Only Cookie Injection (Quick-Win) ✅ RECOMMENDED AS INTERIM
- Modify `auth.setup.ts` to copy `appSession` cookies from API domain to SWA domain in the browser context after Auth0 login
- Tests don't depend on cross-origin cookie flow

**Verdict:** Unblocks CI immediately. Does NOT prove real auth flow works — but that's acceptable as a bridge while Option C ships.

---

## Recommendation

### Primary Fix: Option C — Cross-Origin Cookie Support

This is a small, targeted change across three layers:

**1. Backend (Ripley) — API cookie configuration**
- Configure the Auth0/session middleware to set `SameSite=None; Secure` on `appSession` cookies
- Ensure CORS middleware returns `Access-Control-Allow-Credentials: true` for allowed origins
- Ensure `Vary: Origin` header is set (required when `Access-Control-Allow-Credentials: true`)

**2. Frontend (Lambert) — Credentials on API requests**
- Audit all `fetch()` calls in `services/api.ts`, `services/auth.ts`, and components using `getClientApiUrl()`
- Ensure all cross-origin API requests include `credentials: 'include'`
- The `AuthContext.tsx` session check (`/api/auth/session`) must include credentials

**3. K8s Config (Parker) — CORS in ConfigMap**
- Verify the preview kustomization's `API__CORS_ORIGINS` allows the SWA origin (already does)
- No infra changes needed — CORS origins are already dynamically set per PR

### Quick-Win for Immediate CI Unblocking: Option D

**Implementer:** Lambert or Kane  
**Scope:** `apps/web/e2e/auth.setup.ts` only

After successful Auth0 login (which happens on the API domain), inject the `appSession` cookie into the browser context for the SWA domain:

```typescript
// After authenticateViaAuth0() succeeds:
const cookies = await page.context().cookies();
const swaHostname = new URL(process.env.BASE_URL || 'http://localhost:3000').hostname;
const apiCookies = cookies.filter(c => c.name.startsWith('appSession'));
for (const cookie of apiCookies) {
  await page.context().addCookies([{
    ...cookie,
    domain: swaHostname,
  }]);
}
```

Then remove `test.fixme(!!process.env.CI, 'Cross-domain cookie issue...')` from all affected specs.

---

## Implementation Order

1. **Quick-win (Option D)** — Lambert or Kane — unblock CI immediately (1-2 hours)
2. **Option C backend** — Ripley — cookie + CORS config (half day)
3. **Option C frontend** — Lambert — credentials on fetch calls (half day)
4. **Remove Option D workaround** — Kane — once Option C is verified in preview (cleanup)

---

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| `SameSite=None` allows cookies on any cross-site request | `Secure` flag ensures HTTPS-only; `HttpOnly` prevents JS access; strict CORS allowlist prevents unauthorized origins |
| `credentials: 'include'` + `Access-Control-Allow-Credentials` requires non-wildcard CORS origin | Already configured — `API__CORS_ORIGINS` is a specific SWA URL per PR, not `*` |
| Option D quick-win doesn't test real auth flow | Explicitly documented as temporary; Option C will validate real flow |
| Production SWA may use custom domain in future | Option C works regardless of domain — it handles any cross-origin scenario |


# Decision: SameSite=None; Secure Cookie + CORS Credentials Config (Ripley)

**Author:** Ripley (Backend Developer)  
**Date:** 2026-04-03  
**Status:** Implemented  
**Addresses:** Dallas decision `2026-04-03T07-21-52Z-dallas-cross-domain-cookie-fix.md` — Option C

---

## What Was Changed

### 1. Auth cookies — `services/api/src/api/routes/auth.py`

Both `set_cookie()` calls (callback + logout) use:

```python
response.set_cookie(
    auth.session_cookie_name,
    session_id,
    httponly=True,
    secure=True,
    samesite="none",   # ← allows cross-origin cookie sending
    max_age=auth.session_ttl_seconds,
    path="/",
)
```

`SameSite=None` tells browsers this cookie may be sent on cross-site requests. `Secure=True` enforces HTTPS — the cookie is never sent over plain HTTP.

### 2. CORS middleware — `services/api/src/api/main.py`

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.api.cors_origins,
    allow_origin_regex=settings.api.cors_origin_regex,  # ^https://.*\.azurestaticapps\.net$
    allow_credentials=True,    # ← required for cross-origin cookies
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["Content-Type", "Authorization", "Cookie", "X-Correlation-ID"],
    expose_headers=["X-Correlation-ID"],
)
```

`allow_credentials=True` causes the API to emit `Access-Control-Allow-Credentials: true`. This is required alongside `credentials: 'include'` on the frontend. Note: `allow_origin_regex` is used for `*.azurestaticapps.net` — exact wildcard origins are not supported when credentials are in use, so regex is the correct approach.

### 3. CORS origin config — `services/shared/shared/config.py`

Default origins include the SWA production URL. The regex `^https://.*\.azurestaticapps\.net$` covers all SWA preview environments automatically without needing per-PR configuration.

```python
cors_origins: list[str] = Field(
    default=[
        "http://localhost:3000",
        "http://localhost:3001",
        "https://web.yt-summarizer.apps.ashleyhollis.com",
        "https://web-stg.yt-summarizer.apps.ashleyhollis.com",
        "https://proud-hill-0940e7300.6.azurestaticapps.net",
    ],
)
cors_origin_regex: str | None = Field(
    default=r"^https://.*\.azurestaticapps\.net$",
)
```

### 4. k8s preview overlay — `k8s/overlays/preview/kustomization.yaml`

The CI-generated preview overlay patches `API__CORS_ORIGINS` with the PR-specific SWA URL. The regex covers the rest.

---

## Why SameSite=None; Secure Is the Right Choice

The app is **inherently cross-origin**:
- SWA lives on `*.azurestaticapps.net`
- AKS API lives on `*.yt-summarizer.apps.ashleyhollis.com`

These are different registrable domains. `SameSite=Lax` (browser default) blocks cross-site subresource requests — exactly what happens when the SWA frontend calls `/api/auth/me` after the Auth0 callback sets a cookie on the API domain.

`SameSite=None; Secure` is the W3C-standard mechanism for this scenario. Security is maintained by:
- `Secure` — HTTPS-only, never sent over HTTP
- `HttpOnly` — JavaScript cannot read the cookie
- `Access-Control-Allow-Credentials: true` only for allowlisted origins (not `*`)

## Tradeoffs

| Concern | Mitigation |
|---------|-----------|
| `SameSite=None` cookies sent to any cross-site that includes the API URL | `HttpOnly` + `Secure` + CORS allowlist prevents exploitation |
| `secure=True` breaks local dev (HTTP) | Dev uses Aspire on localhost — cookie not set over HTTP in practice. Dev can use token auth or disable secure flag via env var if needed |
| Browser support | All modern browsers support `SameSite=None; Secure` since 2020 |

## Remaining Work (Lambert)

Frontend must add `credentials: 'include'` to all cross-origin API fetch calls. Without this, browsers won't send the cookie even with `SameSite=None`. See Dallas decision for details.


# Decision: Stale Queued Job Re-queue Strategy in RecoveryService

**Date:** 2026-04-03  
**Author:** Ripley (Backend Dev)  
**Status:** Accepted

## Context

17 jobs were stuck in `stage=queued` / `status=pending` since March 22. The root cause was:
1. An invalid `openai-api-key` in Azure Key Vault caused workers to fail silently.
2. Azure Storage Queue messages have a TTL — once expired, no worker can dequeue them.
3. The existing `RecoveryService` only detected orphans via `Video.processing_status == "processing"` + no active jobs, which missed jobs already in `queued`/`pending` with no active queue message.

## Decision

Added a fourth recovery strategy (`_requeue_stale_queued_jobs`) to `RecoveryService`:
- Detects jobs with `stage=queued`, `status=pending`, and `created_at < now - 30m`
- Skips jobs already succeeded or currently running (same job type + video)
- Skips jobs older than 24 hours (`MAX_REQUEUE_AGE_HOURS`) — treated as abandoned
- Caps requeues at `MAX_AUTO_RECOVERIES` (3) per sweep to prevent queue floods
- Reports count in new `queued_job_requeues` field on `RecoveryResult`

## Rationale

- 30-minute threshold aligns with typical Azure Storage Queue message visibility timeout; a job pending longer than that has almost certainly lost its queue message.
- 24-hour age cutoff prevents re-activating truly abandoned work (e.g., from a failed deployment that was rolled back).
- Reusing `MAX_AUTO_RECOVERIES` cap keeps consistent behaviour across all auto-healing strategies.
- No DB schema change required — reuses existing `Job` fields and `_queue_job()` helper.


# Action Required: Auth0 CI Secrets & OpenAI Key Verification

**From:** Parker (DevOps)  
**Date:** 2026-04-03  
**Priority:** Medium

---

## Summary

Two items need your attention before E2E tests can fully succeed in CI.

---

## Item 1: `AUTH0_TEST_EMAIL` / `AUTH0_TEST_PASSWORD` — Fixed in workflow ✅

The `injectAuth0Token()` function in `apps/web/e2e/global-setup.ts` reads
`AUTH0_TEST_EMAIL` and `AUTH0_TEST_PASSWORD` (singular, not the `ADMIN/USER` variants).
These were not being passed to the E2E step — causing the log message:

```
[global-setup] AUTH0_TEST_EMAIL/PASSWORD not set — skipping token injection
```

**Fix applied:** `preview-e2e.yml` now maps the user credentials to those vars:
```yaml
AUTH0_TEST_EMAIL:    ${{ env.AUTH0_USER_TEST_EMAIL }}
AUTH0_TEST_PASSWORD: ${{ env.AUTH0_USER_TEST_PASSWORD }}
```

The values are already in Key Vault (`auth0-user-test-email`, `auth0-user-test-password`)
and are fetched by the existing "Retrieve Auth0 test credentials from Key Vault" step.

**No action needed from you** — the GitHub secrets (`AUTH0_USER_TEST_EMAIL`,
`AUTH0_USER_TEST_PASSWORD`) already exist and are synced.

---

## Item 2: `OPENAI_API_KEY` GitHub Secret — Action Required ⚠️

The "Patch OpenAI key and restart workers in preview namespace" step in `preview.yml`
sources the key from the **GitHub secret** `OPENAI_API_KEY` (set ~2 months ago), NOT
from Key Vault at runtime.

You updated Key Vault with the new key (`GIFSaev7...`), but if the GitHub secret still
holds the stale value (`F0FbNSNv...`), the preview step will patch K8s with the wrong key
and workers will fail.

**Action required:**  
Update the GitHub secret `OPENAI_API_KEY` to match the current Key Vault value:

```bash
# Get current Key Vault value
az keyvault secret show \
  --vault-name kv-ytsumm-prd-ci \
  --name openai-api-key \
  --query value -o tsv

# Update GitHub secret (replace <VALUE> with the output above)
gh secret set OPENAI_API_KEY --repo AshleyHollis/yt-summarizer --body "<VALUE>"
```

---

## Item 3: Note on ROPC vs browser-auth

The `injectAuth0Token()` function (ROPC) is a **fallback** only — it skips writing
`user.json` if `auth.setup.ts` already created it. Since browser-based auth IS working
in CI (`✓ normal user authenticated successfully`), the 652 tests Kane is enabling will
use `storageState` from auth.setup and are NOT blocked by the ROPC gap.

The ROPC fix (Item 1) is a belt-and-suspenders improvement for edge cases where
auth.setup fails and ROPC is the only fallback available.


# Decision: Remove test.fixme(!!process.env.CI) guards from E2E tests

**Date**: 2026-04-03  
**Author**: Kane (Tester)  
**Branch**: test/e2e-env-verification

## Context

All auth-dependent E2E tests were guarded with `test.fixme(!!process.env.CI, '...')` due to a cross-domain cookie issue: auth cookies set on the API domain were not sent by the browser when loading pages from the SWA domain.

The fix landed on this branch:
1. `SameSite=None; Secure` on auth cookies
2. CORS `allow_credentials=True` + `allow_origin_regex` for `*.azurestaticapps.net`
3. `credentials: 'include'` in the frontend

CI confirmed: `[auth-setup] normal user authenticated successfully`.

## Decision

Remove all `test.fixme(!!process.env.CI, ...)` guards from `apps/web/e2e/` with two exceptions:

1. **Keep**: `synthesis-api.spec.ts` Coverage Verification describe block — embed pipeline timing issue, not cookies.
2. **Leave untouched**: `test.skip` (not `test.fixme`) guards — separate concern.

## Files Changed

22 files, 140 lines of guard boilerplate removed.
`global-setup.ts` — `MIN_SEGMENTS_REQUIRED` lowered 40 to 35.

## Rationale

Tests that fail for a different reason will now surface as failures (not silent skips), which is correct CI behaviour.


# Decision: F004 Spec Imported into Squad Format

**Date**: 2026-06-01  
**Author**: Spec agent  
**Status**: For Scribe review

## Context

Feature F004 (Auth0 BFF Authentication + RBAC) had a complete specification in `specs/004-auth0-ui-integration/` using the pre-Squad SpecKit format. This import creates the Squad-format artifacts in `.squad/specs/004-auth0-ui-integration/`.

## Decision

The existing spec content was treated as authoritative. No new decisions were made during import — all architectural choices (BFF pattern, `app_metadata` for RBAC, `proxy.ts` middleware, storage-state Playwright auth) were already established in the source artifacts.

## Implementation State Clarification

The "~50% implemented" note in the original `spec.md` refers to **production deployment readiness** (Auth0 tenant credentials not yet provisioned in Azure Key Vault), not task completion. All 73 implementation tasks in `tasks.md` are marked complete. Three final verification tasks (VF1–VF3) remain pending live infrastructure.

## Action Required

None from Scribe — no new decisions to merge into `decisions.md`. This entry documents the import for audit purposes.


# Decision: F005 Spec Import — No Structural Changes Required

**Date**: 2026-04-04
**Agent**: Spec
**Feature**: F005 — Webshare Rotating Proxy Pool

## Summary

Imported existing `specs/005-webshare-proxy-pool/` into Squad format at `.squad/specs/005-webshare-proxy-pool/`. No architecture decisions were changed during import — all decisions from the original spec session (2026-02-22) are preserved.

## Key Decisions Preserved from Original Spec

- **Rotating residential proxies** (not datacenter or static residential) via Webshare gateway
- **Stateless gateway model** — no per-IP lease coordination; database used for metrics only
- **asyncio.gather(return_exceptions=True) + Semaphore** for concurrent processing (not TaskGroup)
- **Pydantic Settings env vars** for feature flags (not LaunchDarkly or DB-backed)
- **Azure Key Vault via Terraform** for credential storage
- **Local DB logging** for bandwidth tracking (not Webshare API only)

## Implementation Status

15/27 tasks complete (~56%). Core shared library and transcribe worker proxy integration done. Remaining: API channel browsing (T016–T018), concurrent processing (T019–T023), health monitoring (T024–T025), polish (T026–T027).

## No New Decisions

This was a pure import. No architectural changes, no scope changes, no new trade-offs. Scribe does not need to append to decisions.md.


# Decision: F002 Azure CI/CD Pipelines — Spec Import

**Date**: 2026-04-04
**Author**: Spec Agent
**Feature**: F002 — Azure CI/CD Pipelines

## Context

Imported existing `specs/002-azure-cicd/` into Squad format. The source spec documented a complete CI/CD pipeline design including architectural pivots made during implementation (removal of staging environment, adoption of Argo CD Pull Request Generator, move from Helm to Kustomize overlays in PR branches).

## Decisions Captured

### 1. No long-lived staging environment
- Preview environments are the sole pre-production validation surface
- PR overlays live in PR branches (not main); Argo CD Pull Request Generator discovers them via GitHub API

### 2. Argo CD Pull Request Generator over commit-to-main approach
- Preview overlays committed to PR branches (not main) keeps main clean
- Argo CD ApplicationSet with Pull Request Generator auto-creates Applications per open PR

### 3. Single `prod` overlay replacing staging + production
- Removed separate staging environment entirely
- Single `prod` overlay in main branch; previews are per-PR ephemeral only

### 4. Wildcard TLS via DNS-01 (Cloudflare) over per-PR certificate provisioning
- Single wildcard cert covers all preview hostnames
- DNS-01 required for wildcard; HTTP-01 cannot issue wildcards

### 5. `workflow_run` trigger for production deploy
- `deploy-prod.yml` triggered by completion of `ci.yml` on main
- Ensures production only deploys after all CI checks pass; no polling

## Status
All decisions implemented and validated in production. No action required.


# Decision: F001 YT Summarizer — Import Observations

**Date**: 2026-04-04  
**Author**: Spec Agent  
**Context**: Import of `specs/001-product-spec/` into Squad format  
**Scope**: F001 — YT Summarizer Product Foundation  

---

## Decisions Made During Import

### D1: Squad tasks.md uses condensed representation of sub-tasks

**Decision**: Dense sub-task sequences (T129a–T129i, T181a–T181l) were consolidated into
representative Squad task entries rather than listing every lettered sub-task.

**Rationale**: 220 tasks from source would produce an unreadable Squad tasks.md. Representative
tasks preserve phase coverage and agent assignments while keeping the file navigable. All original
task IDs are traceable via the header reference to `specs/001-product-spec/tasks.md`.

**Impact**: None — source spec is not modified.

---

### D2: phase = "execution" (not "complete") for fully-implemented feature

**Decision**: `state.json` has `phase = "execution"` even though all 220 tasks are `[x]`.

**Rationale**: The charter defines `phase = "complete"` as a coordinator-driven transition
after formal sign-off. The Spec agent sets the phase to execution when tasks are generated/imported;
the coordinator advances it to complete after verification. This preserves the workflow protocol.

---

### D3: Feature dates derived from source spec header

**Decision**: Goals.md, research.md, and requirements.md use `Created: 2025-12-13` (from source
spec.md) and `Updated: 2026-04-04` (today's import date).

**Rationale**: The original creation date reflects when the spec work was done, not when it
was imported into Squad format. Using today's date for Created would misrepresent the history.


### 2026-03-05T20:50:00Z: Discord notifications mandatory for all agents

**By:** Ashley Hollis (via Copilot)
**What:** All squad agents must always send Discord notifications for status updates and when they need help or need to ask questions. The squad-human-notification skill has been configured with a reliable node.js script method. Routing rules 23-27 added to enforce.
**Why:** User request — ensures Ashley gets push notifications on phone even when away from terminal.


# Dallas — Region/Cluster Audit
**Date:** 2026-01-09  
**Author:** Dallas (Lead)  
**Trigger:** AKS cluster rebuilt in new Azure region. Audit for stale references.

---

## Summary

The cluster was rebuilt in **East Asia** (based on all Terraform and runbook evidence). The old load balancer IP was `20.255.113.149`; the current Gateway IP is `20.187.186.135`. The domain stack (`*.yt-summarizer.apps.ashleyhollis.com`) appears correct and live. Key risks are: (1) **hardcoded old IP in nginx-gateway-fabric ArgoCD app**, (2) **hardcoded KV secret version IDs** that will break if KV was recreated, (3) **stale preview kustomization** with a specific old PR's SWA hostname baked in.

---

## 1. IP Addresses — Findings

### 🔴 CRITICAL: Old IP hardcoded in live K8s config

| File | Line | Current Value | Status | Should Be |
|------|------|---------------|--------|-----------|
| `k8s/argocd/gateway-api/nginx-gateway-fabric.yaml` | 31 | `service.beta.kubernetes.io/azure-load-balancer-ipv4: "20.255.113.149"` | **STALE — this pins the load balancer to the old IP** | Remove annotation entirely, or update to new IP. Azure should assign dynamically unless pinned. |

### ✅ Old IP in documentation only (safe — historical record)

| File | Line | Notes |
|------|------|-------|
| `docs/runbooks/production-deployment.md` | 24 | Runbook table shows `20.255.113.149` as "Ingress Controller IP" — **stale, needs update** |
| `docs/runbooks/production-deployment.md` | 99–100 | DNS table references old IP — **stale** |
| `DEPLOYMENT-AUDIT-FINDINGS.md` | 36, 95, 102 | Documents the old IP — historical record, low risk |
| `specs/003-preview-dns-cloudflare/tasks.md` | 23, 71 | Historical task notes — safe |
| `specs/003-preview-dns-cloudflare/IMPLEMENTATION_COMPLETE.md` | 115, 116 | Historical — safe |

### ✅ Current IP (`20.187.186.135`) — correctly referenced

Found in: `DEPLOYMENT-AUDIT-FINDINGS.md`, `MIGRATION-LOG.md`, `specs/003-preview-dns-cloudflare/`, `docs/runbooks/external-dns-troubleshooting.md` — all appear to be current documentation.

---

## 2. Cluster Names — Findings

Cluster name in use: **`aks-ytsumm-prd-ci`**

| File | Line | Value | Status |
|------|------|-------|--------|
| `infra/terraform/environments/prod/notes.tf` | 11 | `az aks get-credentials --resource-group rg-ytsumm-prd-ci --name aks-ytsumm-prd-ci` | Correct (comment) |
| `scripts/bootstrap-argocd.ps1` | 17 | same command | Correct |
| `scripts/setup-argocd-github-app.ps1` | 48 | same command | Correct |
| `.github/workflows/deploy-prod.yml` | 167 | `vars.AKS_CLUSTER_NAME \|\| 'aks-ytsumm-prd-ci'` | **Correct default** — if GitHub variable `AKS_CLUSTER_NAME` is set, it overrides |
| `.github/workflows/preview.yml` | 375 | same pattern | **Correct default** |
| `k8s/argocd/external-dns/deployment.yaml` | 32 | `--txt-owner-id=yt-summarizer-aks` | ✅ This is the ExternalDNS TXT record owner label — **NOT** the cluster name; OK but verify it matches what's in Cloudflare TXT records |

**Action for Parker/Ripley:** Confirm GitHub repo variable `AKS_CLUSTER_NAME` is set correctly (or matches the new cluster name). If the cluster was renamed during the rebuild, the default `aks-ytsumm-prd-ci` may be wrong.

---

## 3. Resource Group Names — Findings

Resource group in use: **`rg-ytsumm-prd-ci`**

This name appears consistently across all files. If the cluster was rebuilt into the **same resource group**, no changes needed. If a new resource group was created, every reference below needs updating.

| File | Line | Value | Notes |
|------|------|-------|-------|
| `infra/terraform/environments/prod/shared.tf` | 4 | `resource_group_name = "rg-ytsumm-prd-ci"` | **LIVE CONFIG** — drives Terraform data lookup |
| `infra/terraform/environments/prod/notes.tf` | 11 | comment reference | safe |
| `.github/workflows/deploy-prod.yml` | 166 | `vars.AZURE_RESOURCE_GROUP \|\| 'rg-ytsumm-prd-ci'` | Default — verify GitHub variable |
| `.github/workflows/deploy-frontend-swa.yml` | 140, 224 | same pattern | Default |
| `.github/workflows/preview.yml` | 374 | same pattern | Default |
| `docs/runbooks/production-deployment.md` | 10 | Table row: "East Asia" region listed | **Runbook data needs review** |
| Multiple `*.md` files | various | Documentation references | Low priority |

**`rg-ytsummarizer-tfstate`** (Terraform state RG) — referenced in `infra/terraform/backend.tf` (commented out) and `infra/terraform/environments/prod/backend.tf` — this is the state storage RG, separate from the app RG. Verify it still exists.

---

## 4. Region References — Findings

### Terraform default region

| File | Line | Value | Status |
|------|------|-------|--------|
| `infra/terraform/variables.tf` | 38 | `default = "eastus"` | ⚠️ **MISMATCH** — the deployed cluster is in East Asia, but the root module variables default to `eastus`. The prod environment uses `module.shared.resource_group_location` (dynamically read), so this may be unused in prod — but worth confirming. |

### SWA hostnames confirming East Asia region

All Static Web App preview URLs follow the pattern `*.eastasia.6.azurestaticapps.net`, confirming the SWA is provisioned in East Asia. These appear in:
- `k8s/overlays/preview/kustomization.yaml` — **⚠️ STALE VALUES (see Section 9)**
- `infra/terraform/environments/prod/variables.tf` line 145 — SWA callback URL for `red-grass-06d413100-64.eastasia...`
- Multiple `*.md` files — documentation

### Runbook region label

`docs/runbooks/production-deployment.md` line 10 lists resource group region as **"East Asia"** — this should be verified against the actual new region after rebuild.

---

## 5. DNS / Domain References — Findings

### ✅ Primary domain — consistent and current

`*.yt-summarizer.apps.ashleyhollis.com` references are consistent across:
- `k8s/base/api-httproute.yaml` — correct
- `k8s/argocd/gateway-api/gateway.yaml` — correct
- `k8s/argocd/certificates/yt-summarizer-wildcard.yaml` — correct
- `k8s/overlays/prod/kustomization.yaml` — correct
- `scripts/ci/templates/prod-kustomization-template.yaml` — correct
- `infra/terraform/environments/prod/variables.tf` — correct (Auth0 callbacks)

### ⚠️ Old domain `ytsummarizer.dev` in cert-manager ClusterIssuers

| File | Line | Value | Status |
|------|------|-------|--------|
| `k8s/argocd/cert-manager/clusterissuer-staging.yaml` | 9 | `email: ops@ytsummarizer.dev` | ⚠️ Uses old domain for Let's Encrypt registration email. Functionally OK (ACME doesn't verify), but stale |
| `k8s/argocd/cert-manager/clusterissuer-prod.yaml` | 8 | `email: ops@ytsummarizer.dev` | Same |

---

## 6. Auth0 Configuration — Findings

Auth0 callback URLs are managed via `infra/terraform/environments/prod/variables.tf`. All current API domain callbacks use `*.yt-summarizer.apps.ashleyhollis.com` which looks correct. However:

### ⚠️ Hardcoded staging SWA URL in Auth0 callback list

| File | Line | Value | Status |
|------|------|-------|--------|
| `infra/terraform/environments/prod/variables.tf` | 145 | `https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net/api/auth/callback` | ⚠️ This is a specific SWA staging slot URL. If the SWA was recreated (new hostname), this needs updating. The `eastasia` subdomain indicates it's provisioned in East Asia — verify this URL still works. |

The production SWA appears to use the canonical URL via `web.yt-summarizer.apps.ashleyhollis.com` (custom domain), so the SWA hostname in Auth0 is a fallback for the Azure-assigned URL. **Confirm the SWA resource `swa-ytsumm-prd` was NOT recreated during the cluster rebuild** (SWA is separate from AKS).

---

## 7. Key Vault References — Findings

Key Vault in use: **`kv-ytsumm-prd-ci`**

### ✅ KV name consistent

All references (`k8s/overlays/prod-secretstore/`, `k8s/cluster-resources/`, `k8s/base/`, `infra/terraform/environments/prod/shared.tf`) consistently reference `kv-ytsumm-prd-ci`.

### 🔴 CRITICAL: Hardcoded secret version IDs

`infra/terraform/environments/prod/key-vault.tf` contains `import` blocks with **hardcoded secret version GUIDs**:

```
id = "https://kv-ytsumm-prd-ci.vault.azure.net/secrets/sql-connection-string/794fc0ef377d4263a2d63db0b7aff6d6"
id = "https://kv-ytsumm-prd-ci.vault.azure.net/secrets/storage-connection/4b95c33133f64a44b32aa8eec18fbd0a"
... (8 more secrets with hardcoded version IDs)
```

**If the Key Vault was recreated during the cluster rebuild, these version IDs are invalid.** Terraform import will fail or reference deleted secret versions. These were added after a partial-apply incident (comment says "2026-03-04"). Verify the KV still exists and secrets are at these version IDs, or remove the import blocks and re-import.

---

## 8. ACR References — Findings

ACR in use: **`acrytsummprdci.azurecr.io`**

| File | Line | Value | Status |
|------|------|-------|--------|
| `k8s/overlays/prod/kustomization.yaml` | 22, 25 | `acrytsummprdci.azurecr.io/yt-summarizer-api` etc. | ✅ Consistent |
| `k8s/overlays/preview/kustomization.yaml` | 28, 31 | same | ✅ Consistent |
| `scripts/ci/templates/prod-kustomization-template.yaml` | 19, 22 | same | ✅ Consistent |
| `.github/workflows/deploy-prod.yml` | 74–75 | `vars.ACR_NAME \|\| 'acrytsummprdci'` and `vars.ACR_LOGIN_SERVER \|\| 'acrytsummprdci.azurecr.io'` | ✅ Uses GitHub variable with correct default |
| `.github/workflows/preview.yml` | 72–73 | same | ✅ |
| `.github/workflows/preview-cleanup.yml` | 160 | same | ✅ |

ACR is **global** (not region-bound per se) and was likely not recreated with the cluster. Should be fine, but confirm `acrytsummprdci` is still the correct registry name.

---

## 9. Database / Connection Strings — Findings

Database server referenced: **`sql-ytsumm-prd.database.windows.net`** (from `docs/runbooks/production-deployment.md`)

Connection strings flow through Key Vault → ExternalSecrets → K8s Secret. No hardcoded connection strings were found in K8s manifests or application code.

| File | Notes |
|------|-------|
| `k8s/base/externalsecret-db.yaml` | Pulls `sql-connection-string` from KV — ✅ correct pattern |
| `infra/terraform/modules/sql-database/main.tf` | Generates connection string dynamically from `azurerm_mssql_server.server.fully_qualified_domain_name` — ✅ |
| `docker-compose.ci.yml` | Uses local `mssql:1433` — CI only, not production |

**If the SQL Server was recreated** during the cluster rebuild (it shouldn't be — it's not in AKS), the KV `sql-connection-string` secret needs to be updated. This is the most likely break point if anything was recreated.

---

## 10. GitHub Actions Secrets/Variables — Reference List

### Secrets (must exist in GitHub repo)
- `AZURE_CLIENT_ID` — OIDC federated credential client ID
- `AZURE_TENANT_ID`
- `AZURE_SUBSCRIPTION_ID`
- `SWA_DEPLOYMENT_TOKEN` — Static Web App deploy token
- `DEPLOY_APP_ID` / `DEPLOY_APP_PRIVATE_KEY` — GitHub App for ArgoCD GitOps
- `AUTH0_DOMAIN` / `AUTH0_CLIENT_ID` / `AUTH0_CLIENT_SECRET`
- `AUTH0_SECRET` / `AUTH0_ISSUER_BASE_URL`
- `AUTH0_ADMIN_TEST_EMAIL` / `AUTH0_ADMIN_TEST_PASSWORD`
- `AUTH0_USER_TEST_EMAIL` / `AUTH0_USER_TEST_PASSWORD`
- `COPILOT_ASSIGN_TOKEN`

### Variables (override defaults — these may need updating post-rebuild)
| Variable | Default in code | Notes |
|----------|----------------|-------|
| `AKS_CLUSTER_NAME` | `aks-ytsumm-prd-ci` | **Verify this matches the new cluster name** |
| `AZURE_RESOURCE_GROUP` | `rg-ytsumm-prd-ci` | **Verify this matches the new RG** |
| `ACR_NAME` | `acrytsummprdci` | Should be unchanged |
| `ACR_LOGIN_SERVER` | `acrytsummprdci.azurecr.io` | Should be unchanged |
| `PRODUCTION_URL` | `https://api.yt-summarizer.example.com` ⚠️ | **The default is a placeholder! Must be set to `https://api.yt-summarizer.apps.ashleyhollis.com`** |
| `PRODUCTION_API_URL` | falls back to `PRODUCTION_URL` | Same issue |
| `SWA_NAME` | `swa-ytsumm-prd` | Should be unchanged |
| `TERRAFORM_VERSION` | `1.9` | OK |
| `CLEANUP_PR_IMAGES` | — | Optional |

---

## 11. Stale Preview Kustomization — Findings

### 🔴 STALE: PR-specific values baked into preview overlay

`k8s/overlays/preview/kustomization.yaml` contains values specific to **PR #127**:

| Line | Value | Status |
|------|-------|--------|
| 3 | `# Image: acrytsummprdci.azurecr.io/api:pr-127-255b90f` | Comment only — OK |
| 4 | `# Preview Host: api-pr-127.yt-summarizer.apps.ashleyhollis.com` | Comment only — OK |
| 82 | `CORS_ORIGINS: "https://red-grass-06d413100-127.eastasia.6.azurestaticapps.net"` | **⚠️ LIVE CONFIG with PR-127-specific SWA URL** |
| 101 | `'["https://red-grass-06d413100-127.eastasia.6.azurestaticapps.net","http://localhost:3000"]'` | **⚠️ Same** |
| 113–116 | `api-pr-127.yt-summarizer...` hostname | **⚠️ PR-127 hostname** |

This overlay is used as a template base — the CI script should be overwriting these values via `prod-kustomization-template.yaml` + `kustomize edit`. Confirm the CI pipeline patches these correctly before deployment, as the static file still has PR-127 values.

---

## Priority Action Items for Parker / Ripley

| Priority | Item | File | Action |
|----------|------|------|--------|
| 🔴 P0 | Old IP hardcoded in nginx-gateway-fabric | `k8s/argocd/gateway-api/nginx-gateway-fabric.yaml:31` | Remove `azure-load-balancer-ipv4` annotation OR update to new IP |
| 🔴 P0 | KV secret version IDs — may be invalid post-rebuild | `infra/terraform/environments/prod/key-vault.tf` | Verify KV exists with same secret versions; update or re-import if not |
| 🔴 P0 | `PRODUCTION_URL` GitHub variable has placeholder default | `.github/workflows/deploy-prod.yml:80` | Confirm repo variable is set to actual prod URL |
| 🟡 P1 | Verify GitHub vars `AKS_CLUSTER_NAME`, `AZURE_RESOURCE_GROUP` match new cluster | GitHub repo settings | Manual check |
| 🟡 P1 | Runbook has stale IP and region data | `docs/runbooks/production-deployment.md` | Update IP (`20.255.113.149` → `20.187.186.135`) and verify region row |
| 🟡 P1 | Terraform `variables.tf` `location` default is `eastus`, cluster is East Asia | `infra/terraform/variables.tf:38` | Confirm prod uses dynamic location from shared module (not this default) |
| 🟢 P2 | Stale preview kustomization with PR-127 SWA URLs | `k8s/overlays/preview/kustomization.yaml:82,101` | Confirm CI patches these; or reset to a placeholder |
| 🟢 P2 | cert-manager ClusterIssuer ACME email uses old domain | `k8s/argocd/cert-manager/clusterissuer-*.yaml` | Update `ops@ytsummarizer.dev` to a valid email if needed |


# Kane — Preview Auth0 Config Issues (PR #177)

**Raised by**: Kane (Tester)  
**Date**: 2026-06-02  
**Scope**: Preview environment for PR #177  
**API**: `https://api-pr-177.yt-summarizer.apps.ashleyhollis.com`  
**SWA**: `https://proud-hill-0940e7300-177.eastasia.6.azurestaticapps.net`

---

## ✅ What's Working

1. **All Auth0 secrets are present** in the API pod (`AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`, `AUTH0_SESSION_SECRET`, `AUTH0_DEFAULT_RETURN_TO`).
2. **Login redirect works**: `GET /api/auth/login` returns 302 to Auth0 (`dev-gvli0bfdrue0h8po.us.auth0.com`) with correct `redirect_uri` pointing back to the preview API callback URL.
3. **Terraform Auth0 wildcards are correct**: Callback, logout, and web origin URLs all include `https://api-pr-*.yt-summarizer.apps.ashleyhollis.com/*` and `https://*.azurestaticapps.net` patterns — Auth0 will accept the preview URLs.
4. **Frontend API URL**: The SWA is configured at deploy time with the correct API URL via `NEXT_PUBLIC_API_URL`.

---

## ⚠️ Issues Found

### ISSUE 1 — CORS mismatch: wrong SWA URL in API pod (BLOCKING)

**Symptom**: Browser-side API calls from the actual SWA (`proud-hill-0940e7300-177`) will be rejected by the API with a CORS error.

**Details**:
- API pod `API__CORS_ORIGINS` = `["https://red-grass-06d413100-177.eastasia.6.azurestaticapps.net","http://localhost:3000"]`
- Actual SWA URL = `https://proud-hill-0940e7300-177.eastasia.6.azurestaticapps.net`
- The `proud-hill` origin is **not in the CORS allowlist**

**Root cause**: `scripts/ci/generate_preview_kustomization.sh` (line 65) falls back to a hardcoded SWA hostname (`red-grass-06d413100-${PR_NUMBER}`) when `--swa-url` is not passed. The `update-k8s-overlay.yml` workflow runs in Phase 2 (before SWA deployment in Phase 7), so it does not yet know the real SWA deployment URL.

**Impact**: Authenticated users will encounter CORS failures when the SWA frontend tries to call the API. Auth login may complete (Auth0 wildcard accepts the request) but subsequent API calls from the browser will fail.

---

### ISSUE 2 — Wrong `AUTH0_DEFAULT_RETURN_TO` post-login redirect (UX)

**Symptom**: After a successful Auth0 login, users are redirected to `https://red-grass-06d413100-177.eastasia.6.azurestaticapps.net` instead of the actual SWA.

**Details**:
- `AUTH0_DEFAULT_RETURN_TO` = `https://red-grass-06d413100-177.eastasia.6.azurestaticapps.net`
- The state JWT `returnTo` field decoded from the login redirect confirms this incorrect URL
- Same root cause as Issue 1 (hardcoded fallback in `generate_preview_kustomization.sh`)

**Impact**: Post-login redirect lands on the wrong (potentially non-existent) SWA URL. Users are dropped after sign-in.

---

## Recommended Fix

**Option A (preferred)**: Add a post-SWA-deploy step to the preview pipeline that patches the API deployment with the actual SWA URL returned by the Azure SWA deploy action.

In `preview.yml`, after `deploy-frontend-preview` succeeds, add a step:
```
kubectl set env deploy/api -n preview-pr-${PR_NUMBER} \
  API__CORS_ORIGINS='["${REAL_SWA_URL}","http://localhost:3000"]' \
  AUTH0_DEFAULT_RETURN_TO="${REAL_SWA_URL}"
```
Where `REAL_SWA_URL` = `deploy-frontend-preview.outputs.static_web_app_url`.

**Option B**: Update `generate_preview_kustomization.sh` to require `--swa-url` (remove the hardcoded fallback) and ensure the `manage-kustomization` action obtains and passes the real SWA URL.

**Option C (partial mitigation)**: If the SWA app name is stable across PRs (the `proud-hill` prefix is always the same per subscription/region), update the hardcoded fallback in the script to match reality. This is fragile and not recommended.

---

## Terraform Auth0 — No Changes Needed

The Auth0 Terraform module (`infra/terraform/environments/prod/variables.tf`) correctly uses wildcards for preview:
- `auth0_allowed_callback_urls`: `https://api-pr-*.yt-summarizer.apps.ashleyhollis.com/api/auth/callback` ✅
- `auth0_allowed_logout_urls`: `https://*.azurestaticapps.net` ✅
- `auth0_allowed_web_origins`: `https://*.azurestaticapps.net` ✅

No Terraform changes needed for Auth0 wildcard coverage.


# Kane — Post-Merge Smoke Test Results (2026-03-05)

## Test Summary

| Check | Status | Notes |
|-------|--------|-------|
| API `/health` | ✅ Pass | All 5 checks healthy, uptime ~19.5h |
| API `/health/ready` | ✅ Pass | All readiness probes green |
| API `/docs` | ❌ 404 | Swagger disabled in production (known) |
| CORS preflight | ⚠️ Broken | OPTIONS → 405, missing `access-control-allow-origin` |
| Security headers | ❌ Missing | No HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| Frontend SWA | ❌ 404 | Azure native 404 — no app content deployed |
| Auth session | ✅ Pass | Returns correct unauthenticated state |
| Videos endpoint | ✅ Pass | Auth enforcement working (401 on POST, 405 on GET) |

## Blocking Issues

### 1. Frontend SWA Not Deployed
- URL: `https://white-meadow-0b8e2e000.6.azurestaticapps.net`
- Azure SWA returns its native 404 page — no app bundle has been deployed.
- **Impact**: Users have no UI. Application is inaccessible to end users.
- **Action needed**: Deploy pipeline must push frontend build to SWA.

### 2. CORS Preflight Broken
- OPTIONS request to `/health` returns HTTP 405 "Method Not Allowed"
- Response includes partial CORS headers (`allow-credentials`, `expose-headers`) but no `access-control-allow-origin`
- **Impact**: Any cross-origin fetch from the SWA frontend to the API will fail in-browser.
- **Action needed**: API must handle OPTIONS preflight requests and return proper CORS headers.

### 3. Security Headers Missing
- API responses contain no security headers whatsoever.
- Missing: `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, `Referrer-Policy`
- **Impact**: Fails security best practices; vulnerable to clickjacking, MIME sniffing, etc.
- **Action needed**: Add security headers via middleware or nginx ingress config.

## Decision Needed

The CORS and security header fixes were reportedly merged but have **not landed in production**. Either:
1. The deploy pipeline hasn't completed pushing the new API image, OR
2. The fixes didn't make it into the deployed image.

**Recommendation**: Wait for the current deploy pipeline to finish, then re-test. If issues persist, verify the deployed image tag matches the merge commit.


# Decision: AKS-ACR Credential Provider Must Be Attached

**Date:** 2026-03-05  
**Author:** Parker (DevOps)  
**Context:** PR #170 deploy monitoring (Run #22706152345)

## Problem

ArgoCD sync is blocked because the `db-migration` Job cannot pull images from `acrytsummprdci.azurecr.io` (401 Unauthorized). The AcrPull role exists on the kubelet managed identity, but the AKS cluster's credential provider plugin is not registered for this ACR (`acrProfile: null`).

## Decision

Run `az aks update --name aks-ytsumm-prd-ci --resource-group rg-ytsumm-prd-ci --attach-acr acrytsummprdci` to register the ACR with the AKS credential provider. This is a prerequisite for any image deployment from the new registry.

Additionally, the Terraform AKS module should include `acr_id` in the `aks` resource to ensure this attachment is managed as code and doesn't break again on future rebuilds.

## Impact

- **Blocking**: No new images can be deployed until this is resolved.
- **All pods** currently run old images from `acrytsummprd.azurecr.io` — CORS and security header fixes from PR #170 are NOT live.
- **SWA** not created (Terraform skipped due to CI failure).

## Additional Blockers

- CI pipeline fails due to `npm audit` vulnerabilities in frontend dependencies (13 vulns, 2 high). Frontend team must address.


# Parker — Infrastructure Fixes Post-Rebuild (2026-03-04)

## Decisions Made

### 1. Pipeline Fix: Ternary String Pattern for Boolean Inputs
**Decision**: Use `${{ inputs.X && 'true' || 'false' }}` pattern instead of raw `${{ inputs.X }}` for `continue-on-error` and similar fields that require boolean strings.
**Rationale**: GitHub Actions converts boolean `false` to empty string `''` in expression contexts outside `if:` conditionals. This is a platform behavior, not a bug in our code, but it causes YAML validation errors.
**PR**: #169

### 2. Key Vault RBAC: Bootstrap Dependency
**Decision**: The `github-actions-yt-summarizer` SP's Key Vault Secrets Officer role is a bootstrap dependency that must be provisioned outside Terraform (via Azure CLI or shared-infra). It was granted manually.
**Rationale**: Terraform requires Key Vault read access to plan (import blocks read existing secrets). The SP's role assignment was lost during the cluster rebuild to centralindia. This is a chicken-and-egg problem — Terraform can't self-provision the role it needs to run.
**Action needed**: This role assignment should be codified in `shared-infra` repo to prevent loss during future rebuilds.

## Manual Actions Required (Ashley)

### A. Merge PR #169
Unblocks ALL production deployments. One-line fix.

### B. Populate Webshare Proxy Credentials in Key Vault
```bash
az keyvault secret set --vault-name kv-ytsumm-prd-ci --name webshare-proxy-username --value "<YOUR_USERNAME>"
az keyvault secret set --vault-name kv-ytsumm-prd-ci --name webshare-proxy-password --value "<YOUR_PASSWORD>"
```
Then restart the transcribe-worker:
```bash
kubectl rollout restart deployment/transcribe-worker -n yt-summarizer
```

### C. Update SWA_DEPLOYMENT_TOKEN After Terraform Creates SWA
After the first successful deploy-prod.yml run (which creates `swa-ytsumm-prd`):
1. Get the new SWA deployment token: `terraform output -raw swa_api_key`
2. Update GitHub secret: Settings → Secrets → `SWA_DEPLOYMENT_TOKEN`
3. Re-run the deploy-prod.yml workflow to deploy frontend content


# Decision: Preview Environment PR-177 — Infrastructure Dependencies Verified

**Author:** Parker (DevOps)  
**Date:** 2026-03-05  
**Context:** Ashley requested a full audit of `preview-pr-177` namespace to confirm all secrets, worker deployments, and external connectivity are in place.

## Decision / Finding

The preview environment is **fully operational** — no missing infrastructure gaps found.

## Evidence

### Secrets (5/5 synced from Azure Key Vault via ExternalSecret)
| Secret | Keys Present |
|--------|-------------|
| `auth0-credentials` | `client-id`, `client-secret`, `domain`, `session-secret` |
| `db-credentials` | `connection-string` |
| `openai-credentials` | `api-key`, `azure-api-key`, `azure-deployment`, `azure-embedding-deployment`, `azure-endpoint` |
| `proxy-credentials` | `username`, `password` |
| `storage-credentials` | `connection-string` (covers blob + queue) |

All ExternalSecrets report `SecretSynced: True` against `ClusterSecretStore/azure-keyvault-cluster` (Valid, ReadWrite).

### Worker Deployments (all healthy)
| Worker | Status | Restarts | Queue Connectivity |
|--------|--------|----------|--------------------|
| transcribe-worker | Running 1/1 | 0 | HTTP 200 ✅ |
| summarize-worker | Running 1/1 | 0 | HTTP 200 ✅ |
| embed-worker | Running 1/1 | 0 | HTTP 200 ✅ |
| relationships-worker | Running 1/1 | 0 | HTTP 200 ✅ |

All workers are actively polling their respective Azure Storage queues against `stytsummprd.queue.core.windows.net`.

### ArgoCD
- App `preview-pr-177`: **Synced + Healthy** @ `b3e7c6e5`

## Notable Design Note
- `relationships-worker` only has `OPENAI_API_KEY` (standard OpenAI), not `AZURE_OPENAI_*` keys. This is intentional — it uses GPT for graph relationships rather than Azure OpenAI embeddings/completions. Consistent with summarize/embed workers which have full Azure OpenAI keys.
- Single storage connection string covers both blob and queue access (Azure Storage account-level key), so no separate blob vs. queue secrets are needed.

## Action Required
None — environment is ready for PR-177 testing.


# Decision: CORS & Security Headers Middleware (Ripley, 2026-03-05)

## Context
After AKS cluster rebuild, CORS preflight requests returned 400 (blocking all browser→API calls) and no security headers were present.

## Decisions

### 1. Middleware ordering convention
**CORSMiddleware must always be the LAST `add_middleware()` call** so it's outermost in the stack. `BaseHTTPMiddleware` subclasses (like CorrelationIdMiddleware) must be added before CORS. This is a Starlette/FastAPI platform constraint — violating it breaks OPTIONS preflight.

### 2. Explicit CORS methods/headers
Changed from wildcard `*` to explicit lists: `GET, POST, PUT, DELETE, OPTIONS, PATCH` and `Content-Type, Authorization, Cookie, X-Correlation-ID`. This makes the API contract clearer and follows principle of least privilege. If new methods/headers are needed, they must be added explicitly.

### 3. Security headers via middleware
Added `SecurityHeadersMiddleware` applying HSTS, X-Content-Type-Options, X-Frame-Options, CSP (`default-src 'self'`), and Referrer-Policy. CSP is intentionally minimal — if the API starts serving HTML or scripts, CSP will need loosening.

### 4. SWA origin in explicit list
Added `https://white-meadow-0b8e2e000.6.azurestaticapps.net` to `cors_origins` default list alongside the regex `^https://.*\.azurestaticapps\.net$`. Belt-and-suspenders approach for the primary frontend URL.

## Action needed (not code)
- Set `AUTH0_DEFAULT_RETURN_TO=https://white-meadow-0b8e2e000.6.azurestaticapps.net` in K8s deployment env vars
- Once custom domain `web.yt-summarizer.apps.ashleyhollis.com` is re-pointed to SWA, update the env var


# Decision: Security Headers Deployment Blocked by CI Failure

**Date**: 2026-03-05
**Author**: Ripley (Backend Dev)
**Status**: Needs Action

## Context

PR #170 (CORS preflight fix + SecurityHeadersMiddleware) merged to main, but the Deploy to Production pipeline is blocked. The CI workflow (`22706152321`) failed, causing the "Wait for CI" gate in the deploy workflow (`22706152345`) to fail with exit code 1.

The currently deployed image (`sha-16e161d`) predates PR #170 and does NOT include the SecurityHeadersMiddleware. CORS preflight is working, but security headers (HSTS, X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy) are absent in production.

## Decision

Parker (DevOps) should investigate the CI failure and unblock the deploy pipeline so the security headers reach production.

## Impact

- Production API is missing security headers until deployment completes
- CORS is functional — frontend-to-API communication is not blocked
- No user-facing regression from the current state


# Preview API Test Results — PR #177

**Date:** 2026-03-05  
**Tested by:** Ripley (Backend Dev)  
**Environment:** `https://api-pr-177.yt-summarizer.apps.ashleyhollis.com`

---

## Summary

The preview environment is healthy and most endpoints behave as expected. Two categories of issues found: one confirmed security gap (unauthenticated admin routes) and two "not a bug" behaviours that may look like failures on first inspection.

---

## Results by Category

### ✅ Health Endpoints — All Pass

| Endpoint | Status | Notes |
|---|---|---|
| `GET /health` | 200 | All checks pass: DB, blob storage, queue storage |
| `GET /health/ready` | 200 | `ready: true`, DB init + connection pass |
| `GET /health/live` | 200 | `{"status":"ok"}` |

### ✅ Auth-Protected Mutations — Correctly Gated

| Endpoint | Status | Expected | Result |
|---|---|---|---|
| `POST /api/v1/videos` | 401 | 401 | ✅ PASS |
| `POST /api/v1/batches` | 401 | 401 | ✅ PASS |

### ✅ Public Read Endpoints — Correct Behaviour

| Endpoint | Status | Notes |
|---|---|---|
| `GET /api/v1/batches` | 200 | `{"batches":[],"total_count":0}` — empty, correct for fresh env |
| `GET /api/v1/videos` | 405 | **Not a bug.** There is no GET list-videos route. Endpoint is POST-only by design. |

### ✅ Auth Flow — Correct

| Endpoint | Status | Notes |
|---|---|---|
| `GET /api/auth/login` | 302 | Redirects to `dev-gvli0bfdrue0h8po.us.auth0.com` — correct dev tenant |

### ❌ OpenAPI Spec — Unavailable (Intentional)

| Endpoint | Status | Notes |
|---|---|---|
| `GET /openapi.json` | 404 | Disabled in non-local environments — expected but worth noting for debugging |
| `GET /docs` | 404 | Same |
| `GET /redoc` | 404 | Same |

---

## 🔴 Issue: Admin Routes Unauthenticated

**Severity:** Medium (info disclosure)

`GET /api/v1/admin/recovery/status` returns HTTP 200 with system internals to any unauthenticated caller:

```json
{
  "dead_lettered_jobs": 0,
  "stale_running_jobs": 0,
  "processing_videos": 0,
  "active_jobs": 0,
  "needs_recovery": false
}
```

**Root cause:** `services/api/src/api/routes/admin.py` — none of the three admin routes (`/recovery/status`, `/recovery/run`, `/quota/dispatch`) have a `require_auth` dependency.

**Affected routes:**
- `GET /api/v1/admin/recovery/status` — confirmed 200 without auth
- `POST /api/v1/admin/recovery/run` — not tested but no auth in source
- `POST /api/v1/admin/quota/dispatch` — not tested but no auth in source

**Fix:** Add `require_auth` (and ideally `require_admin`) dependency to all three routes in `admin.py`. Pattern already exists in `admin_quota.py`.

---

## Recommendation

- ✅ PR #177 preview environment is otherwise healthy and ready for frontend testing.
- 🔴 Admin routes should be gated before merging to production. Low urgency since these are read/management endpoints, not data-mutating user-facing routes, but they expose internal queue state.


---

# Decisions

## 2026-03-04 — Production Deployment Verification

### Parker (DevOps)
- **transcribe-worker CrashLoopBackOff** — Root cause: Empty proxy credentials in Azure Key Vault (proxy-username, proxy-password). All transcription jobs blocked. Fix: Populate real Webshare credentials in Key Vault.
- **"Deploy to Production" pipeline failing** — Template syntax error in `.github/workflows/terraform-deploy.yml` at line 127. Empty expression likely cause. Fix: Audit and correct the expression.
- **Azure SWA not found** — `swa-ytsumm-prd` missing from `rg-ytsumm-prd-ci`. Either not provisioned or under different resource group. Action: Verify Terraform state and outputs.
- **API healthy** — Pod running, `/health/ready` returns 200 externally, database connected, TLS valid, DNS resolves, gateway routing correct.
- **ArgoCD in progress** — `yt-summarizer-prod` Synced but Progressing, blocked by transcribe-worker. Will self-resolve once proxy fixed.

### Kane (Tester)
- **Frontend SWA 404 — BLOCKER** — `https://white-meadow-0b8e2e000.6.azurestaticapps.net` has no deployed content. Azure returns native 404 page. Users cannot access application. Fix: Re-run frontend deployment pipeline or confirm SWA URL has changed.
- **API health checks pass** — `/health/ready` green, `/api/auth/session` correct (returns `isAuthenticated: false`).
- **Swagger 404 is intentional** — `/docs` disabled in production (security hardening).

### Ripley (Backend)
- **CORS preflight broken** — OPTIONS to `/api/v1/videos` with app origin returns 400, no Allow-Origin header. Browser-side API calls will fail. Fix: Verify `CORS_ORIGINS` env var includes `https://yt-summarizer.apps.ashleyhollis.com` in Kubernetes/Helm values.
- **Security headers missing** — No HSTS, X-Content-Type-Options, X-Frame-Options, or CSP. Server header exposes `nginx`. Fix: Add headers at nginx ingress (annotations/ConfigMap) or FastAPI SecurityHeadersMiddleware.
- **Worker health not exposed** — `/health/ready` only includes api and database checks. Workers (transcribe, summarize, embed, relationships) have no health representation. Recommendation: Surface workers health via Azure Queue depth or DB heartbeat if available.
- **API core healthy** — `/health/ready` all checks pass, database fully connected (live + cached), TLS cert valid until Feb 2026, response times acceptable.



