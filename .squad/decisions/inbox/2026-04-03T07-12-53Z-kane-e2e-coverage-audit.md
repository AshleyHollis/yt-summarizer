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
