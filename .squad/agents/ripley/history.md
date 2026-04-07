# Ripley — History

## Project Context
- **Project**: YT Summarizer — YouTube video knowledge library
- **Stack**: Python/FastAPI, SQLAlchemy, Azure Queue Storage, yt-dlp, Auth0
- **User**: Ashley Hollis

## Key Knowledge
- DB connection: get_database_url() checks ConnectionStrings__ytsummarizer (Aspire) FIRST, then DATABASE_URL (.env fallback).
- CORS origins configured in services/shared/shared/config.py (ApiSettings.cors_origins).
- Video quota uses queue-based approach: excess jobs get quota_status='quota_queued'.
- Auth gates use require_auth dependency. Quota: free=5 videos/day + 30 copilot/hr, admin=unlimited.
- RecoveryService provides auto-healing: dead-letter retry, orphan detection, stale job cleanup.
- Login endpoint accepts 'connection' and 'login_hint' query params, forwarded to Auth0.

## Learnings
<!-- Append learnings below -->

### 2026-05-xx — Library 500 fix: noload all lazy-selectin Video relationships

**Root cause of 42 E2E skips:** `Video.segments`, `Video.artifacts`, and `Video.jobs` all have `lazy="selectin"` on the SQLAlchemy model. When SQLAlchemy loads a `Video` object, it auto-fires a SELECT for every `lazy="selectin"` relationship not explicitly overridden. Migration 015 added a `label` column to Segments — any `selectin` load of `Video.segments` on a DB without migration 015 would fail with a 500.

**Fix in library_service.py:**
- `_build_video_query`: noload `segments`, `artifacts`, AND `jobs` (all three have `lazy="selectin"`)
- `get_video_detail`: noload `segments` and `jobs` (artifacts intentionally loaded via `selectinload`)
- Use explicit COUNT queries for segment counts rather than loading the relationship

**Fix in k8s/base/migration-job.yaml:**
- Changed hook from `Sync` (wave 1) to `PreSync`. The old config ran the migration job AFTER default-wave (0) resources like the API deployment — so API pods could start while the DB was still unmigrated. `PreSync` guarantees migrations finish before any sync-phase resource starts.

**Rule:** For any model with `lazy="selectin"` relationships, always explicitly add `noload()` in every query that doesn't need that relationship. Never rely on "not accessing the attribute" to prevent the auto-fire — SQLAlchemy fires on load, not on access.

### 2026-05-xx — CORS custom domain fix for preview environments

**Root cause:** `cors_origin_regex` in `services/shared/shared/config.py` only matched `*.azurestaticapps.net`. E2E tests hit the SWA custom domain (`pr-NNN.yt-summarizer.apps.ashleyhollis.com`) which was rejected by CORS, stripping credentials and making all auth-protected tests fail.

**Fix:** Expanded regex to:
```python
r"^https://.*\.(azurestaticapps\.net|yt-summarizer\.apps\.ashleyhollis\.com)$"
```
This covers both native SWA URLs and all custom-domain preview/prod environments under `*.yt-summarizer.apps.ashleyhollis.com`.

**Also updated:** the fallback `MockSettings.cors_origin_regex` in `services/api/src/api/main.py` to match, so local dev without the shared package also gets the right regex.

**Canonical source of truth:** `services/shared/shared/config.py` `ApiSettings.cors_origin_regex`. `main.py` reads from `settings.api.cors_origin_regex` — no duplicate hardcoded logic.

### 2026-03-22 — Stale Queued Job Re-queue Strategy

**Problem:** 17 videos stuck with `stage=queued`/`status=pending` from March 22. Azure Storage Queue messages had expired (invalid OpenAI key kept workers down). Recovery sweep didn't detect them because orphan detection only queries `Video.processing_status == "processing"` — these videos were likely still in `processing` status but all their jobs were in `queued`/`pending`, not `running`/`failed`.

**Fix:** Added fourth recovery strategy `_requeue_stale_queued_jobs()` to `RecoveryService`. Detects jobs in `queued`/`pending` state for >30 minutes and re-sends queue messages. Guards: skip if succeeded job exists, skip if running job exists, skip if job >24h old (abandoned), cap at `MAX_AUTO_RECOVERIES` per sweep run.

**Key constants added:**
- `STALE_QUEUE_THRESHOLD_MINUTES = 30` — queue message expiry window
- `MAX_REQUEUE_AGE_HOURS = 24` — cutoff for "truly abandoned" jobs

**RecoveryResult** gained `queued_job_requeues: int` field — propagates automatically to `/api/v1/admin/recovery/run` response via Pydantic `response_model=RecoveryResult`.

### 2026-03-05 — PR #177 Preview API Smoke Test

**Environment:** `https://api-pr-177.yt-summarizer.apps.ashleyhollis.com`

**Healthy:**
- All three health endpoints return 200: `/health` (all dependency checks pass — DB, blob, queue), `/health/ready`, `/health/live`.
- Auth flow works: `GET /api/auth/login` redirects (302) to correct Auth0 tenant `dev-gvli0bfdrue0h8po.us.auth0.com`.
- `POST /api/v1/videos` and `POST /api/v1/batches` correctly return 401 without a session cookie.
- `GET /api/v1/batches` returns 200 with empty array — correct for fresh env.

**Known/Expected Behaviours:**
- `GET /api/v1/videos` returns 405 — there is no GET list-videos route; the endpoint only accepts POST. This is consistent with production and is by design.
- `/openapi.json`, `/docs`, `/redoc` all return 404 — OpenAPI spec is disabled in non-local environments (intentional).

**Issues Found:**
1. **`GET /api/v1/admin/recovery/status` returns 200 with no auth required.** The route in `services/api/src/api/routes/admin.py` has no `require_auth` dependency. It exposes internal job-queue counts (dead-lettered jobs, stale jobs, active jobs). This is a **security gap** — low-severity info disclosure but should be gated.
2. `POST /api/v1/admin/recovery/run` and `POST /api/v1/admin/quota/dispatch` also have no `require_auth`. Not verified in this test run but visible in source.

**Auth0 tenant confirmed:** `dev-gvli0bfdrue0h8po.us.auth0.com` — correct dev tenant for preview environments.

### 2026-03-05 — CORS Preflight Fix & Security Headers

**Root cause of CORS 400**: Middleware ordering. `CorrelationIdMiddleware` (a `BaseHTTPMiddleware` subclass) was added after `CORSMiddleware`, making it the outermost wrapper. `BaseHTTPMiddleware` intercepted OPTIONS preflight requests before `CORSMiddleware` could handle them, causing 400 responses. Fix: CORSMiddleware must be added **last** via `add_middleware()` so it's outermost.

**Key rule**: In FastAPI/Starlette, `add_middleware()` inserts at position 0 of an internal list and the stack is built in reverse. The **last** call to `add_middleware` creates the **outermost** middleware. CORS must always be outermost.

**Changes made:**
- Reordered middleware: CorrelationId (first/inner) → SecurityHeaders → CORS (last/outer)
- Added SWA URL `https://white-meadow-0b8e2e000.6.azurestaticapps.net` to explicit `cors_origins` (belt-and-suspenders with regex `^https://.*\.azurestaticapps\.net$`)
- Enumerated allowed methods/headers instead of wildcard `*`
- Created `SecurityHeadersMiddleware` in `services/api/src/api/middleware/security.py`: HSTS, X-Content-Type-Options, X-Frame-Options, CSP (`default-src 'self'`), Referrer-Policy

**Auth config verified:**
- Callback URL: dynamically built from `X-Forwarded-Proto` + `Host` headers — no hardcoded URLs
- Cookie: `samesite="none"`, `secure=True`, no explicit `domain` — correct for cross-origin BFF pattern
- `default_return_to` configurable via `AUTH0_DEFAULT_RETURN_TO` env var — should be set in K8s deployment to SWA URL

**Note:** `AUTH0_DEFAULT_RETURN_TO` env var in K8s deployment should point to `https://white-meadow-0b8e2e000.6.azurestaticapps.net` (or the custom domain once re-pointed).

### 2026-03-04 — Production API Health Check

**Observations from `https://api.yt-summarizer.apps.ashleyhollis.com`:**

- `/health/ready` ✅ returns 200. All checks pass: `api`, `database_init`, `database_connection`, `database_connection_cached` all `true`. DB is healthy.
- `/health/live` ✅ returns 200 `{"status":"ok"}`. Liveness probe works.
- `/api/auth/session` ✅ returns 200 `{"user":null,"isAuthenticated":false}` for unauthenticated requests — correct behaviour.
- `/api/v1/videos` GET returns 405 (Method Not Allowed) — videos endpoint only accepts POST (correct). POST without auth returns 401 as expected.
- `/docs` and `/openapi.json` return 404 — Swagger UI and OpenAPI spec are disabled in production (intentional).
- TLS cert: wildcard `*.yt-summarizer.apps.ashleyhollis.com`, valid until Feb 2026.
- Response times: 534–743ms — all under 2s, acceptable.
- **Worker health** is not exposed through the health endpoint — only API and DB checks are reported.
- **Security headers are missing**: HSTS (`Strict-Transport-Security`), `X-Content-Type-Options`, `X-Frame-Options`, and `Content-Security-Policy` are all absent. Server header exposes `nginx`.
- **CORS issue**: OPTIONS preflight returns HTTP 400 and no `Access-Control-Allow-Origin` header for the app origin (`https://yt-summarizer.apps.ashleyhollis.com`), even though `Access-Control-Allow-Credentials: true` is returned. This could cause frontend requests to fail in the browser.

**Cross-agent findings:**
- Frontend SWA completely inaccessible (Kane) — users cannot reach the app.
- transcribe-worker crash loop (Parker) — all video transcription jobs blocked.
- Deploy pipeline broken (Parker) — infrastructure changes cannot be deployed.
