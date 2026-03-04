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
