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
