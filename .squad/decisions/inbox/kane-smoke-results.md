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
