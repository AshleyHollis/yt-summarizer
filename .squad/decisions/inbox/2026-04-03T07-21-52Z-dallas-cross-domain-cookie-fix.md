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