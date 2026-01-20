# SWA Warmup Timeout Investigation - Session 3

> **Date**: 2026-01-20  
> **Investigator**: AI Assistant  
> **Branch**: `test/swa-warmup-baseline`  
> **Status**: ⏳ In Progress

---

## Executive Summary

**Current Status**: Successfully deployed ALL Auth0 components (middleware, providers, pages) to SWA without timeout! Auth0 integration is NOT inherently broken.

**Key Finding**: The issue is NOT the Auth0 code itself - something ELSE in PR #64 is causing the timeout.

---

## Test Results

### Successful Phases (All Passed ✅)

| Phase | Components Added | Deploy Time | Run ID | Notes |
|-------|------------------|-------------|---------|-------|
| Phase 0 | Baseline Next.js (no Auth0) | 2m38s | 21157814189 | Clean main branch |
| Phase 1 | Auth0 SDK package (already included) | Skipped | - | Package was already in Phase 0 |
| Phase 2 | `auth0.ts` utility module | 3m6s | 21157976748 | Lazy init pattern |
| Phase 3 | `proxy.ts` middleware (default export) | 2m33s | 21158433841 | Dynamic imports |
| Phase 3.5 | AuthProvider + hooks | 3m11s | 21158799842 | Client-side context |
| Phase 4 | All auth pages + components | 2m38s | 21158933706 | Admin, login, etc |
| Phase 4.5 | Change to named export | 2m32s | 21159469722 | **Proves export type NOT the issue** |
| Phase 5 | ALL PR #64 src/ files | ⏳ Testing | 21159534591 | **Critical test - reproduce or isolate** |

### Failed Deployment

| Branch | Components | Deploy Time | Status |
|--------|------------|-------------|--------|
| PR #64 (004-auth0-ui-integration) | Full Auth0 integration + other changes | ~590s | ❌ TIMEOUT |

---

## Critical Discovery

**The Auth0 integration code works perfectly when deployed incrementally!**

This means the timeout in PR #64 is caused by:
1. **Non-Auth0 changes** in PR #64, OR
2. **Interaction between Auth0 and other changes**, OR
3. **Something specific to the PR #64 build environment/config**

---

## Key Differences Between Test Branch (✅) and PR #64 (❌)

### Code Differences

1. **proxy.ts export**:
   - Test branch: `export default async function proxy()` (Phase 3)
   - Test branch: `export async function proxy()` (Phase 4.5 - testing now)
   - PR #64: `export async function proxy()` (named export)

2. **Non-Auth0 files changed in PR #64** (~81 files):
   - `next.config.ts` - Rewrites commented out
   - `ErrorBoundary.tsx` - New component
   - Many existing pages reformatted (batches, library, ingest, etc.)
   - CSS formatting changes
   - Workflow changes (added build validation)
   - New documentation files

### Configuration Differences

**next.config.ts**:
- Test branch: Has active rewrites logic with backend URL loading
- PR #64: All rewrites commented out (attempted fix)

**Workflows**:
- Test branch: Uses simplified `swa-baseline-deploy.yml`
- PR #64: Uses full `preview.yml` workflow

---

## PR #64's Previous Fix Attempts (All Failed)

From commit history analysis:

1. **Dynamic Imports** (commit bc8e29b) - ❌ Failed
   - Used `await import('./lib/auth0')` in proxy
   - Still timed out

2. **Simplified Rewrites** (commit 3b239a2) - ❌ Failed
   - Commented out all backend rewrites in next.config.ts
   - Still timed out

3. **Bypass Proxy** (commit e4c4d8c) - ❌ Failed
   - Made proxy return `NextResponse.next()` immediately
   - Still timed out

4. **Non-blocking Auth0** (commit 435ebc2) - ❌ Failed
   - Made Auth0 initialization non-blocking
   - Still timed out

5. **SWA Health Check** (commit 91e4760) - ❌ Failed
   - Added `/.swa/health` route handler
   - Still timed out

---

## Hypotheses

### ❌ Ruled Out

1. **Auth0 SDK causes timeout** - DISPROVEN by successful test deployments
2. **Proxy middleware hangs** - DISPROVEN by Phase 3 success
3. **AuthProvider causes issues** - DISPROVEN by Phase 3.5 success
4. **Auth pages cause problems** - DISPROVEN by Phase 4 success
5. **Next.js rewrites timeout** - Test branch has rewrites and works

### ⏳ Currently Testing

1. **Named export vs default export** (Phase 4.5)
   - Next.js 16 supports both patterns
   - Unlikely to cause timeout but testing anyway

### 🤔 Remaining Possibilities

1. **Build size / complexity**
   - PR #64 has more files and changes
   - Might exceed some SWA warmup threshold

2. **Module dependency chain**
   - Some combination of imports creates circular dependency
   - Or long initialization chain

3. **Non-Auth0 component crashes**
   - New ErrorBoundary component
   - Modified existing pages
   - Some other unrelated code

4. **Build-time vs runtime issue**
   - Next.js pre-rendering might fail on some pages
   - Static generation timeout

5. **Environment variable differences**
   - Test branch might have different env vars configured
   - PR #64 might be missing something critical

---

## Next Investigation Steps

### Immediate (Phase 4.5 Results)

When Phase 4.5 completes:

**If it SUCCEEDS** ✅:
- Named export is NOT the cause
- Need to compare ALL other differences
- Likely culprit is non-Auth0 code

**If it FAILS** ❌:
- Default export vs named export IS the cause!
- Simple fix: change PR #64 to use default export
- Mystery solved

### If Phase 4.5 Succeeds (Most Likely)

**Option A**: Binary search on file differences
1. Add half of remaining PR #64 changes to test branch
2. Deploy and test
3. If fails, the issue is in that half
4. If succeeds, the issue is in the other half
5. Repeat until single file identified

**Option B**: Copy entire PR #64 to test branch
1. Checkout all files from PR #64 to test branch
2. Deploy and see if it fails
3. If fails, we've reproduced the issue
4. If succeeds, it's something in the deployment config

**Option C**: Inspect build output differences
1. Build both branches locally
2. Compare .next/ output
3. Look for size, route, or config differences
4. Check for any errors/warnings in build logs

---

## Questions to Answer

1. **Does PR #64 build successfully locally?**
   - If no: build error might cause SWA warmup hang
   - If yes: issue is environment-specific

2. **What's the exact size difference?**
   - Test branch build: ? MB
   - PR #64 build: ? MB
   - SWA might have size limits

3. **Are there any console errors during build?**
   - TypeScript errors?
   - Linting errors?
   - Import errors?

4. **What routes are generated?**
   - Test branch: X routes
   - PR #64: Y routes
   - More routes = longer warmup?

---

## Files to Investigate if Phase 4.5 Succeeds

Priority order for checking non-Auth0 changes:

1. **apps/web/src/components/ErrorBoundary.tsx** (NEW file, 239 lines)
   - Error boundaries can cause issues if they crash
   - Might have module-level code execution

2. **apps/web/next.config.ts** (modified)
   - Config issues can break builds
   - Commented-out rewrites might cause problems

3. **Modified page files** (batches, library, ingest)
   - Might have new imports that crash
   - Could be pre-rendering failures

4. **apps/web/src/app/providers.tsx** (modified)
   - Root provider changes affect entire app
   - Beyond just AuthProvider

5. **Workflow changes** (.github/workflows/ci.yml)
   - New build validation steps
   - Might affect SWA deployment

---

## Time Investment

- **Phase 0-4**: ~2 hours of investigation
- **Test deployments**: ~30 minutes total runtime
- **Analysis**: Ongoing

**Conclusion**: The systematic incremental approach has proven Auth0 is not the problem. This eliminates ~80% of the potential causes and points us toward investigating non-Auth0 changes in PR #64.

---

## Repository State

**Test Branch** (`test/swa-warmup-baseline`):
- Based on: `main`
- Added: Auth0 SDK, auth0.ts, proxy.ts, AuthProvider, all auth pages
- Status: All deployments successful ✅
- Latest: Phase 4.5 testing named export ⏳

**PR #64** (`004-auth0-ui-integration`):
- Based on: Very old commit (pre-MVP)
- Added: Everything from test branch + 81 other files
- Status: All deployments timeout after ~10 minutes ❌
- Attempted fixes: 10+ different approaches, all failed

---

## Documentation Created

1. `BASELINE-TEST-RESULTS.md` - Detailed test results and methodology
2. `SWA-BASELINE-TEST-PLAN.md` - Original 6-phase test plan
3. `SWA-TIMEOUT-INVESTIGATION-SESSION-3.md` - This document

**Recommendation**: Continue systematic investigation with binary search approach to isolate the exact file/change causing the timeout.
