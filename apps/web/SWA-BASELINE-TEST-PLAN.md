# SWA Preview Deployment - Baseline Test Plan

> **Created**: 2026-01-20 12:15 AEST  
> **Purpose**: Systematically identify what Auth0 change breaks SWA preview deployments  
> **Branch**: `test/swa-warmup-baseline`  
> **Baseline**: `main` (last known good state before Auth0)

## Problem Context

PR #64 (`004-auth0-ui-integration`) consistently times out during SWA preview deployment warmup phase (~590 seconds). After 5 failed fix attempts, we're taking a systematic approach to identify the exact breaking change.

## Test Strategy

**Approach**: Progressive addition of Auth0 features, testing after each change

**Baseline**: `main` branch (working production deployments, no Auth0)

**Method**: Manual AzCLI deployment to SWA preview environment

## Test Phases

### Phase 0: Baseline ✅ CURRENT

**Branch**: `test/swa-warmup-baseline` (clean from `main`)

**Expected**: Deployment succeeds in < 2 minutes

**Purpose**: Confirm preview infrastructure works with current Next.js 16 setup

**Test Command**:
```bash
# Build
cd apps/web
npm run build

# Get SWA deployment token from secrets
$TOKEN = (gh secret list | Select-String "AZURE_STATIC_WEB_APPS_API_TOKEN")

# Deploy to SWA preview environment using AzCLI
az staticwebapp deployment create \
  --name swa-ytsumm-prd \
  --resource-group rg-ytsumm-prd \
  --environment-name "baseline-test" \
  --source ./apps/web/.next/standalone \
  --output-location .next/static
```

**Success Criteria**:
- [ ] Deployment completes in < 2 minutes
- [ ] App loads successfully
- [ ] Health check responds
- [ ] No Auth0 features (expected)

**If FAILS**:
- Issue is NOT Auth0-related
- Check Next.js 16 compatibility with SWA
- Check if preview environments have platform issues
- **STOP HERE** - escalate to Azure support

---

### Phase 1: Add Auth0 SDK Dependency

**Changes**: Install `@auth0/nextjs-auth0` package only

```bash
cd apps/web
npm install @auth0/nextjs-auth0
npm run build
# Deploy again
```

**Expected**: Should still work (unused dependency)

**Purpose**: Test if SDK package itself causes issues

**Success Criteria**:
- [ ] Deployment completes in < 2 minutes
- [ ] App works same as baseline
- [ ] No Auth0 code executed

**If FAILS**:
- The Auth0 SDK package itself has incompatibility
- Check SDK version compatibility with Next.js 16
- Try downgrading SDK version

---

### Phase 2: Add Auth0 Utility Module

**Changes**: Add `apps/web/src/lib/auth0.ts` (lazy initialization only)

```bash
# Copy auth0.ts from PR #64
git checkout 004-auth0-ui-integration -- apps/web/src/lib/auth0.ts
npm run build
# Deploy again
```

**Expected**: Should still work (module not imported anywhere)

**Purpose**: Test if Auth0 client initialization code causes issues

**Success Criteria**:
- [ ] Deployment completes in < 2 minutes
- [ ] App works (auth0.ts not used)

**If FAILS**:
- Module-level code in auth0.ts crashes during build/runtime
- Check for require() or import statements at module level
- Check for immediate initialization code

---

### Phase 3: Add Proxy Middleware

**Changes**: Add `apps/web/src/proxy.ts` and register middleware

```bash
# Copy proxy.ts from PR #64
git checkout 004-auth0-ui-integration -- apps/web/src/proxy.ts

# Copy middleware.ts from PR #64
git checkout 004-auth0-ui-integration -- apps/web/src/middleware.ts

npm run build
# Deploy again
```

**Expected**: **THIS IS LIKELY WHERE IT BREAKS**

**Purpose**: Test if middleware with Auth0 imports causes warmup timeout

**Success Criteria**:
- [ ] Deployment completes in < 2 minutes
- [ ] Middleware runs on requests
- [ ] Auth0 gracefully disabled (no env vars)

**If FAILS** 🔴:
- **ROOT CAUSE IDENTIFIED**: Middleware with Auth0 imports breaks SWA warmup
- Possible causes:
  - Middleware executed during warmup, crashes server
  - Auth0 SDK initialization hangs when env vars missing
  - Next.js standalone mode incompatible with Auth0 middleware
- **NEXT STEPS**:
  - Remove middleware, confirm it works without it
  - Test different middleware patterns (edge runtime vs node runtime)
  - Test with minimal Auth0 client (no SDK, just fetch calls)
  - Contact Auth0 support about Next.js 16 standalone compatibility

---

### Phase 4: Add Auth0 Error Page

**Changes**: Add `apps/web/src/app/auth-config-error/page.tsx`

```bash
git checkout 004-auth0-ui-integration -- apps/web/src/app/auth-config-error/page.tsx
npm run build
# Deploy again
```

**Expected**: Should work (just a React component)

**Purpose**: Confirm error page doesn't cause issues

---

### Phase 5: Add Protected Admin Routes

**Changes**: Add admin page with role-based access

```bash
git checkout 004-auth0-ui-integration -- apps/web/src/app/admin/
git checkout 004-auth0-ui-integration -- apps/web/src/app/access-denied/
npm run build
# Deploy again
```

**Expected**: Should work (pages use middleware, already tested in Phase 3)

---

### Phase 6: Add Auth0 API Routes

**Changes**: Add Auth0 callback/login/logout routes

```bash
git checkout 004-auth0-ui-integration -- apps/web/src/app/api/auth/
npm run build
# Deploy again
```

**Expected**: Should work (API routes are optional)

---

## Deployment Methods

### Method 1: GitHub Actions (Automated)

**Pros**: Same environment as PR deployments  
**Cons**: Slow feedback loop (~10 min per test)

```bash
git push origin test/swa-warmup-baseline
# Wait for preview workflow to run
```

### Method 2: Using GitHub Actions Deploy Action Directly (Recommended)

**Pros**: Same environment as PR deployments, no AzCLI complexity  
**Cons**: Requires creating minimal workflow on main branch

**Current Approach**: We've added `.github/workflows/test-swa-baseline.yml` to the test branch, but it needs to be merged to main to be discoverable by GitHub.

**Workaround**: Use the SWA GitHub Action from a local workflow run, or manually upload using `swa-cli`

### Method 3: SWA CLI Upload (Current Method)

**Pros**: Works from any branch, mimics GitHub Actions deployment  
**Cons**: Requires SWA CLI installation and deployment token

```bash
# Install SWA CLI
npm install -g @azure/static-web-apps-cli

# Build app (already done)
cd apps/web
npm run build

# Get deployment token from GitHub secrets
$env:SWA_TOKEN = "YOUR_TOKEN_HERE"  # Get from GitHub secrets AZURE_STATIC_WEB_APPS_API_TOKEN

# Deploy using SWA CLI
swa deploy `
  --app-location . `
  --output-location .next/standalone `
  --deployment-token $env:SWA_TOKEN `
  --env baseline-test

# Alternative: Use GitHub Action locally (if workflow exists on main)
```

### Method 3: SWA CLI (Local Testing)

**Pros**: Immediate feedback  
**Cons**: Different runtime than Azure

```bash
cd apps/web
npx @azure/static-web-apps-cli start .next/standalone --port 4280
```

**Note**: SWA CLI may not reproduce the warmup timeout issue (different environment)

---

## ✅ CRITICAL FINDING - Phase 0 Result (UPDATED)

**Date**: 2026-01-20 13:00 AEST  
**Test**: Baseline deployment (clean `main` branch, NO Auth0 code)  
**Method**: GitHub Actions (SWA deploy action)  
**Result**: ✅ **SUCCEEDED in 2m38s**

### What This Means

**Auth0 IS LIKELY THE CAUSE!**

The baseline deployment from `test/swa-warmup-baseline` (which has ZERO Auth0 code) successfully deploys to SWA preview environments in under 3 minutes when using GitHub Actions. This **contradicts** the earlier SWA CLI finding and proves:

1. ✅ The SWA preview infrastructure works correctly
2. ✅ Next.js 16.1.3 is compatible with SWA
3. ✅ The baseline code (no Auth0) deploys successfully
4. ❌ PR #64 (with Auth0) times out consistently
5. ✅ **Auth0 integration code IS causing the timeout**

### Evidence

**GitHub Actions Deployment (CORRECT METHOD)**:
```
Workflow: .github/workflows/swa-baseline-deploy.yml
Run ID: 21157814189
Branch: test/swa-warmup-baseline
Started: 02:52 UTC
Completed: 02:55 UTC
Duration: 2m38s
Status: ✅ SUCCESS
URL: https://red-grass-06d413100-testswawarmupbas.eastasia.6.azurestaticapps.net
Environment Status: Ready
```

**SWA CLI Deployment (INCORRECT - DISREGARD)**:
```
Command: swa deploy --env 66
Started: 12:25 AEST
Result: TIMEOUT at 10 minutes
Note: This was a LOCAL upload timeout, not an Azure warmup timeout!
The deployment never reached Azure's warmup phase.
```

**Key Insight**: The SWA CLI timeout was during the **upload phase** (local → Azure), not the Azure warmup phase. GitHub Actions successfully uploads and deploys, proving the infrastructure works.

### Comparison

| Environment | Code | Auth0 SDK | Auth0 Code | Method | Result | Time |
|-------------|------|-----------|------------|--------|--------|------|
| Production (main) | Clean | ❌ No | ❌ No | GitHub Actions | ✅ Works | ~46s |
| Preview PR #64 (Attempt 1-5) | + Auth0 | ✅ Yes | ✅ Yes | GitHub Actions | ❌ Timeout | ~590s |
| Preview PR #66 (Phase 0+1) | Clean | ✅ **YES** | ❌ No | GitHub Actions | ✅ **WORKS** | **2m38s** |
| Preview PR #66 (SWA CLI) | Clean | ✅ Yes | ❌ No | SWA CLI (local) | ❌ Timeout | ~600s (upload phase) |

**KEY INSIGHT**: Phase 0 baseline actually included Auth0 SDK package in `package.json`! Phase 1 was completed without knowing it.

### Root Cause Analysis

**Pattern Identified**: Auth0 code causes SWA warmup timeout

**Confirmed Facts**:
1. ✅ Baseline deploys successfully via GitHub Actions in 2m38s
2. ✅ **Auth0 SDK package is ALREADY in baseline and works fine!** (discovered 2026-01-20)
3. ❌ PR #64 (with Auth0 code) consistently times out at ~590s during warmup
4. ✅ Next.js 16.1.3 is NOT the issue (baseline works)
5. ✅ SWA preview infrastructure is NOT the issue (baseline works)
6. ✅ Auth0 SDK package itself is NOT the issue (baseline includes it)
7. ✅ Something in the Auth0 **usage code** causes the warmup to hang

**Most Likely Culprits** (in order of probability - updated based on Phase 1 result):
1. **Auth0 Middleware Execution During Warmup** (HIGHEST PROBABILITY):
   - SWA executes middleware during health checks/warmup
   - Auth0 SDK initialization in middleware hangs when env vars are missing
   - `getAuth0Client()` in middleware blocks waiting for configuration

2. **Auth0 Utility Module (`auth0.ts`) Side Effects**:
   - Module-level initialization code runs during import
   - Lazy initialization might not be truly lazy
   - SDK tries to validate config at module load time

3. **Next.js Middleware Runtime Issue**:
   - Middleware in Next.js 16 + SWA might have compatibility issues
   - Edge runtime vs Node runtime mismatch
   - Auth0 SDK not compatible with edge runtime in SWA context

---

## REVISED Strategy (UPDATED)

Since **Auth0 IS the cause**, we proceed with the original phased approach:

### Immediate Actions

1. ✅ **Baseline confirmed working** - Clean code deploys successfully
2. 🔄 **Phase 1-6**: Progressively add Auth0 features to identify exact breaking point
3. 🔄 **Focus on middleware** - Phase 3 is most likely culprit
4. 🔄 **Test workarounds** - Once identified, test solutions

### Next Phase: Add Auth0 SDK Package Only

The original test plan is still valid! We should now:

1. Install Auth0 SDK package (don't use it)
2. Deploy and test if package alone causes issues
3. Continue through phases 2-6 until we find exact breaking point

**Expected Breaking Point**: Phase 3 (middleware with Auth0 imports)

---

## Test Results Tracker (UPDATED)

| Phase | Change | Deploy Method | Time | Result | Notes |
|-------|--------|---------------|------|--------|-------|
| 0 | Baseline (no Auth0 code) | GitHub Actions | 2m38s | ✅ **SUCCESS** | Proves infrastructure works |
| 1 | +Auth0 SDK package | GitHub Actions | 2m38s | ✅ **SUCCESS** | **ALREADY INCLUDED IN PHASE 0!** |
| 2 | +auth0.ts module | GitHub Actions | TBD | ⏳ **IN PROGRESS** | Not imported yet |
| 3 | +proxy middleware | GitHub Actions | TBD | ⏳ Pending | **Expected to fail** |
| 4 | +error page | GitHub Actions | TBD | ⏳ Pending | If Phase 3 passed |
| 5 | +admin routes | GitHub Actions | TBD | ⏳ Pending | If Phase 4 passed |
| 6 | +API routes | GitHub Actions | TBD | ⏳ Pending | If Phase 5 passed |

**Legend**:
- ⏳ Pending / In Progress
- ✅ Success (< 3 min)
- ❌ Failed (timeout or error)
- ⏭️ Skipped (previous phase failed)

**Phase 1 Discovery**: The baseline test unintentionally included Auth0 SDK package in `package.json` (line 22). This serendipitously proved Phase 1 works!

---

## Next Steps (CORRECTED)

### ✅ Phase 1: Auth0 SDK Package - COMPLETE

**Discovery**: The baseline test inadvertently included `@auth0/nextjs-auth0` package in `package.json` (inherited from main branch state).

**Result**: Package installs and builds successfully without causing timeout.

**Conclusion**: Auth0 SDK package itself does NOT cause the issue. The problem is in HOW it's used.

---

### 🔄 Phase 2: Add Auth0 Utility Module - IN PROGRESS

Next step is to add the Auth0 utility module that wraps the SDK:

```bash
# Copy auth0.ts from PR #64
git fetch origin 004-auth0-ui-integration
git show origin/004-auth0-ui-integration:apps/web/src/lib/auth0.ts > apps/web/src/lib/auth0.ts

# Commit and push
git add apps/web/src/lib/auth0.ts
git commit -m "test: Phase 2 - Add auth0.ts utility module (not imported)"
git push

# Trigger deployment
gh workflow run swa-baseline-deploy.yml --ref test/swa-warmup-baseline -f pr_number=66
gh run watch --workflow="swa-baseline-deploy.yml"
```

**Expected**: Should still work (module not imported anywhere yet)  
**If Fails**: Module-level code in auth0.ts has side effects

---

## Test Results Tracker

| Phase | Change | Deploy Method | Time | Result | Notes |
|-------|--------|---------------|------|--------|-------|
| 0 | Baseline (no Auth0) | AzCLI | TBD | ⏳ Pending | Clean main branch |
| 1 | +Auth0 SDK package | AzCLI | TBD | ⏳ Pending | Just npm install |
| 2 | +auth0.ts module | AzCLI | TBD | ⏳ Pending | Not imported yet |
| 3 | +proxy middleware | AzCLI | TBD | ⏳ Pending | **Expected to fail** |
| 4 | +error page | AzCLI | TBD | ⏳ Pending | If Phase 3 passed |
| 5 | +admin routes | AzCLI | TBD | ⏳ Pending | If Phase 4 passed |
| 6 | +API routes | AzCLI | TBD | ⏳ Pending | If Phase 5 passed |

**Legend**:
- ⏳ Pending
- ✅ Success (< 2 min)
- ❌ Failed (timeout or error)
- ⏭️ Skipped (previous phase failed)

---

## Expected Outcome

**Most Likely Scenario**: Phase 3 (proxy middleware) breaks deployment

**Why**:
- Middleware runs on every request, including SWA health checks
- Auth0 SDK might crash/hang during initialization when env vars missing
- Next.js standalone mode might handle middleware differently than dev mode

**If That Happens**:

1. **Confirm**: Remove middleware, redeploy → should work
2. **Isolate**: Add minimal middleware without Auth0 → should work
3. **Debug**: Add Auth0 step by step:
   - Import auth0.ts but don't call it → test
   - Call isAuth0Configured() only → test
   - Call getAuth0Client() → test
   - Use Auth0Client methods → test

4. **Solutions**:
   - Move auth check from middleware to API routes
   - Use edge runtime for middleware (lighter weight)
   - Replace Auth0 SDK with manual JWT validation
   - Use Auth0 Actions/Rules instead of middleware

---

## Next Steps After Root Cause Found

1. Document exact breaking change
2. Check if there's a workaround
3. Contact Auth0 support if SDK issue
4. Contact Vercel/Next.js if middleware issue
5. Contact Azure if SWA platform issue
6. Apply fix to PR #64
7. Retest on PR #64
8. Merge when confirmed working

---

##Quick Reference Commands

```bash
# Switch to test branch
git checkout test/swa-warmup-baseline

# Build frontend
cd apps/web && npm run build && cd ../..

# Check build output size
du -sh apps/web/.next/standalone

# Deploy to Azure (requires az login)
az staticwebapp deployment create \
  --name swa-ytsumm-prd \
  --resource-group rg-ytsumm-prd \
  --environment-name "baseline-test"

# Check deployment status
az staticwebapp show \
  --name swa-ytsumm-prd \
  --resource-group rg-ytsumm-prd

# View SWA environments
az staticwebapp environment list \
  --name swa-ytsumm-prd \
  --resource-group rg-ytsumm-prd

# Delete test environment when done
az staticwebapp environment delete \
  --name swa-ytsumm-prd \
  --resource-group rg-ytsumm-prd \
  --environment-name "baseline-test"
```

---

**Last Updated**: 2026-01-20 13:00 AEST  
**Status**: ✅ Phase 0 Complete - Baseline SUCCESSFUL  
**Next**: Phase 1 - Add Auth0 SDK package  
**Current Branch**: `test/swa-warmup-baseline`  
**Conclusion**: **Auth0 integration is causing the SWA warmup timeout**
