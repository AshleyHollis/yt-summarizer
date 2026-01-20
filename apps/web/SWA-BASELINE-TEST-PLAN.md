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

## 🔴 CRITICAL FINDING - Phase 0 Result

**Date**: 2026-01-20 12:35 AEST  
**Test**: Baseline deployment (clean `main` branch, NO Auth0 code)  
**Method**: SWA CLI direct deployment  
**Result**: ❌ **TIMED OUT at 10 minutes**

### What This Means

**The issue is NOT Auth0-related!**

The baseline deployment from `main` (which has ZERO Auth0 code) still times out after 10 minutes. This proves:

1. ❌ NOT caused by Auth0 SDK
2. ❌ NOT caused by Auth0 middleware
3. ❌ NOT caused by our Auth0 integration code
4. ❌ NOT caused by missing Auth0 env vars
5. ✅ **IS** an SWA platform or Next.js 16 standalone mode issue

### Evidence

```
Command: swa deploy --app-location . --output-location .next/standalone --deployment-token [REDACTED] --env 66
Started: 12:25 AEST
Ended: 12:35 AEST (timeout at 10 minutes)
Status: Preparing deployment. Please wait...
Result: TIMEOUT (no error message, just hung)
```

**Same behavior as GitHub Actions**: Exact 10-minute timeout during "warmup" or "preparing deployment" phase

### Comparison

| Environment | Code | Auth0 | Result | Time |
|-------------|------|-------|--------|------|
| Production (main) | Clean | ❌ No | ✅ Works | ~46s |
| Production (main) via SWA Action | Clean | ❌ No | ✅ Works | ~46s |
| Preview PR #64 | + Auth0 | ✅ Yes | ❌ Timeout | ~590s |
| Preview PR #66 (baseline) | Clean | ❌ No | ❌ Timeout | ~600s |
| SWA CLI PR #66 | Clean | ❌ No | ❌ Timeout | ~600s |

### Root Cause Analysis

**Pattern Identified**: Preview environments (named environments) timeout, production (default environment) works

**Likely Causes**:

1. **SWA Named Environment Bug**:
   - Default environment (`swa-ytsumm-prd`) works fine
   - Named environments (`--env 66`) consistently timeout
   - Possible Azure platform regression or capacity issue

2. **Next.js 16 + SWA Preview Incompatibility**:
   - Next.js 16.1.3 standalone mode might have issues with SWA preview infrastructure
   - Production might use different deployment path than previews
   - Check: When did Next.js 16 get deployed to production? Was it before or after last successful preview?

3. **SWA Regional/Scale Issue**:
   - Preview environments might be deployed to different region or tier
   - Resource constraints on preview infrastructure
   - Warmup timeout hardcoded at 10 minutes (not configurable)

---

## REVISED Strategy

Since the issue is NOT Auth0-related, we need to:

### Immediate Actions

1. ✅ **Document finding** - Auth0 is innocent
2. 🔄 **Test production deployment** - Does deploying to default environment work?
3. 🔄 **Check Next.js version history** - When was Next.js 16 introduced?
4. 🔄 **Review SWA deployment history** - When did preview deployments last work?

### Test Production Default Environment

```bash
# Deploy same code to production (default environment) to confirm it works
cd apps/web
swa deploy \
  --app-location . \
  --output-location .next/standalone \
  --deployment-token [REDACTED]
  # NO --env flag = deploys to default environment
```

**Expected**: Should succeed in < 2 minutes (like production deployments via GitHub Actions)

**If Succeeds**: Confirms named environments are broken  
**If Fails**: Next.js 16 standalone mode issue with SWA

---

## Test Results Tracker (UPDATED)

| Phase | Change | Deploy Method | Time | Result | Notes |
|-------|--------|---------------|------|--------|-------|
| 0 | Baseline (no Auth0) | SWA CLI (env 66) | 600s | ❌ Timeout | **AUTH0 NOT THE CAUSE** |
| 0b | Baseline (no Auth0) | SWA CLI (default) | TBD | ⏳ Pending | Test production env |
| 1-6 | N/A | N/A | N/A | ⏭️ Skipped | Auth0 phases no longer needed |

---

## Next Steps

### Option A: Escalate to Azure Support (Recommended)

**Evidence to Provide**:
- Baseline code (no Auth0) times out in preview environments
- Same code works in production (default environment)
- Consistent 10-minute timeout across:
  - GitHub Actions deployments
  - Manual SWA CLI deployments
- Next.js 16.1.3 standalone mode
- Resource: `swa-ytsumm-prd` in `rg-ytsumm-prd`

**Request**:
- Access to SWA warmup logs for environment `66`
- Confirmation of preview environment limits or issues
- Next.js 16 compatibility status
- Regional/tier differences between default and named environments

### Option B: Workaround - Use Production for Testing

**Temporary Solution**:
- Deploy Auth0 changes directly to production
- Skip preview deployments temporarily
- Add feature flags to disable Auth0 in production if needed
- Test locally with SWA CLI emulator

### Option C: Downgrade Next.js

**Test Hypothesis**:
```bash
# Check when Next.js 16 was introduced
git log --all --oneline -- apps/web/package.json | grep -i next

# Try deploying with Next.js 15
cd apps/web
npm install next@15
npm run build
swa deploy --app-location . --output-location .next/standalone --deployment-token [REDACTED] --env 67
```

---

**CRITICAL FINDING**: The SWA warmup timeout is a **platform/infrastructure issue**, NOT an Auth0 integration issue.

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

**Last Updated**: 2026-01-20 12:15 AEST  
**Status**: Phase 0 - Preparing baseline deployment  
**Current Branch**: `test/swa-warmup-baseline`
