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

### Method 2: AzCLI Direct Deploy (Recommended)

**Pros**: Faster feedback (~2-5 min per test)  
**Cons**: Requires manual setup

```bash
# Authenticate
az login

# Get SWA resource details
az staticwebapp show \
  --name swa-ytsumm-prd \
  --resource-group rg-ytsumm-prd

# Build app
cd apps/web
npm run build

# Deploy
az staticwebapp environment create \
  --name swa-ytsumm-prd \
  --resource-group rg-ytsumm-prd \
  --environment-name "baseline-test" \
  --source ./apps/web/.next/standalone
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
