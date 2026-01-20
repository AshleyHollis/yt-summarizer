# Azure SWA Preview Deployment - Warmup Timeout Investigation

> **Status**: ACTIVE INVESTIGATION (as of 2026-01-20)  
> **Issue**: Preview deployments timeout after ~10 minutes during warmup phase  
> **Branch**: `004-auth0-ui-integration` (PR #64)

## Problem Summary

Azure Static Web Apps preview deployments are failing with:

```
Status: Failed. Time: 589.1550295(s)
Deployment Failed :(
Deployment Failure Reason: Web app warm up timed out. Please try again later.
```

**Timeline**:

- **Working**: Production deployments complete in ~46 seconds
- **Broken**: Preview deployments timeout after ~589 seconds (~10 minutes)
- **Pattern**: Consistent timeout at exactly ~590 seconds across multiple attempts

## What We've Tried

### Attempt 1: Make Auth0 Non-Blocking ✅ IMPLEMENTED

**Hypothesis**: Auth0 SDK initialization was blocking app startup when env vars missing

**Changes Made**:

1. Converted `apps/web/src/lib/auth0.ts` to lazy initialization
2. Added graceful degradation - returns `null` if Auth0 not configured
3. Updated `apps/web/src/proxy.ts` to handle missing Auth0 client
4. Created error page: `apps/web/src/app/auth-config-error/page.tsx`

**Expected Outcome**: App starts successfully, shows error page for protected routes

**Actual Outcome**:

- ✅ Frontend build succeeded
- ❌ Deployment still times out at warmup

**Commits**:

- `98de9da` - "fix(auth): convert auth-config-error page to client component to fix build"
- `435ebc2` - "fix(auth): make Auth0 non-blocking + configure SWA app settings via AzCLI"

---

### Attempt 3: Bypass Proxy Middleware ❌ FAILED

**Hypothesis**: Proxy middleware crashes during startup when Auth0 not available

**Changes Made**:

Completely bypassed all auth logic in `apps/web/src/proxy.ts`:

```typescript
export async function proxy(request: Request) {
  console.log('[Proxy] BYPASSED - Testing SWA warmup issue');
  return NextResponse.next(); // Skip all auth checks
}
```

**Expected Outcome**: App starts without auth logic, warmup succeeds

**Actual Outcome**:

- ✅ Frontend build succeeded
- ✅ Upload to SWA succeeded
- ❌ Deployment still timed out at warmup

**Conclusion**: Proxy middleware is NOT the cause

**Commits**:

- `ba3c581` - "test: bypass proxy middleware to isolate SWA warmup timeout"

**Workflow Run**: 21155101426  
**Time to failure**: ~590 seconds

---

### Attempt 4: Simplify Next.js Rewrites ❌ FAILED

**Hypothesis**: Next.js validates rewrite destinations during startup, hangs when backend unreachable

**Changes Made**:

Removed ALL backend rewrites in `apps/web/next.config.ts`:

```typescript
async rewrites() {
  return {
    beforeFiles: [
      {
        source: '/.swa/health.html',
        destination: '/.swa/health',
      },
    ],
    afterFiles: [], // REMOVED: All backend proxy rewrites
    fallback: [],
  };
}
```

**Expected Outcome**: App starts without trying to contact backend, warmup succeeds

**Actual Outcome**:

- ✅ Frontend build succeeded
- ✅ Upload to SWA succeeded
- ❌ Deployment still timed out at warmup

**Conclusion**: Next.js rewrites are NOT the cause

**Commits**:

- `cd36788` - "test: simplify Next.js rewrites to isolate SWA warmup timeout"

**Workflow Run**: 21155710988  
**Started**: 00:58:23Z  
**Failed**: 01:08:35Z  
**Time to failure**: 583.3 seconds (~9.7 minutes)

**Error**:

```
Deployment Failed :(
Deployment Failure Reason: Web app warm up timed out. Please try again later.
```

---

## What We've Eliminated

Based on systematic testing:

- ❌ Auth0 lazy initialization - Not the cause (made it graceful, still fails)
- ❌ Proxy middleware - Not the cause (bypassed completely, still fails)
- ❌ Next.js rewrites - Not the cause (removed all backend rewrites, still fails)
- ❌ AzCLI app settings timing - Not relevant (runs after warmup succeeds)

**Key Insight**: Something else in the Next.js app is crashing/hanging during initialization

---

### Attempt 2: Configure Auth0 Env Vars via AzCLI ✅ IMPLEMENTED

**Hypothesis**: SWA needs runtime env vars configured after deployment

**Changes Made**:
Added new workflow step in `.github/workflows/preview.yml`:

```yaml
- name: Configure SWA environment app settings (runtime)
  run: |
    ENVIRONMENT_NAME="${{ needs.detect-changes.outputs.pr_number }}"
    az staticwebapp appsettings set \
      --name "swa-ytsumm-prd" \
      --resource-group "rg-ytsumm-prd" \
      --environment-name "$ENVIRONMENT_NAME" \
      --setting-names \
        "AUTH0_SECRET=${{ steps.fetch-auth0.outputs.auth0-session-secret }}" \
        # ... other Auth0 vars
```

**Expected Outcome**: Runtime env vars available after deployment

**Actual Outcome**:

- ⏸️ NEVER EXECUTED - deployment fails before this step runs
- ❌ Deployment still times out at warmup

**Key Learning**: App settings configuration happens AFTER deployment succeeds, so it can't fix warmup timeout

---

## Root Cause Analysis

### What We Know

1. **Build Phase**: ✅ Succeeds
   - `npm run build` completes successfully in CI
   - `skip_app_build: true` in deployment action
   - Pre-built `.next/standalone` folder uploaded

2. **Upload Phase**: ✅ Succeeds
   - Zipping completes in ~5 seconds
   - Upload completes successfully
   - Deployment artifact received by SWA

3. **Warmup Phase**: ❌ FAILS
   - SWA starts the Next.js server in standalone mode
   - Server has **10 minutes** to respond to health checks
   - Timeout occurs at exactly ~589-590 seconds
   - Suggests server never became healthy

4. **What Changed**:
   - **Before**: No Auth0 integration → Preview deploys in ~20 seconds
   - **After**: Auth0 integration → Preview times out at ~590 seconds
   - **Production**: Still works (has Auth0 env vars configured via Terraform)

### Critical Insight from GitHub Issues

Reviewed Azure/static-web-apps issues #1440, #1457, #1496:

**Common Pattern**:

- Issue happens when Next.js server crashes or hangs during startup
- SWA has NO visibility into application logs during warmup
- 10-minute timeout is hardcoded in SWA deployment action
- **Most common causes**:
  1. Uncaught exception during module initialization
  2. Missing required env vars causing app to crash
  3. Middleware intercepting health check endpoints
  4. Database/external service connection hanging indefinitely

**Resolution Patterns**:

- Issue #1440: Self-resolved (likely transient Azure issue)
- Issue #1457: Removed problematic build command
- Issue #1496: Never fully resolved

---

## Hypothesis: Next.js Server Crashing During Startup

### Theory

Even though we made Auth0 **lazy**, there might be another part of the code that:

1. Eagerly imports/initializes Auth0 during module load
2. Crashes the server before it can respond to health checks
3. SWA keeps retrying for 10 minutes, then gives up

### Evidence Supporting This

1. **Our Auth0 lazy init isn't truly lazy**:

   ```typescript
   // apps/web/src/lib/auth0.ts:101-112
   export const auth0 = new Proxy({} as Auth0Client, {
     get(_target, prop) {
       const client = getAuth0Client(); // Called on EVERY property access
       if (!client) {
         throw new Error(...); // 🚨 THROWS if Auth0 not configured
       }
       return (client as any)[prop];
     },
   });
   ```

2. **Where this Proxy might be accessed**:
   - Middleware evaluation (runs on every request, including health checks)
   - API route handlers during import/registration
   - React Server Components during SSR

3. **Middleware still references `auth0`**:
   Need to check if middleware or route handlers import the `auth0` export directly

---

## Next Steps (Prioritized)

### 🔴 HIGH PRIORITY: Investigate What's Crashing the Server

#### Step 1: Check if Proxy `auth0` export is used anywhere

```bash
# Search for direct imports of `auth0` (not `getAuth0Client`)
cd apps/web
grep -r "import.*\bauth0\b" src/
grep -r "auth0\." src/
```

**Why**: If anything accesses `auth0.something` during module load and Auth0 isn't configured, it throws an error

**Action**: Replace all `auth0.X` with `getAuth0Client()?.X` pattern

---

#### Step 2: Add server startup logging

**File**: `apps/web/src/instrumentation.ts` (create if doesn't exist)

```typescript
export async function register() {
  if (process.env.NEXT_RUNTIME === 'nodejs') {
    console.log('[Instrumentation] Server starting...');
    console.log('[Instrumentation] NODE_ENV:', process.env.NODE_ENV);
    console.log('[Instrumentation] Auth0 configured:', !!process.env.AUTH0_SECRET);

    // Attempt to initialize Auth0 to see if it crashes
    try {
      const { isAuth0Configured } = await import('./lib/auth0');
      console.log('[Instrumentation] Auth0 check:', isAuth0Configured());
    } catch (error) {
      console.error('[Instrumentation] Auth0 initialization failed:', error);
    }

    console.log('[Instrumentation] Server started successfully');
  }
}
```

**Why**: Next.js logs from standalone mode should be visible somewhere in SWA

**Caveat**: We can't see SWA logs during warmup (only after deployment succeeds)

---

#### Step 3: Simplify to minimum viable app

Create a test branch with Auth0 completely removed:

```bash
git checkout -b test/swa-warmup-minimal
# Remove all Auth0 imports
# Remove middleware that checks auth
# Deploy and see if warmup succeeds
```

**Why**: Confirms Auth0 integration is the culprit

---

### 🟡 MEDIUM PRIORITY: Compare with Production

#### Step 4: Review production vs preview differences

**Production** (works):

- Auth0 env vars configured via Terraform → `azapi_resource_action.swa_app_settings`
- Default environment (no `--environment-name`)
- Deployed from `main` branch

**Preview** (fails):

- Auth0 env vars NOT configured initially
- Named environment (`--environment-name "64"`)
- Deployed from PR branch

**Key Question**: Does SWA behavior differ between default and named environments?

**Test**:

```bash
# Deploy to production with NO Auth0 env vars
# Temporarily remove from Terraform, re-apply
# See if production also times out
```

---

#### Step 5: Check if Next.js rewrites are causing issues

**File**: `apps/web/next.config.ts:70-124`

Our config has dynamic rewrite loading:

```typescript
async rewrites() {
  let backendUrl = process.env.API_URL || 'http://localhost:8000';

  try {
    const fs = require('fs');
    const configPath = path.join(__dirname, 'backend-config.json');
    if (fs.existsSync(configPath)) {
      const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      if (config.url) {
        backendUrl = config.url;
      }
    }
  } catch (e) {
    // Ignore errors
  }

  return {
    beforeFiles: [
      {
        source: '/.swa/health.html',
        destination: '/.swa/health',
      },
    ],
    afterFiles: [
      {
        source: '/api/proxy/:path*',
        destination: `${backendUrl}/:path*`, // 🚨 Could this hang?
      },
      // ...
    ],
  };
}
```

**Potential Issue**: If Next.js tries to validate rewrite destinations during startup and `backendUrl` is unreachable, it might hang

**Test**:

```typescript
// Temporarily return empty rewrites
async rewrites() {
  return {
    beforeFiles: [
      {
        source: '/.swa/health.html',
        destination: '/.swa/health',
      },
    ],
    afterFiles: [],
    fallback: [],
  };
}
```

---

### 🟢 LOW PRIORITY: Workarounds

#### Option A: Skip preview deployments temporarily

Add condition to workflow:

```yaml
- name: Deploy Frontend Preview
  if: false # Temporarily disable while investigating
```

**Why**: Unblocks PR merges while we investigate

---

#### Option B: Use a simpler health check endpoint

Create `apps/web/src/app/.swa/health/route.ts`:

```typescript
export const dynamic = 'force-dynamic';

export async function GET() {
  return new Response('OK', {
    status: 200,
    headers: { 'Content-Type': 'text/plain' },
  });
}
```

**Why**: Ensures health check doesn't trigger any Auth0/middleware logic

---

## Investigation Commands

### Check Deployment Logs (after deployment)

```bash
# SWA doesn't expose logs during warmup, only after deployment
# But if we could see them, this is how:
az staticwebapp show \
  --name swa-ytsumm-prd \
  --resource-group rg-ytsumm-prd \
  --output json

# Check if preview environment exists
az staticwebapp hostname list \
  --name swa-ytsumm-prd \
  --resource-group rg-ytsumm-prd
```

### Check Current App Settings

```bash
# Production (default environment)
az staticwebapp appsettings list \
  --name swa-ytsumm-prd \
  --resource-group rg-ytsumm-prd

# Preview environment
az staticwebapp appsettings list \
  --name swa-ytsumm-prd \
  --resource-group rg-ytsumm-prd \
  --environment-name 64
```

### Manual Deployment Test

```bash
# Build locally
cd apps/web
npm run build

# Deploy manually with SWA CLI
npx @azure/static-web-apps-cli deploy \
  --app-location . \
  --output-location .next/standalone \
  --deployment-token "$AZURE_STATIC_WEB_APPS_API_TOKEN"
```

---

## External Resources

### GitHub Issues (Azure/static-web-apps)

- **#1440**: Same error, self-resolved (transient Azure issue?)
  - User reverted to working commit, still failed
  - Eventually started working again without changes
  - Suggests possible Azure platform issue
- **#1457**: pnpm causing warmup timeout
  - Removed problematic `api_build_command`
  - Issue: `rm -rf ./node_modules/@next/swc-*` was hanging
- **#1496**: Persistent warmup timeout
  - Same workflow that worked 6 weeks prior
  - No resolution provided

### Key Takeaway

Most warmup timeouts are caused by:

1. Server crash during startup (uncaught exception)
2. Infinite hang (waiting for external service)
3. Misconfigured health check endpoint
4. Build artifacts incompatible with SWA runtime

**Our case likely**: Server crashes before responding to first health check

---

## Comparison: Working vs Broken

### Production (WORKING)

**Workflow**: `.github/workflows/deploy-production.yml`

- Deploys to default SWA environment
- Auth0 env vars configured via **Terraform** BEFORE deployment
- App starts with Auth0 available
- Warmup succeeds in ~46 seconds

**Key Difference**: Auth0 env vars exist when server starts

---

### Preview (BROKEN)

**Workflow**: `.github/workflows/preview.yml`

- Deploys to named environment (PR number)
- Auth0 env vars configured via **AzCLI** AFTER deployment
- App starts WITHOUT Auth0
- Warmup times out at ~590 seconds

**Key Difference**: Auth0 env vars don't exist when server starts

---

### The Real Question

**Why does missing Auth0 env vars cause a 10-minute timeout instead of graceful degradation?**

Our lazy initialization should prevent crashes:

```typescript
export function getAuth0Client(): Auth0Client | null {
  if (!isAuth0Configured()) {
    console.warn('[Auth0] Authentication is DISABLED');
    return null; // ✅ Should not crash
  }
  _auth0Client = new Auth0Client();
  return _auth0Client;
}
```

**But something is still crashing the server.** We need to find what.

---

## Diagnostic Plan

### Phase 1: Code Audit ✅ NEXT

1. Search for all `auth0` import usages (not `getAuth0Client`)
2. Check if middleware accesses `auth0` proxy during evaluation
3. Verify no API routes throw errors during module load
4. Review `next.config.ts` rewrites for potential hangs

### Phase 2: Minimal Reproduction 🔄 PENDING

1. Create test branch without Auth0
2. Deploy to preview
3. Confirm warmup succeeds
4. Incrementally add Auth0 features until failure reproduces

### Phase 3: SWA Configuration 🔄 PENDING

1. Try deploying with `is_static_export: true` (force static, no server)
2. Try deploying with minimal `next.config.ts`
3. Compare SWA configuration between production and preview

### Phase 4: Azure Support 🔄 PENDING

1. If all else fails, open Azure support ticket
2. Provide deployment IDs and workflow run links
3. Request access to SWA warmup logs

---

## Success Criteria

- [ ] Preview deployments complete in < 2 minutes (like production)
- [ ] Server starts successfully without Auth0 env vars
- [ ] Health check endpoint responds within 30 seconds
- [ ] App shows graceful error page when Auth0 not configured
- [ ] After AzCLI sets app settings, auth features work on reload

---

## Related Files

**Modified**:

- `apps/web/src/lib/auth0.ts` - Lazy Auth0 initialization
- `apps/web/src/proxy.ts` - Handle missing Auth0
- `apps/web/src/app/auth-config-error/page.tsx` - Error page
- `.github/workflows/preview.yml` - Added AzCLI app settings step

**Need to Review**:

- `apps/web/src/middleware.ts` - Check if imports `auth0`
- `apps/web/src/app/api/auth/[auth0]/route.ts` - Check if crashes on load
- `apps/web/next.config.ts` - Check rewrite destinations

---

## Notes from Previous Sessions

### Session 2026-01-19 (Evening)

- Implemented Auth0 lazy initialization
- Added AzCLI app settings configuration
- Fixed Next.js build error (client component)
- Deployment still times out

### Session 2026-01-20 (Morning - Option 1)

- Reviewed GitHub issues for similar problems
- Identified server crash as likely root cause
- Created investigation plan
- **TESTED**: Option 1 - Bypass proxy middleware completely
- **RESULT**: ❌ FAILED - Still times out (Run 21155101426)

### Session 2026-01-20 (Morning - Option 2)

- **TESTED**: Option 2 - Simplify Next.js rewrites
- **Changes**: Removed ALL afterFiles rewrites, commented out backend URL config
- **Commit**: cd36788
- **RESULT**: ❌ FAILED - Still times out (Run 21155710988, Time: 583.3s)
- **Conclusion**: Rewrites are NOT the cause

### Session 2026-01-20 (Next - Option 3)

- **PLAN**: Check API routes for module-level issues
- **Target**: `apps/web/src/app/api/proxy/[...path]/route.ts`
- **Action**: Temporarily remove API routes to isolate issue

---

**Last Updated**: 2026-01-20 01:18 UTC  
**Investigators**: OpenCode AI  
**Status**: Under Active Investigation - Testing Option 3
