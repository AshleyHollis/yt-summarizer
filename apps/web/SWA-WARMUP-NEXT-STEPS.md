# Azure SWA Preview Warmup Timeout - Next Steps

> **Quick Start**: Read this first for immediate action items

## TL;DR

**Problem**: Preview deployments timeout after ~10 minutes  
**Root Cause**: Likely server crash during startup (not just missing env vars)  
**Impact**: Cannot deploy previews, blocking Auth0 integration PR #64

## What We've Already Tested

- ✅ **Option 2: Bypass Proxy Middleware** - ❌ FAILED (Run 21155101426, commit ba3c581)
- ✅ **Option 3: Simplify Next.js Rewrites** - ❌ FAILED (Run 21155710988, commit cd36788)
- ✅ **Dynamic Imports in Middleware** - ❌ FAILED (Run 21156496027, commit bc8e29b)

**Conclusion**: The issue is NOT in our Auth0 integration code. It's something deeper.

---

## What To Try Next (Priority Order)

### 🔴 Option 1: Check for Module-Level Crashes (15 minutes)

The proxy middleware is executed during Next.js startup. Look for any code that might crash:

**Files to Check**:

1. `apps/web/src/app/api/proxy/[...path]/route.ts`
2. Any other files in `apps/web/src/app/api/`

**What to look for**:

- Module-level code execution (code outside functions)
- Imports that might fail if Auth0 not configured
- Database connections at module level
- External API calls at module level

**Quick test**:

```bash
# Temporarily remove the proxy API route
cd apps/web
mv src/app/api src/app/api-backup

# Deploy and see if warmup succeeds
git add src/app
git commit -m "test: remove API routes to isolate warmup issue"
git push
```

If deployment succeeds → The issue is in one of the API routes  
If deployment still fails → Issue is elsewhere

---

### 🔴 Option 2: Disable Proxy Middleware Temporarily (10 minutes)

The `src/proxy.ts` middleware runs on EVERY request. Let's see if it's causing the crash.

**File**: `apps/web/src/proxy.ts:70-147`

**Change**:

```typescript
export async function proxy(request: Request) {
  // TEMPORARY: Bypass all auth logic
  console.log('[Proxy] Middleware bypassed for warmup testing');
  return NextResponse.next();
}
```

**Test**:

```bash
git add src/proxy.ts
git commit -m "test: bypass proxy middleware to isolate warmup issue"
git push
```

If deployment succeeds → Proxy middleware is crashing  
If deployment still fails → Issue is NOT in proxy

---

### 🟡 Option 3: Simplify Next.js Config (20 minutes)

Our `next.config.ts` has dynamic rewrite logic that might hang.

**File**: `apps/web/next.config.ts:70-124`

**Current code** (potentially problematic):

```typescript
async rewrites() {
  let backendUrl = process.env.API_URL || 'http://localhost:8000';

  try {
    const fs = require('fs');
    const path = require('path');
    const configPath = path.join(__dirname, 'backend-config.json');
    if (fs.existsSync(configPath)) {
      const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      if (config.url) {
        backendUrl = config.url;
      }
    }
  } catch (e) {
    // Ignore
  }

  return {
    afterFiles: [
      {
        source: '/api/proxy/:path*',
        destination: `${backendUrl}/:path*`, // Could this cause issues?
      },
    ],
  };
}
```

**Simplified version**:

```typescript
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

**Test**:

```bash
# Edit apps/web/next.config.ts
# Simplify rewrites() as shown above
git add next.config.ts
git commit -m "test: simplify rewrites to isolate warmup issue"
# MUST REBUILD since next.config changes aren't picked up by SWA
cd apps/web && npm run build
git add .
git commit -m "chore: rebuild with simplified config"
git push
```

---

### 🟡 Option 4: Deploy WITHOUT Auth0 Code (30 minutes)

Create a clean test branch with Auth0 completely removed:

```bash
# Create test branch
git checkout -b test/swa-no-auth0

# Remove Auth0 files
rm apps/web/src/lib/auth0.ts
rm apps/web/src/proxy.ts
rm apps/web/src/app/auth-config-error/page.tsx

# Update package.json - remove Auth0 SDK
cd apps/web
npm uninstall @auth0/nextjs-auth0

# Remove Auth0 references from code
# (Use editor to search for 'auth0' and remove imports/usage)

# Rebuild
npm run build

# Commit and push
git add .
git commit -m "test: remove Auth0 entirely to isolate warmup issue"
git push --set-upstream origin test/swa-no-auth0
```

If deployment succeeds → Confirms Auth0 integration is the problem  
If deployment still fails → Something else is wrong

---

### 🟢 Option 5: Compare with Production Deployment (10 minutes)

**Hypothesis**: Maybe named environments (`--environment-name "64"`) behave differently

**Test**:
Deploy the SAME branch to production (temporarily):

```bash
# Trigger production deployment with current branch
# (Requires temporarily changing deploy-production.yml to allow this branch)

# OR

# Try deploying to default environment instead of named environment
# In .github/workflows/preview.yml, remove:
#   deployment_environment: ${{ needs.detect-changes.outputs.pr_number }}
```

If production deployment succeeds → Issue specific to named environments  
If production also fails → Issue is with our code, not SWA config

---

### 🟢 Option 6: Add Startup Logging (20 minutes)

Add instrumentation to see WHERE the crash happens:

**Create**: `apps/web/src/instrumentation.ts`

```typescript
export async function register() {
  if (process.env.NEXT_RUNTIME === 'nodejs') {
    console.log('='.repeat(80));
    console.log('[Instrumentation] Server starting...');
    console.log('[Instrumentation] NODE_ENV:', process.env.NODE_ENV);
    console.log('[Instrumentation] NEXT_PUBLIC_API_URL:', process.env.NEXT_PUBLIC_API_URL);
    console.log('[Instrumentation] API_URL:', process.env.API_URL);

    console.log('[Instrumentation] Checking Auth0 configuration...');
    try {
      // Test if Auth0 module loads without crashing
      const auth0Module = await import('./lib/auth0');
      const configured = auth0Module.isAuth0Configured();
      console.log('[Instrumentation] Auth0 configured:', configured);

      if (!configured) {
        console.warn('[Instrumentation] Auth0 NOT configured - this is EXPECTED in preview');
      }
    } catch (error) {
      console.error('[Instrumentation] CRITICAL: Auth0 module failed to load:', error);
      // Don't re-throw - let server start anyway
    }

    console.log('[Instrumentation] Testing proxy module...');
    try {
      await import('./proxy');
      console.log('[Instrumentation] Proxy module loaded successfully');
    } catch (error) {
      console.error('[Instrumentation] CRITICAL: Proxy module failed to load:', error);
    }

    console.log('[Instrumentation] Server startup complete ✓');
    console.log('='.repeat(80));
  }
}
```

**Problem**: We can't see these logs during SWA warmup (only after deployment succeeds)

**Alternative**: Deploy to a regular App Service or VM where we CAN see logs, then migrate back to SWA

---

## What We Know So Far

### ✅ Things That Work

- Frontend build (passes in CI)
- Upload to SWA (completes successfully)
- Production deployments (complete in ~46 seconds)
- Auth0 lazy initialization (returns null if not configured)

### ❌ Things That Don't Work

- Preview deployments (timeout at ~590 seconds)
- SWA warmup phase (server never becomes healthy)

### 🤔 Things We're Not Sure About

- Whether the server is crashing or hanging
- What specific code is causing the crash/hang
- Whether SWA named environments behave differently
- Whether Next.js rewrites are validated against unreachable backends

---

## Key Insights from GitHub Issues

Reviewed similar issues on Azure/static-web-apps:

- **#1440, #1496**: Same error, some self-resolved (Azure transient issues?)
- **#1457**: Caused by `api_build_command` that hung indefinitely

**Common pattern**: Server crashes/hangs before responding to first health check

**SWA timeout**: Hardcoded 10 minutes (600 seconds), our failure at ~590 seconds

---

## Files Modified So Far

1. ✅ `apps/web/src/lib/auth0.ts` - Lazy initialization
2. ✅ `apps/web/src/proxy.ts` - Graceful degradation
3. ✅ `apps/web/src/app/auth-config-error/page.tsx` - Error page
4. ✅ `.github/workflows/preview.yml` - AzCLI app settings step

**None of these fixed the warmup timeout.**

---

## Quick Decision Tree

```
Is the issue urgent?
├─ YES → Option 2 (bypass middleware) - fastest test
└─ NO → Option 1 (check API routes) - most thorough

Did Option 2 fix it?
├─ YES → Problem is in proxy.ts, debug line by line
└─ NO → Try Option 3 (simplify next.config)

Did Option 3 fix it?
├─ YES → Problem is in rewrites configuration
└─ NO → Try Option 4 (remove Auth0 completely)

Did Option 4 fix it?
├─ YES → Confirms Auth0 integration is the problem
│   └─ Incrementally add Auth0 features back
└─ NO → Issue is NOT related to Auth0
    └─ Check other dependencies or open Azure support ticket
```

---

## If All Else Fails

### Nuclear Option: Skip SWA Preview Temporarily

Add to `.github/workflows/preview.yml`:

```yaml
- name: Deploy Frontend Preview
  if: false # TEMPORARY: Disable while investigating warmup timeout
  uses: Azure/static-web-apps-deploy@v1
  # ...
```

**Downside**: No preview deployments until fixed  
**Upside**: Unblocks PR merges for non-frontend changes

---

### Open Azure Support Ticket

If none of the above works, escalate to Azure:

**Information to provide**:

1. SWA resource: `swa-ytsumm-prd` in `rg-ytsumm-prd`
2. Failed deployment IDs from workflow logs
3. Last successful deployment (production)
4. GitHub Actions workflow run links
5. This investigation document

**Request**:

- Access to SWA warmup logs (if they exist)
- Insight into what health checks are failing
- Any platform-side errors/issues

---

## Recommended Sequence

**Day 1** (2 hours):

1. Try Option 2 (bypass middleware) - 10 min
2. If fails, try Option 1 (check API routes) - 15 min
3. If fails, try Option 3 (simplify config) - 20 min

**Day 2** (if Day 1 fails): 4. Try Option 4 (remove Auth0) - 30 min 5. Try Option 5 (production deployment test) - 10 min

**Day 3** (if all fails): 6. Add Option 6 (instrumentation) - 20 min 7. Consider Nuclear Option (skip SWA) 8. Open Azure support ticket

---

## Success Criteria

Once we identify the issue, the fix should result in:

- [ ] Preview deployment completes in < 2 minutes
- [ ] Logs show `[Auth0] Authentication is DISABLED`
- [ ] App starts and responds to health checks within 30 seconds
- [ ] Protected routes show `/auth-config-error` page
- [ ] After AzCLI configures settings, auth works on reload

---

**Last Updated**: 2026-01-20  
**Next Action**: Choose an option from the list above and test
