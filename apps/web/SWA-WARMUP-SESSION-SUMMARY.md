# SWA Warmup Timeout - Session Summary

> **Date**: 2026-01-20  
> **Status**: Investigation in progress  
> **Branch**: `004-auth0-ui-integration` (PR #64)

## Problem

Azure Static Web Apps preview deployments fail with:

```
Deployment Failure Reason: Web app warm up timed out. Please try again later.
```

**Timeline**:

- Build phase: ✅ Succeeds (~2 min)
- Upload phase: ✅ Succeeds (~5 sec)
- Warmup phase: ❌ Times out after ~590 seconds

## What We Did Today

### 1. Investigated Root Cause ✅

- Checked deployment logs (warmup timeout confirmed)
- Reviewed 12+ similar GitHub issues
- Compared with successful production deployments
- Identified likely cause: Server crash during startup

### 2. Created Documentation ✅

Created three comprehensive documents:

**a) SWA-WARMUP-TIMEOUT-INVESTIGATION.md**

- Full timeline of changes made
- Detailed analysis of each attempt
- Comparison with working deployments
- External research findings
- Diagnostic commands and procedures

**b) SWA-WARMUP-NEXT-STEPS.md**

- Prioritized action items (6 options)
- Step-by-step test procedures
- Decision tree for troubleshooting
- Quick wins vs thorough investigation paths

**c) This document** (session summary)

### 3. Analyzed Codebase ✅

**Files Checked**:

- `apps/web/src/lib/auth0.ts` - Lazy initialization (correct)
- `apps/web/src/proxy.ts` - Graceful degradation (correct)
- `apps/web/next.config.ts` - Has dynamic rewrites (potential issue)
- No `middleware.ts` found (uses proxy.ts instead)
- No API routes under `/api/auth/` directory

**Key Finding**:

- Proxy middleware imports `getAuth0Client()` (safe)
- No dangerous module-level `auth0` proxy usage found
- Next.js rewrites configuration uses dynamic backend URL (potential hang point)

## Key Learnings from GitHub Issues

### Issue #1440 (dfahlander/dexie-cloud)

**Symptom**: Exact same error message, same 10-minute timeout  
**Resolution**: Self-resolved after some time (no code changes)  
**Takeaway**: Might be transient Azure platform issue

### Issue #1457 (brianmgray - pnpm issue)

**Symptom**: Warmup timeout after switching to pnpm  
**Root Cause**: `api_build_command` was hanging (`rm -rf ./node_modules/@next/swc-*`)  
**Resolution**: Removed problematic build command  
**Takeaway**: Build commands can cause infinite hangs

### Issue #1496 (dharmendrasha)

**Symptom**: Same error, previously working deployment now fails  
**Resolution**: Never resolved in public discussion  
**Takeaway**: Not all cases have clear solutions

### Common Patterns

1. Server crashes BEFORE responding to first health check
2. SWA has 10-minute timeout (600 sec), failures happen at ~590 sec
3. Most often caused by:
   - Uncaught exceptions during module initialization
   - External service calls hanging indefinitely
   - Missing env vars causing crashes
   - Misconfigured health check endpoints

## What Changed Between Working and Broken

### Before Auth0 Integration (Working)

- No Auth0 SDK
- No proxy middleware
- No protected routes
- Preview deployments: ~20-30 seconds

### After Auth0 Integration (Broken)

- Auth0 SDK added (`@auth0/nextjs-auth0`)
- Proxy middleware added (`src/proxy.ts`)
- Protected routes configuration
- Preview deployments: Timeout at ~590 seconds

### Production (Still Working)

- Same code as preview
- Auth0 env vars configured via Terraform
- Default SWA environment (not named)
- Deployments: ~46 seconds

## Critical Hypothesis

**The server is crashing during startup, NOT just missing env vars.**

Our lazy initialization SHOULD prevent crashes:

```typescript
export function getAuth0Client(): Auth0Client | null {
  if (!isAuth0Configured()) {
    console.warn('[Auth0] Authentication is DISABLED');
    return null; // Should not crash
  }
  _auth0Client = new Auth0Client();
  return _auth0Client;
}
```

**But something ELSE is crashing.** Potential culprits:

1. ❓ Next.js rewrites trying to validate unreachable backend
2. ❓ Proxy middleware crashing despite graceful degradation
3. ❓ Some API route crashing during module load
4. ❓ Auth0 SDK itself crashing in standalone mode
5. ❓ SWA-specific issue with named environments

## Top 3 Recommended Next Steps

### #1: Bypass Proxy Middleware (10 min) 🔴

**File**: `apps/web/src/proxy.ts`

Change proxy function to immediately return:

```typescript
export async function proxy(request: Request) {
  return NextResponse.next();
}
```

**Why**: Fastest way to test if middleware is the culprit

### #2: Simplify Next.js Rewrites (20 min) 🟡

**File**: `apps/web/next.config.ts:70-124`

Remove dynamic backend URL loading and proxy rewrites:

```typescript
async rewrites() {
  return {
    beforeFiles: [
      { source: '/.swa/health.html', destination: '/.swa/health' },
    ],
    afterFiles: [],
    fallback: [],
  };
}
```

**Why**: Dynamic rewrites might cause Next.js to hang during startup

### #3: Deploy to Production (Test) (10 min) 🟢

**Hypothesis**: Named environments behave differently

Deploy same branch to production temporarily (has Auth0 env vars):

- If succeeds → Confirms preview-specific issue
- If fails → Code issue, not SWA config issue

## Files Created/Modified This Session

### New Documentation

- ✅ `apps/web/SWA-WARMUP-TIMEOUT-INVESTIGATION.md` (full details)
- ✅ `apps/web/SWA-WARMUP-NEXT-STEPS.md` (action items)
- ✅ `apps/web/SWA-WARMUP-SESSION-SUMMARY.md` (this file)

### Code Changes (Previous Session)

- ✅ `apps/web/src/lib/auth0.ts` - Lazy init
- ✅ `apps/web/src/proxy.ts` - Graceful degradation
- ✅ `apps/web/src/app/auth-config-error/page.tsx` - Error page
- ✅ `.github/workflows/preview.yml` - AzCLI app settings

**None of the code changes fixed the warmup timeout.**

## Important Context

### Production SWA Configuration (Terraform)

**File**: `infra/terraform/environments/prod/swa.tf`

Auth0 env vars are configured via:

```hcl
resource "azapi_resource_action" "swa_app_settings" {
  # Sets AUTH0_SECRET, AUTH0_ISSUER_BASE_URL, etc.
}
```

**Result**: Production has Auth0 env vars when server starts → works

### Preview SWA Configuration (Workflow)

**File**: `.github/workflows/preview.yml`

Auth0 env vars configured AFTER deployment:

```yaml
- name: Configure SWA environment app settings (runtime)
  run: |
    az staticwebapp appsettings set \
      --environment-name "$PR_NUMBER" \
      # ...
```

**Problem**: Step runs after warmup completes → too late

**Result**: Preview has NO Auth0 env vars when server starts → times out

## Why Making Auth0 "Lazy" Didn't Fix It

We thought: "If Auth0 returns null gracefully, app should start fine"

**Reality**: Something ELSE is crashing the server before it responds to health checks

**Evidence**:

1. Frontend build succeeds (no TypeScript errors)
2. Upload succeeds (artifact is valid)
3. Warmup times out (server never becomes healthy)
4. Production works with same code (has env vars)

**Conclusion**: It's not JUST about missing env vars. The server is CRASHING during startup.

## Comparison Table

| Aspect              | Production (✅ Works) | Preview (❌ Fails)     |
| ------------------- | --------------------- | ---------------------- |
| **Environment**     | Default (no name)     | Named (PR number)      |
| **Auth0 Env Vars**  | ✅ Set via Terraform  | ❌ Not set initially   |
| **Deployment Time** | ~46 seconds           | ~590 seconds (timeout) |
| **App Starts**      | ✅ Yes                | ❌ No (times out)      |
| **Health Check**    | ✅ Responds           | ❌ No response         |
| **Workflow**        | deploy-production.yml | preview.yml            |

## Success Metrics

When we fix this, we should see:

- ✅ Preview deployment completes in < 2 minutes (not 10)
- ✅ Logs show `[Auth0] Authentication is DISABLED`
- ✅ Health check responds within 30 seconds
- ✅ App accessible at preview URL
- ✅ Protected routes redirect to `/auth-config-error`

## Related Resources

### Internal Docs

- `apps/web/SWA-AUTH0-DEPLOYMENT.md` - Production deployment guide
- `docs/auth0-swa-terraform-setup.md` - Terraform Auth0 config
- `AGENTS.md` - General development guidelines

### External Links

- [Azure SWA - Hybrid Next.js](https://learn.microsoft.com/en-us/azure/static-web-apps/deploy-nextjs-hybrid)
- [GitHub Issues: Azure/static-web-apps](https://github.com/Azure/static-web-apps/issues?q=is%3Aissue+warm+up+timed+out)
- [Auth0 Next.js SDK](https://github.com/auth0/nextjs-auth0)

### Workflow Runs

- **Failed (PR #64)**: Run #21154450578 (this deployment)
- **Successful (main)**: Run #21113716842 (production)
- **Successful (PR #63)**: Run #21113843094 (before Auth0)

## Open Questions

1. ❓ Why does production work but preview doesn't? (same code, different env vars)
2. ❓ What EXACTLY is crashing the server during warmup?
3. ❓ Do SWA named environments have different health check behavior?
4. ❓ Are Next.js rewrites validated against destinations during startup?
5. ❓ Can we see ANY logs from the warmup phase?

## Action Items for Next Session

**IMMEDIATE** (choose ONE):

- [ ] Option 1: Bypass proxy middleware (fastest test)
- [ ] Option 2: Simplify next.config rewrites
- [ ] Option 3: Deploy to production as test

**IF ABOVE FAILS**:

- [ ] Option 4: Remove Auth0 completely (clean test)
- [ ] Option 5: Add instrumentation logging
- [ ] Option 6: Open Azure support ticket

**RESEARCH**:

- [ ] Find if SWA exposes warmup logs anywhere
- [ ] Check if other teams have similar issues
- [ ] Look for Next.js standalone mode known issues

---

## Quick Reference Commands

```bash
# Check SWA configuration
az staticwebapp show --name swa-ytsumm-prd --resource-group rg-ytsumm-prd

# List app settings (production)
az staticwebapp appsettings list --name swa-ytsumm-prd --resource-group rg-ytsumm-prd

# List app settings (preview PR #64)
az staticwebapp appsettings list --name swa-ytsumm-prd --resource-group rg-ytsumm-prd --environment-name 64

# View workflow run logs
gh run view 21154450578 --log | less

# Trigger new deployment
git push origin 004-auth0-ui-integration
```

---

**Status**: Ready for next troubleshooting session  
**Priority**: HIGH (blocking PR #64)  
**Estimated Time to Resolution**: 2-4 hours (testing options)
