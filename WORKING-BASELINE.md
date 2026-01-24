# Working SWA Baseline Documentation

**Date Established**: 2026-01-21 06:20 UTC  
**Status**: ✅ **VERIFIED WORKING**

---

## Critical Success Factors

### What Works (DO NOT CHANGE)

1. **SWA Instance**
   - **Name**: `swa-ytsumm-prd`
   - **Hostname**: `white-meadow-0b8e2e000.6.azurestaticapps.net`
   - **Location**: East Asia
   - **SKU**: Free
   - **Created**: 2026-01-21 06:15 UTC
   - **Status**: Fresh instance, no previous deployment issues
   - **Deployment Token**: Updated in GitHub Secrets (`SWA_DEPLOYMENT_TOKEN`)

2. **Working Branch**
   - **Name**: `fix/swa-working-baseline`
   - **Base Commit**: `f1f21a4f3d37196c969d9e20448a5baa09b76898`
   - **Commit Message**: "fix: remove unnecessary Azure login step"
   - **Date**: 2026-01-20 (from test/swa-warmup-baseline)
   - **Last Successful Deployment**: Run #21185824990
   - **Deployment Time**: 32 seconds

3. **Workflow Configuration**
   - **Workflow File**: `.github/workflows/swa-baseline-deploy.yml`
   - **Trigger**: Push to `fix/swa-working-baseline` or `test/swa-warmup-baseline`
   - **Key Settings**:
     ```yaml
     app_location: apps/web
     output_location: ""              # Empty string - WORKS
     skip_app_build: true
     production_branch: main
     ```
   - **Build Environment Variables**:
     ```yaml
     NEXT_PUBLIC_API_URL: "https://api-placeholder.example.com"
     NEXT_PUBLIC_ENVIRONMENT: "preview"
     ```
   - **No Auth0 configuration** (simple baseline)
   - **No job dependencies** (single standalone job)
   - **No complex orchestration**

4. **Frontend Configuration**
   - **Next.js Version**: 16.1.3 (Webpack build)
   - **Node Version**: 20
   - **Build Command**: `next build --webpack` (via `npm run build`)
   - **Output Mode**: Standalone (`.next/standalone`)
   - **Config File**: `apps/web/staticwebapp.config.json` (used by SWA)

5. **Deployment Logs - Success Indicators**
   ```
   Status: InProgress. Time: 0.7788051(s)
   Status: InProgress. Time: 16.7162094(s)
   Status: Succeeded. Time: 32.2839363(s)
   Deployment Complete :)
   ```

---

## What Doesn't Work (Previous Failures)

### Failed SWA Instances
1. **proud-coast-0bd36cb00** - Original instance, stuck in "Uploading" state
2. **proud-smoke-05b9a9c00** - Recreated instance, all deployments canceled after 15s
3. **red-grass-06d413100** - Worked initially, then deleted (was the successful baseline)

### Failed Approaches
- ❌ Changing `output_location` to `.next` (Test 1 failed)
- ❌ Complex workflow with Auth0 config step after deployment
- ❌ Job dependencies and orchestration (preview workflow)
- ❌ Using `proud-smoke` SWA instance (platform rejected all deployments)

---

## Deployment Verification Checklist

When testing new changes, verify:

1. **Deployment succeeds in <60 seconds**
   - Check workflow logs for "Status: Succeeded"
   - Should NOT see "Deployment Canceled" or "Deployment Failed"
   - Should NOT timeout (>5 minutes is a red flag)

2. **Production URL returns 200 OK**
   ```bash
   curl -I https://white-meadow-0b8e2e000.6.azurestaticapps.net
   ```

3. **Preview environment URL (if applicable)**
   - Format: `https://white-meadow-0b8e2e000-{sanitized-branch-name}.eastasia.6.azurestaticapps.net`
   - May take 30-60 seconds after deployment to be accessible

4. **SWA Deployment Logs**
   ```bash
   gh run view {RUN_ID} --log | grep -A 20 "Deploy to SWA"
   ```
   - Look for "Detected standalone folder"
   - Look for "Deployment Complete :)"
   - No "warmup timeout" errors

---

## Current File Structure

### Working Baseline Files (Commit f1f21a4)

```
.github/workflows/
  └── swa-baseline-deploy.yml          ✅ Working workflow

apps/web/
  ├── next.config.ts                   ✅ Standalone output enabled
  ├── staticwebapp.config.json         ✅ SWA routing config
  ├── package.json                     ✅ No Auth0 dependencies
  └── .next/standalone/                ✅ Build output (after npm run build)
```

### Files to Migrate (From Other Branches)

**From PR #69 (fix/swa-backend-integration-baseline):**
- `.github/workflows/preview.yml` - Complex preview workflow
- `.github/workflows/deploy-prod.yml` - Production workflow with Auth0
- Auth0 backend infrastructure (Terraform managed in Key Vault)

**From branch 004-auth0-ui-integration:**
- `apps/web/src/app/api/auth/[auth0]/route.ts` - Auth0 callback
- Auth0 frontend dependencies in package.json
- Environment variable configurations

---

## GitHub Secrets Status

✅ **Updated for Working Baseline:**
- `SWA_DEPLOYMENT_TOKEN` - Deployment token for `white-meadow` instance
- `AZURE_CLIENT_ID` - For Azure OIDC auth
- `AZURE_SUBSCRIPTION_ID` - Subscription ID
- `AZURE_TENANT_ID` - Tenant ID

🔐 **Auth0 Secrets (In Key Vault, not yet used):**
- `auth0-preview-domain`
- `auth0-preview-client-id`
- `auth0-preview-client-secret`
- `auth0-preview-session-secret`

---

## Azure Resources

### Working SWA Instance
```bash
az staticwebapp show \
  --name swa-ytsumm-prd \
  --resource-group rg-ytsumm-prd \
  --query '{name: name, hostname: defaultHostname, sku: sku.name}'
```

Output:
```json
{
  "hostname": "white-meadow-0b8e2e000.6.azurestaticapps.net",
  "name": "swa-ytsumm-prd",
  "sku": "Free"
}
```

### Key Vault (Auth0 Secrets)
```bash
az keyvault show \
  --name kv-ytsumm-prd \
  --query '{name: name, location: location}'
```

---

## Rollback Procedure

If a change breaks deployment:

1. **Immediate Rollback**
   ```bash
   # Checkout working baseline
   git checkout fix/swa-working-baseline

   # Force push to fix/swa-working-baseline
   git push origin fix/swa-working-baseline --force
   ```

2. **Verify Deployment**
   ```bash
   # Wait for workflow to complete
   gh run watch --workflow=swa-baseline-deploy.yml

   # Check production URL
   curl -I https://white-meadow-0b8e2e000.6.azurestaticapps.net
   ```

3. **Document What Broke**
   - Add entry to `MIGRATION-LOG.md`
   - Note the specific change that caused failure
   - Save error logs for analysis

---

## Important Notes

### DO NOT
- ❌ Delete the `white-meadow` SWA instance (it's working!)
- ❌ Run Terraform that recreates SWA (will create new instance)
- ❌ Change `output_location` in workflow
- ❌ Add complex job dependencies without testing
- ❌ Regenerate SWA deployment token (unless absolutely necessary)

### DO
- ✅ Test changes incrementally (one at a time)
- ✅ Document each migration step
- ✅ Verify deployment after each change
- ✅ Keep this document updated
- ✅ Create git tags for known-good states

---

## Git Tags for Known-Good States

```bash
# Tag the working baseline
git tag -a baseline-working-swa-v1 f1f21a4 -m "Working SWA baseline - white-meadow instance"
git push origin baseline-working-swa-v1
```

**Current Tags:**
- `baseline-working-swa-v1` - Commit `f1f21a4` (VERIFIED WORKING)

---

## Next Steps

See `MIGRATION-PLAN.md` for systematic migration of:
1. Auth0 backend infrastructure
2. Auth0 frontend UI
3. Complex preview workflow
4. Production workflow updates

---

## References

- **Successful Deployment Run**: https://github.com/AshleyHollis/yt-summarizer/actions/runs/21185824990
- **Original Successful Run** (deleted instance): https://github.com/AshleyHollis/yt-summarizer/actions/runs/21157814189
- **SWA Troubleshooting Doc**: `SWA-DEPLOYMENT-TROUBLESHOOTING.md`
- **Microsoft SWA Docs**: https://learn.microsoft.com/azure/static-web-apps/
