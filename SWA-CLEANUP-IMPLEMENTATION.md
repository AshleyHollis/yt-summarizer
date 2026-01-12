# SWA Environment Cleanup Implementation Summary

## Changes Made

This implementation adds comprehensive cleanup for Azure Static Web Apps staging environments to prevent hitting the environment limit.

### Files Modified

1. **`.github/workflows/preview-cleanup.yml`**
   - ✅ Added SWA environment deletion on PR close
   - ✅ Added cleanup status reporting
   - ✅ Updated PR comment to include SWA cleanup info
   - ✅ Added job summary with cleanup details

2. **`.github/workflows/preview.yml`**
   - ✅ Added pre-deployment check for stale environments
   - ✅ Reports stale environment count before deployment
   - ✅ Provides early warning if approaching limit

### Files Created

3. **`.github/workflows/swa-cleanup-scheduled.yml`** (NEW)
   - ✅ Daily scheduled cleanup at 2 AM UTC
   - ✅ Finds PRs closed >1 hour ago
   - ✅ Reports stale environments
   - ✅ Manual trigger with dry-run option
   - ✅ Integrates with Azure CLI for environment queries

4. **`.github/actions/cleanup-stale-swa-environments/action.yml`** (NEW)
   - ✅ Reusable action for finding stale environments
   - ✅ Compares open PRs vs closed PRs
   - ✅ Generates cleanup reports

5. **`docs/swa-environment-cleanup.md`** (NEW)
   - ✅ Complete documentation of cleanup strategy
   - ✅ Troubleshooting guide
   - ✅ Configuration requirements
   - ✅ Best practices

## How It Works

### Three-Layer Cleanup Strategy

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: Immediate Cleanup (Primary)                       │
│ Trigger: PR closed event                                   │
│ Action: Delete SWA environment immediately                 │
│ Speed: ~30 seconds                                         │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Layer 2: Pre-Deployment Check (Proactive)                  │
│ Trigger: Before each deployment                            │
│ Action: Report stale environments                          │
│ Speed: ~10 seconds                                         │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Layer 3: Scheduled Cleanup (Safety Net)                    │
│ Trigger: Daily at 2 AM UTC                                 │
│ Action: Find and report stale environments                 │
│ Speed: ~1-2 minutes                                        │
└─────────────────────────────────────────────────────────────┘
```

## Testing the Implementation

### Test 1: PR Close Cleanup (Immediate)

1. Open a test PR that triggers preview deployment
2. Wait for SWA staging environment to be created
3. Close the PR
4. Check "Actions" tab > "PR Cleanup" workflow run
5. Verify:
   - ✅ SWA cleanup step completed
   - ✅ PR comment posted with cleanup status
   - ✅ Job summary shows cleanup details

### Test 2: Scheduled Cleanup (Manual Trigger)

1. Go to Actions > "SWA Cleanup (Scheduled)"
2. Click "Run workflow"
3. Select "Dry run: true"
4. Click "Run workflow"
5. Check the workflow run results
6. Verify:
   - ✅ Lists all open PRs
   - ✅ Lists recently closed PRs
   - ✅ Reports stale environment count
   - ✅ No actual deletion (dry-run mode)

### Test 3: Pre-Deployment Check

1. Open a new PR
2. Check the preview deployment workflow
3. Look for "Pre-deployment cleanup check" step
4. Verify:
   - ✅ Step runs successfully
   - ✅ Reports stale environment count
   - ✅ Deployment continues regardless

## Required Configuration

### Secrets (Already Configured)

- ✅ `SWA_DEPLOYMENT_TOKEN` - Used by cleanup workflows
- ✅ `AZURE_CLIENT_ID` - For scheduled cleanup
- ✅ `AZURE_TENANT_ID` - For scheduled cleanup
- ✅ `AZURE_SUBSCRIPTION_ID` - For scheduled cleanup

### Variables (Optional, with Defaults)

```yaml
SWA_NAME: swa-ytsumm-prd  # Default value
SWA_RESOURCE_GROUP: rg-ytsumm-prd  # Default value
```

If your SWA has different names, set these in GitHub repository variables.

## Immediate Next Steps

### 1. Verify Secrets

```bash
# Check that SWA_DEPLOYMENT_TOKEN is set
gh secret list
```

### 2. Test the PR Cleanup Workflow

Create a test PR and close it to verify cleanup works:

```bash
git checkout -b test-swa-cleanup
echo "test" > test-file.txt
git add test-file.txt
git commit -m "Test SWA cleanup"
git push origin test-swa-cleanup

# Create PR via GitHub UI
# Wait for deployment
# Close the PR
# Check cleanup workflow runs
```

### 3. Run Scheduled Cleanup (Dry Run)

1. Go to: https://github.com/AshleyHollis/yt-summarizer/actions/workflows/swa-cleanup-scheduled.yml
2. Click "Run workflow"
3. Leave "Dry run" checked
4. Click "Run workflow"
5. Review the results

### 4. Clean Up Current Stale Environments

If you have stale environments now:

```bash
# Option A: Use Azure Portal
# 1. Go to Azure Portal
# 2. Find your Static Web App: swa-ytsumm-prd
# 3. Go to "Environments"
# 4. Delete any non-production environments for closed PRs

# Option B: Run scheduled workflow (non-dry-run)
# Only after testing in dry-run mode!
```

## Monitoring

### Daily Checks

- Check scheduled cleanup workflow runs
- Review stale environment reports
- Verify cleanup is working

### When Deployments Fail

1. Check error message
2. If "maximum environments" error:
   - Run scheduled cleanup immediately
   - Check Azure Portal for environment count
   - Manually delete oldest stale environments if needed

### Weekly Review

- Review cleanup workflow success rate
- Check for any failed cleanup attempts
- Adjust scheduled cleanup frequency if needed

## Troubleshooting

### "Maximum environments" error persists

```bash
# 1. Check current environment count
az staticwebapp environment list \
  --name swa-ytsumm-prd \
  --resource-group rg-ytsumm-prd \
  --query "length([?name!='default'])" \
  -o tsv

# 2. List all environments
az staticwebapp environment list \
  --name swa-ytsumm-prd \
  --resource-group rg-ytsumm-prd \
  --output table

# 3. Delete specific environment
az staticwebapp environment delete \
  --name swa-ytsumm-prd \
  --resource-group rg-ytsumm-prd \
  --environment-name <env-name>
```

### Cleanup workflow fails

Check:
1. Workflow run logs for errors
2. SWA_DEPLOYMENT_TOKEN is still valid
3. Azure permissions are correct
4. Static Web App still exists

## Success Metrics

After implementation, you should see:

- ✅ No more "maximum environments" errors
- ✅ Automatic cleanup on every PR close
- ✅ Daily cleanup reports showing 0 stale environments
- ✅ Faster preview deployments (no manual intervention needed)

## Support

For issues or questions:
- See: `docs/swa-environment-cleanup.md` for detailed documentation
- Check: GitHub Actions workflow run logs
- Review: Azure Static Web Apps dashboard in Azure Portal
