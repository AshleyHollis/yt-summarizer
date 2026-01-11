# SWA Cleanup: What Actually Works

## Summary

After discovering that our automated cleanup was **not actually deleting environments**, we've pivoted to a detection-and-manual-cleanup approach.

## The Problem

The `cleanup-stale-swa-environments` action was reporting success ("Cleanup dispatched", "Cleanup initiated") but **none of the environments were being deleted in Azure**.

### Root Cause

The action was sending `repository_dispatch` events:
```bash
gh api repos/$GITHUB_REPOSITORY/dispatches \
  -f event_type='swa-cleanup' \
  -f client_payload[pr_number]="$pr_number"
```

**But:** No workflow was listening for `event_type: swa-cleanup`, so nothing actually happened.

### Why We Can't Auto-Delete

Azure Static Web Apps environments have a critical limitation:

**Environments can ONLY be deleted via:**
1. The `Azure/static-web-apps-deploy` action with `action: close` **when run in PR context**
2. Manual deletion in Azure Portal
3. Azure SWA management API (requires different authentication than deployment token)

**We cannot:**
- Call the deployment action for other PRs from a different workflow
- Use the deployment token to authenticate to the management API
- Delete environments programmatically outside PR close events

## What Actually Works

### ✅ 1. PR Close Cleanup (RELIABLE)

**File:** `.github/workflows/preview-cleanup.yml`

```yaml
- name: Close SWA Environment
  uses: ./.github/actions/close-swa-environment
  with:
    pr-number: ${{ github.event.pull_request.number }}
    swa-deployment-token: ${{ secrets.SWA_DEPLOYMENT_TOKEN }}
```

**Why it works:**
- Runs in PR context (triggered by `on: pull_request: types: [closed]`)
- GitHub provides PR metadata to the Azure SWA action
- Official Azure action can identify which environment to close

**Status:** ✅ Working correctly

### ✅ 2. Stale Environment Detection (HELPFUL)

**File:** `.github/actions/find-stale-prs/action.yml`

```yaml
- name: Find stale PRs
  uses: ./.github/actions/find-stale-prs
  id: check-stale
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    min-age-hours: '168'
    max-prs-to-check: '100'
```

**What it does:**
- Queries GitHub API for open PRs
- Finds recently closed PRs
- Identifies stale PRs (closed >7 days ago)
- Returns count and PR numbers

**Status:** ✅ Working correctly

### ⚠️ 3. Pre-Deployment Check (DETECTION ONLY)

**File:** `.github/workflows/preview.yml`

```yaml
- name: Check for stale SWA environments
  uses: ./.github/actions/find-stale-prs
  id: check-stale
  with:
    min-age-hours: '1'

- name: Report stale environments
  if: steps.check-stale.outputs.stale-count != '0'
  run: |
    echo "⚠️  Found ${{ steps.check-stale.outputs.stale-count }} stale environment(s)"
    echo "💡 To free up SWA environment slots:"
    echo "1. Close stale PRs: gh pr close <NUMBER>"
    echo "2. Or manually delete in Azure Portal"
```

**What it does:**
- Detects stale environments before deployment
- Reports findings with clear instructions
- **Does NOT delete** (Azure API limitation)

**Status:** ⚠️ Detection works, deletion not possible

### ⚠️ 4. Scheduled Detection (WEEKLY REPORT)

**File:** `.github/workflows/swa-cleanup-scheduled.yml`

```yaml
- name: Find stale PRs
  uses: ./.github/actions/find-stale-prs
  id: find-stale
  with:
    min-age-hours: '168'  # 7 days

- name: Report stale environments
  if: steps.find-stale.outputs.stale-count != '0'
  run: |
    echo "📊 Found ${{ steps.find-stale.outputs.stale-count }} stale environment(s)"
    # Provides cleanup instructions
```

**What it does:**
- Runs daily at 2 AM UTC
- Detects PRs closed >7 days ago
- Reports findings with cleanup instructions
- **Does NOT delete** (Azure API limitation)

**Status:** ⚠️ Detection works, deletion not possible

## What Doesn't Work

### ❌ cleanup-stale-swa-environments Action

**File:** `.github/actions/cleanup-stale-swa-environments/action.yml`

**Problem:** 
- Sends `repository_dispatch` events that nothing listens to
- Reports false positives ("Cleanup dispatched") 
- Does not actually delete environments in Azure

**Status:** ❌ DEPRECATED - Do not use

## Manual Cleanup Process

When you hit the "maximum environments" error:

### Option 1: Close Stale PRs (Triggers Auto-Cleanup)
```bash
# List all PRs
gh pr list --state all --limit 50

# Close specific PR (triggers preview-cleanup.yml)
gh pr close 123
```

### Option 2: Azure Portal (Direct Deletion)
1. Navigate to [portal.azure.com](https://portal.azure.com)
2. Find your Static Web App resource
3. Go to: **Environments**
4. Select environments for closed PRs
5. Click **Delete**

## Prevention Strategy

1. **Close PRs promptly** after merging
2. **Review scheduled reports** weekly for stale environments
3. **Monitor environment count** before deployments fail
4. **Use detection warnings** in pre-deployment checks

## Files Changed in This Fix

1. ✅ `.github/workflows/preview.yml` - Changed from cleanup to detection
2. ✅ `.github/workflows/swa-cleanup-scheduled.yml` - Changed from cleanup to detection
3. ✅ `docs/swa-environment-cleanup.md` - Updated to reflect limitations
4. ⚠️ `.github/actions/cleanup-stale-swa-environments/action.yml` - Deprecated (not deleted yet)

## Next Steps

1. ✅ Update documentation (in progress)
2. ⏳ Mark `cleanup-stale-swa-environments` as deprecated
3. ⏳ Add warning comments to deprecated action
4. ⏳ Update SOLID-REFACTORING-SUMMARY.md with limitation discovered
5. ⏳ Commit and push changes

## Lessons Learned

1. **Always verify external API calls succeed** - don't trust "event dispatched" messages
2. **Azure SWA has context-dependent APIs** - deployment token works in PR context only
3. **Detection is valuable even when automation isn't possible** - knowing the problem exists helps
4. **False positive reporting is worse than no reporting** - creates false sense of security

## References

- [Azure Static Web Apps Deploy Action](https://github.com/Azure/static-web-apps-deploy)
- [Azure SWA Environments Documentation](https://learn.microsoft.com/en-us/azure/static-web-apps/review-publish-pull-requests)
- [GitHub repository_dispatch Events](https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#repository_dispatch)
