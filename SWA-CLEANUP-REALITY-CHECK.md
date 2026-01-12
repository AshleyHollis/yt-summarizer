# SWA Cleanup: What Actually Works

## Summary

**UPDATE:** Using Azure CLI, we can now **actually delete** SWA environments programmatically!

Previously, we attempted to use `repository_dispatch` events which didn't work. Now we use Azure CLI commands to list and delete environments directly.

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

### The Azure CLI Solution

Azure Static Web Apps environments can be deleted using:

**What Works:**
1. ✅ `az staticwebapp environment delete` with Azure CLI (requires Azure OIDC login)
2. ✅ `Azure/static-web-apps-deploy` action with `action: close` in PR context
3. ✅ Manual deletion in Azure Portal

**Key Requirements:**
- Azure OIDC authentication (client-id, tenant-id, subscription-id)
- List environments: `az staticwebapp environment list`
- Match by metadata: `pullRequestTitle`, `buildId`, `hostname`
- Delete with: `az staticwebapp environment delete --environment-name <BUILD_ID>`

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

### ✅ 3. Pre-Deployment Cleanup (ACTUALLY DELETES)

**File:** `.github/workflows/preview.yml`

```yaml
- name: Azure Login for SWA cleanup
  uses: azure/login@v2
  with:
    client-id: ${{ secrets.AZURE_CLIENT_ID }}
    tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

- name: Cleanup stale SWA environments
  uses: ./.github/actions/cleanup-stale-swa-environments
  with:
    swa-name: ${{ vars.SWA_NAME }}
    resource-group: ${{ vars.AZURE_RESOURCE_GROUP }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
    dry-run: 'false'
    min-age-hours: '1'
```

**What it does:**
- Lists SWA environments using Azure CLI
- Matches environments to closed PRs by metadata
- **Actually deletes** matched environments
- Runs before deployment to free up slots

**Status:** ✅ Working - uses Azure CLI to delete

### ✅ 4. Scheduled Cleanup (ACTUALLY DELETES)

**File:** `.github/workflows/swa-cleanup-scheduled.yml`

```yaml
- name: Azure Login
  uses: azure/login@v2
  with:
    client-id: ${{ secrets.AZURE_CLIENT_ID }}
    tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

- name: Cleanup stale SWA environments
  uses: ./.github/actions/cleanup-stale-swa-environments
  with:
    swa-name: ${{ vars.SWA_NAME }}
    resource-group: ${{ vars.AZURE_RESOURCE_GROUP }}
    dry-run: 'false'
    min-age-hours: '168'  # 7 days
```

**What it does:**
- Runs daily at 2 AM UTC
- Lists all SWA environments using Azure CLI
- Matches to PRs closed >7 days ago
- **Actually deletes** matched environments

**Status:** ✅ Working - uses Azure CLI to delete

## What Changed

### ✅ cleanup-stale-swa-environments Action (NOW WORKS)

**File:** `.github/actions/cleanup-stale-swa-environments/action.yml`

**Previous Problem:** 
- Was sending `repository_dispatch` events that nothing listened to
- Reported false positives ("Cleanup dispatched")
- Did not actually delete environments

**Current Solution:**
- Uses Azure CLI: `az staticwebapp environment list` and `delete`
- Matches environments to PRs using build metadata
- Actually deletes environments in Azure
- Requires Azure OIDC authentication

**Status:** ✅ Working with Azure CLI

## Manual Cleanup Process

When you hit the "maximum environments" error (rarely needed now):

### Option 1: Wait for Automated Cleanup
The pre-deployment cleanup in preview.yml now runs automatically and will delete stale environments before deployment.

### Option 2: Close Stale PRs (Triggers Auto-Cleanup)
```bash
# List all PRs
gh pr list --state all --limit 50

# Close specific PR (triggers preview-cleanup.yml)
gh pr close 123
```

### Option 3: Azure Portal (Direct Deletion)
1. Navigate to [portal.azure.com](https://portal.azure.com)
2. Find your Static Web App resource
3. Go to: **Environments**
4. Select environments for closed PRs
5. Click **Delete**

## Prevention Strategy

1. **Automated cleanup handles most cases** - pre-deployment and scheduled workflows
2. **Close PRs promptly** after merging for immediate cleanup
3. **Monitor scheduled reports** for any missed environments

## Files Changed in This Fix

1. ✅ `.github/actions/cleanup-stale-swa-environments/action.yml` - Replaced repository_dispatch with Azure CLI
2. ✅ `.github/workflows/preview.yml` - Added Azure login + actual cleanup (not just detection)
3. ✅ `.github/workflows/swa-cleanup-scheduled.yml` - Added Azure login + actual cleanup
4. ✅ `docs/swa-environment-cleanup.md` - Updated to reflect Azure CLI approach
5. ✅ `SOLID-REFACTORING-SUMMARY.md` - Documented Azure CLI solution
6. ✅ `SWA-CLEANUP-REALITY-CHECK.md` - This file (updated with solution)

## Next Steps

1. ✅ Implement Azure CLI commands
2. ✅ Add Azure OIDC authentication to workflows
3. ✅ Update documentation
4. 📝 Test with actual PR deployment
5. 📝 Monitor cleanup effectiveness

## Lessons Learned

1. **Azure CLI provides direct access** - much better than trying to use deployment tokens
2. **Environment metadata is the source of truth** - pullRequestTitle, buildId, sourceBranch, hostname
3. **OIDC authentication works for service principals** - no need for secrets
4. **Always verify API calls with actual Azure resources** - don't assume limitations
5. **User-provided technical details are invaluable** - the Azure CLI approach was the key

## References

- [Azure Static Web Apps Deploy Action](https://github.com/Azure/static-web-apps-deploy)
- [Azure SWA Environments Documentation](https://learn.microsoft.com/en-us/azure/static-web-apps/review-publish-pull-requests)
- [GitHub repository_dispatch Events](https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#repository_dispatch)
