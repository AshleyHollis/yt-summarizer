# Azure Static Web Apps Environment Cleanup Strategy

## Problem Statement

Azure Static Web Apps (SWA) has a limit on the number of staging environments (typically 3-10 depending on the plan). When this limit is reached, new PR deployments fail with:

```
The content server has rejected the request with: BadRequest
Reason: This Static Web App already has the maximum number of staging environments
```

## Solution: Multi-Layered Cleanup Approach

We implement three complementary cleanup strategies to ensure stale environments are removed:

### 1. **Immediate Cleanup on PR Close** (Primary)

**Workflow:** [`.github/workflows/preview-cleanup.yml`](.github/workflows/preview-cleanup.yml)

**Trigger:** Automatically when a PR is closed or merged

**How it works:**
- Listens to PR `closed` events
- Immediately calls Azure SWA deploy action with `action: close`
- Posts a status comment to the PR
- Updates K8s resources via Argo CD

**Benefits:**
- Immediate cleanup when PR is no longer needed
- Zero manual intervention required
- Prevents environment accumulation

**Code:**
```yaml
- name: Cleanup SWA staging environment
  uses: Azure/static-web-apps-deploy@v1
  continue-on-error: true
  with:
    azure_static_web_apps_api_token: ${{ secrets.SWA_DEPLOYMENT_TOKEN }}
    action: close
```

### 2. **Scheduled Cleanup of Stale Environments** (Safety Net)

**Workflow:** [`.github/workflows/swa-cleanup-scheduled.yml`](.github/workflows/swa-cleanup-scheduled.yml)

**Trigger:** 
- Daily at 2 AM UTC (cron schedule)
- Manual dispatch with dry-run option

**How it works:**
- Queries GitHub API for all open PRs
- Finds recently closed PRs (last 30 days)
- Identifies environments from PRs closed >1 hour ago
- Reports stale environments
- Can be run in dry-run mode for safety

**Benefits:**
- Catches any environments missed by PR close trigger
- Provides visibility into environment usage
- Manual trigger allows on-demand cleanup
- Dry-run mode for testing

**Usage:**
```bash
# Manual trigger from GitHub UI
# Actions > SWA Cleanup (Scheduled) > Run workflow
# Toggle "Dry run mode" as needed
```

### 3. **Pre-Deployment Check** (Proactive)

**Workflow:** [`.github/workflows/preview.yml`](.github/workflows/preview.yml)

**Trigger:** Before every SWA deployment

**How it works:**
- Runs before attempting to deploy new environment
- Checks for stale environments from closed PRs
- Reports findings in deployment logs
- Provides early warning if approaching limit

**Benefits:**
- Identifies potential issues before deployment fails
- Provides context for troubleshooting
- No blocking behavior (continues with deployment)

**Code:**
```yaml
- name: Pre-deployment cleanup check
  run: |
    # Check for stale SWA environments
    # Report count and details
    # Continue with deployment
```

## Implementation Details

### SWA Environment Lifecycle

1. **Creation:** When a PR is opened, the preview workflow deploys to SWA
   - SWA automatically creates a staging environment named after the PR
   - Environment URL: `https://<app-name>-<pr-number>.azurestaticapps.net`

2. **Updates:** When PR is updated with new commits
   - Same staging environment is reused
   - No new environment created

3. **Deletion:** When PR is closed
   - `preview-cleanup.yml` triggers immediately
   - SWA deploy action with `action: close` removes the environment
   - K8s resources cleaned up by Argo CD

### Configuration Requirements

The cleanup workflows require the following secrets/variables:

**Secrets:**
- `SWA_DEPLOYMENT_TOKEN`: Azure Static Web Apps deployment token
- `AZURE_CLIENT_ID`: For Azure OIDC authentication (scheduled cleanup)
- `AZURE_TENANT_ID`: For Azure OIDC authentication (scheduled cleanup)
- `AZURE_SUBSCRIPTION_ID`: For Azure OIDC authentication (scheduled cleanup)

**Variables (optional):**
- `SWA_NAME`: Static Web App name (default: `swa-ytsumm-prd`)
- `SWA_RESOURCE_GROUP`: Resource group name (default: `rg-ytsumm-prd`)

### Monitoring and Troubleshooting

#### View Cleanup History

1. **PR Cleanup:**
   - Check the "PR Cleanup" workflow runs for each closed PR
   - View the PR comment posted by the cleanup workflow
   - Check the job summary for detailed status

2. **Scheduled Cleanup:**
   - Actions > SWA Cleanup (Scheduled) > View runs
   - Check the job summary for stale environment report

#### Manual Cleanup

If you need to manually clean up an environment:

```bash
# Option 1: Close specific PR's environment via GitHub UI
# Go to the closed PR > Close and reopen > Close again to retrigger cleanup

# Option 2: Run scheduled cleanup workflow manually
# Actions > SWA Cleanup (Scheduled) > Run workflow > Dry run: false

# Option 3: Use Azure Portal
# Navigate to Static Web App > Environments > Delete specific environment
```

#### Verify Environment Count

```bash
# Using Azure CLI
az staticwebapp environment list \
  --name swa-ytsumm-prd \
  --resource-group rg-ytsumm-prd \
  --query "length([?name!='default'])" \
  -o tsv
```

### Best Practices

1. **Always close PRs properly**
   - Don't just abandon PRs
   - Use GitHub's "Close" button to trigger cleanup workflow

2. **Monitor environment count**
   - Check scheduled cleanup reports regularly
   - Set up alerts if count approaches limit

3. **Use dry-run mode first**
   - When running scheduled cleanup manually
   - Verify what will be deleted before actual deletion

4. **Review cleanup logs**
   - Check for failed cleanup attempts
   - Investigate any environments that weren't cleaned up

5. **Keep PRs clean**
   - Close or merge PRs promptly when done
   - Don't leave draft PRs open indefinitely

## Troubleshooting

### Deployment Still Fails with "Maximum Environments" Error

**Possible causes:**
1. Cleanup workflow didn't run (check workflow runs)
2. Cleanup failed silently (check job logs)
3. Stale environments from before cleanup was implemented

**Resolution:**
```bash
# 1. Check current environment count
az staticwebapp environment list \
  --name swa-ytsumm-prd \
  --resource-group rg-ytsumm-prd

# 2. Run scheduled cleanup manually (dry-run first)
# GitHub Actions > SWA Cleanup (Scheduled) > Run workflow

# 3. If still at limit, manually delete oldest environments via Azure Portal
```

### Cleanup Workflow Fails

**Check:**
1. SWA_DEPLOYMENT_TOKEN is valid
2. Token has correct permissions
3. Static Web App still exists
4. Network connectivity to Azure

**Debug:**
```yaml
# Add to workflow for debugging
- name: Debug SWA token
  run: |
    if [[ -z "${{ secrets.SWA_DEPLOYMENT_TOKEN }}" ]]; then
      echo "ERROR: SWA_DEPLOYMENT_TOKEN is not set"
      exit 1
    fi
```

### Environment Not Deleted After PR Close

**Possible causes:**
1. Cleanup workflow disabled or failed
2. PR closed before workflow was implemented
3. Permissions issue

**Resolution:**
1. Check "PR Cleanup" workflow run for the PR
2. Re-run the failed job if it failed
3. Manually trigger scheduled cleanup
4. As last resort, delete via Azure Portal

## Future Enhancements

Potential improvements to consider:

1. **Azure CLI Integration:**
   - Use Azure CLI to directly query and delete environments
   - More reliable than relying on PR-based cleanup

2. **Proactive Limit Management:**
   - Calculate current environment count
   - Block deployment if at limit with helpful error message
   - Automatically trigger cleanup of oldest stale environment

3. **Metrics and Alerting:**
   - Track environment count over time
   - Alert when approaching limit (e.g., >80% of max)
   - Dashboard showing environment lifecycle

4. **Auto-cleanup Age-based:**
   - Delete environments from PRs closed >7 days ago
   - Configurable retention period
   - Exemptions for specific PRs (labels)

## Related Documentation

- [Azure Static Web Apps Documentation](https://docs.microsoft.com/azure/static-web-apps/)
- [GitHub Actions: Azure/static-web-apps-deploy](https://github.com/Azure/static-web-apps-deploy)
- [Preview Environment Workflow](./preview-workflow-solid-refactoring.md)
- [CI/CD Troubleshooting](./runbooks/ci-cd-troubleshooting.md)
