# Azure Static Web Apps Environment Cleanup Strategy

## Problem Statement

Azure Static Web Apps (SWA) has a limit on the number of staging environments (typically 3-10 depending on the plan). When this limit is reached, new PR deployments fail with:

```
The content server has rejected the request with: BadRequest
Reason: This Static Web App already has the maximum number of staging environments
```

## Solution: Multi-Layered Cleanup Approach

We implement three complementary cleanup strategies using SOLID principles and focused composite actions to ensure stale environments are removed.

### Architecture: Composite Actions (SOLID Principles)

The implementation follows clean code principles with focused, reusable composite actions:

1. **`find-stale-prs`** - Single Responsibility: Find closed PRs
2. **`close-swa-environment`** - Single Responsibility: Close a specific SWA environment
3. **`cleanup-stale-swa-environments`** - Orchestration: Find and cleanup in one action

This modular approach allows for:
- ✅ Easy testing of individual components
- ✅ Reusability across workflows
- ✅ Clear separation of concerns
- ✅ Maintainability

### 1. **Immediate Cleanup on PR Close** (Primary)

**Workflow:** [`.github/workflows/preview-cleanup.yml`](.github/workflows/preview-cleanup.yml)

**Trigger:** Automatically when a PR is closed or merged

**How it works:**
- Listens to PR `closed` events
- Uses the `close-swa-environment` composite action
- Immediately calls Azure SWA deploy action with `action: close`
- Posts a status comment to the PR

**Benefits:**
- Immediate cleanup when PR is no longer needed
- Zero manual intervention required
- Prevents environment accumulation
- Uses focused composite action for reusability

**Code:**
```yaml
- name: Close SWA staging environment
  uses: ./.github/actions/close-swa-environment
  with:
    pr-number: ${{ github.event.pull_request.number }}
    swa-deployment-token: ${{ secrets.SWA_DEPLOYMENT_TOKEN }}
```

### 2. **Scheduled Cleanup of Stale Environments** (Automated)

**Workflow:** [`.github/workflows/swa-cleanup-scheduled.yml`](.github/workflows/swa-cleanup-scheduled.yml)

**Trigger:** 
- Daily at 2 AM UTC (cron schedule)
- Manual dispatch with optional dry-run

**How it works:**
- Authenticates to Azure using OIDC
- Lists all SWA environments using Azure CLI
- Matches environments to closed PRs using build metadata
- **Actually deletes** stale environments (PRs closed >7 days ago)

**Benefits:**
- Catches any environments missed by PR close trigger
- Uses Azure CLI for reliable deletion
- Dry-run mode available for testing
- Automatic cleanup of old environments

**Usage:**
```bash
# Manual trigger from GitHub UI
# Actions > SWA Cleanup (Scheduled) > Run workflow
# Toggle "Dry run mode" if desired
```

**Code:**
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
    github-token: ${{ secrets.GITHUB_TOKEN }}
    swa-name: ${{ vars.SWA_NAME }}
    resource-group: ${{ vars.AZURE_RESOURCE_GROUP }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
    dry-run: 'false'
    min-age-hours: '168'  # 7 days
```

### 3. **Pre-Deployment Cleanup** (Proactive)

**Workflow:** [`.github/workflows/preview.yml`](.github/workflows/preview.yml)

**Trigger:** Before every SWA deployment

**How it works:**
- Authenticates to Azure using OIDC
- Lists all SWA environments using Azure CLI
- Matches environments to closed PRs (closed >1 hour ago)
- **Actually deletes** matched stale environments
- Frees up slots before deploying new environment

**Benefits:**
- Proactively prevents "maximum environments" errors
- Ensures deployment succeeds by making room first
- Uses Azure CLI for reliable deletion
- Automatic, no manual intervention needed

**Code:**
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
    github-token: ${{ secrets.GITHUB_TOKEN }}
    swa-name: ${{ vars.SWA_NAME }}
    resource-group: ${{ vars.AZURE_RESOURCE_GROUP }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
    dry-run: 'false'
    min-age-hours: '1'
```

## Implementation Details

### Azure CLI Approach

The implementation uses Azure CLI commands to directly manage SWA environments:

**1. List Environments:**
```bash
az staticwebapp environment list \
  -n <SWA_NAME> \
  -g <RESOURCE_GROUP> \
  -o json
```

Each environment includes metadata:
- `name` / `buildId`: Environment identifier
- `properties.hostname`: Preview URL
- `properties.sourceBranch`: Source branch name
- `properties.pullRequestTitle`: PR title (if from PR)

**2. Match to PRs:**
- By pullRequestTitle (non-null indicates PR environment)
- By buildId (often equals PR number)
- By hostname pattern (contains `-<PR_NUMBER>.`)

**3. Delete Environment:**
```bash
az staticwebapp environment delete \
  -n <SWA_NAME> \
  -g <RESOURCE_GROUP> \
  --environment-name <BUILD_ID> \
  --yes
```

**4. Safety:**
- Never deletes "default" (production) environment
- Explicit environment name required
- Azure OIDC authentication required

### Composite Actions Architecture

The implementation follows SOLID principles with focused, reusable composite actions:

1. **`find-stale-prs`** - Queries GitHub API for closed PRs
2. **`close-swa-environment`** - Closes specific PR environment (for PR close events)
3. **`cleanup-stale-swa-environments`** - Lists Azure environments, matches to PRs, deletes stale ones

### 1. **Immediate Cleanup on PR Close** (Primary)

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
- `AZURE_CLIENT_ID`: For Azure OIDC authentication
- `AZURE_TENANT_ID`: For Azure OIDC authentication
- `AZURE_SUBSCRIPTION_ID`: For Azure OIDC authentication

**Variables (optional):**
- `SWA_NAME`: Static Web App name (default: `swa-ytsumm-prd`)
- `AZURE_RESOURCE_GROUP`: Resource group name (default: `rg-ytsumm-prd`)

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

This should rarely happen now with automated cleanup, but if it does:

**Immediate fix:**
```bash
# Option 1: Wait a few minutes for pre-deployment cleanup to run
# The preview.yml workflow automatically cleans up stale environments

# Option 2: Trigger scheduled cleanup manually
# GitHub Actions > SWA Cleanup (Scheduled) > Run workflow

# Option 3: Close stale PRs (triggers immediate cleanup)
gh pr close <PR_NUMBER>

# Option 4: Manual deletion via Azure Portal
# Navigate to: portal.azure.com → Static Web App → Environments → Delete
```

**Why it might still happen:**
- Multiple PRs deploying simultaneously
- Cleanup hasn't run yet for recently closed PRs
- Azure CLI authentication issues

**Long-term solution:**
- Automated cleanup handles most cases
- Close PRs promptly after merging
- Monitor scheduled cleanup reports

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
