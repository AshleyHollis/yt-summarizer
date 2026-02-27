# SWA Environment Configuration Fix

**Date**: January 26, 2026  
**Status**: ✅ Fixed  
**Related PRs**: #112, #113, #114, #115, #116

## Problem Summary

Azure Static Web Apps (SWA) environments were incorrectly configured, causing all preview deployments to go to a single shared `preview` environment instead of PR-specific environments.

## Root Cause

When migrating from the official `Azure/static-web-apps-deploy@v1` action to the SWA CLI (`@azure/static-web-apps-cli`):

1. **Azure action auto-detected PR numbers** from GitHub context and created PR-specific staging environments automatically
2. **SWA CLI requires explicit environment names** via `--env` parameter
3. Initial deployments defaulted to `--env preview`, creating a single shared environment
4. Production deployments used `--env production` instead of `--env default`

## Incorrect State (Before Fix)

```
SWA Environments:
├── default       (production, mapped to web.yt-summarizer.apps.ashleyhollis.com)
├── preview       ❌ ALL preview PRs deployed here (shared, incorrect)
└── production    ❌ Created by initial prod deployment (incorrect)
```

**Impact**:
- Preview PRs overwrote each other's deployments
- No isolation between PR environments
- Production deployed to wrong environment

## Correct State (After Fix)

```
SWA Environments:
├── default       ✅ Production (web.yt-summarizer.apps.ashleyhollis.com)
├── pr-115        ✅ Preview for PR #115 (unique)
├── pr-116        ✅ Preview for PR #116 (unique)
└── pr-{number}   ✅ One environment per PR
```

## Changes Made

### 1. Environment Cleanup

```bash
# Deleted incorrect environments
az staticwebapp environment delete --name swa-ytsumm-prd --environment-name preview
az staticwebapp environment delete --name swa-ytsumm-prd --environment-name production
```

### 2. Fixed Environment Naming

**Production** (`.github/workflows/deploy-prod.yml`):
```yaml
- uses: ./.github/actions/deploy-frontend-swa
  with:
    deployment-environment: default  # Changed from 'production'
```

**Preview** (`.github/workflows/preview.yml`):
```yaml
- uses: ./.github/actions/deploy-frontend-swa
  with:
    deployment-environment: pr-${{ github.event.pull_request.number }}
```

### 3. Added GitHub Context to SWA CLI

**File**: `.github/actions/deploy-frontend-swa/deploy-with-retry.sh`

```bash
# Export GitHub context for SWA CLI (fixes "Could not get repository branch/url" warnings)
export GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-}"
export GITHUB_REF="${GITHUB_REF:-}"
export GITHUB_SHA="${GITHUB_SHA:-}"
export GITHUB_HEAD_REF="${GITHUB_HEAD_REF:-}"
export GITHUB_BASE_REF="${GITHUB_BASE_REF:-}"
export GITHUB_EVENT_NAME="${GITHUB_EVENT_NAME:-}"
export GITHUB_ACTOR="${GITHUB_ACTOR:-}"
```

**Before**: SWA CLI showed warnings:
```
ℹ Could not get repository branch. Proceeding
ℹ Could not get repository url. Proceeding
```

**After**: SWA CLI properly detects GitHub context from environment variables.

## Environment Naming Conventions

### Production
- **Environment**: `default` (SWA's main production environment)
- **Hostname**: `white-meadow-0b8e2e000.6.azurestaticapps.net` (auto-assigned)
- **Custom Domain**: `web.yt-summarizer.apps.ashleyhollis.com`
- **Branch**: `main`

### Preview (PR-based)
- **Environment**: `pr-{number}` (e.g., `pr-115`, `pr-116`)
- **Hostname**: `white-meadow-0b8e2e000-{number}.6.azurestaticapps.net` (auto-assigned)
- **Custom Domain**: None (uses auto-generated hostname)
- **Branch**: Feature branch from PR

## Deployment Flow

### Production Deployment
1. PR merged to `main`
2. CI workflow runs (builds artifacts)
3. `deploy-prod` workflow triggers
4. Deploys to `--env default`
5. Custom domain `web.yt-summarizer.apps.ashleyhollis.com` serves production

### Preview Deployment
1. PR opened/updated
2. CI workflow runs (builds artifacts)
3. `preview` workflow triggers
4. Deploys to `--env pr-{PR_NUMBER}`
5. Auto-generated hostname serves preview (e.g., `white-meadow-0b8e2e000-115.6.azurestaticapps.net`)

## Verification Commands

```bash
# List all SWA environments
az staticwebapp environment list --name swa-ytsumm-prd \
  --query "[].{Name:name, Hostname:hostname, Status:status}" -o table

# Check custom domain configuration
az staticwebapp hostname list --name swa-ytsumm-prd \
  --query "[].{Domain:domainName, Status:status}" -o table

# View SWA resource details
az staticwebapp show --name swa-ytsumm-prd \
  --query "{Name:name, DefaultHostname:defaultHostname, CustomDomains:customDomains}" -o json
```

## SWA Environment Limits

Azure Static Web Apps has a **3 preview environment limit** (in addition to production). When this limit is reached, the oldest inactive environment is automatically deleted.

**Preview Cleanup**:
- Automatic: Oldest inactive environments deleted when limit reached
- Manual: `.github/workflows/preview-cleanup.yml` runs when PR closes
- CLI: `az staticwebapp environment delete --name swa-ytsumm-prd --environment-name pr-{number}`

## Related Documentation

- [SWA Deployment Timeout Analysis](./swa-deployment-timeout-analysis.md)
- [Azure SWA CLI Documentation](https://azure.github.io/static-web-apps-cli/)
- [Environment Naming in SWA](https://learn.microsoft.com/azure/static-web-apps/review-publish-pull-requests)

## Lessons Learned

1. **SWA CLI ≠ Azure Action**: The CLI requires explicit configuration that the action auto-detected
2. **GitHub context must be exported**: SWA CLI reads environment variables, not GitHub Actions context
3. **Environment naming matters**: `default` is production, PR environments should use `pr-{number}` pattern
4. **Test environment isolation**: Each PR should have its own environment to prevent conflicts
5. **Document migration changes**: When replacing GitHub Actions with CLI tools, document behavioral differences
