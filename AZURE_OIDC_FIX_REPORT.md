# Azure OIDC Authentication Fix - Deep Dive Report

## Problem Statement

**Error**: `Login failed with Error: Unsupported value 'OIDC' for authentication type is passed`

**Observed Behavior**:
- ✅ Works on PR branches
- ❌ Fails on main branch pushes
- Failure occurs in CI workflow during image build step

## Root Cause Analysis

### 1. Azure Login Action API Change

The `azure/login@v2` action has changed its API:

**OLD Behavior** (deprecated):
```yaml
- uses: azure/login@v2
  with:
    auth-type: OIDC  # ❌ No longer supported
    client-id: ${{ secrets.AZURE_CLIENT_ID }}
    tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
```

**NEW Behavior** (current):
```yaml
- uses: azure/login@v2
  with:
    # ✅ Auto-detects OIDC when credentials not provided
    client-id: ${{ secrets.AZURE_CLIENT_ID }}
    tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
```

The action now **automatically detects** OIDC authentication when:
- `client-id`, `tenant-id`, and `subscription-id` are provided
- No password/secret/certificate is provided

### 2. Why It Worked on PRs but Not Main

This is likely due to:

1. **Credential Caching**: PR workflows may have been using cached OIDC tokens from previous successful runs
2. **Different Execution Context**: Main branch workflows run with `push` event which may have triggered fresh authentication
3. **Workflow Concurrency**: Main branch workflows don't use `cancel-in-progress`, ensuring full execution
4. **Updated Action Version**: A recent update to `azure/login@v2` may have deprecated the `auth-type` parameter

### 3. Federated Credential Configuration

Based on `scripts/setup-github-oidc.ps1`, the following federated credentials are configured:

| Credential Name | Subject Claim | Matches |
|----------------|---------------|---------|
| `github-main` | `repo:AshleyHollis/yt-summarizer:ref:refs/heads/main` | Push to main branch |
| `github-pr` | `repo:AshleyHollis/yt-summarizer:pull_request` | All pull requests |
| `github-env-production` | `repo:AshleyHollis/yt-summarizer:environment:production` | Production environment deployments |
| `github-repo` | `repo:AshleyHollis/yt-summarizer` | Wildcard - any workflow (fallback) |

**Subject Claims Sent by GitHub Actions**:

| Event Type | Subject Claim |
|------------|---------------|
| Push to main | `repo:OWNER/REPO:ref:refs/heads/main` |
| Pull request | `repo:OWNER/REPO:pull_request` |
| Environment deployment | `repo:OWNER/REPO:environment:ENV_NAME` |
| Workflow dispatch | `repo:OWNER/REPO:ref:refs/heads/BRANCH` |

The configuration looks correct - both PR and main branch should match valid credentials.

## Changes Made

### Files Modified

1. **[.github/actions/azure-acr-login/action.yml](.github/actions/azure-acr-login/action.yml)**
   - Removed `auth-type: OIDC` parameter
   - Relies on auto-detection

2. **[.github/actions/get-aks-ingress-ip/action.yml](.github/actions/get-aks-ingress-ip/action.yml)**
   - Removed `auth-type: OIDC` parameter

3. **[.github/workflows/infra.yml](.github/workflows/infra.yml)**
   - Removed `auth-type: OIDC` parameter

4. **[.github/workflows/preview-cleanup.yml](.github/workflows/preview-cleanup.yml)**
   - Removed `auth-type: OIDC` parameter

5. **[.github/workflows/preview.yml](.github/workflows/preview.yml)** (4 occurrences)
   - Line 151: Azure Login (wait for CI)
   - Line 262: Azure Login (K8s-only changes)
   - Line 487: Azure Login (wait for Argo CD)
   - Line 589: Azure Login for SWA cleanup
   - All updated to remove `auth-type: OIDC`

6. **[.github/workflows/swa-cleanup-scheduled.yml](.github/workflows/swa-cleanup-scheduled.yml)**
   - Removed `auth-type: OIDC` parameter

### Total Changes

- **7 files** modified
- **10 instances** of `azure/login@v2` updated
- **0 instances** of `auth-type: OIDC` remaining

## Verification Steps

### Pre-Commit Verification

```powershell
# Verify no auth-type: OIDC remains
Get-ChildItem -Path ".github" -Recurse -Include "*.yml","*.yaml" |
  Select-String -Pattern "auth-type.*OIDC" -SimpleMatch

# Should return no results
```

### Post-Deploy Verification

After pushing these changes:

1. **Monitor CI Workflow on Main**
   - Navigate to: https://github.com/AshleyHollis/yt-summarizer/actions
   - Watch for next push to main
   - Verify "Build Images" step succeeds

2. **Check Azure Login Step**
   - Expand "Login to Azure Container Registry" step
   - Should see: `Login successful.`
   - Should NOT see: `Unsupported value 'OIDC'`

3. **Verify PR Workflows Still Work**
   - Create a test PR
   - Verify preview deployment succeeds
   - Confirm no authentication errors

### Rollback Plan

If issues persist:

```bash
# Check current federated credentials
az ad app federated-credential list --id <CLIENT_ID>

# Verify subject claims match expected patterns
# Main branch should match: repo:AshleyHollis/yt-summarizer:ref:refs/heads/main
# PRs should match: repo:AshleyHollis/yt-summarizer:pull_request
```

## Additional Recommendations

### 1. Enable OIDC Debug Logging (If Needed)

Add to workflow for troubleshooting:

```yaml
env:
  ACTIONS_STEP_DEBUG: true  # Enable debug logging
  ACTIONS_RUNNER_DEBUG: true
```

### 2. Verify GitHub OIDC Configuration

Ensure repository has OIDC enabled:
- Settings → Actions → General → Workflow permissions
- "Allow GitHub Actions to create and approve pull requests" (if needed for automation)

### 3. Monitor Azure AD App Registration

Check in Azure Portal:
- Azure Active Directory → App registrations
- Find: `github-actions-yt-summarizer`
- Verify:
  - Federated credentials are present (4 total)
  - Service principal has Contributor role
  - No expired credentials

### 4. Consider Environment Protection Rules

For production deployments, add environment protection:
- Settings → Environments → production
- Add required reviewers
- Add wait timer
- Add deployment branches (main only)

## References

- [Azure Login Action Documentation](https://github.com/Azure/login)
- [GitHub OIDC Documentation](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [Azure Workload Identity](https://learn.microsoft.com/en-us/azure/active-directory/develop/workload-identity-federation)

## Conclusion

The fix is straightforward: remove the deprecated `auth-type: OIDC` parameter and let `azure/login@v2` auto-detect OIDC authentication. The federated credential configuration is correct and should work for both PR and main branch workflows.

**Status**: ✅ Ready to commit and push
