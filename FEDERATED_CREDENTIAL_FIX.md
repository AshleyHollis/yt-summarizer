# Federated Credential Missing - Fix Guide

## Problem

Azure authentication is failing with:
```
Error: AADSTS700213: No matching federated identity record found for presented assertion subject 'repo:AshleyHollis/yt-summarizer:ref:refs/heads/main'
```

## Root Cause

The federated credential for the `main` branch is either:
1. **Not created** in the Azure AD app registration
2. **Incorrectly configured** with wrong subject claim
3. **Deleted** accidentally
4. Associated with the **wrong app registration**

## Current Status

✅ **azure/login@v2 configuration**: Fixed (auth-type parameter removed)  
❌ **Federated credentials**: Missing or misconfigured in Azure AD

## Solution: Run Setup Script

The easiest fix is to run the OIDC setup script which will create/verify all credentials:

```powershell
# First, login to Azure
az login

# Set your subscription
az account set --subscription <YOUR_SUBSCRIPTION_ID>

# Run the setup script
.\scripts\setup-github-oidc.ps1 `
  -SubscriptionId '<YOUR_SUBSCRIPTION_ID>' `
  -ResourceGroupName 'rg-ytsumm-prd' `
  -GitHubOrg 'AshleyHollis' `
  -GitHubRepo 'yt-summarizer'
```

This will automatically:
- Find or create the Azure AD app registration
- Create 4 federated credentials (if they don't exist)
- Assign necessary permissions
- Output the secrets needed for GitHub

## Manual Fix (Alternative)

If you prefer to add the credential manually:

### Step 1: Get Your App ID

```powershell
# Find the app registration
az ad app list --display-name "github-actions-yt-summarizer" --query "[0].appId" -o tsv
```

### Step 2: Create the Federated Credential

```powershell
# Replace <APP_ID> with the actual app ID from Step 1
az ad app federated-credential create `
  --id <APP_ID> `
  --parameters '{
    "name": "github-main",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:AshleyHollis/yt-summarizer:ref:refs/heads/main",
    "audiences": ["api://AzureADTokenExchange"]
  }'
```

### Step 3: Verify the Credential

```powershell
az ad app federated-credential list --id <APP_ID>
```

You should see output like:
```json
[
  {
    "name": "github-main",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:AshleyHollis/yt-summarizer:ref:refs/heads/main",
    "audiences": [
      "api://AzureADTokenExchange"
    ]
  }
]
```

## Required Federated Credentials

For full GitHub Actions OIDC support, you need these 4 credentials:

| Name | Subject | Purpose |
|------|---------|---------|
| `github-main` | `repo:AshleyHollis/yt-summarizer:ref:refs/heads/main` | Push to main branch |
| `github-pr` | `repo:AshleyHollis/yt-summarizer:pull_request` | All pull requests |
| `github-env-production` | `repo:AshleyHollis/yt-summarizer:environment:production` | Production deployments |
| `github-repo` | `repo:AshleyHollis/yt-summarizer` | Wildcard (any workflow) |

## Verification

After adding the credentials:

1. **Re-run the failed workflow**:
   ```bash
   gh run rerun <run-id>
   ```

2. **Watch for success**:
   ```bash
   gh run watch
   ```

3. **Check the Azure Login step** - it should now show:
   ```
   ✓ Azure CLI Login using OIDC
   ✓ Successfully logged in to Azure
   ```

## Azure Portal Verification (GUI Method)

If you prefer using the Azure Portal:

1. Go to: https://portal.azure.com
2. Navigate to: **Azure Active Directory** → **App registrations**
3. Find: `github-actions-yt-summarizer`
4. Click: **Certificates & secrets** → **Federated credentials** tab
5. Click: **Add credential**
6. Select: **GitHub Actions deploying Azure resources**
7. Fill in:
   - **Organization**: `AshleyHollis`
   - **Repository**: `yt-summarizer`
   - **Entity type**: `Branch`
   - **GitHub branch name**: `main`
   - **Credential name**: `github-main`
8. Click: **Add**

Repeat for other credential types (Pull Request, Environment).

## Common Issues

### Issue: "Credential already exists"

If you get an error that the credential already exists, list them:
```powershell
az ad app federated-credential list --id <APP_ID>
```

Check if the `subject` claim exactly matches. If it's slightly different (e.g., wrong repo name), delete and recreate:
```powershell
az ad app federated-credential delete --id <APP_ID> --federated-credential-id <CREDENTIAL_NAME>
```

### Issue: "Multiple app registrations found"

If you have multiple apps with similar names:
```powershell
# List all apps
az ad app list --display-name "github-actions" --query "[].{name:displayName, appId:appId}"

# Use the correct app ID in GitHub secrets
```

Ensure `AZURE_CLIENT_ID` in GitHub secrets matches the correct app.

### Issue: "Wrong subscription or tenant"

Verify your GitHub secrets:
```bash
# Go to: https://github.com/AshleyHollis/yt-summarizer/settings/secrets/actions
# Verify these secrets are set:
# - AZURE_CLIENT_ID
# - AZURE_TENANT_ID
# - AZURE_SUBSCRIPTION_ID
```

Get the correct values:
```powershell
# Get your tenant ID
az account show --query tenantId -o tsv

# Get your subscription ID
az account show --query id -o tsv

# Get your app client ID
az ad app list --display-name "github-actions-yt-summarizer" --query "[0].appId" -o tsv
```

## Next Steps

After fixing the federated credentials:

1. ✅ Verify all 4 credentials exist
2. ✅ Confirm GitHub secrets are correct
3. ✅ Re-run the failed workflow
4. ✅ Monitor for successful Azure login
5. ✅ Update this document with any additional findings

## References

- [Azure Workload Identity Federation](https://learn.microsoft.com/entra/workload-id/workload-identity-federation)
- [GitHub Actions OIDC](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [Azure Login Action](https://github.com/Azure/login)
