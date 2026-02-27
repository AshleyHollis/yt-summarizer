# Auth0 on Azure Static Web Apps - Terraform Setup

> **Status**: ✅ Terraform configuration complete - ready for deployment

## Overview

This document describes how Auth0 authentication is configured for the Next.js frontend deployed to Azure Static Web Apps (SWA) using Terraform Infrastructure as Code.

## What Was Configured

### 1. Auth0 Callback URLs (Production)

**File**: `infra/terraform/environments/prod/variables.tf`

Added SWA production domain and localhost to Auth0 callback URLs:

```hcl
variable "auth0_allowed_callback_urls" {
  default = [
    # FastAPI BFF endpoints
    "https://api.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0",
    "https://api-stg.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0",
    "https://api-pr-*.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0",
    # Azure Static Web Apps (Next.js @auth0/nextjs-auth0)
    "https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net/api/auth/callback",
    "http://localhost:3000/api/auth/callback",
  ]
}
```

**Also updated**:
- `auth0_allowed_logout_urls` - Added `http://localhost:3000`
- `auth0_allowed_web_origins` - Added `http://localhost:3000`
- `auth0_preview_allowed_callback_urls` - Added `https://*.azurestaticapps.net/api/auth/callback`

### 2. SWA Environment Variables

**File**: `infra/terraform/environments/prod/swa.tf`

Added `azapi_update_resource` to configure Auth0 environment variables in SWA:

```hcl
resource "azapi_update_resource" "swa_app_settings" {
  count = var.enable_auth0 ? 1 : 0

  type        = "Microsoft.Web/staticSites/config@2023-12-01"
  resource_id = "${module.swa.id}/config/appsettings"

  body = jsonencode({
    properties = {
      AUTH0_SECRET           = azurerm_key_vault_secret.auth0_session_secret[0].value
      AUTH0_BASE_URL         = "https://${module.swa.default_host_name}"
      AUTH0_ISSUER_BASE_URL  = "https://${var.auth0_domain}"
      AUTH0_CLIENT_ID        = azurerm_key_vault_secret.auth0_client_id[0].value
      AUTH0_CLIENT_SECRET    = azurerm_key_vault_secret.auth0_client_secret[0].value
    }
  })
}
```

**Key Points**:
- Uses `azapi` provider (Azure REST API) because `azurerm_static_web_app` doesn't support `app_settings`
- Retrieves Auth0 credentials directly from Azure Key Vault secrets
- `AUTH0_BASE_URL` is dynamically set to the SWA's default hostname
- Only created when `var.enable_auth0 = true` (default)

### 3. Azure API Provider

**Files**:
- `infra/terraform/environments/prod/versions.tf` - Added `azapi` provider requirement (~> 2.0)
- `infra/terraform/environments/prod/providers.tf` - Added `azapi` provider configuration

## Architecture

### Credential Flow

```
┌─────────────────┐
│  Azure Key      │
│  Vault          │──────────┐
│  kv-ytsumm-prd  │          │
└─────────────────┘          │
        │                    │
        │ Terraform creates  │ Terraform reads
        │ secrets            │ secrets for SWA
        ▼                    ▼
┌─────────────────┐    ┌──────────────────┐
│ Auth0 Module    │    │ azapi_update     │
│ (module.auth0)  │    │ SWA app_settings │
└─────────────────┘    └──────────────────┘
        │                    │
        │ Creates app        │ Configures env vars
        ▼                    ▼
┌─────────────────┐    ┌──────────────────┐
│ Auth0 Tenant    │◄───│ Azure SWA        │
│ Application     │    │ (Next.js runtime)│
└─────────────────┘    └──────────────────┘
```

### Environment Variables Set in SWA

| Variable | Source | Purpose |
|----------|--------|---------|
| `AUTH0_SECRET` | `auth0-session-secret` (Key Vault) | Session encryption |
| `AUTH0_BASE_URL` | SWA `default_host_name` output | Application base URL |
| `AUTH0_ISSUER_BASE_URL` | `var.auth0_domain` (from env) | Auth0 tenant URL |
| `AUTH0_CLIENT_ID` | `auth0-client-id` (Key Vault) | Auth0 app client ID |
| `AUTH0_CLIENT_SECRET` | `auth0-client-secret` (Key Vault) | Auth0 app secret |

## Deployment Steps

### Prerequisites

1. **Auth0 Terraform Service Account** credentials must be set as environment variables:
   ```bash
   # PowerShell
   $env:AUTH0_DOMAIN = "dev-gvli0bfdrue0h8po.us.auth0.com"
   $env:AUTH0_CLIENT_ID = "Fmh7q7q2OrqUvmSXTgBxr3E7v5KdAbt6"
   $env:AUTH0_CLIENT_SECRET = "<from Azure Key Vault: auth0-terraform-client-secret>"
   ```

   **Retrieve from Key Vault**:
   ```bash
   az keyvault secret show --vault-name kv-ytsumm-prd --name auth0-terraform-client-secret --query value -o tsv
   ```

2. **Azure authentication**:
   ```bash
   az login
   az account set --subscription "28aefbe7-e2af-4b4a-9ce1-92d6672c31bd"
   ```

### Apply Terraform

```bash
cd infra/terraform/environments/prod

# Initialize with new azapi provider
terraform init -upgrade

# Review changes
terraform plan

# Apply changes
terraform apply
```

### Expected Changes

When you run `terraform plan`, you should see:

1. **Auth0 application update** - Callback URLs updated to include SWA domain
2. **New resource created** - `azapi_update_resource.swa_app_settings[0]`

**Sample Output**:
```hcl
# module.auth0[0].auth0_client.client will be updated in-place
~ resource "auth0_client" "client" {
    ~ callbacks = [
        + "https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net/api/auth/callback",
        + "http://localhost:3000/api/auth/callback",
      ]
  }

# azapi_update_resource.swa_app_settings[0] will be created
+ resource "azapi_update_resource" "swa_app_settings" {
    + id          = (known after apply)
    + resource_id = "/subscriptions/.../staticSites/swa-ytsumm-prd/config/appsettings"
    + body        = jsonencode({
        properties = {
          AUTH0_SECRET          = (sensitive value)
          AUTH0_BASE_URL        = "https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net"
          AUTH0_ISSUER_BASE_URL = "https://dev-gvli0bfdrue0h8po.us.auth0.com"
          AUTH0_CLIENT_ID       = (sensitive value)
          AUTH0_CLIENT_SECRET   = (sensitive value)
        }
      })
  }
```

## Verification

After Terraform apply completes:

### 1. Verify Auth0 Callback URLs

**Auth0 Dashboard**:
1. Go to https://manage.auth0.com
2. Applications → `yt-summarizer-api-bff`
3. Settings → Application URIs
4. Verify **Allowed Callback URLs** includes:
   - `https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net/api/auth/callback`
   - `http://localhost:3000/api/auth/callback`

**CLI Verification**:
```bash
# Show callback URLs
terraform output -json | jq '.auth0_application_client_id.value'
# Then check in Auth0 Dashboard or via Auth0 Management API
```

### 2. Verify SWA Environment Variables

**Azure Portal**:
1. Navigate to: Azure Portal → Static Web Apps → `swa-ytsumm-prd`
2. Settings → Configuration
3. Verify variables are set:
   - `AUTH0_SECRET` = `***` (hidden)
   - `AUTH0_BASE_URL` = `https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net`
   - `AUTH0_ISSUER_BASE_URL` = `https://dev-gvli0bfdrue0h8po.us.auth0.com`
   - `AUTH0_CLIENT_ID` = `***` (hidden)
   - `AUTH0_CLIENT_SECRET` = `***` (hidden)

**Azure CLI Verification**:
```bash
az staticwebapp appsettings list \
  --name swa-ytsumm-prd \
  --resource-group rg-ytsumm-prd \
  --query "properties" -o json
```

Expected output:
```json
{
  "AUTH0_SECRET": "***",
  "AUTH0_BASE_URL": "https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net",
  "AUTH0_ISSUER_BASE_URL": "https://dev-gvli0bfdrue0h8po.us.auth0.com",
  "AUTH0_CLIENT_ID": "***",
  "AUTH0_CLIENT_SECRET": "***"
}
```

### 3. Test Auth0 Login Flow

**Prerequisites**:
- Code changes from previous commits must be deployed to SWA:
  - `apps/web/src/app/api/auth/[auth0]/route.ts` (Auth0 SDK route handler)
  - `apps/web/src/middleware.ts` (Updated matcher to exclude `\.swa`)
  - `.github/workflows/deploy-prod.yml` (Fixed `output_location: ""`)

**Test Steps**:

1. **Visit login page**:
   ```bash
   https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net/login
   ```

2. **Click "Sign In"** → Should redirect to Auth0 Universal Login

3. **Login with test user**:
   - Email: `admin@test.yt-summarizer.internal`
   - Password: (Retrieve from Key Vault)
     ```bash
     az keyvault secret show --vault-name kv-ytsumm-prd --name auth0-admin-test-password --query value -o tsv
     ```

4. **Expected behavior**:
   - ✅ Redirects to Auth0 login page
   - ✅ After login, redirects back to SWA (`/api/auth/callback`)
   - ✅ Session cookie is set
   - ✅ User is authenticated

5. **Check session**:
   ```bash
   curl -I https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net/api/auth/me
   # Expected: 200 OK with user profile JSON
   ```

## Troubleshooting

### Error: "azapi provider not found"

**Solution**: Run `terraform init -upgrade`

### Error: "Invalid callback URL"

**Symptoms**: Auth0 redirects back to SWA but shows "Callback URL mismatch" error.

**Solution**:
1. Verify `terraform apply` completed successfully
2. Check Auth0 Dashboard → Application → Settings → Allowed Callback URLs
3. Ensure SWA domain matches exactly (with `/api/auth/callback` path)

### Error: "AUTH0_SECRET is required"

**Symptoms**: Auth0 SDK throws error about missing `AUTH0_SECRET` variable.

**Solution**:
1. Verify Terraform created `azapi_update_resource.swa_app_settings[0]`
2. Check Azure Portal → SWA → Configuration for env vars
3. If missing, run `terraform apply` again

### Error: "Invalid state" during callback

**Symptoms**: Auth0 redirects back but shows "Invalid state parameter" error.

**Cause**: Session not persisting (usually due to missing `AUTH0_SECRET`).

**Solution**:
1. Verify `AUTH0_SECRET` is set in SWA configuration
2. Clear browser cookies and try again
3. Check Next.js logs in Azure Portal → SWA → Logs

## Manual Verification (Optional)

If you prefer to verify SWA environment variables were set correctly using Azure CLI:

```bash
# List all app settings
az staticwebapp appsettings list \
  --name swa-ytsumm-prd \
  --resource-group rg-ytsumm-prd

# Check specific setting (non-sensitive)
az staticwebapp appsettings list \
  --name swa-ytsumm-prd \
  --resource-group rg-ytsumm-prd \
  --query "properties.AUTH0_BASE_URL" -o tsv
```

## Next Steps

After Terraform deployment is verified:

1. **Deploy code changes** to SWA via GitHub Actions (if not already deployed)
2. **Test login flow** end-to-end
3. **Update custom domain** (if applicable) - Add custom domain callback URLs to Terraform variables
4. **Monitor logs** - Check Azure Portal → SWA → Logs for any runtime errors

## Related Documentation

- [Auth0 Terraform Service Account](./auth0-terraform-service-account.md) - Credentials for Terraform provider
- [Auth0 Setup Runbook](./runbooks/auth0-setup.md) - Initial Auth0 tenant setup
- [SWA Auth0 Deployment Guide (Manual)](../apps/web/SWA-AUTH0-DEPLOYMENT.md) - Alternative manual configuration steps
- [Auth0 Dashboard Checklist](../AUTH0-DASHBOARD-CHECKLIST.md) - Auth0 dashboard configuration reference

## Infrastructure Changes Summary

| File | Change | Purpose |
|------|--------|---------|
| `infra/terraform/environments/prod/versions.tf` | Added `azapi` provider | Enable Azure REST API calls |
| `infra/terraform/environments/prod/providers.tf` | Configured `azapi` provider | Configure provider settings |
| `infra/terraform/environments/prod/variables.tf` | Updated callback URL variables | Add SWA domain to Auth0 |
| `infra/terraform/environments/prod/swa.tf` | Added `azapi_update_resource` | Configure SWA env vars |

All changes are tracked in version control and deployable via `terraform apply`.
