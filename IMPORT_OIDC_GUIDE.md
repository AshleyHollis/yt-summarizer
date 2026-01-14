# Terraform Import Guide for GitHub OIDC Resources

## Overview

This guide helps you import the existing GitHub OIDC resources that were created by `setup-github-oidc.ps1` into Terraform state.

## Prerequisites

- Azure CLI installed and authenticated
- Terraform installed
- In the `infra/terraform/environments/prod` directory

## Step 1: Query Existing Resources

First, let's identify the existing Azure AD resources:

```powershell
# Set variables
$GitHubOrg = "AshleyHollis"
$GitHubRepo = "yt-summarizer"
$AppName = "github-actions-$GitHubRepo"

# Get the application
$app = az ad app list --display-name $AppName --query "[0]" | ConvertFrom-Json
Write-Host "Application ID: $($app.appId)"
Write-Host "Application Object ID: $($app.id)"
Write-Host ""

# Get the service principal
$sp = az ad sp list --filter "appId eq '$($app.appId)'" --query "[0]" | ConvertFrom-Json
Write-Host "Service Principal Object ID: $($sp.id)"
Write-Host ""

# Get federated credentials
$creds = az ad app federated-credential list --id $app.id --query "[].{name: name, id: id}" | ConvertFrom-Json
Write-Host "Federated Credentials:"
$creds | ForEach-Object { Write-Host "  - $($_.name) ($($_.id))" }
Write-Host ""

# Get role assignments
$contributorRole = az role assignment list --assignee $sp.id --scope "/subscriptions/28aefbe7-e2af-4b4a-9ce1-92d6672c31bd" --query "[?roleDefinitionName=='Contributor'].{name: roleDefinitionName, id: id}" | ConvertFrom-Json
Write-Host "Contributor Role Assignment:"
$contributorRole | ForEach-Object { Write-Host "  - $($_.name) ($($_.id))" }
Write-Host ""

$acrRole = az role assignment list --assignee $sp.id --scope "/subscriptions/28aefbe7-e2af-4b4a-9ce1-92d6672c31bd/resourceGroups/rg-ytsumm-prd/providers/Microsoft.ContainerRegistry/registries/acrytsummprd" --query "[?roleDefinitionName=='AcrPush'].{name: roleDefinitionName, id: id}" | ConvertFrom-Json
Write-Host "AcrPush Role Assignment:"
$acrRole | ForEach-Object { Write-Host "  - $($_.name) ($($_.id))" }
```

Replace the `<APP_ID>`, `<SP_OBJECT_ID>`, and role assignment IDs in the import commands below.

## Step 2: Import Resources into Terraform

Run these commands one at a time. Wait for each to succeed before running the next.

```bash
# Initialize Terraform (if not already initialized)
terraform init

# 1. Import the Azure AD Application
terraform import module.github_oidc.azuread_application.github_actions <APP_ID>

# 2. Import the Service Principal
terraform import module.github_oidc.azuread_service_principal.github_actions <SP_OBJECT_ID>

# 3. Import federated credential for main branch
terraform import module.github_oidc.azuread_application_federated_identity_credential.main <MAIN_CRED_ID>

# 4. Import federated credential for pull requests
terraform import module.github_oidc.azuread_application_federated_identity_credential.pull_request <PR_CRED_ID>

# 5. Import federated credential for production environment
terraform import module.github_oidc.azuread_application_federated_identity_credential.production <PROD_CRED_ID>

# 6. Import federated credential for repository-wide
terraform import module.github_oidc.azuread_application_federated_identity_credential.repository <REPO_CRED_ID>

# 7. Import Contributor role assignment on subscription
terraform import module.github_oidc.azurerm_role_assignment.contributor[0] <CONTRIBUTOR_ROLE_ID>

# 8. Import AcrPush role assignment
terraform import module.github_oidc.azurerm_role_assignment.acr_push[0] <ACR_PUSH_ROLE_ID>
```

## Step 3: Verify Imports

Check that all resources are now in state:

```bash
terraform state list | grep github_oidc
```

Expected output:
```
module.github_oidc.azuread_application.github_actions
module.github_oidc.azuread_service_principal.github_actions
module.github_oidc.azuread_application_federated_identity_credential.main
module.github_oidc.azuread_application_federated_identity_credential.pull_request
module.github_oidc.azuread_application_federated_identity_credential.production
module.github_oidc.azuread_application_federated_identity_credential.repository
module.github_oidc.azurerm_role_assignment.contributor[0]
module.github_oidc.azurerm_role_assignment.acr_push[0]
```

## Step 4: Run Plan to Verify

After importing, run a plan to verify there are no more changes:

```bash
terraform plan
```

Expected result: No changes. Your existing resources should now match the live environment.

## Common Issues

### "Resource already exists" error

If you get this error, run `terraform state rm <resource-address>` first:

```bash
# Example: Remove from state
terraform state rm module.github_oidc.azuread_application.github_actions

# Then try importing again
terraform import module.github_oidc.azuread_application.github_actions <APP_ID>
```

### Import fails with "importing from the API is not supported"

Some Terraform providers don't support importing. The Terraform module uses:
- `hashicorp/azuread` for Azure AD resources
- `hashicorp/azurerm` for role assignments

Both providers support import, but you need the exact resource ID.

### Resource not found

Double-check:
- You're in the correct directory (`infra/terraform/environments/prod`)
- Terraform is initialized
- The resource ID matches exactly (no extra spaces, quotes, etc.)
