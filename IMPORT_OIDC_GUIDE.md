# Terraform Import Guide for GitHub OIDC Resources

## Overview

This guide helps you import existing GitHub OIDC resources that were created by `setup-github-oidc.ps1` into Terraform state.

## Current State of Existing Resources

Based on Azure CLI queries, the following resources exist:

| Resource | ID | Matches Terraform | Action |
|----------|-----|------------------|--------|
| Azure AD Application | f005883d-5861-47b7-9d7a-177625da6811 | ✓ | Import |
| Service Principal | 0a8480bd-2b41-449f-b16e-badd5616ae15 | ✓ | Import |
| Federated Credential (repo) | aa3d558b-e8ed-433c-ac74-85547c808b85 | ✓ | Import |
| Federated Credential (pr) | 7680e3f7-8b5c-4170-9cfc-61215188a018 | ✓ | Import |
| Federated Credential (production) | d7c05803-e9ac-4525-abee-b9ea9eeb09ca | ✓ | Import |
| Federated Credential (main) | 5bc0488c-c9af-4f02-a190-b90ebd957f37 | ❌ | Delete & Recreate |
| Preview Branch Credential | 8d15658c-53ea-477e-b5b5-bd64891edfbb | ❌ | Ignore |

**Note**: The existing `github-main` credential has an incorrect subject (`refs/heads/*` instead of `refs/heads/main`). This must be deleted and recreated by Terraform.

## Prerequisites

- Azure CLI installed and authenticated
- Terraform installed
- In the `infra/terraform/environments/prod` directory

## Step 1: Delete Incorrect Credential

```powershell
az ad app federated-credential delete --id f005883d-5861-47b7-9d7a-177625da6811 --federated-credential-id 5bc0488c-c9af-4f02-a190-b90ebd957f37
```

## Step 2: Import Resources into Terraform

Run these commands one at a time. Wait for each to succeed before running the next.

```bash
# Initialize Terraform (if not already initialized)
terraform init

# 1. Import Azure AD Application
terraform import module.github_oidc.azuread_application.github_actions f005883d-5861-47b7-9d7a-177625da6811

# 2. Import Service Principal
terraform import module.github_oidc.azuread_service_principal.github_actions 0a8480bd-2b41-449f-b16e-badd5616ae15

# 3. Import federated credential for repository-wide
terraform import module.github_oidc.azuread_application_federated_identity_credential.repository aa3d558b-e8ed-433c-ac74-85547c808b85

# 4. Import federated credential for pull requests
terraform import module.github_oidc.azuread_application_federated_identity_credential.pull_request 7680e3f7-8b5c-4170-9cfc-61215188a018

# 5. Import federated credential for production environment
terraform import module.github_oidc.azuread_application_federated_identity_credential.production d7c05803-e9ac-4525-abee-b9ea9eeb09ca

# 6. Import Contributor role assignment on subscription
# Use this command to find the role assignment ID:
# az role assignment list --assignee 0a8480bd-2b41-449f-b16e-badd5616ae15 --scope "/subscriptions/28aefbe7-e2af-4b4a-9ce1-92d6672c31bd" --query "[?roleDefinitionName=='Contributor'].{name: roleDefinitionName, id: id}"

terraform import module.github_oidc.azurerm_role_assignment.contributor[0] <CONTRIBUTOR_ROLE_ID>

# 7. Import AcrPush role assignment
# Use this command to find the role assignment ID:
# az role assignment list --assignee 0a8480bd-2b41-449f-b16e-badd5616ae15 --scope "/subscriptions/28aefbe7-e2af-4b4a-9ce1-92d6672c31bd/resourceGroups/rg-ytsumm-prd/providers/Microsoft.ContainerRegistry/registries/acrytsummprd" --query "[?roleDefinitionName=='AcrPush'].{name: roleDefinitionName, id: id}"

terraform import module.github_oidc.azurerm_role_assignment.acr_push[0] <ACR_PUSH_ROLE_ID>
```

## Step 3: Verify Plan to See Create/Update

After importing, run a plan to see what Terraform wants to create or update:

```bash
terraform plan
```

Expected result:
- `github-main` credential will be created (corrected subject)
- Other resources should show no changes

## Step 4: Apply Changes

If the plan looks correct, apply to create the corrected `github-main` credential:

```bash
terraform apply
```

## Step 5: Final Verification

Check that all resources are now in state:

```bash
terraform state list | grep github_oidc
```

Expected output:
```
module.github_oidc.azuread_application.github_actions
module.github_oidc.azuread_service_principal.github_actions
module.github_oidc.azuread_application_federated_identity_credential.main (newly created)
module.github_oidc.azuread_application_federated_identity_credential.pull_request
module.github_oidc.azuread_application_federated_identity_credential.production
module.github_oidc.azuread_application_federated_identity_credential.repository
module.github_oidc.azurerm_role_assignment.contributor[0]
module.github_oidc.azurerm_role_assignment.acr_push[0]
```

## Common Issues

### "Resource already exists" error

If you get this error, run `terraform state rm <resource-address>` first:

```bash
# Example: Remove from state
terraform state rm module.github_oidc.azuread_application.github_actions

# Then try importing again
terraform import module.github_oidc.azuread_application.github_actions <APP_ID>
```

### "Importing from API is not supported" error

Some Terraform providers don't support importing. The Terraform module uses:
- `hashicorp/azuread` for Azure AD resources
- `hashicorp/azurerm` for role assignments

Both providers support import, but you need the exact resource ID.

### Resource not found

Double-check:
- You're in the correct directory (`infra/terraform/environments/prod`)
- Terraform is initialized
- The resource ID matches exactly (no extra spaces, quotes, etc.)

