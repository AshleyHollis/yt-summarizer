# Quick Import Commands for GitHub OIDC

Run these commands in `infra/terraform/environments/prod` directory:

```powershell
terraform init

# Note: azuread provider uses application OBJECT ID, not app ID
terraform import module.github_oidc.azuread_application.github_actions /applications/8d0da409-3026-40b6-ae14-c1da724eb1b9

# Note: azuread provider uses /servicePrincipals/<OBJECT_ID> format
terraform import module.github_oidc.azuread_service_principal.github_actions /servicePrincipals/0a8480bd-2b41-449f-b16e-badd5616ae15

# Note: azuread provider uses /federatedIdentityCredentials/<CRED_ID> format
terraform import module.github_oidc.azuread_application_federated_identity_credential.repository /federatedIdentityCredentials/aa3d558b-e8ed-433c-ac74-85547c808b85

terraform import module.github_oidc.azuread_application_federated_identity_credential.pull_request /federatedIdentityCredentials/7680e3f7-8b5c-4170-9cfc-61215188a018

terraform import module.github_oidc.azuread_application_federated_identity_credential.production /federatedIdentityCredentials/d7c05803-e9ac-4525-abee-b9ea9eeb09ca

terraform import module.github_oidc.azurerm_role_assignment.contributor[0] <CONTRIBUTOR_ROLE_ID>

terraform import module.github_oidc.azurerm_role_assignment.acr_push[0] <ACR_PUSH_ROLE_ID>
```

Replace `<CONTRIBUTOR_ROLE_ID>` and `<ACR_PUSH_ROLE_ID>` with actual IDs from:

```powershell
az role assignment list --assignee 0a8480bd-2b41-449f-b16e-badd5616ae15 --scope "/subscriptions/28aefbe7-e2af-4b4a-9ce1-92d6672c31bd" --query "[?roleDefinitionName=='Contributor'].{name: roleDefinitionName, id: id}"

az role assignment list --assignee 0a8480bd-2b41-449f-b16e-badd5616ae15 --scope "/subscriptions/28aefbe7-e2af-4b4a-9ce1-92d6672c31bd/resourceGroups/rg-ytsumm-prd/providers/Microsoft.ContainerRegistry/registries/acrytsummprd" --query "[?roleDefinitionName=='AcrPush'].{name: roleDefinitionName, id: id}"
```

After imports, verify with:

```powershell
terraform state list | Select-String github_oidc
terraform plan
```
