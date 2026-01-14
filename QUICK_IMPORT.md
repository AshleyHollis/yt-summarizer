# Quick Import Commands for GitHub OIDC

Run these commands in `infra/terraform/environments/prod` directory:

```powershell
terraform init

terraform import module.github_oidc.azuread_application.github_actions f005883d-5861-47b7-9d7a-177625da6811

terraform import module.github_oidc.azuread_service_principal.github_actions 0a8480bd-2b41-449f-b16e-badd5616ae15

terraform import module.github_oidc.azuread_application_federated_identity_credential.repository aa3d558b-e8ed-433c-ac74-85547c808b85

terraform import module.github_oidc.azuread_application_federated_identity_credential.pull_request 7680e3f7-8b5c-4170-9cfc-61215188a018

terraform import module.github_oidc.azuread_application_federated_identity_credential.production d7c05803-e9ac-4525-abee-b9ea9eeb09ca

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
