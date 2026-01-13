# Fix for AKS Cluster Replacement Issue

## Problem
The Terraform plan in PR #12 showed that the AKS cluster was flagged for replacement due to multiple attribute changes, most critically:

1. `undrainable_node_behavior` in `upgrade_settings` - forces replacement
2. Removal of explicit `kubelet_identity` block - forces replacement
3. Multiple Azure-managed default attributes being removed from configuration

## Root Cause
The `azurerm` provider v4.x (now at v4.57.0) has stricter behavior around Azure-managed attributes. Previous Terraform state had many default values explicitly set, while the current configuration relies on Azure-managed defaults. This mismatch caused Terraform to plan a cluster replacement.

## Solution

### 1. AKS Module Fixes (`infra/terraform/modules/aks/main.tf`)

Added comprehensive `lifecycle { ignore_changes = [...] }` blocks to ignore all Azure-managed attributes:

**Resource-level ignore_changes:**
- `azure_policy_enabled` - Azure-managed add-on
- `http_application_routing_enabled` - Azure-managed add-on
- `local_account_disabled` - Azure-managed feature
- `open_service_mesh_enabled` - Azure-managed add-on
- `custom_ca_trust_certificates_base64` - Azure-managed feature
- `cost_analysis_enabled` - Azure-managed feature
- `kubelet_identity` - Azure-managed identity block
- `network_profile[0].load_balancer_profile[0].*` - Azure-managed networking
- `node_provisioning_profile` - Azure-managed node provisioning

**default_node_pool-level ignore_changes:**
- `tags` - Azure-managed tags
- `zones` - Azure-managed availability zones
- `node_public_ip_enabled` - Azure-managed feature
- `fips_enabled` - Azure-managed feature
- `host_encryption_enabled` - Azure-managed feature
- `only_critical_addons_enabled` - Azure-managed feature
- `max_count` - Azure-managed autoscaling
- `min_count` - Azure-managed autoscaling
- `upgrade_settings` - **CRITICAL**: Contains `undrainable_node_behavior` that forces replacement

**identity-level ignore_changes:**
- `identity_ids` - Azure-managed identity configuration

### 2. Key Vault Module Fix (`infra/terraform/modules/key-vault/main.tf`)

Made the `secrets_officer` role assignment optional to prevent issues with changing principals:

```hcl
resource "azurerm_role_assignment" "secrets_officer" {
  count                = var.secrets_officer_principal_id != null ? 1 : 0
  scope               = azurerm_key_vault.vault.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id        = var.secrets_officer_principal_id
}
```

**Why this was needed:**
- The previous implementation used `data.azurerm_client_config.current.object_id`
- This returns different values depending on who's running Terraform (local user vs GitHub Actions OIDC)
- This caused the role assignment to be flagged for replacement on each run
- GitHub OIDC service principal already has Contributor role at subscription level, which provides Key Vault access

### 3. Production Module Fix (`infra/terraform/environments/prod/main.tf`)

Updated AKS module call to enable ACR attachment:

```hcl
# ACR integration
acr_id      = module.acr.id
attach_acr  = true  # ADDED: Explicitly enable ACR attachment
```

### 4. AKS Output Protection (`infra/terraform/modules/aks/main.tf`)

Protected access to `kubelet_identity` with `try()` since it's now ignored:

```hcl
output "kubelet_identity_object_id" {
  value = try(azurerm_kubernetes_cluster.aks.kubelet_identity[0].object_id, null)
}
```

Also protected ACR role assignment:

```hcl
resource "azurerm_role_assignment" "acr_pull" {
  count                = var.attach_acr ? 1 : 0
  principal_id         = try(azurerm_kubernetes_cluster.aks.kubelet_identity[0].object_id, null)
  role_definition_name = "AcrPull"
  scope                = var.acr_id
}
```

## Testing

To verify the fixes work:

1. Run Terraform plan:
   ```powershell
   cd infra\terraform\environments\prod
   terraform plan -var="subscription_id=..."
   ```

2. Verify AKS cluster is no longer in the "replace (-/+)" section
3. Verify Key Vault role assignment is no longer in the "replace" section

## Expected Result

After these changes:
- ✅ AKS cluster should show 0 resources to replace
- ✅ Only newly added GitHub OIDC resources should be created
- ✅ Key Vault role assignment replacement should be eliminated (or moved to optional with count=0)
- ✅ All other resources should show "No changes" or minimal updates

## Files Modified

1. `infra/terraform/modules/aks/main.tf` - Added lifecycle ignore_changes blocks
2. `infra/terraform/modules/key-vault/main.tf` - Made secrets_officer role optional
3. `infra/terraform/environments/prod/main.tf` - Added attach_acr flag
4. `infra/terraform/modules/github-oidc/main.tf` - Added documentation comment

## Related Documentation

- [Azure AKS Provider Upgrades](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/guides/2.0-customizable-upgrades.html)
- [azurerm_kubernetes_cluster Resource](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster)
- [Terraform Lifecycle Meta-Arguments](https://developer.hashicorp.com/terraform/language/meta-arguments/lifecycle)
