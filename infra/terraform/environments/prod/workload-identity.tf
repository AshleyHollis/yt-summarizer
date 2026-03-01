# =============================================================================
# Workload Identity for External Secrets Operator
# =============================================================================
# Creates a User-Assigned Managed Identity that External Secrets uses to
# access Azure Key Vault via Workload Identity federation

resource "azurerm_user_assigned_identity" "external_secrets" {
  name                = "id-${local.name_prefix}-eso"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.common_tags
}

# Federated credential linking K8s ServiceAccount to Azure Identity
resource "azurerm_federated_identity_credential" "external_secrets" {
  name                = "fedcred-${local.name_prefix}-eso"
  resource_group_name = azurerm_resource_group.main.name
  parent_id           = azurerm_user_assigned_identity.external_secrets.id
  audience            = ["api://AzureADTokenExchange"]
  issuer              = module.aks.oidc_issuer_url
  subject             = "system:serviceaccount:yt-summarizer:yt-summarizer-sa"
}

# Grant the managed identity access to read secrets from Key Vault
resource "azurerm_role_assignment" "external_secrets_kv_reader" {
  scope                = module.key_vault.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.external_secrets.principal_id
}

removed {
  from = azurerm_user_assigned_identity.external_secrets

  lifecycle {
    destroy = false
  }
}

removed {
  from = azurerm_federated_identity_credential.external_secrets

  lifecycle {
    destroy = false
  }
}

removed {
  from = azurerm_role_assignment.external_secrets_kv_reader

  lifecycle {
    destroy = false
  }
}
