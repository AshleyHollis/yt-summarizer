# =============================================================================
# Azure Key Vault
# =============================================================================

module "key_vault" {
  source = "../../modules/key-vault"

  name                         = "kv-${local.name_prefix}"
  resource_group_name          = azurerm_resource_group.main.name
  location                     = azurerm_resource_group.main.location
  purge_protection_enabled     = true
  secrets_officer_principal_id = var.key_vault_secrets_officer_principal_id

  secrets = {
    "sql-connection-string" = module.sql.connection_string
    "storage-connection"    = module.storage.primary_connection_string
    "openai-api-key"        = var.openai_api_key
    "cloudflare-api-token"  = var.cloudflare_api_token
  }

  tags = local.common_tags
}
