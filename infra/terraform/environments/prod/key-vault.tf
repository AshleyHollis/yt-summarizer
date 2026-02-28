# =============================================================================
# Azure Key Vault
# =============================================================================

# Import existing secrets that were created outside Terraform state
import {
  to = module.key_vault.azurerm_key_vault_secret.secrets["webshare-proxy-password"]
  id = "https://kv-ytsumm-prd.vault.azure.net/secrets/webshare-proxy-password"
}

import {
  to = module.key_vault.azurerm_key_vault_secret.secrets["webshare-proxy-username"]
  id = "https://kv-ytsumm-prd.vault.azure.net/secrets/webshare-proxy-username"
}

module "key_vault" {
  source = "../../modules/key-vault"

  name                         = "kv-${local.name_prefix}"
  resource_group_name          = azurerm_resource_group.main.name
  location                     = azurerm_resource_group.main.location
  purge_protection_enabled     = true
  secrets_officer_principal_id = var.key_vault_secrets_officer_principal_id

  secrets = {
    "sql-connection-string"   = module.sql.connection_string
    "storage-connection"      = module.storage.primary_connection_string
    "openai-api-key"          = var.openai_api_key
    "cloudflare-api-token"    = var.cloudflare_api_token
    "webshare-proxy-username" = var.webshare_proxy_username
    "webshare-proxy-password" = var.webshare_proxy_password
  }

  tags = local.common_tags
}
