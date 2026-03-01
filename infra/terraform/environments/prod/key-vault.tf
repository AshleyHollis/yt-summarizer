# =============================================================================
# Azure Key Vault Secrets
# =============================================================================

# Import existing secrets that were created outside Terraform state
import {
  to = azurerm_key_vault_secret.secrets["webshare-proxy-password"]
  id = "https://kv-ytsumm-prd.vault.azure.net/secrets/webshare-proxy-password/8a2287910ec6476eb2774e5738fd019e"
}

import {
  to = azurerm_key_vault_secret.secrets["webshare-proxy-username"]
  id = "https://kv-ytsumm-prd.vault.azure.net/secrets/webshare-proxy-username/c5b190b9862b4906a60d0b5b220ab631"
}

locals {
  app_secrets = {
    "sql-connection-string"   = module.sql.connection_string
    "storage-connection"      = module.storage.primary_connection_string
    "openai-api-key"          = var.openai_api_key
    "cloudflare-api-token"    = var.cloudflare_api_token
    "webshare-proxy-username" = var.webshare_proxy_username
    "webshare-proxy-password" = var.webshare_proxy_password
  }
}

resource "azurerm_key_vault_secret" "secrets" {
  for_each     = nonsensitive(local.app_secrets)
  name         = each.key
  value        = sensitive(each.value)
  key_vault_id = module.shared.key_vault_id
}

# =============================================================================
# Removed blocks - resources migrated to shared-infra
# =============================================================================

removed {
  from = module.key_vault.azurerm_key_vault.vault

  lifecycle {
    destroy = false
  }
}

removed {
  from = module.key_vault.azurerm_role_assignment.secrets_officer

  lifecycle {
    destroy = false
  }
}
