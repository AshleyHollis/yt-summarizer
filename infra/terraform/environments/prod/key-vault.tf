# =============================================================================
# Azure Key Vault Secrets
# =============================================================================

# Import existing secrets that were created outside Terraform state
# (All secrets need import after partial apply destroyed state on 2026-03-04)
import {
  to = azurerm_key_vault_secret.secrets["sql-connection-string"]
  id = "https://kv-ytsumm-prd-ci.vault.azure.net/secrets/sql-connection-string/8979e2069cd44505adba82428f7c1687"
}

import {
  to = azurerm_key_vault_secret.secrets["storage-connection"]
  id = "https://kv-ytsumm-prd-ci.vault.azure.net/secrets/storage-connection/3175ff02640d429b93f122ea17cd8961"
}

import {
  to = azurerm_key_vault_secret.secrets["openai-api-key"]
  id = "https://kv-ytsumm-prd-ci.vault.azure.net/secrets/openai-api-key/3c7bf96664c94db48de535c813b6a950"
}

import {
  to = azurerm_key_vault_secret.secrets["azure-openai-api-key"]
  id = "https://kv-ytsumm-prd-ci.vault.azure.net/secrets/azure-openai-api-key/fa9ace2d255a47d89f7720b9ce2a567c"
}

import {
  to = azurerm_key_vault_secret.secrets["azure-openai-endpoint"]
  id = "https://kv-ytsumm-prd-ci.vault.azure.net/secrets/azure-openai-endpoint/a7b2ed33716148cebbae5a15929b843c"
}

import {
  to = azurerm_key_vault_secret.secrets["azure-openai-deployment"]
  id = "https://kv-ytsumm-prd-ci.vault.azure.net/secrets/azure-openai-deployment/1d59afaa483b482fb1204dcc7b7f1cb6"
}

import {
  to = azurerm_key_vault_secret.secrets["azure-openai-embedding-deployment"]
  id = "https://kv-ytsumm-prd-ci.vault.azure.net/secrets/azure-openai-embedding-deployment/11e903fa1abd48208c4f259e3a2ee433"
}

import {
  to = azurerm_key_vault_secret.secrets["cloudflare-api-token"]
  id = "https://kv-ytsumm-prd-ci.vault.azure.net/secrets/cloudflare-api-token/81238a78de9b4ef8bfa99256058acfcb"
}

import {
  to = azurerm_key_vault_secret.secrets["webshare-proxy-username"]
  id = "https://kv-ytsumm-prd-ci.vault.azure.net/secrets/webshare-proxy-username/429b5c1ade41471483aca3c91ae553c3"
}

import {
  to = azurerm_key_vault_secret.secrets["webshare-proxy-password"]
  id = "https://kv-ytsumm-prd-ci.vault.azure.net/secrets/webshare-proxy-password/2e795e5880c442d1860a0fae24ce4cea"
}

locals {
  app_secrets = {
    "sql-connection-string"             = module.sql.connection_string
    "storage-connection"                = module.storage.primary_connection_string
    "openai-api-key"                    = var.openai_api_key
    "azure-openai-api-key"              = var.azure_openai_api_key
    "azure-openai-endpoint"             = var.azure_openai_endpoint
    "azure-openai-deployment"           = var.azure_openai_deployment
    "azure-openai-embedding-deployment" = var.azure_openai_embedding_deployment
    "cloudflare-api-token"              = var.cloudflare_api_token
    "webshare-proxy-username"           = var.webshare_proxy_username
    "webshare-proxy-password"           = var.webshare_proxy_password
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
