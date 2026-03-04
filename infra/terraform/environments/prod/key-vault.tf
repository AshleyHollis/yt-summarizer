# =============================================================================
# Azure Key Vault Secrets
# =============================================================================

# Import existing secrets that were created outside Terraform state
# (All secrets need import after partial apply destroyed state on 2026-03-04)
import {
  to = azurerm_key_vault_secret.secrets["sql-connection-string"]
  id = "https://kv-ytsumm-prd.vault.azure.net/secrets/sql-connection-string/794fc0ef377d4263a2d63db0b7aff6d6"
}

import {
  to = azurerm_key_vault_secret.secrets["storage-connection"]
  id = "https://kv-ytsumm-prd.vault.azure.net/secrets/storage-connection/4b95c33133f64a44b32aa8eec18fbd0a"
}

import {
  to = azurerm_key_vault_secret.secrets["openai-api-key"]
  id = "https://kv-ytsumm-prd.vault.azure.net/secrets/openai-api-key/c8f65984fa984088a5424015734c42e2"
}

import {
  to = azurerm_key_vault_secret.secrets["azure-openai-api-key"]
  id = "https://kv-ytsumm-prd.vault.azure.net/secrets/azure-openai-api-key/1f5731d215474c89b8ebda98dcabc621"
}

import {
  to = azurerm_key_vault_secret.secrets["azure-openai-endpoint"]
  id = "https://kv-ytsumm-prd.vault.azure.net/secrets/azure-openai-endpoint/89b3a333679d4005afa3b28987fb131a"
}

import {
  to = azurerm_key_vault_secret.secrets["azure-openai-deployment"]
  id = "https://kv-ytsumm-prd.vault.azure.net/secrets/azure-openai-deployment/dc03f43bce2645a9b223e080da3034cd"
}

import {
  to = azurerm_key_vault_secret.secrets["azure-openai-embedding-deployment"]
  id = "https://kv-ytsumm-prd.vault.azure.net/secrets/azure-openai-embedding-deployment/08d7880e8913466ebecf5ad7557784ed"
}

import {
  to = azurerm_key_vault_secret.secrets["cloudflare-api-token"]
  id = "https://kv-ytsumm-prd.vault.azure.net/secrets/cloudflare-api-token/2c36824f08b340979717d0e236ab1c4a"
}

import {
  to = azurerm_key_vault_secret.secrets["webshare-proxy-username"]
  id = "https://kv-ytsumm-prd.vault.azure.net/secrets/webshare-proxy-username/dc30133af7fd4c48a2d666e2be4529c5"
}

import {
  to = azurerm_key_vault_secret.secrets["webshare-proxy-password"]
  id = "https://kv-ytsumm-prd.vault.azure.net/secrets/webshare-proxy-password/7d1e39d0742d40fdad974c39fe11c7da"
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
