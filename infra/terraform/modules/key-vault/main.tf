# =============================================================================
# Azure Key Vault Module
# =============================================================================
# Creates an Azure Key Vault for secrets management

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.85"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = ">= 2.47"
    }
  }
}

# -----------------------------------------------------------------------------
# Data Sources
# -----------------------------------------------------------------------------

data "azurerm_client_config" "current" {}

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

variable "name" {
  description = "Name of the Key Vault (must be globally unique)"
  type        = string
}

variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
}

variable "location" {
  description = "Azure region"
  type        = string
}

variable "sku_name" {
  description = "SKU name for the Key Vault"
  type        = string
  default     = "standard"
}

variable "soft_delete_retention_days" {
  description = "Days to retain soft-deleted secrets"
  type        = number
  default     = 7
}

variable "purge_protection_enabled" {
  description = "Enable purge protection"
  type        = bool
  default     = false # Set to true for production
}

variable "enable_rbac_authorization" {
  description = "Use RBAC instead of access policies"
  type        = bool
  default     = true
}

variable "secrets" {
  description = "Secrets to create in the Key Vault"
  type        = map(string)
  default     = {}
  sensitive   = true
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
variable "secrets_officer_principal_id" {
  description = "Principal ID to grant Key Vault Secrets Officer role (optional, defaults to current user)"
  type        = string
  default     = null
}
# -----------------------------------------------------------------------------
# Resources
# -----------------------------------------------------------------------------

resource "azurerm_key_vault" "vault" {
  name                       = var.name
  location                   = var.location
  resource_group_name        = var.resource_group_name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = var.sku_name
  soft_delete_retention_days = var.soft_delete_retention_days
  purge_protection_enabled   = var.purge_protection_enabled
  rbac_authorization_enabled = var.enable_rbac_authorization # Renamed from enable_rbac_authorization in azurerm 4.x

  tags = var.tags
}

# Grant a specific principal access to manage secrets (optional)
# If not specified, secrets can still be created via GitHub OIDC Contributor role
resource "azurerm_role_assignment" "secrets_officer" {
  count                = var.secrets_officer_principal_id != null ? 1 : 0
  scope                = azurerm_key_vault.vault.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = var.secrets_officer_principal_id
}

# Create secrets
resource "azurerm_key_vault_secret" "secrets" {
  for_each     = nonsensitive(var.secrets)
  name         = each.key
  value        = sensitive(each.value)
  key_vault_id = azurerm_key_vault.vault.id
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "id" {
  description = "The ID of the Key Vault"
  value       = azurerm_key_vault.vault.id
}

output "name" {
  description = "The name of the Key Vault"
  value       = azurerm_key_vault.vault.name
}

output "vault_uri" {
  description = "The URI of the Key Vault"
  value       = azurerm_key_vault.vault.vault_uri
}

output "tenant_id" {
  description = "The tenant ID of the Key Vault"
  value       = azurerm_key_vault.vault.tenant_id
}
