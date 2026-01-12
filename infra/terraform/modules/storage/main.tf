# =============================================================================
# Azure Storage Module (Blob + Queue)
# =============================================================================
# Creates an Azure Storage Account with blob and queue services

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.85"
    }
  }
}

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

variable "name" {
  description = "Name of the storage account (must be globally unique, lowercase, no hyphens)"
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

variable "account_tier" {
  description = "Account tier (Standard or Premium)"
  type        = string
  default     = "Standard"
}

variable "account_replication_type" {
  description = "Replication type (LRS, GRS, RAGRS, ZRS)"
  type        = string
  default     = "LRS"
}

variable "allow_blob_public_access" {
  description = "Allow public access to blobs"
  type        = bool
  default     = false
}

variable "containers" {
  description = "List of blob containers to create"
  type = list(object({
    name                  = string
    container_access_type = optional(string, "private")
  }))
  default = []
}

variable "queues" {
  description = "List of queues to create"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

# -----------------------------------------------------------------------------
# Resources
# -----------------------------------------------------------------------------

resource "azurerm_storage_account" "storage" {
  name                     = var.name
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = var.account_tier
  account_replication_type = var.account_replication_type

  allow_nested_items_to_be_public = var.allow_blob_public_access

  # Enable blob versioning for data protection
  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 7
    }
  }

  tags = var.tags
}

# Create blob containers
resource "azurerm_storage_container" "containers" {
  for_each              = { for c in var.containers : c.name => c }
  name                  = each.value.name
  storage_account_id   = azurerm_storage_account.storage.id
  container_access_type = each.value.container_access_type
}

# Create queues
resource "azurerm_storage_queue" "queues" {
  for_each             = toset(var.queues)
  name                 = each.value
  storage_account_id = azurerm_storage_account.storage.id
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "id" {
  description = "The ID of the storage account"
  value       = azurerm_storage_account.storage.id
}

output "name" {
  description = "The name of the storage account"
  value       = azurerm_storage_account.storage.name
}

output "primary_connection_string" {
  description = "Primary connection string"
  value       = azurerm_storage_account.storage.primary_connection_string
  sensitive   = true
}

output "primary_access_key" {
  description = "Primary access key"
  value       = azurerm_storage_account.storage.primary_access_key
  sensitive   = true
}

output "primary_blob_endpoint" {
  description = "Primary blob endpoint"
  value       = azurerm_storage_account.storage.primary_blob_endpoint
}

output "primary_queue_endpoint" {
  description = "Primary queue endpoint"
  value       = azurerm_storage_account.storage.primary_queue_endpoint
}
