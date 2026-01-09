# =============================================================================
# Azure Container Registry Module
# =============================================================================
# Creates an Azure Container Registry for Docker images

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
  description = "Name of the container registry (must be globally unique)"
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

variable "sku" {
  description = "SKU for the container registry"
  type        = string
  default     = "Basic"
}

variable "admin_enabled" {
  description = "Enable admin user for the registry"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

# -----------------------------------------------------------------------------
# Resources
# -----------------------------------------------------------------------------

resource "azurerm_container_registry" "acr" {
  name                = var.name
  resource_group_name = var.resource_group_name
  location            = var.location
  sku                 = var.sku
  admin_enabled       = var.admin_enabled

  tags = var.tags
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "id" {
  description = "The ID of the container registry"
  value       = azurerm_container_registry.acr.id
}

output "name" {
  description = "The name of the container registry"
  value       = azurerm_container_registry.acr.name
}

output "login_server" {
  description = "The login server of the container registry"
  value       = azurerm_container_registry.acr.login_server
}

output "admin_username" {
  description = "The admin username of the container registry"
  value       = azurerm_container_registry.acr.admin_username
  sensitive   = true
}

output "admin_password" {
  description = "The admin password of the container registry"
  value       = azurerm_container_registry.acr.admin_password
  sensitive   = true
}
