# =============================================================================
# Azure Static Web Apps Module
# =============================================================================
# Creates an Azure Static Web App for the Next.js frontend

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
  description = "Name of the Static Web App"
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

variable "sku_tier" {
  description = "SKU tier for the Static Web App"
  type        = string
  default     = "Free"
}

variable "sku_size" {
  description = "SKU size for the Static Web App"
  type        = string
  default     = "Free"
}

variable "api_url" {
  description = "URL of the backend API for proxy configuration"
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

# -----------------------------------------------------------------------------
# Resources
# -----------------------------------------------------------------------------

resource "azurerm_static_web_app" "swa" {
  name                = var.name
  resource_group_name = var.resource_group_name
  location            = var.location
  sku_tier            = var.sku_tier
  sku_size            = var.sku_size

  tags = var.tags
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "id" {
  description = "The ID of the Static Web App"
  value       = azurerm_static_web_app.swa.id
}

output "name" {
  description = "The name of the Static Web App"
  value       = azurerm_static_web_app.swa.name
}

output "default_host_name" {
  description = "The default hostname of the Static Web App"
  value       = azurerm_static_web_app.swa.default_host_name
}

output "api_key" {
  description = "The API key for deployment (used by GitHub Actions)"
  value       = azurerm_static_web_app.swa.api_key
  sensitive   = true
}
