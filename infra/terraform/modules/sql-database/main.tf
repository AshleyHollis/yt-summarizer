# =============================================================================
# Azure SQL Database Module
# =============================================================================
# Creates an Azure SQL Server and Database with serverless compute

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

variable "server_name" {
  description = "Name of the SQL Server (must be globally unique)"
  type        = string
}

variable "database_name" {
  description = "Name of the database"
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

variable "admin_username" {
  description = "Administrator username"
  type        = string
}

variable "admin_password" {
  description = "Administrator password"
  type        = string
  sensitive   = true
}

variable "sku_name" {
  description = "SKU name for the database"
  type        = string
  default     = "GP_S_Gen5_1" # Serverless General Purpose
}

variable "max_size_gb" {
  description = "Maximum database size in GB"
  type        = number
  default     = 32
}

variable "min_capacity" {
  description = "Minimum capacity for serverless (vCores)"
  type        = number
  default     = 0.5
}

variable "auto_pause_delay_in_minutes" {
  description = "Auto-pause delay in minutes (-1 to disable)"
  type        = number
  default     = 60 # Pause after 1 hour of inactivity
}

variable "allow_azure_services" {
  description = "Allow Azure services to access the server"
  type        = bool
  default     = true
}

variable "firewall_rules" {
  description = "Firewall rules to create"
  type = list(object({
    name             = string
    start_ip_address = string
    end_ip_address   = string
  }))
  default = []
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

# -----------------------------------------------------------------------------
# Resources
# -----------------------------------------------------------------------------

resource "azurerm_mssql_server" "server" {
  name                         = var.server_name
  resource_group_name          = var.resource_group_name
  location                     = var.location
  version                      = "12.0"
  administrator_login          = var.admin_username
  administrator_login_password = var.admin_password

  # Minimum TLS version for security
  minimum_tls_version = "1.2"

  tags = var.tags
}

resource "azurerm_mssql_database" "database" {
  name                        = var.database_name
  server_id                   = azurerm_mssql_server.server.id
  sku_name                    = var.sku_name
  max_size_gb                 = var.max_size_gb
  min_capacity                = var.min_capacity
  auto_pause_delay_in_minutes = var.auto_pause_delay_in_minutes

  # Enable zone redundancy for production (not needed for hobby project)
  zone_redundant = false

  tags = var.tags
}

# Allow Azure services (needed for AKS access)
resource "azurerm_mssql_firewall_rule" "azure_services" {
  count            = var.allow_azure_services ? 1 : 0
  name             = "AllowAzureServices"
  server_id        = azurerm_mssql_server.server.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

# Custom firewall rules
resource "azurerm_mssql_firewall_rule" "custom" {
  for_each         = { for rule in var.firewall_rules : rule.name => rule }
  name             = each.value.name
  server_id        = azurerm_mssql_server.server.id
  start_ip_address = each.value.start_ip_address
  end_ip_address   = each.value.end_ip_address
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "server_id" {
  description = "The ID of the SQL Server"
  value       = azurerm_mssql_server.server.id
}

output "server_name" {
  description = "The name of the SQL Server"
  value       = azurerm_mssql_server.server.name
}

output "server_fqdn" {
  description = "The FQDN of the SQL Server"
  value       = azurerm_mssql_server.server.fully_qualified_domain_name
}

output "database_id" {
  description = "The ID of the database"
  value       = azurerm_mssql_database.database.id
}

output "database_name" {
  description = "The name of the database"
  value       = azurerm_mssql_database.database.name
}

output "connection_string" {
  description = "Connection string for the database"
  value       = "Server=tcp:${azurerm_mssql_server.server.fully_qualified_domain_name},1433;Initial Catalog=${azurerm_mssql_database.database.name};User ID=${var.admin_username};Password=${var.admin_password};Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
  sensitive   = true
}
