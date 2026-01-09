# =============================================================================
# Production Environment Configuration
# =============================================================================
# Single production environment - previews share this infrastructure
# but run in different AKS namespaces

terraform {
  required_version = ">= 1.5.0"
}

# -----------------------------------------------------------------------------
# Local Variables
# -----------------------------------------------------------------------------

locals {
  environment = "prod"
  name_prefix = "ytsumm-prd"
  
  common_tags = {
    Environment = local.environment
    Project     = "yt-summarizer"
    ManagedBy   = "terraform"
  }
}

# -----------------------------------------------------------------------------
# Resource Group
# -----------------------------------------------------------------------------

resource "azurerm_resource_group" "main" {
  name     = "rg-${local.name_prefix}"
  location = var.location
  tags     = local.common_tags
}

# -----------------------------------------------------------------------------
# Azure Container Registry
# Shared by production and preview environments
# -----------------------------------------------------------------------------

module "acr" {
  source = "../../modules/container-registry"

  name                = replace("acr${local.name_prefix}", "-", "")
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = var.acr_sku

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# Azure Key Vault
# -----------------------------------------------------------------------------

module "key_vault" {
  source = "../../modules/key-vault"

  name                     = "kv-${local.name_prefix}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  purge_protection_enabled = true

  secrets = {
    "sql-connection-string" = module.sql.connection_string
    "storage-connection"    = module.storage.primary_connection_string
  }

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# Azure Storage (Blob + Queue)
# -----------------------------------------------------------------------------

module "storage" {
  source = "../../modules/storage"

  name                = replace("st${local.name_prefix}", "-", "")
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  # Use GRS for production data protection
  account_replication_type = "GRS"

  containers = [
    { name = "transcripts" },
    { name = "summaries" },
    { name = "embeddings" }
  ]

  queues = [
    "transcribe-queue",
    "summarize-queue",
    "embed-queue",
    "relationships-queue"
  ]

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# Azure SQL Database
# -----------------------------------------------------------------------------

module "sql" {
  source = "../../modules/sql-database"

  server_name         = "sql-${local.name_prefix}"
  database_name       = "ytsummarizer"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  admin_username      = var.sql_admin_username
  admin_password      = var.sql_admin_password

  # Serverless for cost savings
  sku_name                    = "GP_S_Gen5_1"
  auto_pause_delay_in_minutes = 120

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# AKS Cluster
# Single-node cluster hosts both production and preview namespaces
# -----------------------------------------------------------------------------

module "aks" {
  source = "../../modules/aks"

  name                = "aks-${local.name_prefix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  dns_prefix          = local.name_prefix
  kubernetes_version  = var.kubernetes_version

  # Single-node for cost savings (~$30/month)
  node_count   = 1
  node_vm_size = var.aks_node_size

  # ACR integration
  acr_id = module.acr.id

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# Static Web App
# -----------------------------------------------------------------------------

module "swa" {
  source = "../../modules/static-web-app"

  name                = "swa-${local.name_prefix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku_tier            = "Free"

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# Nginx Ingress Controller
# Handles routing for both production and preview environments
# -----------------------------------------------------------------------------

module "nginx_ingress" {
  source = "../../modules/nginx-ingress"

  depends_on = [module.aks]
}

# -----------------------------------------------------------------------------
# External Secrets Operator
# -----------------------------------------------------------------------------

module "external_secrets" {
  source = "../../modules/external-secrets"

  key_vault_name      = module.key_vault.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  client_id           = module.aks.identity_principal_id
  app_namespace       = "yt-summarizer"

  depends_on = [module.aks, module.key_vault]
}

# -----------------------------------------------------------------------------
# Argo CD
# Manages production + preview ApplicationSet
# -----------------------------------------------------------------------------

module "argocd" {
  source = "../../modules/argocd"

  namespace     = "argocd"
  chart_version = "5.51.6"

  ingress_enabled = true
  ingress_host    = "argocd.${var.domain}"
  ingress_class   = "nginx"

  github_org  = var.github_org
  github_repo = var.github_repo

  depends_on = [module.aks, module.nginx_ingress]
}

# -----------------------------------------------------------------------------
# Data Sources
# -----------------------------------------------------------------------------

data "azurerm_client_config" "current" {}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "resource_group_name" {
  value = azurerm_resource_group.main.name
}

output "acr_login_server" {
  value = module.acr.login_server
}

output "aks_cluster_name" {
  value = module.aks.name
}

output "aks_fqdn" {
  value = module.aks.fqdn
}

output "swa_hostname" {
  value = module.swa.default_host_name
}

output "swa_api_key" {
  value     = module.swa.api_key
  sensitive = true
}

output "key_vault_uri" {
  value = module.key_vault.vault_uri
}

output "sql_server_fqdn" {
  value = module.sql.server_fqdn
}

output "storage_primary_endpoint" {
  value = module.storage.primary_blob_endpoint
}
