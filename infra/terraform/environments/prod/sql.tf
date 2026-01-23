# =============================================================================
# Azure SQL Database
# =============================================================================

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
  auto_pause_delay_in_minutes = 60 # Reduced from 120 to pause faster

  # Cost optimization: Reduced from 32GB to 2GB (sufficient for development)
  max_size_gb = 2

  # Min capacity already at optimal 0.5 vCores (default)

  tags = local.common_tags
}
