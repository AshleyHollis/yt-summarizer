# =============================================================================
# Azure SQL Database
# =============================================================================

module "sql" {
  source = "../../modules/sql-database"

  server_name         = "sql-${local.name_prefix}"
  database_name       = "ytsummarizer"
  resource_group_name = module.shared.resource_group_name
  location            = module.shared.resource_group_location
  admin_username      = var.sql_admin_username
  admin_password      = var.sql_admin_password

  # Basic tier for cost savings (~$5/month vs ~$374/month for serverless that never pauses)
  # Changed from Serverless because workers run 24/7 preventing auto-pause
  # Basic is optimal for always-on workloads: 5 DTUs, 2GB max
  sku_name    = "Basic"
  max_size_gb = 2

  # Don't set serverless-specific parameters for Basic tier
  auto_pause_delay_in_minutes = null
  min_capacity                = null

  tags = local.common_tags
}
