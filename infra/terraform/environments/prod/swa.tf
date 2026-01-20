# =============================================================================
# Static Web App
# =============================================================================

module "swa" {
  source = "../../modules/static-web-app"

  name                = "swa-${local.name_prefix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku_tier            = "Free"

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# SWA Environment Variables
# -----------------------------------------------------------------------------
# NOTE: App settings are now managed via Azure CLI in deployment pipelines
# instead of Terraform to avoid state drift and provide more flexible updates.
# See: .github/actions/prepare-swa-deployment/script.sh
