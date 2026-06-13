# =============================================================================
# Data Sources
# =============================================================================

data "azurerm_client_config" "current" {}

data "azurerm_container_registry" "shared" {
  name                = var.acr_name
  resource_group_name = var.acr_resource_group_name != "" ? var.acr_resource_group_name : module.shared.resource_group_name
}
