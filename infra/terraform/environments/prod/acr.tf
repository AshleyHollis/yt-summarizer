# =============================================================================
# Azure Container Registry
# =============================================================================
# Shared by production and preview environments

module "acr" {
  source = "../../modules/container-registry"

  name                = replace("acr${local.name_prefix}", "-", "")
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = var.acr_sku

  tags = local.common_tags
}

# =============================================================================
# Removed blocks - resources migrated to shared-infra
# =============================================================================

removed {
  from = module.acr.azurerm_container_registry.acr

  lifecycle {
    destroy = false
  }
}
