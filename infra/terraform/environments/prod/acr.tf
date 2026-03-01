# =============================================================================
# Azure Container Registry - MIGRATED TO shared-infra
# =============================================================================

removed {
  from = module.acr.azurerm_container_registry.acr

  lifecycle {
    destroy = false
  }
}
