# =============================================================================
# Resource Group - MIGRATED TO shared-infra
# =============================================================================

removed {
  from = azurerm_resource_group.main

  lifecycle {
    destroy = false
  }
}
