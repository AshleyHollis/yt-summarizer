# =============================================================================
# Resource Group
# =============================================================================

resource "azurerm_resource_group" "main" {
  name     = "rg-${local.name_prefix}"
  location = var.location
  tags     = local.common_tags
}

removed {
  from = azurerm_resource_group.main

  lifecycle {
    destroy = false
  }
}
