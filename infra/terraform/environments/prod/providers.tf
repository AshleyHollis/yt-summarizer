# =============================================================================
# Provider Configuration for Production
# =============================================================================

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = false
    }
  }
  subscription_id = var.subscription_id
}

# Helm and Kubernetes providers will be configured after AKS is created
# using data sources to get credentials
