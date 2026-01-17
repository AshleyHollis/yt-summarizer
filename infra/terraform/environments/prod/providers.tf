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

provider "auth0" {
  # Uses AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET environment variables.
}

# Helm and Kubernetes providers will be configured after AKS is created
# using data sources to get credentials

