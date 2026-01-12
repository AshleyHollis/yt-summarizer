# =============================================================================
# Terraform Providers Configuration
# =============================================================================
# Defines all required providers for Azure infrastructure management

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.85"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.47"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.24"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

# Azure Resource Manager provider
provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = false
      recover_soft_deleted_key_vaults = true
    }
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }

  # Uses Azure CLI or OIDC authentication
  # In GitHub Actions, uses federated credentials
  use_oidc = var.use_oidc
}

# Azure AD provider for OIDC and identity management
provider "azuread" {
  use_oidc = var.use_oidc
}

# Kubernetes provider - configured after AKS cluster creation
provider "kubernetes" {
  # Configuration is injected by the AKS module
  # host                   = module.aks.host
  # client_certificate     = base64decode(module.aks.client_certificate)
  # client_key             = base64decode(module.aks.client_key)
  # cluster_ca_certificate = base64decode(module.aks.cluster_ca_certificate)
}

# Helm provider for Argo CD and other Helm charts
provider "helm" {
  kubernetes {
    # Configuration is injected by the AKS module
    # host                   = module.aks.host
    # client_certificate     = base64decode(module.aks.client_certificate)
    # client_key             = base64decode(module.aks.client_key)
    # cluster_ca_certificate = base64decode(module.aks.cluster_ca_certificate)
  }
}
