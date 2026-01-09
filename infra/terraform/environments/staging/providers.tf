# =============================================================================
# Provider Configuration for Staging
# =============================================================================

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"  # Upgraded from 3.85 to fix Azure ARM API 404 eventual consistency issues
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"  # Upgraded to match azurerm 4.x compatibility
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.24"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
  }
}

provider "azurerm" {
  subscription_id = "28aefbe7-e2af-4b4a-9ce1-92d6672c31bd"  # Required in azurerm 4.x
  features {
    key_vault {
      purge_soft_delete_on_destroy = false
    }
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}

provider "azuread" {}

# Kubernetes provider configured after AKS is created
# NOTE: Temporarily unconfigured for initial import
provider "kubernetes" {
  # host                   = try(module.aks.host, null)
  # client_certificate     = try(base64decode(module.aks.client_certificate), null)
  # client_key             = try(base64decode(module.aks.client_key), null)
  # cluster_ca_certificate = try(base64decode(module.aks.cluster_ca_certificate), null)
}

provider "helm" {
  # kubernetes {
  #   host                   = try(module.aks.host, null)
  #   client_certificate     = try(base64decode(module.aks.client_certificate), null)
  #   client_key             = try(base64decode(module.aks.client_key), null)
  #   cluster_ca_certificate = try(base64decode(module.aks.cluster_ca_certificate), null)
  # }
}
