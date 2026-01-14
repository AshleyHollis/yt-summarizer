# =============================================================================
# GitHub Actions OIDC Module
# =============================================================================
# Creates and manages Azure AD app registration with federated credentials
# for GitHub Actions workflows to authenticate to Azure using OIDC

terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = ">= 3.7.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.85"
    }
  }
}

# -----------------------------------------------------------------------------
# Data Sources
# -----------------------------------------------------------------------------

data "azurerm_subscription" "current" {}
data "azurerm_client_config" "current" {}

# -----------------------------------------------------------------------------
# Azure AD Application
# -----------------------------------------------------------------------------

resource "azuread_application" "github_actions" {
  display_name = var.application_name
  owners       = [data.azurerm_client_config.current.object_id]

  # Convert map tags to set of strings for Azure AD
  tags = [for k, v in var.tags : "${k}:${v}"]
}

# -----------------------------------------------------------------------------
# Service Principal
# -----------------------------------------------------------------------------

resource "azuread_service_principal" "github_actions" {
  client_id = azuread_application.github_actions.client_id
  owners    = [data.azurerm_client_config.current.object_id]

  # Note: tags are inherited from the application
}

# -----------------------------------------------------------------------------
# Federated Credentials for GitHub Actions
# -----------------------------------------------------------------------------

# Main branch credential - for push events to main
resource "azuread_application_federated_identity_credential" "main" {
  application_id = azuread_application.github_actions.id
  display_name   = "github-main"
  description    = "Federated credential for GitHub Actions on main branch"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = "repo:${var.github_organization}/${var.github_repository}:ref:refs/heads/main"
}

# Pull request credential - for all PRs
resource "azuread_application_federated_identity_credential" "pull_request" {
  application_id = azuread_application.github_actions.id
  display_name   = "github-pr"
  description    = "Federated credential for GitHub Actions pull requests"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = "repo:${var.github_organization}/${var.github_repository}:pull_request"
}

# Production environment credential - for environment deployments
resource "azuread_application_federated_identity_credential" "production" {
  application_id = azuread_application.github_actions.id
  display_name   = "github-env-production"
  description    = "Federated credential for GitHub Actions production environment"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = "repo:${var.github_organization}/${var.github_repository}:environment:production"
}

# Repository-wide credential - wildcard for any workflow
resource "azuread_application_federated_identity_credential" "repository-tf" {
  application_id = azuread_application.github_actions.id
  display_name   = "github-repo"
  description    = "Federated credential for any GitHub Actions workflow in repository (managed by Terraform)"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = "repo:${var.github_organization}/${var.github_repository}:tf-managed"
}

# -----------------------------------------------------------------------------
# Role Assignments
# -----------------------------------------------------------------------------

# Contributor role on subscription (for resource management)
resource "azurerm_role_assignment" "contributor" {
  count                = var.assign_contributor_role ? 1 : 0
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Contributor"
  principal_id         = azuread_service_principal.github_actions.object_id
}

# AcrPush role on specific ACR (if provided)
resource "azurerm_role_assignment" "acr_push" {
  count                = var.acr_id != "" ? 1 : 0
  scope                = var.acr_id
  role_definition_name = "AcrPush"
  principal_id         = azuread_service_principal.github_actions.object_id
}

# Note: Key Vault permissions are provided via Contributor role at subscription level
# when RBAC authorization is enabled on the Key Vault
