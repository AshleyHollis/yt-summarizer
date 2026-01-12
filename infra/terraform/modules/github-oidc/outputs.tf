# =============================================================================
# GitHub Actions OIDC Module - Outputs
# =============================================================================

output "application_id" {
  description = "Azure AD Application (Client) ID - use as AZURE_CLIENT_ID in GitHub secrets"
  value       = azuread_application.github_actions.client_id
  sensitive   = false
}

output "tenant_id" {
  description = "Azure AD Tenant ID - use as AZURE_TENANT_ID in GitHub secrets"
  value       = data.azurerm_client_config.current.tenant_id
  sensitive   = false
}

output "subscription_id" {
  description = "Azure Subscription ID - use as AZURE_SUBSCRIPTION_ID in GitHub secrets"
  value       = data.azurerm_subscription.current.subscription_id
  sensitive   = false
}

output "service_principal_object_id" {
  description = "Service principal object ID for role assignments"
  value       = azuread_service_principal.github_actions.object_id
  sensitive   = false
}

output "federated_credentials" {
  description = "List of federated credential subjects"
  value = {
    main        = azuread_application_federated_identity_credential.main.subject
    pull_request = azuread_application_federated_identity_credential.pull_request.subject
    production  = azuread_application_federated_identity_credential.production.subject
    repository  = azuread_application_federated_identity_credential.repository.subject
  }
}

output "github_secrets" {
  description = "GitHub secrets configuration (for documentation)"
  value = {
    AZURE_CLIENT_ID       = azuread_application.github_actions.client_id
    AZURE_TENANT_ID       = data.azurerm_client_config.current.tenant_id
    AZURE_SUBSCRIPTION_ID = data.azurerm_subscription.current.subscription_id
  }
  sensitive = false
}
