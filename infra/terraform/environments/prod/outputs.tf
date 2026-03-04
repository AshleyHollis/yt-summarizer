# =============================================================================
# Outputs
# =============================================================================

output "swa_hostname" {
  value = module.swa.default_host_name
}

output "swa_api_key" {
  value     = module.swa.api_key
  sensitive = true
}

output "sql_server_fqdn" {
  value = module.sql.server_fqdn
}

output "storage_primary_endpoint" {
  value = module.storage.primary_blob_endpoint
}

output "auth0_application_client_id" {
  description = "Auth0 BFF application client ID (also stored in Key Vault as 'auth0-client-id')"
  value       = var.enable_auth0 ? module.auth0[0].application_client_id : null
}

output "auth0_api_identifier" {
  description = "Auth0 API identifier (audience)"
  value       = var.enable_auth0 ? module.auth0[0].api_identifier : null
}

output "auth0_credentials_stored" {
  description = "Auth0 BFF credentials stored in Azure Key Vault"
  value = var.enable_auth0 ? {
    domain         = "Stored as: auth0-domain"
    client_id      = "Stored as: auth0-client-id"
    client_secret  = "Stored as: auth0-client-secret (sensitive)"
    session_secret = "Stored as: auth0-session-secret (sensitive)"
    note           = "These credentials are synced to Kubernetes via ExternalSecret"
  } : null
}

output "auth0_preview_application_client_id" {
  description = "Auth0 Preview BFF application client ID (shared by all preview environments)"
  value       = var.enable_auth0 ? module.auth0_preview[0].application_client_id : null
}

output "auth0_preview_credentials_stored" {
  description = "Auth0 Preview BFF credentials stored in Azure Key Vault (shared by all preview environments)"
  value = var.enable_auth0 ? {
    domain         = "Stored as: auth0-preview-domain"
    client_id      = "Stored as: auth0-preview-client-id"
    client_secret  = "Stored as: auth0-preview-client-secret (sensitive)"
    session_secret = "Stored as: auth0-preview-session-secret (sensitive)"
    note           = "These credentials are synced to Kubernetes preview namespaces via ExternalSecret"
  } : null
}
