# =============================================================================
# Auth0 Configuration
# =============================================================================
# IMPORTANT: Auth0 module requires the Management API application to have:
#   - read:clients, create:clients, update:clients
#   - read:resource_servers, create:resource_servers, update:resource_servers
# Configure these scopes in Auth0 Dashboard → (Terraform M2M App) → APIs → Auth0 Management API

# -----------------------------------------------------------------------------
# Generate random session secret for Auth0 BFF
# -----------------------------------------------------------------------------
resource "random_password" "auth0_session_secret" {
  length  = 32
  special = true
}

# -----------------------------------------------------------------------------
# Create Auth0 Application and API
# -----------------------------------------------------------------------------
module "auth0" {
  count  = var.enable_auth0 ? 1 : 0
  source = "../../modules/auth0"

  auth0_domain          = var.auth0_domain
  application_name      = var.auth0_application_name
  api_name              = var.auth0_api_name
  api_identifier        = var.auth0_api_identifier
  allowed_callback_urls = var.auth0_allowed_callback_urls
  allowed_logout_urls   = var.auth0_allowed_logout_urls
  allowed_web_origins   = var.auth0_allowed_web_origins
}

# -----------------------------------------------------------------------------
# Store Auth0 BFF Credentials in Azure Key Vault
# -----------------------------------------------------------------------------
# IMPORTANT: These are the credentials for the BFF application (NOT the Terraform service account)
# These credentials will be synced to Kubernetes via ExternalSecret for runtime use

resource "azurerm_key_vault_secret" "auth0_domain" {
  count        = var.enable_auth0 ? 1 : 0
  name         = "auth0-domain"
  value        = module.auth0[0].auth0_domain
  key_vault_id = module.key_vault.id

  depends_on = [module.key_vault]
}

resource "azurerm_key_vault_secret" "auth0_client_id" {
  count        = var.enable_auth0 ? 1 : 0
  name         = "auth0-client-id"
  value        = module.auth0[0].application_client_id
  key_vault_id = module.key_vault.id

  depends_on = [module.key_vault]
}

resource "azurerm_key_vault_secret" "auth0_client_secret" {
  count        = var.enable_auth0 ? 1 : 0
  name         = "auth0-client-secret"
  value        = module.auth0[0].application_client_secret
  key_vault_id = module.key_vault.id

  depends_on = [module.key_vault]
}

resource "azurerm_key_vault_secret" "auth0_session_secret" {
  count        = var.enable_auth0 ? 1 : 0
  name         = "auth0-session-secret"
  value        = random_password.auth0_session_secret.result
  key_vault_id = module.key_vault.id

  depends_on = [module.key_vault]
}

