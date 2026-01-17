# =============================================================================
# Auth0 Configuration
# =============================================================================
# IMPORTANT: Auth0 module requires the Management API application to have:
#   - read:clients, create:clients, update:clients
#   - read:resource_servers, create:resource_servers, update:resource_servers
# Configure these scopes in Auth0 Dashboard → Applications → (Terraform M2M App) → APIs → Auth0 Management API

module "auth0" {
  count  = var.enable_auth0 ? 1 : 0
  source = "../../modules/auth0"

  application_name      = var.auth0_application_name
  api_name              = var.auth0_api_name
  api_identifier        = var.auth0_api_identifier
  allowed_callback_urls = var.auth0_allowed_callback_urls
  allowed_logout_urls   = var.auth0_allowed_logout_urls
  allowed_web_origins   = var.auth0_allowed_web_origins
}
