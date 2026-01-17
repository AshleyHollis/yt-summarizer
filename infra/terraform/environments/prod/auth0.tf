# =============================================================================
# Auth0 Configuration
# =============================================================================

module "auth0" {
  source = "../../modules/auth0"

  application_name      = var.auth0_application_name
  api_name              = var.auth0_api_name
  api_identifier        = var.auth0_api_identifier
  allowed_callback_urls = var.auth0_allowed_callback_urls
  allowed_logout_urls   = var.auth0_allowed_logout_urls
  allowed_web_origins   = var.auth0_allowed_web_origins
}
