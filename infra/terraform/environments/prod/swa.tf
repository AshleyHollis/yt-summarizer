# =============================================================================
# Static Web App
# =============================================================================

module "swa" {
  source = "../../modules/static-web-app"

  name                = "swa-${local.name_prefix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku_tier            = "Standard"
  sku_size            = "Standard"

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# Configure SWA Environment Variables for Auth0 (Next.js @auth0/nextjs-auth0)
# -----------------------------------------------------------------------------
# IMPORTANT: SWA environment variables are runtime settings for the Next.js app.
# They are NOT build-time variables - they are injected at request time by Azure.
# The azurerm_static_web_app resource does not support app_settings, so we use azapi.
# NOTE: We use azapi_resource_action (PUT) instead of azapi_update_resource (PATCH)
# because the SWA config/appsettings endpoint doesn't support GET or PATCH operations.

resource "azapi_resource_action" "swa_app_settings" {
  count = var.enable_auth0 ? 1 : 0

  type        = "Microsoft.Web/staticSites@2023-12-01"
  resource_id = module.swa.id
  action      = "config/appsettings"
  method      = "PUT"

  body = {
    properties = {
      AUTH0_SECRET          = azurerm_key_vault_secret.auth0_session_secret[0].value
      AUTH0_BASE_URL        = "https://${module.swa.default_host_name}"
      AUTH0_ISSUER_BASE_URL = "https://${var.auth0_domain}"
      AUTH0_CLIENT_ID       = azurerm_key_vault_secret.auth0_client_id[0].value
      AUTH0_CLIENT_SECRET   = azurerm_key_vault_secret.auth0_client_secret[0].value
    }
  }

  depends_on = [
    module.swa,
    azurerm_key_vault_secret.auth0_session_secret,
    azurerm_key_vault_secret.auth0_client_id,
    azurerm_key_vault_secret.auth0_client_secret,
  ]
}
