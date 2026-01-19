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

resource "random_password" "auth0_preview_session_secret" {
  length  = 32
  special = true
}

# -----------------------------------------------------------------------------
# T044-T045: Generate random passwords for test users
# -----------------------------------------------------------------------------
resource "random_password" "admin_test_password" {
  length  = 24
  special = true
  lower   = true
  upper   = true
  numeric = true
}

resource "random_password" "normal_test_password" {
  length  = 24
  special = true
  lower   = true
  upper   = true
  numeric = true
}

# -----------------------------------------------------------------------------
# Create Auth0 Application and API (Production)
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

  # T012: Connection configuration
  enable_database_connection = var.enable_auth0_database_connection
  terraform_client_id        = var.auth0_terraform_client_id
  enable_google_connection   = var.enable_auth0_google_connection
  google_client_id           = var.auth0_google_client_id
  google_client_secret       = var.auth0_google_client_secret
  enable_github_connection   = var.enable_auth0_github_connection
  github_client_id           = var.auth0_github_client_id
  github_client_secret       = var.auth0_github_client_secret

  # T012: User and role configuration (T044-T045: Use generated passwords)
  test_users = [
    {
      email          = "admin@test.yt-summarizer.internal"
      password       = random_password.admin_test_password.result
      email_verified = true
      role           = "admin"
    },
    {
      email          = "user@test.yt-summarizer.internal"
      password       = random_password.normal_test_password.result
      email_verified = true
      role           = "user"
    }
  ]
  enable_role_action = var.enable_auth0_role_action
}

# -----------------------------------------------------------------------------
# Create Auth0 Application for Preview Environments
# -----------------------------------------------------------------------------
module "auth0_preview" {
  count  = var.enable_auth0 ? 1 : 0
  source = "../../modules/auth0"

  auth0_domain          = var.auth0_domain
  application_name      = "${var.auth0_application_name}-preview"
  api_name              = "${var.auth0_api_name} (Preview)"
  api_identifier        = var.auth0_preview_api_identifier
  allowed_callback_urls = var.auth0_preview_allowed_callback_urls
  allowed_logout_urls   = var.auth0_preview_allowed_logout_urls
  allowed_web_origins   = var.auth0_preview_allowed_web_origins

  # T012: Share connections with production (don't create duplicates)
  # Connections are tenant-level resources, so we only create them once in prod module
  enable_database_connection = false
  enable_google_connection   = false
  enable_github_connection   = false

  # T012: No test users or actions for preview app (share with prod)
  test_users         = []
  enable_role_action = false
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

# -----------------------------------------------------------------------------
# Store Preview Auth0 BFF Credentials in Azure Key Vault
# -----------------------------------------------------------------------------
# These credentials are used by preview environments (preview-pr-* namespaces)
# Shared by all preview environments to avoid creating individual apps per PR

resource "azurerm_key_vault_secret" "auth0_preview_domain" {
  count        = var.enable_auth0 ? 1 : 0
  name         = "auth0-preview-domain"
  value        = module.auth0_preview[0].auth0_domain
  key_vault_id = module.key_vault.id

  depends_on = [module.key_vault]
}

resource "azurerm_key_vault_secret" "auth0_preview_client_id" {
  count        = var.enable_auth0 ? 1 : 0
  name         = "auth0-preview-client-id"
  value        = module.auth0_preview[0].application_client_id
  key_vault_id = module.key_vault.id

  depends_on = [module.key_vault]
}

resource "azurerm_key_vault_secret" "auth0_preview_client_secret" {
  count        = var.enable_auth0 ? 1 : 0
  name         = "auth0-preview-client-secret"
  value        = module.auth0_preview[0].application_client_secret
  key_vault_id = module.key_vault.id

  depends_on = [module.key_vault]
}

resource "azurerm_key_vault_secret" "auth0_preview_session_secret" {
  count        = var.enable_auth0 ? 1 : 0
  name         = "auth0-preview-session-secret"
  value        = random_password.auth0_preview_session_secret.result
  key_vault_id = module.key_vault.id

  depends_on = [module.key_vault]
}

# -----------------------------------------------------------------------------
# T046-T047: Store Test User Credentials in Azure Key Vault
# -----------------------------------------------------------------------------
# These credentials are used by E2E tests for programmatic authentication
# IMPORTANT: Test user emails use .internal domain to avoid conflicts

resource "azurerm_key_vault_secret" "auth0_admin_test_email" {
  count        = var.enable_auth0 ? 1 : 0
  name         = "auth0-admin-test-email"
  value        = "admin@test.yt-summarizer.internal"
  key_vault_id = module.key_vault.id

  depends_on = [module.key_vault]
}

resource "azurerm_key_vault_secret" "auth0_admin_test_password" {
  count        = var.enable_auth0 ? 1 : 0
  name         = "auth0-admin-test-password"
  value        = random_password.admin_test_password.result
  key_vault_id = module.key_vault.id

  depends_on = [module.key_vault]
}

resource "azurerm_key_vault_secret" "auth0_user_test_email" {
  count        = var.enable_auth0 ? 1 : 0
  name         = "auth0-user-test-email"
  value        = "user@test.yt-summarizer.internal"
  key_vault_id = module.key_vault.id

  depends_on = [module.key_vault]
}

resource "azurerm_key_vault_secret" "auth0_user_test_password" {
  count        = var.enable_auth0 ? 1 : 0
  name         = "auth0-user-test-password"
  value        = random_password.normal_test_password.result
  key_vault_id = module.key_vault.id

  depends_on = [module.key_vault]
}
