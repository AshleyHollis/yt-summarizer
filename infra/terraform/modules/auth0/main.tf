# =============================================================================
# Auth0 Module
# =============================================================================
# Configures Auth0 application and optional API resource server.

terraform {
  required_providers {
    auth0 = {
      source  = "auth0/auth0"
      version = ">= 1.0"
    }
  }
}

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

variable "auth0_domain" {
  description = "Auth0 tenant domain (e.g., yourapp.us.auth0.com)"
  type        = string
}

variable "application_name" {
  description = "Auth0 application name for the API BFF"
  type        = string
  default     = "yt-summarizer-api-bff"
}

variable "api_name" {
  description = "Auth0 API name (resource server)"
  type        = string
  default     = "YT Summarizer API"
}

variable "api_identifier" {
  description = "Auth0 API identifier (audience). Leave empty to skip creation."
  type        = string
  default     = ""
}

variable "allowed_callback_urls" {
  description = "Allowed Auth0 callback URLs"
  type        = list(string)
  default     = []
}

variable "allowed_logout_urls" {
  description = "Allowed Auth0 logout URLs"
  type        = list(string)
  default     = []
}

variable "allowed_web_origins" {
  description = "Allowed Auth0 web origins"
  type        = list(string)
  default     = []
}

# T009: Connection support
variable "enable_database_connection" {
  description = "Enable Auth0 database connection for username/password auth"
  type        = bool
  default     = false
}

variable "enable_google_connection" {
  description = "Enable Google OAuth connection"
  type        = bool
  default     = false
}

variable "google_client_id" {
  description = "Google OAuth client ID"
  type        = string
  default     = ""
  sensitive   = true
}

variable "google_client_secret" {
  description = "Google OAuth client secret"
  type        = string
  default     = ""
  sensitive   = true
}

variable "enable_github_connection" {
  description = "Enable GitHub OAuth connection"
  type        = bool
  default     = false
}

variable "github_client_id" {
  description = "GitHub OAuth client ID"
  type        = string
  default     = ""
  sensitive   = true
}

variable "github_client_secret" {
  description = "GitHub OAuth client secret"
  type        = string
  default     = ""
  sensitive   = true
}

# T010: User support
variable "test_users" {
  description = "List of test users to create"
  type = list(object({
    email          = string
    password       = string
    email_verified = bool
    role           = string # 'admin' or 'normal'
  }))
  default = []
  # Note: Not marked sensitive here to allow for_each iteration
  # Individual resource attributes (password) are marked sensitive instead
}

# T011: Action support
variable "enable_role_action" {
  description = "Enable Auth0 Action to add role claims to tokens"
  type        = bool
  default     = false
}

# -----------------------------------------------------------------------------
# Resources
# -----------------------------------------------------------------------------

# T009: Database connection (username/password)
resource "auth0_connection" "database" {
  count = var.enable_database_connection ? 1 : 0

  name     = "Username-Password-Authentication"
  strategy = "auth0"

  options {
    password_policy = "good"
    password_history {
      enable = true
      size   = 5
    }
    password_no_personal_info {
      enable = true
    }
    password_dictionary {
      enable = true
    }
    brute_force_protection         = true
    enabled_database_customization = false
  }
}

# T009: Enable database connection for BFF client
resource "auth0_connection_clients" "database_clients" {
  count = var.enable_database_connection ? 1 : 0

  connection_id   = auth0_connection.database[0].id
  enabled_clients = [auth0_client.bff.id]
}

# T009: Google OAuth connection
resource "auth0_connection" "google" {
  count = var.enable_google_connection ? 1 : 0

  name     = "google-oauth2"
  strategy = "google-oauth2"

  options {
    client_id     = var.google_client_id
    client_secret = var.google_client_secret
    scopes        = ["email", "profile"]
  }
}

# T009: Enable Google connection for BFF client
resource "auth0_connection_clients" "google_clients" {
  count = var.enable_google_connection ? 1 : 0

  connection_id   = auth0_connection.google[0].id
  enabled_clients = [auth0_client.bff.id]
}

# T009: GitHub OAuth connection
resource "auth0_connection" "github" {
  count = var.enable_github_connection ? 1 : 0

  name     = "github"
  strategy = "github"

  options {
    client_id     = var.github_client_id
    client_secret = var.github_client_secret
    scopes        = ["user:email", "read:user"]
  }
}

# T009: Enable GitHub connection for BFF client
resource "auth0_connection_clients" "github_clients" {
  count = var.enable_github_connection ? 1 : 0

  connection_id   = auth0_connection.github[0].id
  enabled_clients = [auth0_client.bff.id]
}

resource "auth0_client" "bff" {
  name     = var.application_name
  app_type = "regular_web"

  callbacks           = var.allowed_callback_urls
  allowed_logout_urls = var.allowed_logout_urls
  allowed_origins     = var.allowed_web_origins
  web_origins         = var.allowed_web_origins
  oidc_conformant     = true

  grant_types = [
    "authorization_code",
    "refresh_token",
  ]
}

# Retrieve the client credentials (including client_secret)
# The auth0_client_credentials resource retrieves the secret after creation
resource "auth0_client_credentials" "bff" {
  client_id = auth0_client.bff.id

  authentication_method = "client_secret_post"
}

resource "auth0_resource_server" "api" {
  count = var.api_identifier != "" ? 1 : 0

  name                 = var.api_name
  identifier           = var.api_identifier
  signing_alg          = "RS256"
  allow_offline_access = true
}

# T010: Test users
resource "auth0_user" "test_user" {
  for_each = { for idx, user in var.test_users : idx => user }

  connection_name = var.enable_database_connection ? auth0_connection.database[0].name : null
  email           = each.value.email
  password        = sensitive(each.value.password)
  email_verified  = each.value.email_verified

  app_metadata = jsonencode({
    role = each.value.role
  })

  # Ensure database connection is enabled for the BFF client before creating users
  depends_on = [
    auth0_connection.database,
    auth0_connection_clients.database_clients
  ]

  lifecycle {
    ignore_changes = [password]
  }
}

# T011: Action to add role claims to tokens
resource "auth0_action" "add_role_claims" {
  count = var.enable_role_action ? 1 : 0

  name    = "Add Role Claims to Tokens"
  runtime = "node18"
  deploy  = true

  supported_triggers {
    id      = "post-login"
    version = "v3"
  }

  code = <<-EOT
    /**
     * Handler that will be called during the execution of a PostLogin flow.
     *
     * @param {Event} event - Details about the user and the context in which they are logging in.
     * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
     */
    exports.onExecutePostLogin = async (event, api) => {
      const namespace = 'https://yt-summarizer.com/';

      if (event.user.app_metadata && event.user.app_metadata.role) {
        const role = event.user.app_metadata.role;

        // Add role to ID token
        api.idToken.setCustomClaim(`$${namespace}role`, role);

        // Add role to access token
        api.accessToken.setCustomClaim(`$${namespace}role`, role);
      }
    };
  EOT
}

# T011: Bind action to post-login trigger
resource "auth0_trigger_action" "add_role_claims_binding" {
  count = var.enable_role_action ? 1 : 0

  trigger      = "post-login"
  action_id    = auth0_action.add_role_claims[0].id
  display_name = "Add Role Claims to Tokens"
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "auth0_domain" {
  description = "Auth0 tenant domain"
  value       = var.auth0_domain
}

output "application_client_id" {
  description = "Auth0 application client ID"
  value       = auth0_client.bff.client_id
}

output "application_client_secret" {
  description = "Auth0 application client secret"
  value       = auth0_client_credentials.bff.client_secret
  sensitive   = true
}

output "application_name" {
  description = "Auth0 application name"
  value       = auth0_client.bff.name
}

output "api_identifier" {
  description = "Auth0 API identifier (audience)"
  value       = var.api_identifier != "" ? auth0_resource_server.api[0].identifier : null
}
