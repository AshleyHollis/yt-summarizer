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

# -----------------------------------------------------------------------------
# Resources
# -----------------------------------------------------------------------------

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
