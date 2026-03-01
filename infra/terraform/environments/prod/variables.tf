# =============================================================================
# Variables for Production Environment
# =============================================================================

variable "subscription_id" {
  description = "Azure subscription ID"
  type        = string
}

variable "location" {
  description = "Azure region for resources"
  type        = string
  default     = "eastasia"
}

variable "sql_admin_username" {
  description = "SQL Server admin username"
  type        = string
  default     = "sqladmin"
}

variable "sql_admin_password" {
  description = "SQL Server admin password"
  type        = string
  sensitive   = true
}

variable "key_vault_secrets_officer_principal_id" {
  description = "Principal ID with Key Vault Secrets Officer access"
  type        = string
  default     = "eac9556a-cd81-431f-a1ec-d6940b2d92d3"
}

variable "domain" {
  description = "Base domain for the application"
  type        = string
  default     = "yt-summarizer.example.com"
}


variable "github_org" {
  description = "GitHub organization/owner name"
  type        = string
  default     = "AshleyHollis"
}

variable "github_repo" {
  description = "GitHub repository name"
  type        = string
  default     = "yt-summarizer"
}

variable "openai_api_key" {
  description = "OpenAI API key for summarization"
  type        = string
  sensitive   = true
}

variable "cloudflare_api_token" {
  description = "Cloudflare API token for DNS-01 challenges"
  type        = string
  sensitive   = true
}

# -----------------------------------------------------------------------------
# Webshare Rotating Residential Proxy
# -----------------------------------------------------------------------------

variable "webshare_proxy_username" {
  description = "Webshare rotating residential proxy username (sourced from Webshare dashboard)"
  type        = string
  sensitive   = false
  default     = ""
}

variable "webshare_proxy_password" {
  description = "Webshare rotating residential proxy password (sourced from Webshare dashboard)"
  type        = string
  sensitive   = true
  default     = ""
}

# -----------------------------------------------------------------------------
# Auth0
# -----------------------------------------------------------------------------

variable "auth0_domain" {
  description = "Auth0 tenant domain (e.g., yourapp.us.auth0.com). Read from AUTH0_DOMAIN environment variable."
  type        = string
  default     = ""
}

variable "auth0_terraform_client_id" {
  description = "Auth0 Terraform service account client ID (for enabling connection access)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "enable_auth0" {
  description = "Enable Auth0 resources (requires proper Auth0 Management API permissions)"
  type        = bool
  default     = true
}

variable "auth0_application_name" {
  description = "Auth0 application name for the API BFF"
  type        = string
  default     = "yt-summarizer-api-bff"
}

variable "auth0_api_name" {
  description = "Auth0 API name (resource server)"
  type        = string
  default     = "YT Summarizer API"
}

variable "auth0_api_identifier" {
  description = "Auth0 API identifier (audience)"
  type        = string
  default     = "https://api.yt-summarizer.apps.ashleyhollis.com"
}

variable "auth0_allowed_callback_urls" {
  description = "Allowed Auth0 callback URLs for the BFF"
  type        = list(string)
  default = [
    "https://api.yt-summarizer.apps.ashleyhollis.com/api/auth/callback",
    "https://api.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0",
    "https://api-stg.yt-summarizer.apps.ashleyhollis.com/api/auth/callback",
    "https://api-stg.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0",
    "https://api-pr-*.yt-summarizer.apps.ashleyhollis.com/api/auth/callback",
    "https://api-pr-*.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0",
    # Azure Static Web Apps (Next.js @auth0/nextjs-auth0)
    "https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net/api/auth/callback",
    "http://localhost:3000/api/auth/callback",
  ]
}

variable "auth0_allowed_logout_urls" {
  description = "Allowed Auth0 logout URLs for the BFF"
  type        = list(string)
  default = [
    "https://web.yt-summarizer.apps.ashleyhollis.com",
    "https://web-stg.yt-summarizer.apps.ashleyhollis.com",
    "https://*.azurestaticapps.net",
    "http://localhost:3000",
  ]
}

variable "auth0_allowed_web_origins" {
  description = "Allowed Auth0 web origins for CORS/session flows"
  type        = list(string)
  default = [
    "https://web.yt-summarizer.apps.ashleyhollis.com",
    "https://web-stg.yt-summarizer.apps.ashleyhollis.com",
    "https://*.azurestaticapps.net",
    "http://localhost:3000",
  ]
}

# -----------------------------------------------------------------------------
# Preview Auth0 Application Variables
# -----------------------------------------------------------------------------
# Preview environments share a single Auth0 application to avoid creating
# individual apps per PR. Wildcards in URLs allow all preview-pr-* namespaces.

variable "auth0_preview_api_identifier" {
  description = "Auth0 API identifier for preview environments (leave empty to skip API creation)"
  type        = string
  default     = "" # Preview environments don't need a separate API resource server
}

variable "auth0_preview_allowed_callback_urls" {
  description = "Allowed Auth0 callback URLs for preview environments"
  type        = list(string)
  default = [
    "https://api-pr-*.yt-summarizer.apps.ashleyhollis.com/api/auth/callback",
    "https://api-pr-*.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0",
    "https://*.azurestaticapps.net/api/auth/callback",
  ]
}

variable "auth0_preview_allowed_logout_urls" {
  description = "Allowed Auth0 logout URLs for preview environments"
  type        = list(string)
  default = [
    "https://*.azurestaticapps.net",
  ]
}

variable "auth0_preview_allowed_web_origins" {
  description = "Allowed Auth0 web origins for preview environments"
  type        = list(string)
  default = [
    "https://*.azurestaticapps.net",
  ]
}

# -----------------------------------------------------------------------------
# T012: Auth0 Connections and Test Users
# -----------------------------------------------------------------------------

variable "enable_auth0_database_connection" {
  description = "Enable Auth0 database connection for username/password auth"
  type        = bool
  default     = true
}

variable "enable_auth0_google_connection" {
  description = "Enable Google OAuth connection"
  type        = bool
  default     = true
}

variable "auth0_google_client_id" {
  description = "Google OAuth client ID (from Azure Key Vault)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "auth0_google_client_secret" {
  description = "Google OAuth client secret (from Azure Key Vault)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "enable_auth0_github_connection" {
  description = "Enable GitHub OAuth connection"
  type        = bool
  default     = true
}

variable "auth0_github_client_id" {
  description = "GitHub OAuth client ID (from Azure Key Vault)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "auth0_github_client_secret" {
  description = "GitHub OAuth client secret (from Azure Key Vault)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "enable_auth0_role_action" {
  description = "Enable Auth0 Action to add role claims to tokens"
  type        = bool
  default     = true
}

variable "auth0_test_users" {
  description = "Map of test users to create in Auth0 (key = email address)"
  type = map(object({
    password       = string
    email_verified = bool
    role           = string # 'admin' or 'normal'
  }))
  default   = {}
  sensitive = true
  # NOTE: Using sensitive = true with nonsensitive() in for_each allows proper protection
  # Map keys (emails) are exposed as resource IDs, values (passwords) stay protected
}
