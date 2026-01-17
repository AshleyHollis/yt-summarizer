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

variable "acr_sku" {
  description = "SKU for Azure Container Registry"
  type        = string
  default     = "Basic"
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

variable "kubernetes_version" {
  description = "Kubernetes version for AKS"
  type        = string
  default     = "1.33"
}

variable "aks_node_size" {
  description = "VM size for AKS nodes"
  type        = string
  default     = "Standard_B4als_v2" # 4 vCPUs, 8GB RAM, 100 max pods
}

variable "aks_os_disk_size_gb" {
  description = "OS disk size for AKS nodes in GB"
  type        = number
  default     = 128
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
# Auth0
# -----------------------------------------------------------------------------

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
    "https://api.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0",
    "https://api-stg.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0",
    "https://api-pr-*.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0",
  ]
}

variable "auth0_allowed_logout_urls" {
  description = "Allowed Auth0 logout URLs for the BFF"
  type        = list(string)
  default = [
    "https://web.yt-summarizer.apps.ashleyhollis.com",
    "https://web-stg.yt-summarizer.apps.ashleyhollis.com",
    "https://*.azurestaticapps.net",
  ]
}

variable "auth0_allowed_web_origins" {
  description = "Allowed Auth0 web origins for CORS/session flows"
  type        = list(string)
  default = [
    "https://web.yt-summarizer.apps.ashleyhollis.com",
    "https://web-stg.yt-summarizer.apps.ashleyhollis.com",
    "https://*.azurestaticapps.net",
  ]
}
