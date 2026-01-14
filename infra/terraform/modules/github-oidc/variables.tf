# =============================================================================
# GitHub Actions OIDC Module - Variables
# =============================================================================

variable "application_name" {
  description = "Name of the Azure AD application for GitHub Actions"
  type        = string
  default     = "github-actions-yt-summarizer"
}

variable "github_organization" {
  description = "GitHub organization or username"
  type        = string
}

variable "github_repository" {
  description = "GitHub repository name"
  type        = string
}

variable "assign_contributor_role" {
  description = "Whether to assign Contributor role on subscription"
  type        = bool
  default     = true
}

variable "acr_id" {
  description = "Azure Container Registry resource ID for AcrPush role assignment"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
