# =============================================================================
# Variables for Staging Environment
# =============================================================================

variable "location" {
  description = "Azure region for resources"
  type        = string
  default     = "eastasia"  # Hong Kong - closest SWA region to Australia
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
  default     = "Standard_B2s"
}

variable "domain" {
  description = "Base domain for the application"
  type        = string
  default     = "yt-summarizer.local"
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

variable "deploy_k8s" {
  description = "Whether to deploy Kubernetes resources (set to true after AKS is created)"
  type        = bool
  default     = false
}
