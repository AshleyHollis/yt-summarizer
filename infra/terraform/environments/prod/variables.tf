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
