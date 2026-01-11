# =============================================================================
# Common Terraform Variables
# =============================================================================
# Shared variables used across all environments

# -----------------------------------------------------------------------------
# Authentication
# -----------------------------------------------------------------------------

variable "use_oidc" {
  description = "Use OIDC authentication (true for GitHub Actions, false for local CLI)"
  type        = bool
  default     = false
}

# -----------------------------------------------------------------------------
# Project Configuration
# -----------------------------------------------------------------------------

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "ytsummarizer"
}

variable "environment" {
  description = "Environment name (staging, production)"
  type        = string
  validation {
    condition     = contains(["staging", "production"], var.environment)
    error_message = "Environment must be 'staging' or 'production'."
  }
}

variable "location" {
  description = "Azure region for resources"
  type        = string
  default     = "eastus"
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

# -----------------------------------------------------------------------------
# Networking
# -----------------------------------------------------------------------------

variable "vnet_address_space" {
  description = "Address space for the virtual network"
  type        = list(string)
  default     = ["10.0.0.0/16"]
}

variable "aks_subnet_prefix" {
  description = "Subnet prefix for AKS nodes"
  type        = string
  default     = "10.0.1.0/24"
}

# -----------------------------------------------------------------------------
# AKS Configuration
# -----------------------------------------------------------------------------

variable "aks_node_size" {
  description = "VM size for AKS nodes"
  type        = string
  default     = "Standard_B4als_v2"  # 4 vCPUs, 8GB RAM, ~$97/month
}

variable "aks_node_count" {
  description = "Number of AKS nodes (single-node for cost savings)"
  type        = number
  default     = 1
}

variable "kubernetes_version" {
  description = "Kubernetes version for AKS"
  type        = string
  default     = "1.28"
}

# -----------------------------------------------------------------------------
# Container Registry
# -----------------------------------------------------------------------------

variable "acr_sku" {
  description = "SKU for Azure Container Registry"
  type        = string
  default     = "Basic"  # ~$5/month
}

# -----------------------------------------------------------------------------
# SQL Database
# -----------------------------------------------------------------------------

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

variable "sql_sku_name" {
  description = "SQL Database SKU (serverless for cost savings)"
  type        = string
  default     = "GP_S_Gen5_1"  # Serverless General Purpose
}

# -----------------------------------------------------------------------------
# Static Web App
# -----------------------------------------------------------------------------

variable "swa_sku_tier" {
  description = "SKU tier for Static Web Apps"
  type        = string
  default     = "Free"
}

variable "swa_sku_size" {
  description = "SKU size for Static Web Apps"
  type        = string
  default     = "Free"
}

# -----------------------------------------------------------------------------
# Key Vault
# -----------------------------------------------------------------------------

variable "key_vault_sku" {
  description = "SKU for Azure Key Vault"
  type        = string
  default     = "standard"
}

# -----------------------------------------------------------------------------
# GitHub Repository (for OIDC)
# -----------------------------------------------------------------------------

variable "github_repository" {
  description = "GitHub repository in format owner/repo"
  type        = string
  default     = "AshleyHollis/yt-summarizer"
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

# -----------------------------------------------------------------------------
# Domain Configuration
# -----------------------------------------------------------------------------

variable "domain" {
  description = "Base domain for the application (e.g., example.com)"
  type        = string
  default     = "yt-summarizer.local"
}
