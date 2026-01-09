# =============================================================================
# External Secrets Operator Module
# =============================================================================
# Deploys External Secrets Operator to AKS for Key Vault integration

terraform {
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.12"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.24"
    }
  }
}

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

variable "namespace" {
  description = "Kubernetes namespace for External Secrets Operator"
  type        = string
  default     = "external-secrets"
}

variable "create_namespace" {
  description = "Create the namespace if it doesn't exist"
  type        = bool
  default     = true
}

variable "chart_version" {
  description = "Helm chart version for external-secrets"
  type        = string
  default     = "0.9.11"
}

variable "values" {
  description = "Additional Helm values"
  type        = list(string)
  default     = []
}

variable "key_vault_name" {
  description = "Name of the Azure Key Vault"
  type        = string
  default     = ""
}

variable "tenant_id" {
  description = "Azure AD Tenant ID"
  type        = string
  default     = ""
}

variable "client_id" {
  description = "Client ID for workload identity"
  type        = string
  default     = ""
}

variable "app_namespace" {
  description = "Namespace for the application"
  type        = string
  default     = "yt-summarizer"
}

# -----------------------------------------------------------------------------
# Resources
# -----------------------------------------------------------------------------

resource "helm_release" "external_secrets" {
  name             = "external-secrets"
  repository       = "https://charts.external-secrets.io"
  chart            = "external-secrets"
  version          = var.chart_version
  namespace        = var.namespace
  create_namespace = var.create_namespace

  # Install CRDs
  set {
    name  = "installCRDs"
    value = "true"
  }

  # Resource limits for cost-constrained environment
  set {
    name  = "resources.requests.cpu"
    value = "50m"
  }

  set {
    name  = "resources.requests.memory"
    value = "64Mi"
  }

  set {
    name  = "resources.limits.cpu"
    value = "100m"
  }

  set {
    name  = "resources.limits.memory"
    value = "128Mi"
  }

  # Webhook configuration
  set {
    name  = "webhook.resources.requests.cpu"
    value = "25m"
  }

  set {
    name  = "webhook.resources.requests.memory"
    value = "32Mi"
  }

  # Add custom values
  values = var.values
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "namespace" {
  description = "Namespace where External Secrets Operator is installed"
  value       = var.namespace
}

output "release_name" {
  description = "Name of the Helm release"
  value       = helm_release.external_secrets.name
}
