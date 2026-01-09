# =============================================================================
# NGINX Ingress Controller Module
# =============================================================================
# Deploys NGINX Ingress Controller to AKS using Helm

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
  description = "Kubernetes namespace for the ingress controller"
  type        = string
  default     = "ingress-nginx"
}

variable "create_namespace" {
  description = "Create the namespace if it doesn't exist"
  type        = bool
  default     = true
}

variable "chart_version" {
  description = "Helm chart version for nginx-ingress"
  type        = string
  default     = "4.9.0"
}

variable "replica_count" {
  description = "Number of ingress controller replicas"
  type        = number
  default     = 1 # Single replica for cost savings
}

variable "service_annotations" {
  description = "Annotations for the LoadBalancer service"
  type        = map(string)
  default     = {}
}

variable "values" {
  description = "Additional Helm values"
  type        = list(string)
  default     = []
}

# -----------------------------------------------------------------------------
# Resources
# -----------------------------------------------------------------------------

resource "helm_release" "nginx_ingress" {
  name             = "ingress-nginx"
  repository       = "https://kubernetes.github.io/ingress-nginx"
  chart            = "ingress-nginx"
  version          = var.chart_version
  namespace        = var.namespace
  create_namespace = var.create_namespace

  set {
    name  = "controller.replicaCount"
    value = var.replica_count
  }

  # Use LoadBalancer for external access
  set {
    name  = "controller.service.type"
    value = "LoadBalancer"
  }

  # Enable metrics for observability
  set {
    name  = "controller.metrics.enabled"
    value = "true"
  }

  # Resource limits for cost-constrained environment
  set {
    name  = "controller.resources.requests.cpu"
    value = "100m"
  }

  set {
    name  = "controller.resources.requests.memory"
    value = "128Mi"
  }

  set {
    name  = "controller.resources.limits.cpu"
    value = "200m"
  }

  set {
    name  = "controller.resources.limits.memory"
    value = "256Mi"
  }

  # Add custom values
  values = var.values
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "namespace" {
  description = "Namespace where ingress controller is installed"
  value       = var.namespace
}

output "release_name" {
  description = "Name of the Helm release"
  value       = helm_release.nginx_ingress.name
}
