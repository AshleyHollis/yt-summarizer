# =============================================================================
# Argo CD Module
# =============================================================================
# Installs Argo CD via Helm into the AKS cluster

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
  description = "Kubernetes namespace for Argo CD"
  type        = string
  default     = "argocd"
}

variable "chart_version" {
  description = "Argo CD Helm chart version"
  type        = string
  default     = "5.51.6"  # Matches Argo CD v2.9.x
}

variable "admin_password_hash" {
  description = "Bcrypt hash of admin password (generate with: htpasswd -nbBC 10 '' $PASSWORD | tr -d ':')"
  type        = string
  default     = null
  sensitive   = true
}

variable "ingress_enabled" {
  description = "Enable ingress for Argo CD server"
  type        = bool
  default     = true
}

variable "ingress_host" {
  description = "Hostname for Argo CD ingress"
  type        = string
  default     = ""
}

variable "ingress_class" {
  description = "Ingress class to use"
  type        = string
  default     = "nginx"
}

variable "ingress_tls_enabled" {
  description = "Enable TLS for ingress"
  type        = bool
  default     = true
}

variable "ingress_tls_secret" {
  description = "TLS secret name for ingress"
  type        = string
  default     = "argocd-tls"
}

variable "github_org" {
  description = "GitHub organization for OIDC authentication"
  type        = string
  default     = ""
}

variable "github_repo" {
  description = "GitHub repository for GitOps"
  type        = string
  default     = ""
}

variable "github_ssh_private_key" {
  description = "SSH private key for GitHub repository access"
  type        = string
  default     = ""
  sensitive   = true
}

variable "server_resources" {
  description = "Resource limits for Argo CD server"
  type = object({
    requests_cpu    = string
    requests_memory = string
    limits_cpu      = string
    limits_memory   = string
  })
  default = {
    requests_cpu    = "50m"
    requests_memory = "128Mi"
    limits_cpu      = "200m"
    limits_memory   = "256Mi"
  }
}

# -----------------------------------------------------------------------------
# Resources
# -----------------------------------------------------------------------------

resource "kubernetes_namespace" "argocd" {
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }
}

resource "helm_release" "argocd" {
  name       = "argocd"
  repository = "https://argoproj.github.io/argo-helm"
  chart      = "argo-cd"
  version    = var.chart_version
  namespace  = kubernetes_namespace.argocd.metadata[0].name

  # Core settings
  set {
    name  = "global.image.tag"
    value = "v2.9.5"
  }

  # Server configuration - resource optimized for single-node
  set {
    name  = "server.resources.requests.cpu"
    value = var.server_resources.requests_cpu
  }
  set {
    name  = "server.resources.requests.memory"
    value = var.server_resources.requests_memory
  }
  set {
    name  = "server.resources.limits.cpu"
    value = var.server_resources.limits_cpu
  }
  set {
    name  = "server.resources.limits.memory"
    value = var.server_resources.limits_memory
  }

  # Disable HA for single-node cluster
  set {
    name  = "controller.replicas"
    value = "1"
  }
  set {
    name  = "server.replicas"
    value = "1"
  }
  set {
    name  = "repoServer.replicas"
    value = "1"
  }
  set {
    name  = "applicationSet.replicas"
    value = "1"
  }
  set {
    name  = "redis.enabled"
    value = "true"
  }
  set {
    name  = "redis-ha.enabled"
    value = "false"
  }

  # Ingress configuration
  dynamic "set" {
    for_each = var.ingress_enabled ? [1] : []
    content {
      name  = "server.ingress.enabled"
      value = "true"
    }
  }
  dynamic "set" {
    for_each = var.ingress_enabled && var.ingress_host != "" ? [1] : []
    content {
      name  = "server.ingress.hosts[0]"
      value = var.ingress_host
    }
  }
  dynamic "set" {
    for_each = var.ingress_enabled ? [1] : []
    content {
      name  = "server.ingress.ingressClassName"
      value = var.ingress_class
    }
  }
  dynamic "set" {
    for_each = var.ingress_enabled && var.ingress_tls_enabled ? [1] : []
    content {
      name  = "server.ingress.tls[0].secretName"
      value = var.ingress_tls_secret
    }
  }
  dynamic "set" {
    for_each = var.ingress_enabled && var.ingress_tls_enabled && var.ingress_host != "" ? [1] : []
    content {
      name  = "server.ingress.tls[0].hosts[0]"
      value = var.ingress_host
    }
  }

  # Admin password (if provided)
  dynamic "set_sensitive" {
    for_each = var.admin_password_hash != null ? [1] : []
    content {
      name  = "configs.secret.argocdServerAdminPassword"
      value = var.admin_password_hash
    }
  }

  # Insecure mode for internal access (TLS termination at ingress)
  set {
    name  = "server.extraArgs[0]"
    value = "--insecure"
  }

  depends_on = [kubernetes_namespace.argocd]
}

# GitHub repository secret (if SSH key provided)
resource "kubernetes_secret" "github_repo" {
  count = var.github_ssh_private_key != "" ? 1 : 0

  metadata {
    name      = "github-repo"
    namespace = kubernetes_namespace.argocd.metadata[0].name
    labels = {
      "argocd.argoproj.io/secret-type" = "repository"
    }
  }

  data = {
    type          = "git"
    url           = "git@github.com:${var.github_org}/${var.github_repo}.git"
    sshPrivateKey = var.github_ssh_private_key
  }

  depends_on = [helm_release.argocd]
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "namespace" {
  description = "Namespace where Argo CD is installed"
  value       = kubernetes_namespace.argocd.metadata[0].name
}

output "server_service" {
  description = "Argo CD server service name"
  value       = "argocd-server"
}

output "helm_release_name" {
  description = "Name of the Helm release"
  value       = helm_release.argocd.name
}

output "chart_version" {
  description = "Version of the Argo CD Helm chart"
  value       = helm_release.argocd.version
}
