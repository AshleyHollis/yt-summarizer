# =============================================================================
# Argo CD Project Configuration
# =============================================================================
# Configures Argo CD AppProject for yt-summarizer with proper RBAC

# Note: Variables github_org and github_repo are defined in main.tf

# -----------------------------------------------------------------------------
# Local Variables for Project
# -----------------------------------------------------------------------------

locals {
  argocd_namespace = var.namespace
  project_name     = "yt-summarizer"
  app_namespace    = "yt-summarizer"
  cluster_server   = "https://kubernetes.default.svc"
}

# -----------------------------------------------------------------------------
# Resources
# -----------------------------------------------------------------------------

# Argo CD AppProject - scopes what Applications can do
resource "kubernetes_manifest" "argocd_project" {
  manifest = {
    apiVersion = "argoproj.io/v1alpha1"
    kind       = "AppProject"
    metadata = {
      name      = local.project_name
      namespace = local.argocd_namespace
    }
    spec = {
      description = "yt-summarizer application project"

      # Allow applications only in the app namespace
      destinations = [
        {
          namespace = local.app_namespace
          server    = local.cluster_server
        }
      ]

      # Only allow sourcing from our repository
      sourceRepos = [
        "https://github.com/${var.github_org}/${var.github_repo}.git",
        "git@github.com:${var.github_org}/${var.github_repo}.git"
      ]

      # Cluster resource whitelist - what cluster-scoped resources can be created
      clusterResourceWhitelist = [
        {
          group = ""
          kind  = "Namespace"
        }
      ]

      # Namespace resource blacklist - prevent dangerous resources
      namespaceResourceBlacklist = [
        {
          group = ""
          kind  = "ResourceQuota"
        },
        {
          group = ""
          kind  = "LimitRange"
        },
        {
          group = "networking.k8s.io"
          kind  = "NetworkPolicy"
        }
      ]

      # Orphaned resources monitoring
      orphanedResources = {
        warn = true
      }

      # Sync windows for production (optional maintenance windows)
      syncWindows = []

      # Roles for RBAC
      roles = [
        {
          name        = "developer"
          description = "Developer access - read-only"
          policies = [
            "p, proj:${local.project_name}:developer, applications, get, ${local.project_name}/*, allow",
            "p, proj:${local.project_name}:developer, applications, sync, ${local.project_name}/*, deny"
          ]
        },
        {
          name        = "deployer"
          description = "Deployer access - can sync staging"
          policies = [
            "p, proj:${local.project_name}:deployer, applications, get, ${local.project_name}/*, allow",
            "p, proj:${local.project_name}:deployer, applications, sync, ${local.project_name}/*-staging, allow",
            "p, proj:${local.project_name}:deployer, applications, sync, ${local.project_name}/*-production, deny"
          ]
        },
        {
          name        = "admin"
          description = "Admin access - full control"
          policies = [
            "p, proj:${local.project_name}:admin, applications, *, ${local.project_name}/*, allow"
          ]
        }
      ]
    }
  }
}

# Application namespace
resource "kubernetes_namespace" "app" {
  metadata {
    name = local.app_namespace
    labels = {
      "app.kubernetes.io/managed-by" = "argocd"
      "argocd.argoproj.io/project"   = local.project_name
    }
  }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "project_name" {
  description = "Name of the Argo CD project"
  value       = local.project_name
}

output "app_namespace" {
  description = "Application namespace"
  value       = kubernetes_namespace.app.metadata[0].name
}
