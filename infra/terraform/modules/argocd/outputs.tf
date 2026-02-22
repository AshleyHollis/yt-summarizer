# =============================================================================
# ArgoCD Module Outputs
# =============================================================================

output "namespace" {
  description = "The namespace ArgoCD is installed in."
  value       = kubernetes_namespace.argocd.metadata[0].name
}

output "chart_version" {
  description = "The Helm chart version deployed."
  value       = helm_release.argocd.version
}
