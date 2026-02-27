# =============================================================================
# ArgoCD Module Variables
# =============================================================================

variable "namespace" {
  description = "Kubernetes namespace to install ArgoCD into."
  type        = string
  default     = "argocd"
}

variable "chart_version" {
  description = "Helm chart version for argo/argo-cd. Pin this to control upgrades."
  type        = string
  default     = "7.3.11"
}
