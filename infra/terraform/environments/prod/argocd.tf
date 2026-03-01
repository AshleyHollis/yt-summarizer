# =============================================================================
# ArgoCD Installation (MIGRATING TO shared-infra)
# =============================================================================
# ArgoCD is moving to shared-infra as a platform component.
# These removed blocks ensure resources stay in Azure but are no longer
# managed by yt-summarizer's Terraform state.

removed {
  from = module.argocd.kubernetes_namespace.argocd

  lifecycle {
    destroy = false
  }
}

removed {
  from = module.argocd.helm_release.argocd

  lifecycle {
    destroy = false
  }
}
