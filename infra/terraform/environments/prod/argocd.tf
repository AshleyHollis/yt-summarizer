# =============================================================================
# ArgoCD Installation
# =============================================================================
# Installs ArgoCD via Helm so it is always present after `terraform apply`.
# This prevents the cluster-stopped / ArgoCD-missing scenario.
#
# Disaster recovery:
#   terraform apply -target=module.argocd
#
# To upgrade ArgoCD, bump chart_version below and apply.

module "argocd" {
  source = "../../modules/argocd"

  namespace     = "argocd"
  chart_version = "7.3.11"

  depends_on = [module.aks]
}
