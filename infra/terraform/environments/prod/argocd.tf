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

# Import the pre-existing argocd namespace (created by bootstrap-argocd.ps1).
# This is a one-time import; once the resource is in state this block is a no-op.
import {
  to = module.argocd.kubernetes_namespace.argocd
  id = "argocd"
}

module "argocd" {
  source = "../../modules/argocd"

  namespace     = "argocd"
  chart_version = "7.3.11"

  depends_on = [module.aks]
}
