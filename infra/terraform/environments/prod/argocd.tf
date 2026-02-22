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

# Import pre-existing resources created by bootstrap-argocd.ps1 (Helm install).
# These blocks are one-time imports; once resources are in state they are no-ops.
import {
  to = module.argocd.kubernetes_namespace.argocd
  id = "argocd"
}

import {
  to = module.argocd.helm_release.argocd
  id = "argocd/argocd"
}

module "argocd" {
  source = "../../modules/argocd"

  namespace     = "argocd"
  chart_version = "7.3.11"

  depends_on = [module.aks]
}
