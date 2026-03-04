# =============================================================================
# Cluster Components - Managed by Argo CD (not Terraform)
# =============================================================================
#
# The following components are NOT managed by Terraform:
# - Nginx Ingress Controller → k8s/argocd/infra-apps.yaml
# - External Secrets Operator → k8s/argocd/infra-apps.yaml
# - Argo CD → scripts/bootstrap-argocd.ps1
#
# After terraform apply, run:
#   1. az aks get-credentials --resource-group rg-ytsumm-prd-ci --name aks-ytsumm-prd-ci
#   2. ./scripts/bootstrap-argocd.ps1
#   3. kubectl apply -f k8s/argocd/infra-apps.yaml
# =============================================================================
