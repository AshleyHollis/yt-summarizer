# =============================================================================
# AKS Cluster - MIGRATED TO shared-infra
# =============================================================================

removed {
  from = module.aks.azurerm_kubernetes_cluster.aks

  lifecycle {
    destroy = false
  }
}
