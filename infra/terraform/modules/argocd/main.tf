# =============================================================================
# ArgoCD Module - Installs ArgoCD via Helm
# =============================================================================
# Manages ArgoCD installation on AKS to ensure it survives cluster restarts
# and can be recovered via `terraform apply -target=module.argocd`.

resource "kubernetes_namespace" "argocd" {
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }

  lifecycle {
    ignore_changes = [metadata[0].annotations, metadata[0].labels]
  }
}

resource "helm_release" "argocd" {
  name       = "argocd"
  repository = "https://argoproj.github.io/argo-helm"
  chart      = "argo-cd"
  version    = var.chart_version
  namespace  = kubernetes_namespace.argocd.metadata[0].name

  # Allow in-cluster access without TLS (TLS terminated at ingress/gateway)
  set {
    name  = "configs.params.server\\.insecure"
    value = "true"
  }

  # ClusterIP - exposed via kubectl port-forward or ingress, not LoadBalancer
  set {
    name  = "server.service.type"
    value = "ClusterIP"
  }

  # Resource limits for single-node cluster cost savings
  set {
    name  = "server.resources.requests.cpu"
    value = "50m"
  }
  set {
    name  = "server.resources.requests.memory"
    value = "128Mi"
  }
  set {
    name  = "server.resources.limits.cpu"
    value = "500m"
  }
  set {
    name  = "server.resources.limits.memory"
    value = "512Mi"
  }

  set {
    name  = "repoServer.resources.requests.cpu"
    value = "50m"
  }
  set {
    name  = "repoServer.resources.requests.memory"
    value = "128Mi"
  }
  set {
    name  = "repoServer.resources.limits.cpu"
    value = "500m"
  }
  set {
    name  = "repoServer.resources.limits.memory"
    value = "512Mi"
  }

  # Wait for all pods to be ready before Terraform considers this complete
  wait    = true
  timeout = 300

  depends_on = [kubernetes_namespace.argocd]
}
