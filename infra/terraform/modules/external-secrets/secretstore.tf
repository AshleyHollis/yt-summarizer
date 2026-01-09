# =============================================================================
# ClusterSecretStore for Azure Key Vault
# =============================================================================
# Creates a ClusterSecretStore that connects to Azure Key Vault
# using workload identity (OIDC)

# Note: terraform block and kubernetes provider defined in main.tf

# -----------------------------------------------------------------------------
# Local Variables for SecretStore
# -----------------------------------------------------------------------------

locals {
  secret_store_name         = "azure-key-vault"
  service_account_name      = "external-secrets-sa"
  service_account_namespace = var.namespace
}

# -----------------------------------------------------------------------------
# Resources
# -----------------------------------------------------------------------------

# Service account for workload identity
resource "kubernetes_service_account" "eso" {
  count = var.key_vault_name != "" ? 1 : 0

  metadata {
    name      = local.service_account_name
    namespace = local.service_account_namespace
    annotations = {
      "azure.workload.identity/client-id" = var.client_id
    }
    labels = {
      "azure.workload.identity/use" = "true"
    }
  }
}

# ClusterSecretStore for Azure Key Vault
resource "kubernetes_manifest" "cluster_secret_store" {
  count = var.key_vault_name != "" ? 1 : 0

  manifest = {
    apiVersion = "external-secrets.io/v1beta1"
    kind       = "ClusterSecretStore"
    metadata = {
      name = local.secret_store_name
    }
    spec = {
      provider = {
        azurekv = {
          authType = "WorkloadIdentity"
          vaultUrl = "https://${var.key_vault_name}.vault.azure.net/"
          serviceAccountRef = {
            name      = local.service_account_name
            namespace = local.service_account_namespace
          }
        }
      }
    }
  }

  depends_on = [kubernetes_service_account.eso]
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "secret_store_name" {
  description = "Name of the ClusterSecretStore"
  value       = var.key_vault_name != "" ? local.secret_store_name : null
}

output "service_account_name" {
  description = "Name of the service account"
  value       = var.key_vault_name != "" ? local.service_account_name : null
}
