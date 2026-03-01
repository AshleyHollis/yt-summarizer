# =============================================================================
# Workload Identity for External Secrets Operator - MIGRATED TO shared-infra
# =============================================================================

removed {
  from = azurerm_user_assigned_identity.external_secrets

  lifecycle {
    destroy = false
  }
}

removed {
  from = azurerm_federated_identity_credential.external_secrets

  lifecycle {
    destroy = false
  }
}

removed {
  from = azurerm_role_assignment.external_secrets_kv_reader

  lifecycle {
    destroy = false
  }
}
