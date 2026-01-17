# =============================================================================
# Outputs
# =============================================================================

output "resource_group_name" {
  value = azurerm_resource_group.main.name
}

output "acr_login_server" {
  value = module.acr.login_server
}

output "aks_cluster_name" {
  value = module.aks.name
}

output "aks_fqdn" {
  value = module.aks.fqdn
}

output "swa_hostname" {
  value = module.swa.default_host_name
}

output "swa_api_key" {
  value     = module.swa.api_key
  sensitive = true
}

output "key_vault_uri" {
  value = module.key_vault.vault_uri
}

output "key_vault_tenant_id" {
  description = "Tenant ID for Key Vault (needed for Workload Identity)"
  value       = module.key_vault.tenant_id
}

output "workload_identity_client_id" {
  description = "Client ID for External Secrets Workload Identity"
  value       = azurerm_user_assigned_identity.external_secrets.client_id
}

output "aks_oidc_issuer_url" {
  description = "OIDC issuer URL for Workload Identity"
  value       = module.aks.oidc_issuer_url
}

output "sql_server_fqdn" {
  value = module.sql.server_fqdn
}

output "storage_primary_endpoint" {
  value = module.storage.primary_blob_endpoint
}

output "auth0_application_client_id" {
  description = "Auth0 BFF application client ID (also stored in Key Vault as 'auth0-client-id')"
  value       = var.enable_auth0 ? module.auth0[0].application_client_id : null
}

output "auth0_api_identifier" {
  description = "Auth0 API identifier (audience)"
  value       = var.enable_auth0 ? module.auth0[0].api_identifier : null
}

output "auth0_credentials_stored" {
  description = "Auth0 BFF credentials stored in Azure Key Vault"
  value = var.enable_auth0 ? {
    domain         = "Stored as: auth0-domain"
    client_id      = "Stored as: auth0-client-id"
    client_secret  = "Stored as: auth0-client-secret (sensitive)"
    session_secret = "Stored as: auth0-session-secret (sensitive)"
    note           = "These credentials are synced to Kubernetes via ExternalSecret"
  } : null
}

# GitHub Actions OIDC outputs
output "github_oidc_application_id" {
  description = "GitHub Actions OIDC - Application (Client) ID for AZURE_CLIENT_ID secret"
  value       = module.github_oidc.application_id
}

output "github_oidc_tenant_id" {
  description = "GitHub Actions OIDC - Tenant ID for AZURE_TENANT_ID secret"
  value       = module.github_oidc.tenant_id
}

output "github_oidc_subscription_id" {
  description = "GitHub Actions OIDC - Subscription ID for AZURE_SUBSCRIPTION_ID secret"
  value       = module.github_oidc.subscription_id
}

output "github_oidc_secrets" {
  description = "GitHub repository secrets configuration (copy these to GitHub)"
  value       = module.github_oidc.github_secrets
}

output "github_oidc_federated_credentials" {
  description = "Federated credential subjects configured for GitHub Actions"
  value       = module.github_oidc.federated_credentials
}

# Output for post-deploy instructions
output "post_deploy_instructions" {
  value = <<-EOT

    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ NEXT STEPS: Bootstrap Argo CD and Cluster Components                      ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║ 1. Configure GitHub Secrets (REQUIRED FOR CI/CD):                         ║
    ║    Go to: https://github.com/AshleyHollis/yt-summarizer/settings/secrets/actions ║
    ║                                                                            ║
    ║    AZURE_CLIENT_ID = ${module.github_oidc.application_id}                ║
    ║    AZURE_TENANT_ID = ${module.github_oidc.tenant_id}                     ║
    ║    AZURE_SUBSCRIPTION_ID = ${module.github_oidc.subscription_id}         ║
    ║                                                                            ║
    ║ 2. Verify Auth0 BFF Credentials in Key Vault:                             ║
    ║    az keyvault secret list --vault-name ${module.key_vault.name} --query "[?starts_with(name, 'auth0-')].name" ║
    ║    ✅ Should show: auth0-domain, auth0-client-id, auth0-client-secret, auth0-session-secret ║
    ║                                                                            ║
    ║ 3. Get AKS credentials:                                                    ║
    ║    az aks get-credentials --resource-group ${azurerm_resource_group.main.name} --name ${module.aks.name}   ║
    ║                                                                            ║
    ║ 4. Bootstrap Argo CD:                                                      ║
    ║    ./scripts/bootstrap-argocd.ps1                                          ║
    ║                                                                            ║
    ║ 5. Apply infrastructure apps (ingress-nginx, external-secrets):            ║
    ║    kubectl apply -f k8s/argocd/infra-apps.yaml                             ║
    ║                                                                            ║
    ║ 6. Apply application configs:                                              ║
    ║    kubectl apply -f k8s/argocd/prod-app.yaml                               ║
    ║    kubectl apply -f k8s/argocd/preview-appset.yaml                         ║
    ║                                                                            ║
    ║ 7. Verify ExternalSecret synced Auth0 credentials:                         ║
    ║    kubectl get secret auth0-credentials -n yt-summarizer                   ║
    ║    kubectl get secret auth0-credentials -n preview-pr-<NUMBER>             ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
  EOT
}
