# =============================================================================
# Terraform Backend Configuration
# =============================================================================
# Stores Terraform state in Azure Blob Storage with state locking

terraform {
  backend "azurerm" {
    # These values are typically provided via CLI or environment variables:
    # -backend-config="resource_group_name=rg-ytsummarizer-tfstate"
    # -backend-config="storage_account_name=stytsummarizertfstate"
    # -backend-config="container_name=tfstate"
    # -backend-config="key=<environment>.tfstate"

    # State locking is enabled by default via Azure Blob lease
    use_oidc = true # Use OIDC authentication in GitHub Actions
  }
}
