# Managing GitHub Actions OIDC with Terraform

## Overview

GitHub Actions OIDC authentication to Azure is now fully managed as Infrastructure as Code using Terraform. This eliminates the need for ad-hoc scripts and ensures all configuration is versioned, repeatable, and documented.

## What Changed

### Before (❌ Ad-hoc Approach)
- Manual script execution: `.\scripts\setup-github-oidc.ps1`
- Configuration not tracked in version control
- Hard to reproduce across environments
- No visibility into changes
- Manual secret management

### After (✅ Infrastructure as Code)
- Terraform module: `infra/terraform/modules/github-oidc`
- All configuration in version control
- Fully reproducible via `terraform apply`
- Changes tracked in git history
- Automatic output of required secrets

## Architecture

```
infra/terraform/
├── modules/
│   └── github-oidc/          # New module for OIDC federation
│       ├── main.tf           # App registration & federated credentials
│       ├── variables.tf      # Configuration inputs
│       ├── outputs.tf        # GitHub secrets values
│       └── README.md         # Module documentation
└── environments/
    └── prod/
        └── main.tf           # Includes github_oidc module
```

## What Gets Created

The Terraform module creates and manages:

1. **Azure AD Application**
   - Name: `github-actions-yt-summarizer`
   - Purpose: OIDC authentication for GitHub Actions

2. **Service Principal**
   - Linked to the application
   - Used for Azure API calls

3. **Federated Identity Credentials** (4 total):
   - `github-main`: Push events to main branch
   - `github-pr`: All pull request workflows
   - `github-env-production`: Production environment deployments
   - `github-repo`: Wildcard for any workflow

4. **Role Assignments**:
   - `Contributor` role on subscription (for resource management)
   - `AcrPush` role on ACR (for image push)

## Usage

### Initial Setup

1. **Apply Terraform** (one-time or when changes are needed):
   ```bash
   cd infra/terraform/environments/prod
   terraform init
   terraform plan
   terraform apply
   ```

2. **Get GitHub Secrets** from Terraform outputs:
   ```bash
   # View all GitHub secrets
   terraform output github_oidc_secrets
   
   # Or get individual values
   terraform output github_oidc_application_id
   terraform output github_oidc_tenant_id
   terraform output github_oidc_subscription_id
   ```

3. **Configure GitHub Secrets** (one-time):
   - Go to: https://github.com/AshleyHollis/yt-summarizer/settings/secrets/actions
   - Add these repository secrets:
     ```
     AZURE_CLIENT_ID       = <terraform output github_oidc_application_id>
     AZURE_TENANT_ID       = <terraform output github_oidc_tenant_id>
     AZURE_SUBSCRIPTION_ID = <terraform output github_oidc_subscription_id>
     ```

### Making Changes

To add/modify federated credentials:

1. **Edit Terraform configuration**:
   ```hcl
   # infra/terraform/modules/github-oidc/main.tf
   
   # Example: Add credential for staging environment
   resource "azuread_application_federated_identity_credential" "staging" {
     application_id = azuread_application.github_actions.id
     display_name   = "github-env-staging"
     description    = "Federated credential for staging environment"
     audiences      = ["api://AzureADTokenExchange"]
     issuer         = "https://token.actions.githubusercontent.com"
     subject        = "repo:${var.github_organization}/${var.github_repository}:environment:staging"
   }
   ```

2. **Apply changes**:
   ```bash
   terraform plan   # Preview changes
   terraform apply  # Apply changes
   ```

3. **No GitHub Actions changes needed** - workflows automatically use new credentials

## Benefits

### 1. Version Control
All OIDC configuration is tracked in git:
```bash
git log infra/terraform/modules/github-oidc/
```

### 2. Reproducibility
Destroy and recreate everything:
```bash
terraform destroy
terraform apply
```

### 3. Drift Detection
Terraform detects manual changes:
```bash
terraform plan  # Shows if someone manually modified Azure AD
```

### 4. Documentation
- Module README documents purpose and usage
- Terraform configuration is self-documenting
- Outputs clearly show what secrets are needed

### 5. State Management
- Current configuration stored in Terraform state
- Can query current values without Azure portal
- Changes require intentional `terraform apply`

## Workflow Integration

GitHub Actions workflows don't need any changes. They continue to use:

```yaml
- uses: azure/login@v2
  with:
    client-id: ${{ secrets.AZURE_CLIENT_ID }}
    tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
```

The Terraform module ensures these values are correct and federated credentials exist.

## Terraform State

The module stores in Terraform state:
- Application ID (client ID)
- Tenant ID
- Service Principal object ID
- Federated credential IDs

**Note**: No secrets or passwords are stored. OIDC uses trust relationships, not secrets.

## Migration from Ad-hoc Script

If you previously used `setup-github-oidc.ps1`:

1. The script-created app registration will be **adopted** by Terraform
2. Terraform will detect and manage existing resources
3. No duplicate resources created
4. Can safely delete the script after migration

To import existing app:
```bash
# Find existing app
az ad app list --display-name "github-actions-yt-summarizer" --query "[0].id" -o tsv

# Import into Terraform (if needed)
terraform import module.github_oidc.azuread_application.github_actions <app-id>
```

## Troubleshooting

### "Credential already exists" error

Terraform will adopt existing credentials. If conflicts occur:

```bash
# List existing credentials
az ad app federated-credential list --id <app-id>

# Let Terraform manage them
terraform import module.github_oidc.azuread_application_federated_identity_credential.main <credential-id>
```

### Verifying Configuration

```bash
# Check what Terraform created
terraform state list | grep github_oidc

# Show specific resource
terraform state show module.github_oidc.azuread_application.github_actions

# Verify federated credentials
terraform output github_oidc_federated_credentials
```

### Testing Authentication

After applying Terraform, test in GitHub Actions:

1. Trigger a workflow on main branch
2. Check "Azure Login" step
3. Should see: "Successfully logged into Azure"

## Security Considerations

1. **No Secrets in Code**: Only resource IDs and names in Terraform
2. **OIDC Trust**: Authentication based on GitHub's OIDC issuer
3. **Scoped Credentials**: Each credential limited to specific workflows
4. **Short-lived Tokens**: GitHub issues tokens valid for ~60 minutes
5. **Least Privilege**: Role assignments follow principle of least privilege

## Best Practices

1. **Always use Terraform** for OIDC changes (not Azure Portal)
2. **Review plans** before applying (`terraform plan`)
3. **Commit changes** to git before applying
4. **Document reasons** for credential additions in commit messages
5. **Test workflows** after Terraform changes

## Related Documentation

- [Module README](infra/terraform/modules/github-oidc/README.md)
- [Azure Workload Identity](https://learn.microsoft.com/entra/workload-id/workload-identity-federation)
- [GitHub OIDC](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [Terraform Azure AD Provider](https://registry.terraform.io/providers/hashicorp/azuread/latest/docs)

## Support

For issues with:
- **Terraform configuration**: Check module README and Terraform docs
- **GitHub Actions authentication**: Check workflow logs and GitHub secrets
- **Azure AD issues**: Use `az ad app` commands to inspect configuration
