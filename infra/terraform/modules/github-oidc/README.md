# GitHub Actions OIDC Module

This Terraform module creates and manages Azure AD app registration with federated credentials for GitHub Actions OIDC authentication.

## Features

- Creates Azure AD application registration
- Creates service principal
- Configures 4 federated identity credentials:
  - **Main branch**: For push events to main
  - **Pull requests**: For all PR workflows
  - **Production environment**: For environment-based deployments
  - **Repository-wide**: Wildcard for any workflow
- Assigns necessary Azure role assignments
- Outputs all required values for GitHub secrets

## Usage

```hcl
module "github_oidc" {
  source = "../../modules/github-oidc"

  github_organization      = "AshleyHollis"
  github_repository        = "yt-summarizer"
  assign_contributor_role  = true
  acr_id                   = module.acr.id

  tags = local.common_tags
}
```

## Outputs

The module outputs the following values that should be configured as GitHub repository secrets:

- `AZURE_CLIENT_ID` - Application (client) ID
- `AZURE_TENANT_ID` - Azure AD tenant ID
- `AZURE_SUBSCRIPTION_ID` - Azure subscription ID

## GitHub Secrets Configuration

After applying this module, configure the GitHub repository secrets at:
`https://github.com/{org}/{repo}/settings/secrets/actions`

```bash
# Get the output values
terraform output -json github_oidc_secrets

# Or individually
terraform output github_oidc_application_id
terraform output github_oidc_tenant_id
terraform output github_oidc_subscription_id
```

## Federated Credentials

The module creates these federated identity credentials:

| Name | Subject Pattern | Usage |
|------|----------------|-------|
| `github-main` | `repo:ORG/REPO:ref:refs/heads/main` | Push to main branch |
| `github-pr` | `repo:ORG/REPO:pull_request` | All pull requests |
| `github-env-production` | `repo:ORG/REPO:environment:production` | Production deployments |
| `github-repo` | `repo:ORG/REPO` | Any workflow (fallback) |

## Role Assignments

- **Contributor** on subscription (if `assign_contributor_role = true`)
- **AcrPush** on ACR (if `acr_id` is provided)

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.5.0 |
| azuread | ~> 2.47 |
| azurerm | ~> 3.85 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| application_name | Name of Azure AD application | `string` | `"github-actions-yt-summarizer"` | no |
| github_organization | GitHub org or username | `string` | n/a | yes |
| github_repository | GitHub repository name | `string` | n/a | yes |
| assign_contributor_role | Assign Contributor role | `bool` | `true` | no |
| acr_id | ACR resource ID | `string` | `""` | no |
| tags | Resource tags | `map(string)` | `{}` | no |

## Security Considerations

- No secrets are stored in Terraform state
- Uses OIDC (no passwords or certificates)
- Federated credentials are scoped to specific repository
- Role assignments follow least-privilege principle
- All authentication tokens are short-lived

## Maintenance

This module is idempotent and can be re-applied safely. Changes to federated credentials will be detected and applied automatically.

To update credentials:
1. Modify the module configuration
2. Run `terraform plan` to preview changes
3. Run `terraform apply` to apply changes
4. No GitHub Actions workflow changes needed
