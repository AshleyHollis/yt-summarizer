# Auth0 Terraform Service Account

This document describes the Auth0 Machine-to-Machine (M2M) application used by Terraform and GitHub Actions to manage Auth0 resources programmatically.

## Overview

The **Terraform Service Account** is a dedicated Auth0 M2M application that allows automated systems (Terraform, GitHub Actions) to create and manage Auth0 applications and resource servers. This is separate from the user-facing `yt-summarizer-api-bff` application that handles end-user authentication.

### Credential Separation

This project uses **two separate sets of Auth0 credentials** for different purposes:

| Credential Set | Purpose | Type | Used By | Storage Location |
|---------------|---------|------|---------|------------------|
| **Terraform Service Account** | Manage Auth0 resources via Terraform | M2M Application | GitHub Actions, Local Terraform | GitHub Secrets + Azure Key Vault |
| **yt-summarizer-api-bff** | Authenticate end-users | Regular Web Application | API pods at runtime | Azure Key Vault → Kubernetes Secrets |

**Important:** Never confuse these two credential sets. The service account is for deployment automation, while the BFF credentials are for user authentication.

## Application Details

**Auth0 Application Name:** Terraform Service Account  
**Application Type:** Machine-to-Machine (non_interactive)  
**Auth0 Domain:** `dev-gvli0bfdrue0h8po.us.auth0.com`  
**Client ID:** `Fmh7q7q2OrqUvmSXTgBxr3E7v5KdAbt6`  
**Client Secret:** (Stored in GitHub Secrets and Azure Key Vault)

**Grant Type:** `client_credentials`  
**Authentication Method:** Client credentials flow (no user interaction)

## Granted Permissions

The service account has the following Auth0 Management API permissions:

### Client Management
- `read:clients` - Read Auth0 applications
- `create:clients` - Create new Auth0 applications
- `update:clients` - Update existing Auth0 applications
- `delete:clients` - Delete Auth0 applications

### Client Grants Management
- `read:client_grants` - Read client grant configurations
- `create:client_grants` - Grant applications access to APIs
- `update:client_grants` - Update client grant scopes
- `delete:client_grants` - Remove client grants

### Resource Server Management
- `read:resource_servers` - Read Auth0 APIs (resource servers)
- `create:resource_servers` - Create new APIs
- `update:resource_servers` - Update API configurations
- `delete:resource_servers` - Delete APIs

These permissions allow Terraform to:
1. Create the `yt-summarizer-api-bff` application
2. Configure callback URLs, logout URLs, and allowed origins
3. Create custom APIs (if needed)
4. Grant the BFF application access to APIs

## Credential Storage

### GitHub Secrets (for CI/CD)

The service account credentials are stored as GitHub repository secrets and automatically injected into GitHub Actions workflows:

```yaml
# These secrets are available in all workflows
secrets.AUTH0_DOMAIN          # dev-gvli0bfdrue0h8po.us.auth0.com
secrets.AUTH0_CLIENT_ID       # Fmh7q7q2OrqUvmSXTgBxr3E7v5KdAbt6
secrets.AUTH0_CLIENT_SECRET   # (redacted)
```

**Set via:**
```bash
gh secret set AUTH0_DOMAIN --body "dev-gvli0bfdrue0h8po.us.auth0.com"
gh secret set AUTH0_CLIENT_ID --body "Fmh7q7q2OrqUvmSXTgBxr3E7v5KdAbt6"
gh secret set AUTH0_CLIENT_SECRET --body "<secret>"
```

### Azure Key Vault (for local development and reference)

The service account credentials are also stored in Azure Key Vault `kv-ytsumm-prd` for local Terraform runs:

```
auth0-terraform-domain         # dev-gvli0bfdrue0h8po.us.auth0.com
auth0-terraform-client-id      # Fmh7q7q2OrqUvmSXTgBxr3E7v5KdAbt6
auth0-terraform-client-secret  # (redacted)
```

**Set via:**
```bash
az keyvault secret set --vault-name kv-ytsumm-prd --name auth0-terraform-domain --value "dev-gvli0bfdrue0h8po.us.auth0.com"
az keyvault secret set --vault-name kv-ytsumm-prd --name auth0-terraform-client-id --value "Fmh7q7q2OrqUvmSXTgBxr3E7v5KdAbt6"
az keyvault secret set --vault-name kv-ytsumm-prd --name auth0-terraform-client-secret --value "<secret>"
```

## Usage in GitHub Actions

GitHub Actions workflows automatically use the service account credentials when running Terraform. The credentials are passed as environment variables:

### deploy-prod.yml

```yaml
terraform-plan:
  env:
    # Auth0 Terraform service account credentials (for managing Auth0 resources)
    AUTH0_DOMAIN: ${{ secrets.AUTH0_DOMAIN }}
    AUTH0_CLIENT_ID: ${{ secrets.AUTH0_CLIENT_ID }}
    AUTH0_CLIENT_SECRET: ${{ secrets.AUTH0_CLIENT_SECRET }}
  steps:
    - name: Terraform Plan
      run: terraform plan
      # The Auth0 provider reads AUTH0_* environment variables automatically
```

### preview.yml

```yaml
terraform:
  env:
    # Auth0 Terraform service account credentials (for managing Auth0 resources)
    AUTH0_DOMAIN: ${{ secrets.AUTH0_DOMAIN }}
    AUTH0_CLIENT_ID: ${{ secrets.AUTH0_CLIENT_ID }}
    AUTH0_CLIENT_SECRET: ${{ secrets.AUTH0_CLIENT_SECRET }}
  steps:
    - name: Terraform Plan
      run: terraform plan
      # The Auth0 provider reads AUTH0_* environment variables automatically
```

**Key Points:**
- The workflows set `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET` as environment variables
- The Auth0 Terraform provider automatically reads these environment variables
- No explicit provider configuration is needed in the workflow

## Usage in Terraform

The Auth0 provider is configured to use environment variables in `infra/terraform/environments/prod/providers.tf`:

```hcl
provider "auth0" {
  # Reads from environment variables:
  # - AUTH0_DOMAIN
  # - AUTH0_CLIENT_ID
  # - AUTH0_CLIENT_SECRET
  # No explicit configuration needed - provider uses env vars automatically
}
```

### Local Terraform Usage

To run Terraform locally with the service account:

```bash
cd infra/terraform/environments/prod

# Load Auth0 credentials from Azure Key Vault
export AUTH0_DOMAIN=$(az keyvault secret show --vault-name kv-ytsumm-prd --name auth0-terraform-domain --query value -o tsv)
export AUTH0_CLIENT_ID=$(az keyvault secret show --vault-name kv-ytsumm-prd --name auth0-terraform-client-id --query value -o tsv)
export AUTH0_CLIENT_SECRET=$(az keyvault secret show --vault-name kv-ytsumm-prd --name auth0-terraform-client-secret --query value -o tsv)

# Or set them manually
export AUTH0_DOMAIN="dev-gvli0bfdrue0h8po.us.auth0.com"
export AUTH0_CLIENT_ID="Fmh7q7q2OrqUvmSXTgBxr3E7v5KdAbt6"
export AUTH0_CLIENT_SECRET="<your-secret>"

# Set other required Terraform variables
export TF_VAR_subscription_id="<azure-subscription-id>"
export TF_VAR_sql_admin_password="<sql-password>"
export TF_VAR_openai_api_key="<openai-key>"
export TF_VAR_cloudflare_api_token="<cloudflare-token>"
export TF_VAR_enable_auth0=true

# Run Terraform
terraform init
terraform plan
terraform apply
```

## What Terraform Creates

When you run Terraform with `enable_auth0 = true`, the Auth0 module creates:

### 1. yt-summarizer-api-bff Application

A **Regular Web Application** for user authentication with:

**Configuration:**
- **Application Type:** Regular Web Application
- **Grant Types:** authorization_code, refresh_token
- **OIDC Conformant:** Yes
- **Callback URLs:**
  - `https://api.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0` (production)
  - `https://api-stg.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0` (staging)
  - `https://api-pr-*.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0` (preview wildcard)
- **Logout URLs:** Same as callback URLs (without `/callback/auth0`)
- **Web Origins:** `https://*.azurestaticapps.net` (for CORS)

**Outputs:**
- `application_client_id` - The client ID for runtime use
- `client_secret` - The client secret (must be stored in Azure Key Vault)

### 2. Optional API Resource Server

If `auth0_api_identifier` is set, Terraform also creates an Auth0 API (resource server).

**Configuration:**
- **Name:** YT Summarizer API
- **Identifier:** (Custom audience URL)
- **Signing Algorithm:** RS256
- **Offline Access:** Enabled

## Post-Deployment Steps

After Terraform successfully creates the `yt-summarizer-api-bff` application:

### 1. Verify BFF Credentials Are Stored in Azure Key Vault

**Terraform automatically stores the BFF application credentials** in Azure Key Vault. Verify they are present:

```bash
# List all Auth0 secrets
az keyvault secret list --vault-name kv-ytsumm-prd --query "[?starts_with(name, 'auth0-')].name"

# Expected output:
# Service Account (for Terraform):
#   - auth0-terraform-domain
#   - auth0-terraform-client-id
#   - auth0-terraform-client-secret
#
# BFF Application (for runtime):
#   - auth0-domain
#   - auth0-client-id
#   - auth0-client-secret
#   - auth0-session-secret (auto-generated by Terraform)
```

### 2. Verify ExternalSecret Syncs Credentials to Kubernetes

The BFF credentials (NOT the service account credentials) are synced to Kubernetes via ExternalSecret:

```bash
# Check production namespace
kubectl get secret auth0-credentials -n yt-summarizer

# Check preview namespace (after creating a preview)
kubectl get secret auth0-credentials -n preview-pr-42

# Verify the secret contains all required keys
kubectl get secret auth0-credentials -n yt-summarizer -o jsonpath='{.data}' | jq 'keys'
# Expected: ["AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET", "AUTH0_DOMAIN", "AUTH0_SESSION_SECRET"]
```

### 2. Verify ExternalSecret Sync

The Kubernetes ExternalSecret controller will automatically sync these secrets within ~1 minute:

```bash
# Check ExternalSecret status
kubectl get externalsecret auth0-secrets -n yt-summarizer

# Verify secret was created
kubectl get secret auth0-secrets -n yt-summarizer
```

### 3. Verify API Pods

```bash
# Check that API pods have the Auth0 environment variables
kubectl describe deployment api -n yt-summarizer | grep -A 4 "Environment:"

# Should show:
# AUTH0_DOMAIN (from secret)
# AUTH0_CLIENT_ID (from secret)
# AUTH0_CLIENT_SECRET (from secret)
# AUTH0_SESSION_SECRET (from secret)
```

## Troubleshooting

### Terraform fails with "Invalid credentials"

**Symptoms:**
```
Error: failed to retrieve access token: 401 Unauthorized
```

**Cause:** The service account credentials are incorrect or missing.

**Solution:**
1. Verify GitHub Secrets are set correctly:
   ```bash
   gh secret list | grep AUTH0
   ```

2. For local runs, verify environment variables:
   ```bash
   echo $AUTH0_DOMAIN
   echo $AUTH0_CLIENT_ID
   echo $AUTH0_CLIENT_SECRET  # Should not be empty
   ```

3. Test credentials manually:
   ```bash
   curl -X POST https://dev-gvli0bfdrue0h8po.us.auth0.com/oauth/token \
     -H "Content-Type: application/json" \
     -d '{
       "client_id": "'$AUTH0_CLIENT_ID'",
       "client_secret": "'$AUTH0_CLIENT_SECRET'",
       "audience": "https://dev-gvli0bfdrue0h8po.us.auth0.com/api/v2/",
       "grant_type": "client_credentials"
     }'
   ```

### Terraform fails with "Insufficient permissions"

**Symptoms:**
```
Error: 403 Insufficient scope
```

**Cause:** The service account doesn't have the required Management API permissions.

**Solution:**
1. Go to Auth0 Dashboard → Applications → Terraform Service Account
2. Click on "APIs" tab
3. Expand "Auth0 Management API"
4. Verify these scopes are granted:
   - `read:clients`, `create:clients`, `update:clients`, `delete:clients`
   - `read:client_grants`, `create:client_grants`, `update:client_grants`, `delete:client_grants`
   - `read:resource_servers`, `create:resource_servers`, `update:resource_servers`, `delete:resource_servers`

### Application created but pods can't authenticate

**Symptoms:**
- Terraform succeeds
- API pods are running
- Login redirects fail or return 401 errors

**Cause:** The BFF application credentials weren't stored in Azure Key Vault, or ExternalSecret hasn't synced yet.

**Solution:**
1. Verify secrets exist in Azure Key Vault:
   ```bash
   az keyvault secret list --vault-name kv-ytsumm-prd --query "[?starts_with(name, 'auth0')].name"
   ```

2. Check ExternalSecret status:
   ```bash
   kubectl describe externalsecret auth0-secrets -n yt-summarizer
   ```

3. Manually trigger a sync:
   ```bash
   kubectl annotate externalsecret auth0-secrets force-sync=$(date +%s) -n yt-summarizer
   ```

## Rotating Credentials

If the service account credentials need to be rotated:

### 1. Generate New Client Secret in Auth0

1. Go to Auth0 Dashboard → Applications → Terraform Service Account
2. Go to "Settings" tab
3. Scroll to "Client Secret"
4. Click "Rotate" and confirm
5. Copy the new client secret

### 2. Update GitHub Secrets

```bash
gh secret set AUTH0_CLIENT_SECRET --body "<new-secret>"
```

### 3. Update Azure Key Vault

```bash
az keyvault secret set --vault-name kv-ytsumm-prd --name auth0-terraform-client-secret --value "<new-secret>"
```

### 4. Test Locally

```bash
export AUTH0_CLIENT_SECRET="<new-secret>"
cd infra/terraform/environments/prod
terraform plan  # Should succeed
```

**Note:** The old secret will continue to work for ~24 hours after rotation, allowing time for all systems to be updated.

## Security Best Practices

1. **Never commit credentials to Git** - Always use GitHub Secrets and Azure Key Vault
2. **Principle of least privilege** - The service account only has permissions needed for Terraform
3. **Separate credentials** - Deployment credentials are separate from runtime credentials
4. **Rotate regularly** - Rotate the client secret every 90 days or when team members leave
5. **Audit access** - Review Auth0 logs regularly for unauthorized access attempts
6. **Use environment variables** - Never hardcode credentials in Terraform files

## Related Documentation

- [Auth0 Setup Runbook](./auth0-setup.md) - End-to-end setup guide
- [Terraform Auth0 Module](../../infra/terraform/modules/auth0/README.md) - Module documentation
- [GitHub Actions Workflows](../../.github/workflows/README.md) - CI/CD pipeline documentation

## References

- [Auth0 Management API Documentation](https://auth0.com/docs/api/management/v2)
- [Auth0 Terraform Provider Documentation](https://registry.terraform.io/providers/auth0/auth0/latest/docs)
- [Auth0 Client Credentials Flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-credentials-flow)
