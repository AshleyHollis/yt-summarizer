# Auth0 Setup for Preview Environments

**Author**: OpenCode AI  
**Date**: January 17, 2026  
**Feature**: 003-preview-dns-cloudflare  
**Purpose**: Configure Auth0 for authentication across production, staging, and preview environments

---

## Overview

This runbook guides you through setting up Auth0 for the YT Summarizer application with support for:
- Production environment authentication
- Staging environment authentication  
- Dynamic preview environment authentication (wildcard callback URLs)
- Cross-origin authentication between Static Web Apps and API

### Important: Two Sets of Auth0 Credentials

This project uses **TWO separate Auth0 applications** for different purposes:

| Application | Purpose | Type | Used By | When |
|-------------|---------|------|---------|------|
| **Terraform Service Account** | Manage Auth0 resources | M2M App | Terraform, GitHub Actions | During infrastructure provisioning |
| **yt-summarizer-api-bff** | Authenticate end users | Web App | API pods at runtime | During user authentication |

**Critical:** The Terraform service account CREATES the BFF application. You must set up the service account first (Option A, Step 1-3), then Terraform will create the BFF application automatically (Step 4).

**For detailed information** about the Terraform service account, see: [`docs/auth0-terraform-service-account.md`](../auth0-terraform-service-account.md)

---

## Prerequisites

- Auth0 account (free tier is sufficient)
- Access to Azure Key Vault for secret storage
- GitHub repository admin access for secrets configuration
- Terraform installed locally (for automated setup) OR Auth0 Dashboard access (for manual setup)

---

## Option A: Automated Setup via Terraform (Recommended)

### Step 1: Create Auth0 Terraform Service Account

> **What is this?** A dedicated M2M application that allows Terraform to create and manage Auth0 resources programmatically.

1. **Navigate to Auth0 Dashboard** → Applications → Create Application
2. **Application settings:**
   - Name: `Terraform Service Account`
   - Type: **Machine to Machine Applications**
   - Authorize for: **Auth0 Management API**

3. **Grant required permissions:**
   ```
   read:client_grants, create:client_grants, delete:client_grants, update:client_grants
   read:clients, create:clients, update:clients, delete:clients
   read:resource_servers, create:resource_servers, update:resource_servers, delete:resource_servers
   ```

4. **Save credentials:**
   - Domain (e.g., `yourtenantname.us.auth0.com`)
   - Client ID
   - Client Secret

> **Important:** These credentials are ONLY for Terraform. They are NOT the credentials your API will use at runtime.

### Step 2: Store Terraform Service Account Credentials in GitHub Secrets

Add the following secrets to your GitHub repository (Settings → Secrets and variables → Actions → New repository secret):

| Secret Name | Value | Purpose | Example |
|-------------|-------|---------|---------|
| `AUTH0_DOMAIN` | Auth0 tenant domain | Terraform authentication | `myapp.us.auth0.com` |
| `AUTH0_CLIENT_ID` | Service account Client ID | Terraform authentication | `abc123...` |
| `AUTH0_CLIENT_SECRET` | Service account Client Secret | Terraform authentication | `xyz789...` |

**Command-line setup:**
```bash
# Set the Terraform service account credentials as GitHub Secrets
gh secret set AUTH0_DOMAIN --body "yourtenantname.us.auth0.com"
gh secret set AUTH0_CLIENT_ID --body "your-service-account-client-id"
gh secret set AUTH0_CLIENT_SECRET --body "your-service-account-client-secret"
```

### Step 3: Store Terraform Service Account Credentials in Azure Key Vault (Optional - for local runs)

If you plan to run Terraform locally, also store the credentials in Azure Key Vault:

```powershell
# Store Terraform service account credentials for local development
az keyvault secret set `
  --vault-name "kv-ytsumm-prd" `
  --name "auth0-terraform-domain" `
  --value "yourtenantname.us.auth0.com"

az keyvault secret set `
  --vault-name "kv-ytsumm-prd" `
  --name "auth0-terraform-client-id" `
  --value "your-service-account-client-id"

az keyvault secret set `
  --vault-name "kv-ytsumm-prd" `
  --name "auth0-terraform-client-secret" `
  --value "your-service-account-client-secret"
```

> **Note:** These are stored separately from the BFF credentials (`auth0-domain`, `auth0-client-id`, etc.) which will be created in Step 4.

### Step 4: Run Terraform to Create the BFF Application

> **What does this do?** Terraform uses the service account credentials to CREATE a new Auth0 application called `yt-summarizer-api-bff` that your API will use for end-user authentication.

The Terraform configuration will create a new Auth0 application called `yt-summarizer-api-bff` with pre-configured callback URLs and web origins.

**Option 1: Via GitHub Actions (Recommended)**

1. Trigger the `Deploy to Production` workflow manually:
   ```
   Actions → Deploy to Production → Run workflow → Enable "Run terraform" → Run
   ```

2. The workflow will:
   - Plan Terraform changes
   - Create the Auth0 application
   - Output the application credentials

**Option 2: Run Locally**

```powershell
# Navigate to Terraform directory
cd infra/terraform/environments/prod

# Set Terraform service account credentials (NOT the BFF app credentials)
$env:AUTH0_DOMAIN = "yourtenantname.auth0.com"
$env:AUTH0_CLIENT_ID = "terraform-service-account-client-id"
$env:AUTH0_CLIENT_SECRET = "terraform-service-account-client-secret"

# Plan changes
terraform init
terraform plan

# Apply (creates Auth0 BFF application and API)
terraform apply
```

> **Remember:** These environment variables are the **Terraform service account** credentials, not the BFF application credentials. Terraform will create the BFF app for you.

### Step 5: Verify BFF Application Credentials in Azure Key Vault

> **Important:** Terraform now automatically stores the BFF credentials in Azure Key Vault. You no longer need to manually add them!

After Terraform creates the BFF application, it automatically stores the credentials in Azure Key Vault:

1. **Verify the BFF application was created:**
   - Go to Auth0 Dashboard → Applications → `yt-summarizer-api-bff`
   - You should see the application with all the configured callback URLs

2. **Verify secrets are in Azure Key Vault:**
   ```powershell
   # List all Auth0 secrets (should show both service account and BFF credentials)
   az keyvault secret list --vault-name "kv-ytsumm-prd" --query "[?starts_with(name, 'auth0-')].name"
   
   # Expected output:
   # - auth0-terraform-domain (service account)
   # - auth0-terraform-client-id (service account)
   # - auth0-terraform-client-secret (service account)
   # - auth0-domain (BFF application)
   # - auth0-client-id (BFF application)
   # - auth0-client-secret (BFF application)
   # - auth0-session-secret (BFF application - auto-generated)
   ```

3. **View a secret value (optional):**
   ```powershell
   # View the BFF client ID
   az keyvault secret show --vault-name "kv-ytsumm-prd" --name "auth0-client-id" --query "value" -o tsv
   ```

> **Note:** The `auth0-session-secret` is automatically generated by Terraform as a secure random string. You don't need to create it manually.

### Credential Storage Summary

After completing the setup, you should have two sets of credentials stored:

#### Terraform Service Account (for infrastructure management)
- **GitHub Secrets:** `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`
- **Azure Key Vault:** `auth0-terraform-domain`, `auth0-terraform-client-id`, `auth0-terraform-client-secret`
- **Used by:** Terraform, GitHub Actions workflows
- **Purpose:** Create and manage Auth0 resources

#### BFF Application (for user authentication)
- **Azure Key Vault only:** `auth0-domain`, `auth0-client-id`, `auth0-client-secret`, `auth0-session-secret`
- **Synced to Kubernetes:** Via ExternalSecret (see `k8s/base/externalsecret-auth0.yaml`)
- **Used by:** API pods at runtime
- **Purpose:** Authenticate end users

> **See also:** [`docs/auth0-terraform-service-account.md`](../auth0-terraform-service-account.md) for detailed documentation on the service account setup.

### Step 6: Verify Configuration

The Terraform configuration automatically sets up:

✅ **Allowed Callback URLs:**
- `https://api.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0`
- `https://api-stg.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0`
- `https://api-pr-*.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0` (wildcard)

✅ **Allowed Logout URLs:**
- `https://web.yt-summarizer.apps.ashleyhollis.com`
- `https://web-stg.yt-summarizer.apps.ashleyhollis.com`
- `https://*.azurestaticapps.net` (for SWA previews)

✅ **Allowed Web Origins:**
- `https://web.yt-summarizer.apps.ashleyhollis.com`
- `https://web-stg.yt-summarizer.apps.ashleyhollis.com`
- `https://*.azurestaticapps.net`

---

## Option B: Manual Setup via Auth0 Dashboard

If you prefer not to use Terraform or don't have the Management API permissions:

### Step 1: Create Application in Auth0 Dashboard

1. **Navigate to** Auth0 Dashboard → Applications → Create Application
2. **Application settings:**
   - Name: `yt-summarizer-api-bff`
   - Type: **Regular Web Applications**
   - Click **Create**

### Step 2: Configure Application Settings

1. **Application URIs** tab:

   **Allowed Callback URLs:**
   ```
   https://api.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0,
   https://api-stg.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0,
   https://api-pr-*.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0
   ```

   **Allowed Logout URLs:**
   ```
   https://web.yt-summarizer.apps.ashleyhollis.com,
   https://web-stg.yt-summarizer.apps.ashleyhollis.com,
   https://*.azurestaticapps.net
   ```

   **Allowed Web Origins:**
   ```
   https://web.yt-summarizer.apps.ashleyhollis.com,
   https://web-stg.yt-summarizer.apps.ashleyhollis.com,
   https://*.azurestaticapps.net
   ```

2. **Advanced Settings**:
   - Grant Types: Enable **Authorization Code** and **Refresh Token**
   - OIDC Conformant: **Enabled**

3. **Save Changes**

### Step 3: Store Credentials in Azure Key Vault

Follow the same steps as in "Option A: Step 4" above, using the credentials from the Auth0 Dashboard.

---

## Verification

### 1. Check Kubernetes Secrets Sync

Verify that the ExternalSecret controller synced the Auth0 credentials from Azure Key Vault to Kubernetes:

```bash
# Production namespace
kubectl get secret auth0-credentials -n yt-summarizer

# Preview namespace (after creating a preview)
kubectl get secret auth0-credentials -n preview-pr-42
```

Expected output:
```
NAME                TYPE     DATA   AGE
auth0-credentials   Opaque   4      5m
```

### 2. Verify API Pod Environment Variables

```bash
# Check that API pod has Auth0 env vars
kubectl get pod -n yt-summarizer -l app.kubernetes.io/name=api -o yaml | grep -A 20 "env:"
```

Expected environment variables:
- `AUTH0_DOMAIN`
- `AUTH0_CLIENT_ID`
- `AUTH0_CLIENT_SECRET`
- `AUTH0_SESSION_SECRET`

### 3. Test Auth Endpoints

```bash
# Test login endpoint (should redirect to Auth0)
curl -I https://api.yt-summarizer.apps.ashleyhollis.com/api/auth/login

# Expected: HTTP 302 redirect to Auth0 domain
```

---

## Troubleshooting

### Issue: "Auth0 is not configured" error

**Symptom:** API returns 500 error with message "Auth0 is not configured"

**Cause:** One or more Auth0 environment variables are missing or empty

**Fix:**
1. Check ExternalSecret status:
   ```bash
   kubectl describe externalsecret auth0-credentials -n yt-summarizer
   ```

2. Verify secrets exist in Azure Key Vault:
   ```bash
   az keyvault secret list --vault-name "<your-keyvault-name>" --query "[?starts_with(name, 'auth0-')].name"
   ```

3. Check API pod logs:
   ```bash
   kubectl logs -n yt-summarizer -l app.kubernetes.io/name=api --tail=50
   ```

### Issue: Callback URL not allowed

**Symptom:** After Auth0 login, user sees "Callback URL mismatch" error

**Cause:** The callback URL is not in the Auth0 allowed list

**Fix:**
1. Check the exact callback URL from the error message
2. Go to Auth0 Dashboard → Applications → yt-summarizer-api-bff → Settings → Allowed Callback URLs
3. Verify the URL pattern matches (e.g., `https://api-pr-42...` should match `https://api-pr-*...`)
4. If using Terraform, check `infra/terraform/environments/prod/variables.tf` and re-apply

### Issue: CORS errors from SWA preview

**Symptom:** Browser console shows CORS error when calling API from SWA preview

**Cause:** SWA preview origin not in allowed list

**Fix:**
1. Verify the SWA preview URL (e.g., `https://abc123.azurestaticapps.net`)
2. Check that `https://*.azurestaticapps.net` is in Auth0's "Allowed Web Origins"
3. Check API CORS configuration in `services/shared/shared/config.py`:
   ```python
   cors_origin_regex: str | None = Field(
       default=r"^https://.*\.azurestaticapps\.net$",
   )
   ```

### Issue: Wildcard callback URLs not working

**Symptom:** Preview environments fail to authenticate even though wildcard is configured

**Cause:** Auth0 free tier may not support wildcards in some regions/configurations

**Workaround:**
1. Use GitHub Actions to dynamically add/remove callback URLs via Auth0 Management API
2. Update `.github/workflows/preview.yml` to add callback URL on PR create
3. Update `.github/workflows/preview-cleanup.yml` to remove callback URL on PR close

---

## Security Considerations

1. **Session Secret Rotation:**
   - The `AUTH0_SESSION_SECRET` is used to sign auth state payloads
   - Rotate this secret every 90 days
   - When rotating, old sessions will be invalidated

2. **Client Secret Protection:**
   - Never commit the Auth0 client secret to git
   - Always store in Azure Key Vault
   - Use Kubernetes ExternalSecrets to inject into pods

3. **Callback URL Validation:**
   - The Auth0 BFF validates that `returnTo` URLs match allowed CORS origins
   - This prevents open redirect attacks

4. **Session Storage:**
   - Current implementation uses in-memory session storage
   - For production, consider using Redis for distributed sessions
   - See `services/api/src/api/routes/auth.py` for implementation

---

## References

- [Auth0 Documentation](https://auth0.com/docs)
- [Auth0 Terraform Provider](https://registry.terraform.io/providers/auth0/auth0/latest/docs)
- [Auth0 Management API](https://auth0.com/docs/api/management/v2)
- [BFF Pattern](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps#section-6.2)
