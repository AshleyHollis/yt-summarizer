# Fix Auth0 Terraform Service Account Permissions

## Problem
Terraform is failing with "403 Forbidden: Insufficient scope" errors when trying to create:
- Auth0 connections (database, Google, GitHub)
- Auth0 actions (role claims)

## Root Cause
The Auth0 Terraform service account is missing required Management API scopes.

## Solution

### Option 1: Run via GitHub Actions (Automated)

1. **Merge this PR to main** (or push workflow to main branch):
   ```bash
   # The configure-auth0-permissions.yml workflow needs to be on main to run
   ```

2. **Trigger the workflow**:
   ```bash
   gh workflow run configure-auth0-permissions.yml
   ```

3. **Monitor the run**:
   ```bash
   gh run watch
   ```

### Option 2: Run Script Locally (Manual)

1. **Get Auth0 credentials from GitHub Secrets** (requires admin access):
   ```bash
   # You'll need to manually copy these from GitHub Secrets UI:
   # Settings → Secrets and variables → Actions → Repository secrets
   
   # Look for:
   # - AUTH0_DOMAIN
   # - AUTH0_CLIENT_ID  
   # - AUTH0_CLIENT_SECRET
   ```

2. **Run the configuration script**:
   ```powershell
   cd C:\Users\ashle\Source\GitHub\AshleyHollis\yt-summarizer
   
   # Set environment variables (replace with actual values from GitHub Secrets)
   $env:AUTH0_DOMAIN = "dev-gvli0bfdrue0h8po.us.auth0.com"
   $env:AUTH0_CLIENT_ID = "Fmh7q7q2OrqUvmSXTgBxr3E7v5KdAbt6"
   $env:AUTH0_CLIENT_SECRET = "<get-from-github-secrets>"
   
   # Run the script
   .\scripts\configure-auth0-permissions.ps1
   ```

3. **Verify success**:
   The script will output:
   ```
   ✅ Successfully updated client grant!
   
   New scopes:
      - read:clients
      - create:clients
      - update:clients
      - delete:clients
      - read:client_grants
      - create:client_grants
      - update:client_grants
      - delete:client_grants
      - read:resource_servers
      - create:resource_servers
      - update:resource_servers
      - delete:resource_servers
      - read:connections          ← NEW
      - create:connections         ← NEW
      - update:connections         ← NEW
      - delete:connections         ← NEW
      - read:actions               ← NEW
      - create:actions             ← NEW
      - update:actions             ← NEW
      - delete:actions             ← NEW
      - read:roles                 ← NEW
      - create:roles               ← NEW
      - update:roles               ← NEW
      - delete:roles               ← NEW
      - read:role_members          ← NEW
      - create:role_members        ← NEW
      - delete:role_members        ← NEW
   ```

### Option 3: Configure via Auth0 Dashboard (Manual UI)

1. **Login to Auth0 Dashboard**: https://manage.auth0.com

2. **Navigate to the Terraform Service Account**:
   - Applications → Machine to Machine Applications
   - Find: "Terraform Service Account"

3. **Update API Permissions**:
   - Click on the application
   - Go to "APIs" tab
   - Expand "Auth0 Management API"
   - Click "Update" or "Authorize"

4. **Grant Additional Scopes**:
   Find and enable these scopes (in addition to existing ones):
   
   **Connections:**
   - ☑ read:connections
   - ☑ create:connections
   - ☑ update:connections
   - ☑ delete:connections
   
   **Actions:**
   - ☑ read:actions
   - ☑ create:actions
   - ☑ update:actions
   - ☑ delete:actions
   
   **Roles (RBAC):**
   - ☑ read:roles
   - ☑ create:roles
   - ☑ update:roles
   - ☑ delete:roles
   - ☑ read:role_members
   - ☑ create:role_members
   - ☑ delete:role_members

5. **Save Changes**

## After Fixing Permissions

1. **Re-trigger the preview pipeline**:
   ```bash
   # Push an empty commit to trigger the pipeline
   git commit --allow-empty -m "chore: re-trigger pipeline after Auth0 permissions fix"
   git push
   ```

2. **Monitor Terraform Apply**:
   - Go to: https://github.com/AshleyHollis/yt-summarizer/actions
   - Find the "Preview Deployment" workflow
   - Check the "Terraform Apply" job
   - Should now succeed and create all 16 Auth0 resources

## Expected Terraform Resources

After permissions are fixed, Terraform will create:

1. **Auth0 Application**: `yt-summarizer-api-bff` (for user authentication)
2. **Auth0 API**: `yt-summarizer-api` (resource server)
3. **Auth0 Connections**:
   - Database connection (username/password)
   - Google OAuth connection
   - GitHub OAuth connection
4. **Auth0 Action**: `add-role-claims` (adds user roles to JWT)
5. **Auth0 Roles**:
   - Admin role
   - User role
6. **Client Grants** and other configuration

## Verification

After Terraform succeeds:

1. **Check Auth0 Dashboard**:
   - Applications → Should see "yt-summarizer-api-bff"
   - APIs → Should see "yt-summarizer-api"
   - Authentication → Database → Should see custom connection
   - Authentication → Social → Should see Google and GitHub
   - Actions → Library → Should see "add-role-claims"
   - User Management → Roles → Should see admin and user roles

2. **Check Azure Key Vault**:
   ```bash
   az keyvault secret list --vault-name kv-ytsumm-prd --query "[?starts_with(name, 'auth0-')].name"
   
   # Should show:
   # - auth0-terraform-domain (service account)
   # - auth0-terraform-client-id (service account)
   # - auth0-terraform-client-secret (service account)
   # - auth0-domain (BFF app)
   # - auth0-client-id (BFF app)
   # - auth0-client-secret (BFF app)
   # - auth0-session-secret (BFF app)
   ```

3. **Check Kubernetes Secret Sync**:
   ```bash
   kubectl get secret auth0-credentials -n yt-summarizer
   ```

## Related Files

- **Script**: `scripts/configure-auth0-permissions.ps1`
- **Workflow**: `.github/workflows/configure-auth0-permissions.yml`
- **Documentation**: `docs/auth0-terraform-service-account.md`
- **Terraform Module**: `infra/terraform/modules/auth0/main.tf`
