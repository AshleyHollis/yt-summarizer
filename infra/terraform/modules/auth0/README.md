# Auth0 Terraform Module

This module configures Auth0 application and API resources for the YT Summarizer.

## Prerequisites

### Required Auth0 Management API Permissions

The Machine-to-Machine application used by Terraform (via `AUTH0_CLIENT_ID` and `AUTH0_CLIENT_SECRET`) **must have the following scopes** granted in the Auth0 Management API:

**Required Scopes:**
- `read:clients` - Read client applications
- `create:clients` - Create client applications
- `update:clients` - Update client applications
- `delete:clients` - Delete client applications
- `read:client_keys` - **CRITICAL:** Read client secrets (required for auth0_client_credentials resource)
- `read:client_credentials` - **CRITICAL:** Read client credential details (required for auth0_client_credentials resource)
- `read:client_grants` - Read client grants
- `create:client_grants` - Create client grants
- `update:client_grants` - Update client grants
- `delete:client_grants` - Delete client grants
- `read:resource_servers` - Read API resource servers
- `create:resource_servers` - Create API resource servers
- `update:resource_servers` - Update API resource servers
- `delete:resource_servers` - Delete API resource servers

> **⚠️ IMPORTANT:** Without `read:client_keys` and `read:client_credentials` scopes, the `auth0_client_credentials` resource will return **empty client secrets**, causing authentication failures!

### How to Grant Permissions

1. **Log in to Auth0 Dashboard** → https://manage.auth0.com/
2. **Navigate to Applications** → Applications
3. **Find or Create the Terraform M2M Application**:
   - If you don't have one, create a new **Machine to Machine** application
   - Name it something like "Terraform Management API"
4. **Configure API Access**:
   - Click on the application
   - Go to the **APIs** tab
   - Find **Auth0 Management API** and click the arrow to expand
   - Check the following permissions:
     - ✅ `read:clients`
     - ✅ `create:clients`
     - ✅ `update:clients`
     - ✅ `delete:clients`
     - ✅ `read:client_keys` ← **CRITICAL for retrieving client secrets**
     - ✅ `read:client_credentials` ← **CRITICAL for retrieving client secrets**
     - ✅ `read:client_grants`
     - ✅ `create:client_grants`
     - ✅ `update:client_grants`
     - ✅ `delete:client_grants`
     - ✅ `read:resource_servers`
     - ✅ `create:resource_servers`
     - ✅ `update:resource_servers`
     - ✅ `delete:resource_servers`
   - Click **Update**
5. **Get Credentials**:
   - Go to the **Settings** tab
   - Copy the **Client ID** → Set as `AUTH0_CLIENT_ID` environment variable
   - Copy the **Client Secret** → Set as `AUTH0_CLIENT_SECRET` environment variable
   - Copy your **Domain** → Set as `AUTH0_DOMAIN` environment variable

## Environment Variables

```bash
export AUTH0_DOMAIN="your-tenant.auth0.com"
export AUTH0_CLIENT_ID="your-m2m-client-id"
export AUTH0_CLIENT_SECRET="your-m2m-client-secret"
```

## Enabling Auth0 in Terraform

By default, Auth0 resources are **disabled** to prevent deployment failures when permissions are not configured.

To enable Auth0:

```hcl
# infra/terraform/environments/prod/terraform.tfvars
enable_auth0 = true
```

Or via command line:

```bash
terraform apply -var="enable_auth0=true"
```

## Troubleshooting

### Error: "403 Forbidden: Insufficient scope, expected any of: read:client_keys" or "read:client_credentials"

This error occurs when the Terraform M2M application lacks the `read:client_keys` or `read:client_credentials` scopes. These scopes are **required** for the `auth0_client_credentials` resource to retrieve client secrets.

**Fix:** Follow the "How to Grant Permissions" section above and ensure both `read:client_keys` and `read:client_credentials` are checked.

**Symptoms when scopes are missing:**
- Terraform runs without errors
- Client secrets in Azure Key Vault are **empty strings**
- ExternalSecrets sync successfully but contain empty values
- API authentication fails with "invalid client secret"

### Error: "oauth2: access_denied" "Unauthorized"

This error means the M2M application doesn't have the required permissions. Follow the "How to Grant Permissions" section above.

### Error: "Invalid credentials"

- Verify `AUTH0_DOMAIN` does **not** include `https://`
- Verify `AUTH0_CLIENT_ID` and `AUTH0_CLIENT_SECRET` are correct
- Ensure the M2M application is **enabled** in Auth0

## Resources Created

When enabled (`enable_auth0 = true`), this module creates:

1. **Auth0 Client** (`auth0_client.bff`):
   - Application type: Regular Web Application
   - Grant types: Authorization Code, Refresh Token
   - Configured with callback URLs, logout URLs, and web origins

2. **Auth0 Client Credentials** (`auth0_client_credentials.bff`):
   - Retrieves the client secret for the BFF application
   - Requires `read:client_keys` and `read:client_credentials` scopes
   - The client secret is outputted via `application_client_secret` for secure storage in Azure Key Vault

3. **Auth0 Resource Server** (`auth0_resource_server.api`) - Optional:
   - Created only if `api_identifier` is provided
   - Signing algorithm: RS256
   - Offline access enabled for refresh tokens

## Outputs

- `auth0_domain` - Auth0 tenant domain
- `application_client_id` - Auth0 application client ID
- `application_client_secret` - Auth0 application client secret (sensitive)
- `application_name` - Auth0 application name
- `api_identifier` - Auth0 API identifier (audience) if resource server is created
