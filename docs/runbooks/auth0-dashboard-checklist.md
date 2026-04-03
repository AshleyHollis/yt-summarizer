# Auth0 Dashboard Configuration Checklist

> **Use this checklist to configure Auth0 for production deployment on Azure Static Web Apps**

## Access Auth0 Dashboard

1. Go to: https://manage.auth0.com
2. Log in with your Auth0 account
3. Select tenant: `dev-yt-summarizer` (or your tenant name)

---

## Step 1: Application Settings

### Navigate to Application
- [ ] Go to **Applications** → **Applications** in left sidebar
- [ ] Find application: **yt-summarizer-production** (or create if missing)
- [ ] Click on the application name to open settings

### Basic Information
- [ ] **Application Type**: Regular Web Application ✅
- [ ] **Token Endpoint Authentication Method**: Post ✅
- [ ] Copy **Domain**: `dev-yt-summarizer.us.auth0.com` (for `AUTH0_ISSUER_BASE_URL`)
- [ ] Copy **Client ID**: (for `AUTH0_CLIENT_ID`)
- [ ] Copy **Client Secret**: (for `AUTH0_CLIENT_SECRET`)
  - **CRITICAL**: Store in Azure Key Vault, never commit to git

### Application URIs

**Allowed Callback URLs** (comma-separated, no spaces):
```
https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net/api/auth/callback,http://localhost:3000/api/auth/callback
```
- [ ] Paste into **Allowed Callback URLs** field
- [ ] Verify NO trailing slashes
- [ ] Verify HTTPS for production domain

**Allowed Logout URLs** (comma-separated):
```
https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net,http://localhost:3000
```
- [ ] Paste into **Allowed Logout URLs** field
- [ ] Verify NO trailing slashes

**Allowed Web Origins** (comma-separated):
```
https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net,http://localhost:3000
```
- [ ] Paste into **Allowed Web Origins** field
- [ ] Required for CORS and silent authentication

### Advanced Settings

- [ ] Go to **Advanced Settings** tab
- [ ] **Grant Types**:
  - [x] Authorization Code
  - [x] Refresh Token
  - [ ] Implicit (leave unchecked - not secure)
  - [ ] Password (only enable for test accounts, see Step 4)
- [ ] **Refresh Token Settings**:
  - [ ] **Refresh Token Rotation**: Enabled (reuse detection)
  - [ ] **Refresh Token Expiration**: Absolute 30 days, Inactivity 7 days
- [ ] Click **Save Changes** at bottom

---

## Step 2: Social Connections (Google & GitHub)

### Configure Google OAuth

#### Prerequisites
1. [ ] Google OAuth app created in [Google Cloud Console](https://console.cloud.google.com/)
2. [ ] OAuth 2.0 Client ID credentials created
3. [ ] **Authorized redirect URIs** in Google Console includes:
   ```
   https://dev-yt-summarizer.us.auth0.com/login/callback
   ```

#### Auth0 Configuration
- [ ] Go to **Authentication** → **Social** in left sidebar
- [ ] Find **Google** and click the toggle to enable
- [ ] Click on **Google** to configure
- [ ] **Client ID**: (from Google Cloud Console)
- [ ] **Client Secret**: (from Google Cloud Console)
- [ ] **Attributes**: Email, Profile (default)
- [ ] **Permissions**: email, profile (default)
- [ ] Click **Save**
- [ ] Go to **Applications** tab
- [ ] Enable for **yt-summarizer-production** application
- [ ] Click **Save**

### Configure GitHub OAuth

#### Prerequisites
1. [ ] GitHub OAuth app created in [GitHub Developer Settings](https://github.com/settings/developers)
2. [ ] **Authorization callback URL** in GitHub app includes:
   ```
   https://dev-yt-summarizer.us.auth0.com/login/callback
   ```

#### Auth0 Configuration
- [ ] Go to **Authentication** → **Social** in left sidebar
- [ ] Find **GitHub** and click the toggle to enable
- [ ] Click on **GitHub** to configure
- [ ] **Client ID**: (from GitHub OAuth app)
- [ ] **Client Secret**: (from GitHub OAuth app)
- [ ] **Attributes**: Email, Profile (default)
- [ ] **Permissions**: user:email, read:user (default)
- [ ] Click **Save**
- [ ] Go to **Applications** tab
- [ ] Enable for **yt-summarizer-production** application
- [ ] Click **Save**

---

## Step 3: Database Connection (Username/Password for Test Accounts)

### Create Database Connection
- [ ] Go to **Authentication** → **Database** in left sidebar
- [ ] Click **+ Create DB Connection**
- [ ] **Name**: `Username-Password-Authentication` (use exact name)
- [ ] **Database**: Built-in Auth0 user store
- [ ] Click **Create**

### Password Policy
- [ ] Go to **Password Policy** tab
- [ ] **Password Strength**: Good (8 chars, mixed case, number, special)
- [ ] **Password History**: 5 passwords
- [ ] **Password Dictionary**: Enabled
- [ ] Click **Save**

### Applications
- [ ] Go to **Applications** tab
- [ ] Enable for **yt-summarizer-production**
- [ ] Click **Save**

### Settings (Optional for Test Accounts)
- [ ] Go to **Settings** tab
- [ ] **Disable Sign Ups**: Enabled (only for production - test accounts created via Terraform)
- [ ] **Requires Username**: Optional (use email as username)
- [ ] **Import Users to Auth0**: Disabled
- [ ] Click **Save**

---

## Step 4: Enable Resource Owner Password Grant (For E2E Tests ONLY)

**⚠️ WARNING**: Only enable this for test accounts. Do NOT use for production user authentication.

### Application Settings
- [ ] Go to **Applications** → **yt-summarizer-production**
- [ ] **Advanced Settings** → **Grant Types**
- [ ] Enable **Password** grant type
- [ ] Scroll to **Authentication Methods**
- [ ] Verify **None** is NOT selected (use Post or Basic)
- [ ] Click **Save Changes**

**Why**: Playwright E2E tests use programmatic authentication (username/password grant) to obtain tokens without browser interaction.

---

## Step 5: Auth0 Actions (Role Claims)

### Create Action for Adding Roles to Tokens

- [ ] Go to **Actions** → **Library** in left sidebar
- [ ] Click **+ Build Custom**
- [ ] **Name**: `Add Roles to Tokens`
- [ ] **Trigger**: **Login / Post Login**
- [ ] **Runtime**: Node 18 (Recommended)
- [ ] Click **Create**

### Action Code
Paste this code:

```javascript
/**
 * Add role claims to ID and Access tokens
 *
 * Reads user.app_metadata.role and injects as custom claim
 * Namespace: https://yt-summarizer.com/role
 */
exports.onExecutePostLogin = async (event, api) => {
  const namespace = 'https://yt-summarizer.com/';

  if (event.user.app_metadata && event.user.app_metadata.role) {
    const role = event.user.app_metadata.role;

    // Add role to ID token (for frontend)
    api.idToken.setCustomClaim(`${namespace}role`, role);

    // Add role to Access token (for API authorization)
    api.accessToken.setCustomClaim(`${namespace}role`, role);
  } else {
    // Default role if missing
    api.idToken.setCustomClaim(`${namespace}role`, 'normal');
    api.accessToken.setCustomClaim(`${namespace}role`, 'normal');
  }
};
```

- [ ] Paste code into editor
- [ ] Click **Deploy** (top right)
- [ ] Wait for "Deployed" status

### Bind Action to Login Flow
- [ ] Go to **Actions** → **Flows** → **Login**
- [ ] Find **Add Roles to Tokens** in right sidebar (Custom tab)
- [ ] Drag and drop between **Start** and **Complete** nodes
- [ ] Click **Apply** (top right)
- [ ] Confirm "Flow Updated" notification

---

## Step 6: Test Users (Via Terraform - Automated)

**Note**: Test users are created via Terraform. This section is for manual creation if needed.

### Manual Test User Creation (Optional)

#### Admin Test User
- [ ] Go to **User Management** → **Users**
- [ ] Click **+ Create User**
- [ ] **Email**: `admin@test.yt-summarizer.internal`
- [ ] **Password**: (secure random password, store in Azure Key Vault)
- [ ] **Connection**: Username-Password-Authentication
- [ ] **Email Verified**: Yes
- [ ] Click **Create**
- [ ] Click on the user
- [ ] Scroll to **Metadata** section → **App Metadata** tab
- [ ] Add:
  ```json
  {
    "role": "admin"
  }
  ```
- [ ] Click **Save**

#### Normal Test User
- [ ] Repeat steps above with:
  - Email: `user@test.yt-summarizer.internal`
  - App Metadata: `{"role": "normal"}`

**Recommended**: Use Terraform to create test users instead (see `infra/terraform/modules/auth0/main.tf`)

---

## Step 7: Verify Configuration

### Test Login Flow (Manual)
1. [ ] Open browser to: `https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net/api/auth/login`
2. [ ] Expect: Redirect to Auth0 Universal Login page
3. [ ] Click "Continue with Google" or "Continue with GitHub"
4. [ ] Complete OAuth flow
5. [ ] Expect: Redirect back to `https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net/api/auth/callback?code=...`
6. [ ] Expect: Final redirect to app home page
7. [ ] Verify: User profile appears in navbar
8. [ ] Refresh page
9. [ ] Verify: Still logged in (session persists)
10. [ ] Click "Sign out"
11. [ ] Verify: Logged out successfully

### Test Username/Password Login
1. [ ] Navigate to: `https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net/login`
2. [ ] Click "Username-Password" tab
3. [ ] Enter test user credentials
4. [ ] Click "Sign In"
5. [ ] Verify: Logged in successfully

### Check Auth0 Logs
- [ ] Go to **Monitoring** → **Logs**
- [ ] Look for recent **Success Login** events
- [ ] Verify no errors in log stream
- [ ] Check **User** field matches your test login
- [ ] Check **Connection** shows correct provider (google-oauth2, github, auth0)

---

## Step 8: Environment Variable Confirmation

These values should be set in **Azure Portal** → **Static Web Apps** → **Configuration**:

- [ ] `AUTH0_SECRET` = (32+ hex bytes from Key Vault)
- [ ] `AUTH0_BASE_URL` = `https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net`
- [ ] `AUTH0_ISSUER_BASE_URL` = `https://dev-yt-summarizer.us.auth0.com`
- [ ] `AUTH0_CLIENT_ID` = (from Step 1)
- [ ] `AUTH0_CLIENT_SECRET` = (from Step 1, stored in Key Vault)

**See**: `apps/web/SWA-AUTH0-DEPLOYMENT.md` for detailed instructions.

---

## Troubleshooting

### "redirect_uri_mismatch" error
- [ ] Verify callback URL in Step 1 matches **exactly** (no trailing slash)
- [ ] Verify protocol is `https://` for production, `http://` for localhost

### "access_denied" error
- [ ] Check Auth0 Logs for specific error message
- [ ] Verify application is enabled for selected connection (Step 2)
- [ ] Verify user has required permissions

### No role in token claims
- [ ] Verify Action is deployed (Step 5)
- [ ] Verify Action is bound to Login flow (Step 5)
- [ ] Verify user has `app_metadata.role` set (Step 6)
- [ ] Check token contents at https://jwt.io

### E2E tests fail authentication
- [ ] Verify Password grant enabled (Step 4)
- [ ] Verify test user exists (Step 6)
- [ ] Verify test credentials in Azure Key Vault
- [ ] Check Auth0 Logs for failed login attempts

---

## Completion Checklist

Before marking Auth0 configuration as complete:

- [ ] All 5 Application URIs configured (Step 1)
- [ ] Google OAuth enabled and configured (Step 2)
- [ ] GitHub OAuth enabled and configured (Step 2)
- [ ] Database connection created (Step 3)
- [ ] Password grant enabled for tests (Step 4)
- [ ] Role Action deployed and bound to Login flow (Step 5)
- [ ] Test users created (Step 6 or Terraform)
- [ ] Manual login test successful (Step 7)
- [ ] Auth0 logs show successful logins (Step 7)
- [ ] Environment variables set in Azure Portal (Step 8)

---

**Status**: ✅ Configuration complete when all items checked

**Last Updated**: 2026-01-19  
**Maintainer**: YT Summarizer Team  
**Auth0 Tenant**: dev-yt-summarizer.us.auth0.com
