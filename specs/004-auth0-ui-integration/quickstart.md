# Auth0 UI Integration - Local Development Quickstart

> **Quick setup guide for developers** to get Auth0 authentication working in local development.

**Time to complete**: ~15 minutes

---

## Prerequisites

Before you begin, ensure you have:

- [ ] Node.js 20+ installed
- [ ] npm or pnpm installed
- [ ] Access to the YT Summarizer codebase
- [ ] Auth0 tenant credentials (or access to Azure Key Vault for production credentials)
- [ ] Terraform installed (if provisioning test users)

---

## Step 1: Install Dependencies

```bash
cd apps/web
npm install
```

This installs `@auth0/nextjs-auth0` and other required packages.

---

## Step 2: Configure Environment Variables

### Option A: Use Existing Production Credentials (Recommended)

If you have access to the production Auth0 tenant:

```bash
# Navigate to web app directory
cd apps/web

# Copy example env file
cp .env.example .env.local

# Retrieve credentials from Azure Key Vault
az keyvault secret show --vault-name yt-summarizer-kv --name auth0-secret --query value -o tsv
az keyvault secret show --vault-name yt-summarizer-kv --name auth0-client-id --query value -o tsv
az keyvault secret show --vault-name yt-summarizer-kv --name auth0-client-secret --query value -o tsv
```

Edit `.env.local` with the retrieved values:

```bash
# Auth0 Configuration (Production Tenant)
AUTH0_SECRET="<from-key-vault>"
AUTH0_BASE_URL="http://localhost:3000"
AUTH0_ISSUER_BASE_URL="https://dev-yt-summarizer.us.auth0.com"
AUTH0_CLIENT_ID="<from-key-vault>"
AUTH0_CLIENT_SECRET="<from-key-vault>"

# Optional: Test user credentials (for E2E tests)
AUTH0_ADMIN_TEST_EMAIL="admin@test.yt-summarizer.internal"
AUTH0_ADMIN_TEST_PASSWORD="<from-key-vault>"
AUTH0_USER_TEST_EMAIL="user@test.yt-summarizer.internal"
AUTH0_USER_TEST_PASSWORD="<from-key-vault>"
```

### Option B: Create Your Own Auth0 Tenant (Development)

If you want a separate development tenant:

1. **Create Auth0 Account**:
   - Go to https://auth0.com/signup
   - Create a free account
   - Choose a tenant domain (e.g., `dev-yourname.us.auth0.com`)

2. **Create Auth0 Application**:
   - In Auth0 Dashboard → Applications → Create Application
   - Name: "YT Summarizer Dev"
   - Type: "Regular Web Application"
   - Technology: "Next.js"

3. **Configure Application Settings**:
   - **Allowed Callback URLs**: `http://localhost:3000/api/auth/callback`
   - **Allowed Logout URLs**: `http://localhost:3000`
   - **Allowed Web Origins**: `http://localhost:3000`
   - Save changes

4. **Copy Credentials**:
   - Go to Settings tab
   - Copy "Domain", "Client ID", "Client Secret"

5. **Create `.env.local`**:
   ```bash
   cd apps/web
   cp .env.example .env.local
   ```

6. **Edit `.env.local`**:
   ```bash
   # Generate random secret
   AUTH0_SECRET="$(openssl rand -hex 32)"
   
   # Your Auth0 application settings
   AUTH0_BASE_URL="http://localhost:3000"
   AUTH0_ISSUER_BASE_URL="https://YOUR-TENANT.us.auth0.com"
   AUTH0_CLIENT_ID="YOUR-CLIENT-ID"
   AUTH0_CLIENT_SECRET="YOUR-CLIENT-SECRET"
   ```

---

## Step 3: Configure Social Connections (Optional)

To enable Google and GitHub login:

### Google OAuth

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable "Google+ API"
4. Create OAuth 2.0 credentials:
   - **Authorized redirect URIs**: `https://YOUR-TENANT.us.auth0.com/login/callback`
5. Copy Client ID and Client Secret
6. In Auth0 Dashboard → Authentication → Social:
   - Enable Google
   - Paste Google Client ID and Secret
   - Save

### GitHub OAuth

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill in details:
   - **Application name**: YT Summarizer Dev
   - **Homepage URL**: `http://localhost:3000`
   - **Authorization callback URL**: `https://YOUR-TENANT.us.auth0.com/login/callback`
4. Copy Client ID and Client Secret
5. In Auth0 Dashboard → Authentication → Social:
   - Enable GitHub
   - Paste GitHub Client ID and Secret
   - Save

---

## Step 4: Create Test Users

### Option A: Use Terraform (Production Approach)

If you're using the production tenant and have Terraform access:

```bash
# Navigate to Terraform directory
cd infra/terraform/environments/prod

# Initialize Terraform (if not already done)
terraform init

# Plan and apply (creates test users)
terraform plan
terraform apply
```

This creates:
- `admin@test.yt-summarizer.internal` (admin role)
- `user@test.yt-summarizer.internal` (user role)

Passwords are randomly generated and stored in Azure Key Vault.

### Option B: Create Manually (Development)

For development tenants, create test users manually:

1. In Auth0 Dashboard → User Management → Users
2. Click "Create User"
3. Fill in:
   - **Email**: `admin@test.local`
   - **Password**: (choose secure password)
   - **Connection**: "Username-Password-Authentication"
4. Click "Create"
5. Edit user → Metadata (App Metadata tab):
   ```json
   {
     "role": "admin"
   }
   ```
6. Save

Repeat for normal user:
- **Email**: `user@test.local`
- **App Metadata**: `{"role": "user"}`

---

## Step 5: Configure Auth0 Actions (Role Claims)

This step adds role information to the ID token so the app can enforce RBAC.

1. In Auth0 Dashboard → Actions → Library
2. Click "Build Custom"
3. Name: "Add Roles to Tokens"
4. Trigger: "Login / Post Login"
5. Code:
   ```javascript
   exports.onExecutePostLogin = async (event, api) => {
     const namespace = 'https://yt-summarizer.com/';
     
     if (event.user.app_metadata && event.user.app_metadata.role) {
       const role = event.user.app_metadata.role;
       
       // Add role to ID token
       api.idToken.setCustomClaim(`${namespace}role`, role);
       
       // Add role to access token (for API authorization)
       api.accessToken.setCustomClaim(`${namespace}role`, role);
     }
   };
   ```
6. Click "Deploy"
7. Go to Actions → Flows → Login
8. Drag "Add Roles to Tokens" to the flow (between "Start" and "Complete")
9. Click "Apply"

---

## Step 6: Start the Development Server

```bash
cd apps/web
npm run dev
```

The app will be available at http://localhost:3000

---

## Step 7: Test Authentication

### Test Social Login (if configured)

1. Navigate to http://localhost:3000/login
2. Click "Sign in with Google" or "Sign in with GitHub"
3. Complete OAuth flow
4. You should be redirected to the home page
5. Your profile should appear in the navbar

### Test Username/Password Login

1. Navigate to http://localhost:3000/login
2. Scroll to "Sign in with Username/Password" section
3. Enter:
   - **Email**: `admin@test.local` (or your created user)
   - **Password**: (your password)
4. Click "Sign In"
5. You should be redirected to the home page

### Test Admin Access

1. Log in as admin user (`admin@test.local`)
2. Navigate to http://localhost:3000/admin
3. You should see the admin dashboard
4. Logout
5. Log in as normal user (`user@test.local`)
6. Navigate to http://localhost:3000/admin
7. You should be redirected to `/access-denied`

---

## Step 8: Run Tests

### Unit Tests

```bash
cd apps/web
npm run test:run
```

Expected output:
```
✓ apps/web/src/__tests__/hooks/useAuth.test.tsx (10 tests)
✓ apps/web/src/__tests__/lib/auth-utils.test.ts (36 tests)
✓ apps/web/src/__tests__/components/auth/LoginButton.test.tsx (14 tests)
✓ apps/web/src/__tests__/components/auth/UserProfile.test.tsx (25 tests)
... (411 tests total)
```

### E2E Tests (Requires Test User Credentials)

First, set test user credentials:

```bash
# Export test credentials
export AUTH0_ADMIN_TEST_EMAIL="admin@test.local"
export AUTH0_ADMIN_TEST_PASSWORD="your-admin-password"
export AUTH0_USER_TEST_EMAIL="user@test.local"
export AUTH0_USER_TEST_PASSWORD="your-user-password"
```

Run Playwright auth setup:

```bash
cd apps/web
npx playwright test --project=setup
```

Expected output:
```
✓ [setup] › auth.setup.ts:41:7 › authenticate as admin (5s)
✓ [setup] › auth.setup.ts:97:7 › authenticate as normal user (4s)
```

Run E2E tests:

```bash
npx playwright test
```

Or run specific auth tests:

```bash
npx playwright test e2e/auth-social-login.spec.ts
npx playwright test e2e/rbac-admin-access.spec.ts
npx playwright test e2e/auth-username-password.spec.ts
```

---

## Troubleshooting

### Issue: "Auth0 is not configured"

**Cause**: Missing environment variables

**Solution**: Verify `.env.local` exists and contains all required variables:

```bash
cat apps/web/.env.local | grep AUTH0
```

Should show:
```
AUTH0_SECRET=...
AUTH0_BASE_URL=http://localhost:3000
AUTH0_ISSUER_BASE_URL=https://...
AUTH0_CLIENT_ID=...
AUTH0_CLIENT_SECRET=...
```

### Issue: "Callback URL mismatch"

**Cause**: Auth0 application not configured with correct callback URL

**Solution**: In Auth0 Dashboard → Applications → Your App → Settings:
- Add `http://localhost:3000/api/auth/callback` to "Allowed Callback URLs"
- Add `http://localhost:3000` to "Allowed Logout URLs"
- Add `http://localhost:3000` to "Allowed Web Origins"
- Save changes

### Issue: "Cannot read properties of null (reading 'roles')"

**Cause**: User doesn't have roles in `app_metadata`

**Solution**: Edit user in Auth0 Dashboard:
1. Go to User Management → Users
2. Click on the user
3. Scroll to "Metadata" section
4. Click "App Metadata" tab
5. Add:
   ```json
   {
     "role": "user"
   }
   ```
6. Save

### Issue: Redirect loop on login

**Cause**: Middleware configuration issue

**Solution**: Check `apps/web/src/middleware.ts`:
```typescript
export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
};
```

Ensure `/api/auth` routes are excluded from middleware.

### Issue: E2E tests fail with "Timeout waiting for login"

**Cause**: Test credentials incorrect or Auth0 tenant not accessible

**Solution**:
1. Verify credentials:
   ```bash
   echo $AUTH0_ADMIN_TEST_EMAIL
   echo $AUTH0_USER_TEST_EMAIL
   ```
2. Manually test login at http://localhost:3000/login
3. Check browser console for errors
4. Verify Auth0 Action is deployed and active

### Issue: "CORS error" in browser console

**Cause**: Missing CORS configuration

**Solution**: In Auth0 Dashboard → Applications → Your App → Settings:
- Add `http://localhost:3000` to "Allowed Web Origins"
- Save changes

---

## Next Steps

Once you have authentication working locally:

1. **Read the full documentation**: `apps/web/src/components/auth/README.md`
2. **Explore the codebase**:
   - Auth context: `apps/web/src/contexts/AuthContext.tsx`
   - Auth hooks: `apps/web/src/hooks/useAuth.ts`
   - Auth components: `apps/web/src/components/auth/`
   - Middleware: `apps/web/src/middleware.ts`
3. **Try adding a new role** (see README section "Adding New Roles")
4. **Try adding a new social provider** (see README section "Adding New Social Providers")

---

## Production Deployment

For production deployment:

1. **Never commit `.env.local`** to version control
2. **Store credentials in Azure Key Vault**:
   ```bash
   az keyvault secret set --vault-name yt-summarizer-kv --name auth0-secret --value "..."
   az keyvault secret set --vault-name yt-summarizer-kv --name auth0-client-id --value "..."
   az keyvault secret set --vault-name yt-summarizer-kv --name auth0-client-secret --value "..."
   ```
3. **Use Terraform for infrastructure**:
   ```bash
   cd infra/terraform/environments/prod
   terraform apply
   ```
4. **Set production environment variables** in your hosting platform (Vercel, Azure Static Web Apps, etc.)

---

## Additional Resources

- **Auth0 Next.js SDK**: https://github.com/auth0/nextjs-auth0
- **Auth0 Dashboard**: https://manage.auth0.com/
- **Auth0 Docs**: https://auth0.com/docs
- **Full Auth Module README**: `apps/web/src/components/auth/README.md`

---

## Getting Help

If you encounter issues not covered in this guide:

1. Check the [Auth Module README](../apps/web/src/components/auth/README.md) troubleshooting section
2. Review Auth0 logs in the Dashboard → Monitoring → Logs
3. Check browser console for errors
4. Review Next.js server logs in terminal
5. Ask in team chat or open an issue

**Happy coding! 🚀**
