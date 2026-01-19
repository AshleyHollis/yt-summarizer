# Auth0 on Azure Static Web Apps - Production Deployment Guide

> **Recommended Approach**: Use Terraform to configure Auth0 and SWA environment variables automatically.  
> See: [Auth0 SWA Terraform Setup](../../docs/auth0-swa-terraform-setup.md)

> **This Guide**: Manual configuration steps (for reference or troubleshooting).

## Problem Summary

The Auth0 login fails with HTTP 500 in production on Azure Static Web Apps due to:

1. Missing Auth0 API route handler (`/api/auth/[auth0]/route.ts`) - ✅ **FIXED**
2. Missing SWA health check exclusion in middleware matcher - ✅ **FIXED**
3. Missing server-side environment variables in Azure Portal - ⚙️ **Use Terraform** (see link above)
4. Incorrect Auth0 callback URLs for production domain - ⚙️ **Use Terraform** (see link above)

## Solution Architecture

### 1. Hybrid Next.js Rendering on SWA

Auth0's Next.js SDK (`@auth0/nextjs-auth0`) **requires server-side rendering** for session management. Azure Static Web Apps supports this via "Hybrid Next.js" mode.

**Configuration** (already correct in `next.config.ts`):

```typescript
output: 'standalone'; // ✅ Enables hybrid rendering
// NOT: output: 'export' // ❌ Would break Auth0
```

**Deployment** (already correct in `deploy-prod.yml`):

```yaml
- uses: Azure/static-web-apps-deploy@v1
  with:
    app_location: apps/web
    output_location: '' # ✅ Empty for hybrid Next.js
    skip_app_build: true # ✅ Build separately with env vars
```

### 2. Required Environment Variables

Auth0 Next.js SDK requires **5 mandatory server-side environment variables**:

| Variable                | Type        | Where to Set | Example                                                         |
| ----------------------- | ----------- | ------------ | --------------------------------------------------------------- |
| `AUTH0_SECRET`          | Server-only | Azure Portal | `openssl rand -hex 32`                                          |
| `AUTH0_BASE_URL`        | Server-only | Azure Portal | `https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net` |
| `AUTH0_ISSUER_BASE_URL` | Server-only | Azure Portal | `https://dev-yt-summarizer.us.auth0.com`                        |
| `AUTH0_CLIENT_ID`       | Server-only | Azure Portal | `abc123...`                                                     |
| `AUTH0_CLIENT_SECRET`   | Server-only | Azure Portal | `xyz789...` (from Auth0 app settings)                           |

**Why split between build-time and runtime?**

- **Build-time** (`NEXT_PUBLIC_*` in GitHub Actions `env:`): Inlined into browser bundle during `next build`
- **Runtime** (Azure Portal env vars): Available to Next.js API routes and server components at runtime

**Current Issue**: Server-only vars (AUTH0\_\*) are **missing** from Azure Portal → causes 500 errors.

### 3. Setting Environment Variables in Azure Portal

#### Option A: Azure Portal UI

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to your Static Web App: `swa-ytsumm-prd`
3. Settings → Configuration
4. Click "+ Add" for each variable:
   - `AUTH0_SECRET` = `<retrieve from Azure Key Vault: auth0-secret>`
   - `AUTH0_BASE_URL` = `https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net`
   - `AUTH0_ISSUER_BASE_URL` = `https://dev-yt-summarizer.us.auth0.com`
   - `AUTH0_CLIENT_ID` = `<retrieve from Azure Key Vault: auth0-client-id>`
   - `AUTH0_CLIENT_SECRET` = `<retrieve from Azure Key Vault: auth0-client-secret>`
5. Click "Save"
6. Redeploy the app (or wait for next deployment)

#### Option B: Azure CLI

```bash
# Retrieve secrets from Azure Key Vault
AUTH0_SECRET=$(az keyvault secret show --vault-name yt-summarizer-kv --name auth0-secret --query value -o tsv)
AUTH0_CLIENT_ID=$(az keyvault secret show --vault-name yt-summarizer-kv --name auth0-client-id --query value -o tsv)
AUTH0_CLIENT_SECRET=$(az keyvault secret show --vault-name yt-summarizer-kv --name auth0-client-secret --query value -o tsv)

# Set in SWA (replace resource group and SWA name if different)
az staticwebapp appsettings set \
  --name swa-ytsumm-prd \
  --resource-group rg-ytsumm-prd \
  --setting-names \
    AUTH0_SECRET="$AUTH0_SECRET" \
    AUTH0_BASE_URL="https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net" \
    AUTH0_ISSUER_BASE_URL="https://dev-yt-summarizer.us.auth0.com" \
    AUTH0_CLIENT_ID="$AUTH0_CLIENT_ID" \
    AUTH0_CLIENT_SECRET="$AUTH0_CLIENT_SECRET"
```

**Note**: These are server-side variables and NOT exposed to the browser.

### 4. Auth0 Dashboard Configuration

The production SWA domain must be registered in Auth0 application settings.

#### Required Settings in Auth0 Dashboard

1. Navigate to: https://manage.auth0.com → Applications → `yt-summarizer-production`
2. Settings tab → Application URIs

**Allowed Callback URLs** (comma-separated):

```
https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net/api/auth/callback,
http://localhost:3000/api/auth/callback
```

**Allowed Logout URLs** (comma-separated):

```
https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net,
http://localhost:3000
```

**Allowed Web Origins** (comma-separated):

```
https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net,
http://localhost:3000
```

3. Scroll to bottom → Click "Save Changes"

**Critical**: If these URLs don't match exactly, Auth0 will reject the callback with a `redirect_uri_mismatch` error.

### 5. Middleware Configuration (Already Fixed)

The middleware matcher must **exclude** Azure SWA internal paths (`/.swa/*`) to prevent intercepting health checks.

**Fixed in `apps/web/src/middleware.ts`**:

```typescript
export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt|\\.swa).*)',
    //                                                                    ^^^^^^ CRITICAL
  ],
};
```

**Why**: Azure SWA probes `/.swa/health.html` to verify app deployment. If middleware intercepts this, SWA marks the deployment as unhealthy.

### 6. Auth0 API Route Handler (Already Fixed)

The Auth0 Next.js SDK requires a catch-all API route handler to process login/logout/callback requests.

**Created at `apps/web/src/app/api/auth/[auth0]/route.ts`**:

```typescript
import { auth0 } from '@/lib/auth0';

export const GET = auth0.handleAuth();
export const POST = auth0.handleAuth();
```

This exposes:

- `GET /api/auth/login` → Redirects to Auth0 Universal Login
- `GET /api/auth/logout` → Clears session and redirects
- `GET /api/auth/callback` → Exchanges OAuth code for tokens
- `GET /api/auth/me` → Returns current user session

## Deployment Checklist

Use this checklist before deploying to production:

### Pre-Deployment

- [x] `next.config.ts` has `output: 'standalone'`
- [x] Middleware matcher excludes `\.swa` paths
- [x] Auth0 API route handler exists at `apps/web/src/app/api/auth/[auth0]/route.ts`
- [ ] Environment variables set in Azure Portal (see Section 3)
- [ ] Auth0 callback URLs configured (see Section 4)

### Post-Deployment Validation

- [ ] Visit `https://<your-swa-domain>/.swa/health.html` → Should return 200 OK
- [ ] Visit `https://<your-swa-domain>/api/auth/login` → Should redirect to Auth0 (302)
- [ ] Complete Auth0 login → Should redirect back to app with session cookie
- [ ] Visit `https://<your-swa-domain>/api/auth/me` → Should return user profile (200)
- [ ] Refresh page → Session should persist (no re-login required)
- [ ] Logout → Session should be cleared

## Testing Locally

Before deploying, test the full Auth0 flow locally:

```bash
# Set local environment variables
cd apps/web
cp .env.example .env.local

# Edit .env.local with Auth0 credentials
# AUTH0_SECRET="<generate with: openssl rand -hex 32>"
# AUTH0_BASE_URL="http://localhost:3000"
# AUTH0_ISSUER_BASE_URL="https://dev-yt-summarizer.us.auth0.com"
# AUTH0_CLIENT_ID="<from Auth0>"
# AUTH0_CLIENT_SECRET="<from Auth0>"

# Start dev server
npm run dev
```

**Test Flow**:

1. Visit http://localhost:3000/login
2. Click "Sign in with Google" or "Sign in with GitHub"
3. Complete OAuth flow → Should redirect back to http://localhost:3000
4. Verify user is logged in (navbar shows profile)
5. Refresh page → Session should persist
6. Click logout → Session should clear

## Troubleshooting

### Error: "Cannot find module '@auth0/nextjs-auth0/server'"

**Cause**: Package not installed
**Fix**: `cd apps/web && npm install`

### Error: HTTP 500 on `/api/auth/login`

**Cause**: Missing environment variables or incorrect middleware
**Fix**:

1. Check Azure Portal env vars (Section 3)
2. Verify middleware excludes `\.swa` (Section 5)
3. Verify route handler exists (Section 6)

### Error: "redirect_uri_mismatch"

**Cause**: Auth0 callback URL not registered
**Fix**: Add production SWA URL to Auth0 dashboard (Section 4)

### Error: "Callback URL mismatch"

**Cause**: `AUTH0_BASE_URL` env var doesn't match actual SWA domain
**Fix**: Verify `AUTH0_BASE_URL=https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net`

### Error: Session not persisting across page refreshes

**Cause**: `AUTH0_SECRET` env var missing or incorrect
**Fix**: Verify `AUTH0_SECRET` in Azure Portal (must be 32+ random hex bytes)

### Error: SWA deployment fails health check

**Cause**: Middleware intercepting `/.swa/health.html`
**Fix**: Add `\\.swa` to middleware matcher exclusion (Section 5)

## Production Deployment Flow

### Manual Deployment (Option A: GitHub Actions)

```bash
# 1. Merge PR with Auth0 fixes to main
git checkout main
git pull

# 2. Deploy workflow will:
#    - Build Next.js app with standalone output
#    - Deploy to Azure Static Web Apps
#    - SWA picks up env vars from Azure Portal

# 3. Verify deployment
curl -I https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net/.swa/health.html
# Expect: HTTP/2 200

curl -I https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net/api/auth/login
# Expect: HTTP/2 302 (redirect to Auth0)
```

### Manual Deployment (Option B: Azure CLI)

```bash
# Set environment variables in Azure Portal first (Section 3)

# Build locally
cd apps/web
npm run build

# Deploy to SWA
az staticwebapp deploy \
  --name swa-ytsumm-prd \
  --resource-group rg-ytsumm-prd \
  --source .
```

## Expected Behavior After Fix

### 1. Login Flow (Happy Path)

```
User clicks "Sign in"
  → Browser: GET /api/auth/login
  → Server: Generates Auth0 authorization URL with PKCE challenge
  → Browser: 302 redirect to https://dev-yt-summarizer.us.auth0.com/authorize?...
  → User: Completes OAuth consent screen
  → Auth0: 302 redirect to https://<swa-domain>/api/auth/callback?code=...
  → Server: Exchanges code for tokens, creates encrypted session cookie
  → Browser: 302 redirect to home page with session cookie set
  → User: Now authenticated, session persists across refreshes
```

### 2. Logout Flow

```
User clicks "Sign out"
  → Browser: GET /api/auth/logout
  → Server: Clears session cookie
  → Browser: 302 redirect to Auth0 logout endpoint
  → Auth0: 302 redirect back to https://<swa-domain>
  → User: Now logged out
```

### 3. Session Management

- **Session cookie**: `appSession` (httpOnly, secure, SameSite=Lax)
- **Cookie lifetime**: 24 hours (rolling session)
- **Refresh tokens**: Automatically refreshed before expiration
- **Storage**: Encrypted server-side (not accessible to client JavaScript)

## Security Notes

1. **Never commit secrets**: All Auth0 credentials in Azure Key Vault
2. **HTTPS only**: Auth0 requires HTTPS in production (SWA provides this automatically)
3. **Cookie security**: Session cookies are httpOnly, secure, and SameSite=Lax
4. **PKCE**: Auth0 SDK uses PKCE flow by default (no state parameter needed)
5. **Refresh tokens**: Rotation enabled (refresh tokens invalidated after use)

## References

- [Auth0 Next.js SDK Docs](https://github.com/auth0/nextjs-auth0)
- [Azure SWA Hybrid Next.js](https://learn.microsoft.com/en-us/azure/static-web-apps/deploy-nextjs-hybrid)
- [Next.js Middleware](https://nextjs.org/docs/app/building-your-application/routing/middleware)
- [Auth0 Universal Login](https://auth0.com/docs/authenticate/login/auth0-universal-login)

## Support

If Auth0 login still fails after following this guide:

1. Check Azure SWA logs: `az staticwebapp logs show --name swa-ytsumm-prd --resource-group rg-ytsumm-prd`
2. Check Auth0 logs: https://manage.auth0.com → Monitoring → Logs
3. Verify all 5 environment variables are set in Azure Portal
4. Verify Auth0 callback URLs match production SWA domain exactly
5. Test locally first with the same Auth0 application credentials

---

**Last Updated**: 2026-01-19  
**Status**: Ready for production deployment
