# Auth Module Documentation

> **Auth0 UI Integration with Role-Based Access Control**
>
> This module provides secure authentication and authorization for the YT Summarizer application using Auth0 and Next.js.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Components](#components)
- [Authentication Flow](#authentication-flow)
- [Role-Based Access Control](#role-based-access-control)
- [API Integration](#api-integration)
- [Testing](#testing)
- [Adding New Roles](#adding-new-roles)
- [Adding New Social Providers](#adding-new-social-providers)
- [Troubleshooting](#troubleshooting)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         YT Summarizer Frontend                      │
│                            (Next.js App)                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐        │
│  │ Login Page   │    │   Navbar     │    │ Admin Page   │        │
│  │              │    │              │    │              │        │
│  │ - Social     │    │ - UserProfile│    │ - Protected  │        │
│  │ - Username/  │    │ - Logout     │    │ - RBAC Check │        │
│  │   Password   │    │ - Role Badge │    │              │        │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘        │
│         │                   │                   │                 │
│         └───────────────────┼───────────────────┘                 │
│                             │                                     │
│                    ┌────────▼────────┐                            │
│                    │  AuthContext    │                            │
│                    │  (useAuth hook) │                            │
│                    │                 │                            │
│                    │ - User state    │                            │
│                    │ - Session mgmt  │                            │
│                    │ - Role checks   │                            │
│                    └────────┬────────┘                            │
│                             │                                     │
│         ┌───────────────────┼───────────────────┐                │
│         │                   │                   │                │
│    ┌────▼─────┐      ┌──────▼──────┐     ┌─────▼──────┐         │
│    │Middleware│      │   API       │     │ Auth Utils │         │
│    │          │      │   Routes    │     │            │         │
│    │- Route   │      │             │     │- hasRole() │         │
│    │  protect │      │/api/auth/   │     │- getUser() │         │
│    │- RBAC    │      │  [auth0]    │     │            │         │
│    └────┬─────┘      └──────┬──────┘     └────────────┘         │
│         │                   │                                     │
└─────────┼───────────────────┼─────────────────────────────────────┘
          │                   │
          │      HTTPS        │
          │   (redirects)     │
          │                   │
    ┌─────▼───────────────────▼─────┐
    │        Auth0 Tenant           │
    │   (Authentication Provider)   │
    ├───────────────────────────────┤
    │ - OAuth Connections           │
    │   • Google                    │
    │   • GitHub                    │
    │ - Database Connection         │
    │   • Username/Password         │
    │ - Auth0 Actions               │
    │   • Role Claims Injection     │
    │ - User Management             │
    │   • Test Accounts             │
    │   • Role Assignment           │
    └───────────────────────────────┘
```

### Key Components

1. **AuthContext**: Central state management for authentication
2. **useAuth Hook**: Public API for accessing auth state
3. **Middleware**: Route protection and RBAC enforcement
4. **Auth API Routes**: Next.js API routes for Auth0 SDK integration
5. **Auth Components**: UI components (LoginButton, UserProfile, etc.)
6. **Auth Utilities**: Helper functions for role checking and user data

---

## Components

### Core Components

#### `AuthContext.tsx`

Provides authentication state to the entire application using React Context API.

```typescript
interface User {
  sub: string;
  email?: string;
  name?: string;
  picture?: string;
  roles?: Role[];
}

interface Session {
  user: User;
  accessToken?: string;
  expiresAt?: Date;
}
```

**Usage**:

```tsx
import { AuthProvider } from '@/contexts/AuthContext';

export default function RootLayout({ children }) {
  return <AuthProvider>{children}</AuthProvider>;
}
```

#### `useAuth.ts`

React hook for accessing authentication state and methods.

```typescript
const { user, isLoading, isAuthenticated, login, logout } = useAuth();
```

**Returns**:

- `user`: Current user object or `null`
- `isLoading`: Boolean indicating if auth state is loading
- `isAuthenticated`: Boolean indicating if user is authenticated
- `login()`: Function to redirect to login page
- `logout()`: Function to sign out and clear session

### UI Components

#### `LoginButton.tsx`

Displays social login buttons (Google, GitHub) and triggers OAuth flow.

```tsx
<LoginButton provider="google" />
<LoginButton provider="github" />
```

#### `UserProfile.tsx`

Displays user information and logout button in the navbar.

```tsx
<UserProfile />
// Shows: user avatar, email, role badge, logout button
```

#### `LogoutButton.tsx`

Standalone logout button component.

```tsx
<LogoutButton />
```

#### `UsernamePasswordForm.tsx`

Login form for username/password authentication (used for test accounts).

```tsx
<UsernamePasswordForm onSuccess={(user) => console.log('Logged in:', user)} />
```

#### `RoleBasedComponent.tsx`

Conditionally renders children based on user roles.

```tsx
<RoleBasedComponent requiredRole="admin">
  <AdminPanel />
</RoleBasedComponent>
```

### Utilities

#### `auth-utils.ts`

Helper functions for working with authentication data.

```typescript
// Check if user has specific role
hasRole(user, 'admin'); // => boolean

// Get user display name
getUserDisplayName(user); // => string

// Check if session is expired
isSessionExpired(session); // => boolean
```

---

## Authentication Flow

### Social Login (Google/GitHub)

```
1. User clicks "Sign in with Google"
   ↓
2. Redirected to /api/auth/login?returnTo=/dashboard
   ↓
3. Auth0 SDK redirects to Auth0 hosted login
   ↓
4. User authenticates with Google
   ↓
5. Auth0 redirects to /api/auth/callback with authorization code
   ↓
6. Auth0 SDK exchanges code for tokens
   ↓
7. Auth0 Action adds role claims to ID token
   ↓
8. User redirected to /dashboard with encrypted session cookie
   ↓
9. AuthContext loads user from session
```

### Username/Password Login

```
1. User enters email and password in UsernamePasswordForm
   ↓
2. Form submits to /api/auth/login with credentials
   ↓
3. Auth0 SDK redirects to Auth0 with connection=Username-Password-Authentication
   ↓
4. Auth0 validates credentials against database connection
   ↓
5. Auth0 redirects to /api/auth/callback (same as social login flow)
   ↓
6. User redirected with session cookie
```

### Session Management

- **Storage**: Encrypted session cookie (`appSession`) set by `@auth0/nextjs-auth0`
- **Lifetime**: Configurable via `AUTH0_SESSION_DURATION` (default: 7 days)
- **Refresh**: Automatic token refresh handled by Auth0 SDK
- **Logout**: Clears session cookie and redirects to Auth0 logout endpoint

---

## Role-Based Access Control

### Role Structure

The application uses a simple role-based access control system:

- **admin**: Full access to all features, including admin dashboard
- **user**: Standard access to main application features

### Role Assignment

Roles are assigned in Auth0 user metadata:

```json
{
  "user_metadata": {},
  "app_metadata": {
    "roles": ["admin"]
  }
}
```

### Role Claims in Tokens

An Auth0 Action (`add-roles-to-tokens`) automatically adds role claims to the ID token:

```javascript
exports.onExecutePostLogin = async (event, api) => {
  const roles = event.user.app_metadata?.roles || ['user'];
  api.idToken.setCustomClaim('https://yt-summarizer.com/roles', roles);
};
```

### Route Protection

#### Middleware Protection

Routes are protected at the middleware level (`middleware.ts`):

```typescript
export function middleware(request: NextRequest) {
  if (request.nextUrl.pathname.startsWith('/admin')) {
    const session = await getSession();
    if (!session?.user) {
      return NextResponse.redirect(new URL('/login', request.url));
    }
    if (!hasRole(session.user, 'admin')) {
      return NextResponse.redirect(new URL('/access-denied', request.url));
    }
  }
}
```

#### Component-Level Protection

```tsx
import { RoleBasedComponent } from '@/components/auth/RoleBasedComponent';

<RoleBasedComponent requiredRole="admin">
  <AdminDashboard />
</RoleBasedComponent>;
```

#### Programmatic Checks

```typescript
import { useAuth } from '@/hooks/useAuth';
import { hasRole } from '@/lib/auth-utils';

function MyComponent() {
  const { user } = useAuth();

  if (hasRole(user, 'admin')) {
    return <AdminView />;
  }
  return <UserView />;
}
```

---

## API Integration

The application includes backend API authentication (`services/api`):

### API Auth Endpoints

- `GET /api/auth/login?returnTo={url}`: Initiates Auth0 login flow
- `GET /api/auth/callback/auth0`: Handles OAuth callback
- `POST /api/auth/logout`: Clears session and logs out
- `GET /api/auth/me`: Returns current user information

### Session Cookie Authentication

The API uses session cookies for authentication (set by the Next.js frontend):

```typescript
// In API request
fetch('/api/auth/me', {
  credentials: 'include', // Send session cookie
});
```

### FastAPI Integration

The Python API (`services/api`) has matching auth endpoints that validate the same session:

```python
from api.routes.auth import router

app.include_router(router)  # Adds /api/auth endpoints
```

---

## Testing

### Unit Tests

#### Testing with `useAuth` Hook

```typescript
import { renderHook } from '@testing-library/react';
import { useAuth } from '@/hooks/useAuth';

test('useAuth returns user when authenticated', () => {
  const { result } = renderHook(() => useAuth());
  expect(result.current.isAuthenticated).toBe(true);
  expect(result.current.user).toBeDefined();
});
```

#### Testing Role Utilities

```typescript
import { hasRole } from '@/lib/auth-utils';

test('hasRole returns true for admin user', () => {
  const user = { sub: '123', roles: [{ name: 'admin' }] };
  expect(hasRole(user, 'admin')).toBe(true);
});
```

### E2E Tests

E2E tests use programmatic authentication via Playwright:

```typescript
// auth.setup.ts creates authenticated sessions
test.use({ storageState: 'playwright/.auth/user.json' });

test('authenticated user can access dashboard', async ({ page }) => {
  await page.goto('/dashboard');
  await expect(page).toHaveURL('/dashboard');
});
```

#### Test User Credentials

Test users are provisioned via Terraform and stored in Azure Key Vault:

- **Admin User**: `admin@test.yt-summarizer.internal` (role: admin)
- **Normal User**: `user@test.yt-summarizer.internal` (role: user)

Credentials are retrieved in CI/CD via:

```yaml
- name: Retrieve Auth0 test credentials from Key Vault
  uses: azure/CLI@v2
  with:
    inlineScript: |
      echo "AUTH0_ADMIN_TEST_EMAIL=$(az keyvault secret show --vault-name "yt-summarizer-kv" --name "auth0-admin-test-email" --query "value" -o tsv)" >> $GITHUB_ENV
      # ... (see .github/workflows/preview-e2e.yml)
```

---

## Adding New Roles

To add a new role (e.g., `moderator`):

### 1. Update Terraform User Provisioning

Edit `infra/terraform/environments/prod/auth0.tf`:

```hcl
resource "auth0_user" "moderator_test_user" {
  connection_name = "Username-Password-Authentication"
  email          = "moderator@test.yt-summarizer.internal"
  password       = random_password.moderator_test_password.result
  email_verified = true

  app_metadata = jsonencode({
    roles = ["moderator"]
  })
}
```

### 2. Update TypeScript Types

Edit `apps/web/src/types/auth.ts`:

```typescript
export type Role = {
  name: 'admin' | 'user' | 'moderator';
};
```

### 3. Update Middleware

Edit `apps/web/src/middleware.ts` to protect moderator-only routes:

```typescript
if (request.nextUrl.pathname.startsWith('/moderator')) {
  if (!hasRole(session.user, 'moderator')) {
    return NextResponse.redirect(new URL('/access-denied', request.url));
  }
}
```

### 4. Create Protected Pages

Create `apps/web/src/app/moderator/page.tsx`:

```tsx
export default function ModeratorDashboard() {
  return <div>Moderator Dashboard</div>;
}
```

### 5. Add Navigation

Update `apps/web/src/components/Navbar.tsx`:

```tsx
{
  hasRole(user, 'moderator') && <Link href="/moderator">Moderator</Link>;
}
```

### 6. Deploy Changes

```bash
# Apply Terraform changes
cd infra/terraform/environments/prod
terraform apply

# Deploy application
# (follow your normal deployment process)
```

---

## Adding New Social Providers

To add a new social login provider (e.g., Microsoft):

### 1. Create Auth0 Connection via Terraform

Edit `infra/terraform/modules/auth0/main.tf`:

```hcl
# Microsoft Social Connection
resource "auth0_connection" "microsoft" {
  count   = contains(var.enabled_connections, "microsoft") ? 1 : 0
  name    = "microsoft"
  strategy = "windowslive"

  options {
    client_id     = var.microsoft_client_id
    client_secret = var.microsoft_client_secret
    scopes        = ["openid", "profile", "email"]
  }
}

# Enable for application
resource "auth0_connection_clients" "microsoft_clients" {
  count          = contains(var.enabled_connections, "microsoft") ? 1 : 0
  connection_id  = auth0_connection.microsoft[0].id
  enabled_client_ids = [var.client_id]
}
```

### 2. Add Variables

Edit `infra/terraform/environments/prod/variables.tf`:

```hcl
variable "microsoft_client_id" {
  description = "Microsoft OAuth Client ID"
  type        = string
  sensitive   = true
}

variable "microsoft_client_secret" {
  description = "Microsoft OAuth Client Secret"
  type        = string
  sensitive   = true
}
```

### 3. Update Terraform Configuration

Edit `infra/terraform/environments/prod/auth0.tf`:

```hcl
module "auth0" {
  source = "../../modules/auth0"

  enabled_connections = ["google", "github", "microsoft"]
  microsoft_client_id     = var.microsoft_client_id
  microsoft_client_secret = var.microsoft_client_secret
  # ...
}
```

### 4. Add UI Button

Edit `apps/web/src/components/auth/LoginButton.tsx`:

```tsx
export function LoginButton({ provider }: { provider: 'google' | 'github' | 'microsoft' }) {
  const providerConfig = {
    // ...
    microsoft: {
      name: 'Microsoft',
      icon: <MicrosoftIcon />,
      connection: 'microsoft',
    },
  };
  // ...
}
```

### 5. Update Login Page

Edit `apps/web/src/app/login/page.tsx`:

```tsx
<LoginButton provider="microsoft" />
```

### 6. Deploy

```bash
# Store credentials in Terraform variables or Azure Key Vault
az keyvault secret set --vault-name yt-summarizer-kv --name microsoft-client-id --value "..."
az keyvault secret set --vault-name yt-summarizer-kv --name microsoft-client-secret --value "..."

# Apply Terraform
cd infra/terraform/environments/prod
terraform apply
```

---

## Troubleshooting

### Common Issues

#### "Auth0 is not configured" Error

**Cause**: Missing environment variables

**Solution**: Verify all required environment variables are set:

```bash
# Required variables
AUTH0_SECRET=<random-32-char-string>
AUTH0_BASE_URL=http://localhost:3000
AUTH0_ISSUER_BASE_URL=https://your-tenant.us.auth0.com
AUTH0_CLIENT_ID=<your-client-id>
AUTH0_CLIENT_SECRET=<your-client-secret>
```

Generate `AUTH0_SECRET`:

```bash
openssl rand -hex 32
```

#### Session Not Persisting

**Cause**: Cookie domain mismatch or SameSite issues

**Solution**: Check cookie settings in Auth0 SDK configuration. For local development:

```bash
# Use HTTP for local development
AUTH0_BASE_URL=http://localhost:3000

# For production, use HTTPS
AUTH0_BASE_URL=https://your-domain.com
```

#### "Not authenticated" on `/api/auth/me`

**Cause**: Session cookie not sent or expired

**Solution**:

1. Check if session cookie is present in browser DevTools
2. Verify `credentials: 'include'` is set in fetch requests
3. Check if session has expired (default: 7 days)

#### E2E Tests Failing with Auth Errors

**Cause**: Test credentials not configured or expired

**Solution**: Verify environment variables are set:

```bash
# For local E2E tests
export AUTH0_ADMIN_TEST_EMAIL="admin@test.yt-summarizer.internal"
export AUTH0_ADMIN_TEST_PASSWORD="<from-key-vault>"
export AUTH0_USER_TEST_EMAIL="user@test.yt-summarizer.internal"
export AUTH0_USER_TEST_PASSWORD="<from-key-vault>"
```

Retrieve from Key Vault:

```bash
az keyvault secret show --vault-name yt-summarizer-kv --name auth0-admin-test-password --query value -o tsv
```

#### Middleware Redirect Loop

**Cause**: Middleware redirecting authenticated users back to login

**Solution**: Check middleware configuration in `middleware.ts`:

```typescript
// Exclude auth routes from middleware
export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
};
```

#### Role Claims Not Appearing in Token

**Cause**: Auth0 Action not triggered or misconfigured

**Solution**:

1. Verify Action is deployed in Auth0 Dashboard
2. Check Action is bound to "post-login" trigger
3. View Action logs in Auth0 Dashboard for errors

---

## Additional Resources

- **Auth0 Next.js SDK**: https://github.com/auth0/nextjs-auth0
- **Auth0 Actions**: https://auth0.com/docs/customize/actions
- **Auth0 Terraform Provider**: https://registry.terraform.io/providers/auth0/auth0/latest/docs
- **Next.js Middleware**: https://nextjs.org/docs/app/building-your-application/routing/middleware
- **Playwright Auth**: https://playwright.dev/docs/auth

---

## License

This auth module is part of the YT Summarizer project.
