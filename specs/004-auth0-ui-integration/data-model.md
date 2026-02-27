# Data Model: Auth0 UI Integration

**Date**: 2026-01-19  
**Status**: Design  
**Source**: [spec.md](./spec.md) § Key Entities

---

## Overview

This feature integrates Auth0 authentication into the UI. **Auth0 is the authoritative data store** for user identities, sessions, and roles. The application does not duplicate this data in Azure SQL; instead, it reads from Auth0 tokens and sessions.

---

## Entities

### 1. User

**Description**: Represents an authenticated person using the application.

**Storage**: Auth0 user database (managed service)

**Attributes**:

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `sub` | string | Yes | Unique user identifier (Auth0 format) | `"auth0\|123456"` or `"google-oauth2\|789012"` |
| `email` | string | Yes | User's email address | `"user@example.com"` |
| `email_verified` | boolean | Yes | Whether email has been verified | `true` |
| `name` | string | No | User's display name | `"John Doe"` |
| `picture` | string | No | Profile picture URL (social providers only) | `"https://lh3.googleusercontent.com/..."` |
| `username` | string | No | Username (database connection only) | `"testuser123"` |
| `app_metadata.role` | string | Yes | User role (admin or normal) | `"admin"` or `"normal"` |
| `updated_at` | datetime | Yes | Last profile update timestamp | `"2026-01-19T10:30:00.000Z"` |

**Relationships**:
- Has one active Session at a time (1:1)
- Belongs to one Role (1:1)
- Authenticated via one AuthenticationMethod (1:1)

**Validation Rules**:
- `email` must be valid email format
- `app_metadata.role` must be either `"admin"` or `"normal"`
- `sub` is unique across all users

**State Transitions**:
- Created → Active (after first login)
- Active → Suspended (if Auth0 account blocked)
- Active → Deleted (if account removed)

**TypeScript Interface** (frontend representation):
```typescript
interface User {
  sub: string;
  email: string;
  email_verified: boolean;
  name?: string;
  picture?: string;
  username?: string;
  'https://yt-summarizer.com/role': 'admin' | 'normal'; // Custom claim
  updated_at: string;
}
```

---

### 2. Session

**Description**: Represents an active user session with authentication tokens.

**Storage**: Encrypted HTTP-only cookies (managed by `@auth0/nextjs-auth0`)

**Attributes**:

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `accessToken` | string | Yes | JWT access token for API calls | `"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."` |
| `refreshToken` | string | No | Refresh token for token renewal | `"v1.M0rTg..."` |
| `idToken` | string | Yes | OpenID Connect ID token | `"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."` |
| `tokenType` | string | Yes | Token type (always "Bearer") | `"Bearer"` |
| `expiresAt` | number | Yes | Access token expiration (Unix timestamp) | `1737287400` |
| `user` | User | Yes | User profile information | (see User entity) |

**Relationships**:
- Belongs to one User (1:1)

**Validation Rules**:
- `accessToken` must be valid JWT signed by Auth0
- `expiresAt` must be in the future for active sessions
- `user.sub` must match token `sub` claim

**State Transitions**:
- Active → Expired (when `expiresAt` is reached)
- Active → Refreshed (when refresh token is used)
- Active → Logged Out (when user signs out)

**TypeScript Interface**:
```typescript
interface Session {
  user: User;
  accessToken: string;
  refreshToken?: string;
  idToken: string;
  tokenType: 'Bearer';
  expiresAt: number;
}
```

**Security Properties**:
- Stored in encrypted, HTTP-only, SameSite=Lax cookies
- Not accessible to client-side JavaScript
- Automatically refreshed before expiration
- Rotation enabled (refresh token invalidated after use)

---

### 3. Role

**Description**: Defines user permissions and access levels.

**Storage**: Embedded in User entity (`app_metadata.role`)

**Values**:

| Role | Description | Permissions |
|------|-------------|-------------|
| `admin` | Administrator with full access | Access to admin dashboard, user management, system configuration, all normal user features |
| `normal` | Standard user with limited access | Access to video submission, viewing summaries, personal library; **no access** to admin features |

**Validation Rules**:
- Role must be exactly `"admin"` or `"normal"` (case-sensitive)
- Each user has exactly one role
- Role changes require Auth0 Management API update

**Authorization Checks**:
```typescript
// Frontend
const hasAdminAccess = user['https://yt-summarizer.com/role'] === 'admin';

// Backend (Python)
role = token.get('https://yt-summarizer.com/role')
if role != 'admin':
    raise HTTPException(status_code=403, detail="Admin access required")
```

**Extensibility** (FR-030, SC-018):
- Adding new roles (e.g., `"moderator"`) requires:
  1. Update Terraform user provisioning (`app_metadata.role = "moderator"`)
  2. Update Auth0 Action to include new role in token claims
  3. Add role constant to frontend (`type Role = 'admin' | 'normal' | 'moderator'`)
  4. Update authorization checks (`hasRole(user, 'moderator')`)
- **No changes to core auth logic required** (config-driven)

---

### 4. TestAccount

**Description**: Special user accounts created for automated testing.

**Storage**: Auth0 database connection + Azure Key Vault (credentials)

**Attributes**:

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `email` | string | Yes | Test account email | `"admin@test.yt-summarizer.internal"` |
| `password` | string | Yes | Securely generated password | (stored in Key Vault) |
| `role` | string | Yes | Account role (admin or normal) | `"admin"` |
| `key_vault_secret_name` | string | Yes | Key Vault secret reference | `"auth0-test-admin-password"` |
| `connection` | string | Yes | Auth0 connection name | `"Username-Password-Authentication"` |

**Provisioning**:
```hcl
# Terraform
resource "random_password" "test_admin" {
  length = 16
  special = true
}

resource "auth0_user" "test_admin" {
  connection_name = auth0_connection.database.name
  email = "admin@test.yt-summarizer.com"
  password = random_password.test_admin.result
  email_verified = true
  app_metadata = jsonencode({ role = "admin" })
}

resource "azurerm_key_vault_secret" "test_admin_password" {
  name = "auth0-test-admin-password"
  value = random_password.test_admin.result
  key_vault_id = module.key_vault.id
}
```

**Usage** (CI/CD):
```yaml
# GitHub Actions
- name: Retrieve Test Credentials
  uses: azure/get-keyvault-secrets@v1
  with:
    keyvault: ${{ secrets.AZURE_KEY_VAULT_NAME }}
    secrets: 'auth0-test-admin-password'
  env:
    AUTH0_TEST_ADMIN_PASSWORD: ${{ steps.secrets.outputs.auth0-test-admin-password }}
```

**Test Accounts Required**:
1. Admin test account (for admin feature testing)
2. Normal user test account (for RBAC testing)

---

### 5. AuthenticationMethod

**Description**: Defines how a user authenticated.

**Storage**: Derived from `user.sub` prefix

**Values**:

| Method | Sub Prefix | Description | Example |
|--------|------------|-------------|---------|
| Google OAuth | `google-oauth2|` | Social login via Google | `google-oauth2|123456789` |
| GitHub OAuth | `github|` | Social login via GitHub | `github|987654321` |
| Username-Password | `auth0|` | Database connection (test accounts) | `auth0|5f8d3a2b1c` |

**Extraction Logic**:
```typescript
function getAuthMethod(sub: string): 'social' | 'database' {
  if (sub.startsWith('auth0|')) return 'database';
  return 'social';
}

function getProvider(sub: string): string {
  const [provider] = sub.split('|');
  return provider; // "google-oauth2", "github", "auth0"
}
```

---

## Data Flow Diagrams

### OAuth Login Flow

```
User                    Next.js App             Auth0                 Browser Cookie
  │                          │                    │                         │
  │  Click "Sign in"         │                    │                         │
  ├──────────────────────────>│                    │                         │
  │                          │  Redirect /auth0   │                         │
  │                          ├───────────────────>│                         │
  │                          │                    │  Consent Screen         │
  │<──────────────────────────────────────────────┤                         │
  │  Approve                 │                    │                         │
  ├─────────────────────────────────────────────>│                         │
  │                          │                    │  Redirect /callback     │
  │                          │<───────────────────┤                         │
  │                          │                    │                         │
  │                          │  Exchange code     │                         │
  │                          ├───────────────────>│                         │
  │                          │  ← Tokens          │                         │
  │                          │<───────────────────┤                         │
  │                          │                    │  Set session cookie     │
  │                          ├────────────────────────────────────────────>│
  │  Redirect to dashboard   │                    │                         │
  │<──────────────────────────┤                    │                         │
```

### Role-Based Access Check

```
User Request            Next.js Middleware      Session Cookie        API Backend
  │                          │                         │                    │
  │  GET /admin/users        │                         │                    │
  ├─────────────────────────>│                         │                    │
  │                          │  Read session           │                    │
  │                          ├────────────────────────>│                    │
  │                          │  ← User + role          │                    │
  │                          │<────────────────────────┤                    │
  │                          │                         │                    │
  │  [If role !== 'admin']   │                         │                    │
  │  403 Forbidden           │                         │                    │
  │<─────────────────────────┤                         │                    │
  │                          │                         │                    │
  │  [If role === 'admin']   │                         │                    │
  │  Forward with token      │                         │                    │
  │                          ├──────────────────────────────────────────────>│
  │                          │                         │   Validate JWT     │
  │                          │                         │   Check role claim │
  │                          │                         │   ← Response       │
  │  200 OK                  │<────────────────────────────────────────────────┤
  │<─────────────────────────┤                         │                    │
```

---

## Validation Summary

| Entity | Primary Key | Unique Constraints | Foreign Keys |
|--------|-------------|-------------------|--------------|
| User | `sub` | `email` | None (external) |
| Session | (cookie ID) | None | `user.sub` |
| Role | (enum value) | None | None (embedded) |
| TestAccount | `email` | `email` | None (external) |
| AuthenticationMethod | (derived) | None | `user.sub` (derived) |

---

## Security Considerations

1. **No Password Storage**: Application never sees or stores user passwords. Auth0 handles all credential management.
2. **Token Encryption**: Sessions stored in encrypted cookies with `httpOnly`, `secure`, `sameSite=Lax` flags.
3. **Role Tampering Protection**: Roles stored in Auth0 `app_metadata` (not user-modifiable), added to JWT via server-side Action.
4. **Test Account Isolation**: Test credentials in Key Vault with access policies restricting to CI/CD service principal.
5. **Audit Trail**: All auth events logged with correlation IDs (FR-035).

---

## Migration Path (Future)

If upgrading to Auth0 paid tier in the future:

1. **Native RBAC**: Migrate from `app_metadata.role` to Auth0 Roles API
2. **Permissions**: Add granular permissions beyond simple roles
3. **Organizations**: Group users by organization/tenant
4. **MFA**: Enable multi-factor authentication

Migration does **not** require application code changes due to extensibility design (FR-029, FR-030).
