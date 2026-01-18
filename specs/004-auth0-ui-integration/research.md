# Phase 0 Research: Auth0 UI Integration

**Date**: 2026-01-19  
**Status**: Complete  
**Purpose**: Technology decisions and patterns for Auth0 authentication implementation

---

## 1. Auth0 Next.js SDK (`@auth0/nextjs-auth0`)

### Decision: Use @auth0/nextjs-auth0 SDK with Next.js 16 proxy.ts pattern

**Rationale**:
- Official Auth0 SDK designed specifically for Next.js
- Handles session management, token refresh, and route protection automatically
- Next.js 16 introduces `proxy.ts` for auth middleware (replaces `middleware.ts`)
- Supports both server-side and client-side authentication patterns
- Compatible with existing Terraform Auth0 configuration

**Setup Pattern**:
```
apps/web/
├── lib/auth0.ts          # Auth0Client initialization
├── proxy.ts              # Next.js 16 auth middleware
└── app/api/auth/[auth0]/ # Route handlers (built-in)
```

**Configuration Requirements**:
- Environment variables: `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`, `AUTH0_SECRET`, `APP_BASE_URL`
- Auth0 Dashboard: Configure callback URLs, logout URLs, web origins
- Session: Rolling sessions (24h), refresh token rotation enabled

**Best Practices**:
- Use broad matcher pattern in `proxy.ts` for rolling sessions
- Store secrets in Azure Key Vault, load via environment
- Enable refresh token rotation for security
- Use namespaced custom claims for roles (`https://yt-summarizer.com/roles`)

**Alternatives Considered**:
- **NextAuth.js**: More generic, requires custom Auth0 provider configuration
- **Custom OAuth implementation**: Too much boilerplate, reinvents wheel
- **Auth0 SPA SDK**: Client-side only, doesn't support BFF pattern

---

## 2. Role-Based Access Control (RBAC)

### Decision: Use app_metadata for role storage (Auth0 Free tier compatible)

**Rationale**:
- Auth0 Free tier does not include native RBAC features (roles/permissions API)
- `app_metadata` is available on Free tier and can store custom role information
- Can be accessed in Auth0 Actions and added to tokens as custom claims
- Sufficient for simple two-role system (admin vs normal)
- Can migrate to native RBAC if/when upgrading to paid tier

**Implementation Pattern**:
```typescript
// User creation (Terraform)
app_metadata = jsonencode({
  role = "admin"  // or "normal"
})

// Action (add to tokens)
api.idToken.setCustomClaim('https://yt-summarizer.com/role', user.app_metadata.role);
api.accessToken.setCustomClaim('https://yt-summarizer.com/role', user.app_metadata.role);

// Frontend check
const user = await getSession();
const role = user['https://yt-summarizer.com/role'];
if (role === 'admin') { /* show admin UI */ }

// Backend check (FastAPI already validates tokens)
role = token['https://yt-summarizer.com/role']
```

**Alternatives Considered**:
- **Native Auth0 RBAC**: Requires Professional tier ($240/month base)
- **Database-stored roles**: Adds complexity, requires sync
- **JWT claims only**: No persistent storage, can't query by role

---

## 3. Terraform Auth0 Provider

### Decision: Extend existing auth0 module for connections, users, and Actions

**Rationale**:
- Repository already has `infra/terraform/modules/auth0/` module
- Auth0 provider supports all required resources (connections, users, Actions)
- Terraform is mandatory per repository requirements (zero manual config)
- Existing pattern: store credentials in Azure Key Vault via Terraform

**Resources to Add**:
1. `auth0_connection` (database + social providers)
2. `auth0_user` (test accounts)
3. `auth0_action` (role assignment to tokens)
4. `auth0_action_trigger_binding` (bind action to post-login)
5. `azurerm_key_vault_secret` (test account passwords)

**Connection Strategy**:
- Database connection: `auth0` strategy (Auth0 user store)
- Social connections: Google, GitHub (requires OAuth app credentials)
- Password policy: "good" (8 chars, mixed case, number, special)
- Email verification: enabled

**User Provisioning Pattern**:
```hcl
resource "random_password" "test_user" {
  length = 16
  special = true
}

resource "auth0_user" "test_admin" {
  connection_name = auth0_connection.database.name
  email = "admin@test.example.com"
  password = random_password.test_user.result
  email_verified = true
  app_metadata = jsonencode({ role = "admin" })
}

resource "azurerm_key_vault_secret" "test_admin_password" {
  name = "auth0-test-admin-password"
  value = random_password.test_user.result
  key_vault_id = module.key_vault.id
}
```

**Alternatives Considered**:
- **Manual Auth0 Dashboard**: Violates IaC requirement
- **Auth0 Management API scripts**: Less declarative than Terraform
- **Pulumi**: Not used in repository

---

## 4. E2E Testing with Playwright

### Decision: Programmatic authentication with storage state reuse

**Rationale**:
- UI-based OAuth flows are slow (30+ seconds per test)
- Programmatic token acquisition via Auth0 API is fast (< 1 second)
- Storage state reuse eliminates redundant auth calls
- Aligns with requirement: test execution time < 20% increase (SC-014)

**Setup Pattern**:
```typescript
// auth.setup.ts (global setup)
setup('authenticate', async ({ request }) => {
  const response = await request.post('https://DOMAIN.auth0.com/oauth/token', {
    data: {
      grant_type: 'password',
      username: process.env.AUTH0_TEST_USERNAME,
      password: process.env.AUTH0_TEST_PASSWORD,
      client_id: process.env.AUTH0_CLIENT_ID,
      client_secret: process.env.AUTH0_CLIENT_SECRET,
      scope: 'openid profile email'
    }
  });
  
  const tokens = await response.json();
  // Save to playwright/.auth/user.json
  await context.storageState({ path: authFile });
});

// playwright.config.ts
projects: [
  { name: 'setup', testMatch: /.*\.setup\.ts/ },
  {
    name: 'chromium',
    use: { storageState: 'playwright/.auth/user.json' },
    dependencies: ['setup']
  }
]
```

**Test Account Strategy**:
- Use database connection (Username-Password-Authentication)
- Enable Resource Owner Password Grant in Auth0 Dashboard
- Store credentials in environment variables (GitHub Secrets in CI)
- Create 2 personas: admin and normal user

**Performance Optimization**:
- Authenticate once per worker (not per test)
- Cache auth state files between runs
- Use conditional authentication for unauthenticated flows

**Alternatives Considered**:
- **UI-based OAuth flow**: Too slow, flaky redirects
- **Mock authentication**: Doesn't test real Auth0 integration
- **Per-test authentication**: Violates performance constraint

---

## 5. Vitest Unit Testing

### Decision: Mock Auth0 SDK with test fixtures

**Rationale**:
- Unit tests should not make real Auth0 API calls
- Auth0 SDK provides context (`@auth0/nextjs-auth0`) that can be mocked
- Test isolation: each test controls auth state independently
- Fast execution: no network calls

**Mocking Pattern**:
```typescript
// __tests__/setup.ts
vi.mock('@auth0/nextjs-auth0', () => ({
  getSession: vi.fn(),
  withPageAuthRequired: (component) => component,
  withApiAuthRequired: (handler) => handler
}));

// Test file
import { getSession } from '@auth0/nextjs-auth0';

test('admin user sees admin features', async () => {
  vi.mocked(getSession).mockResolvedValue({
    user: {
      sub: 'auth0|123',
      email: 'admin@test.com',
      'https://yt-summarizer.com/role': 'admin'
    }
  });
  
  render(<AdminPanel />);
  expect(screen.getByText('Admin Dashboard')).toBeInTheDocument();
});
```

**Alternatives Considered**:
- **Real Auth0 calls**: Too slow for unit tests
- **No mocking**: Tests fail without auth

---

## 6. Social Provider Configuration

### Decision: Configure Google and GitHub via Terraform with externalized credentials

**Rationale**:
- Specification requires minimum 2 social providers (Google, GitHub)
- OAuth app credentials must be registered externally
- Terraform can manage Auth0 connection configuration
- Credentials stored in Azure Key Vault, referenced via Terraform variables

**Setup Process**:
1. Register OAuth apps in Google Cloud Console and GitHub Settings
2. Store Client ID and Client Secret in Azure Key Vault
3. Reference in Terraform variables
4. Create `auth0_connection` resources for each provider

**Terraform Pattern**:
```hcl
resource "auth0_connection" "google" {
  name = "google-oauth2"
  strategy = "google-oauth2"
  
  options {
    client_id = var.google_oauth_client_id
    client_secret = var.google_oauth_client_secret
    scopes = ["email", "profile"]
  }
}

resource "auth0_connection" "github" {
  name = "github"
  strategy = "github"
  
  options {
    client_id = var.github_oauth_client_id
    client_secret = var.github_oauth_client_secret
    scopes = ["user:email", "read:user"]
  }
}
```

**Credential Flow**:
```
Google/GitHub Developer Console
  → Azure Key Vault (manual one-time setup)
  → Terraform variables (var.google_oauth_client_id)
  → auth0_connection resource
```

**Alternatives Considered**:
- **Auth0 dev keys**: Not allowed in production
- **Manual Dashboard config**: Violates IaC requirement

---

## 7. CI/CD Integration

### Decision: Retrieve test credentials from Azure Key Vault in GitHub Actions

**Rationale**:
- Repository requirement: all secrets in Azure Key Vault
- GitHub Actions can authenticate to Azure via OIDC (already configured)
- Test credentials stored as Key Vault secrets via Terraform
- Exposed as environment variables during test execution

**GitHub Actions Pattern**:
```yaml
- name: Retrieve Auth0 Test Credentials
  uses: azure/get-keyvault-secrets@v1
  with:
    keyvault: ${{ secrets.AZURE_KEY_VAULT_NAME }}
    secrets: |
      auth0-test-admin-username
      auth0-test-admin-password
      auth0-test-user-username
      auth0-test-user-password
  env:
    AUTH0_TEST_ADMIN_USERNAME: ${{ steps.secrets.outputs.auth0-test-admin-username }}
    AUTH0_TEST_ADMIN_PASSWORD: ${{ steps.secrets.outputs.auth0-test-admin-password }}
```

**Test Execution**:
```bash
# Existing script already handles environment variables
./scripts/run-tests.ps1 -Component web -Mode e2e
```

**Rate Limiting Protection**:
- Worker-scoped auth (max 1 token request per worker)
- Setup project dependencies (auth runs once before tests)
- Auth0 Free tier limit: ~10 req/sec (sufficient for CI)

**Alternatives Considered**:
- **GitHub Secrets directly**: Violates Key Vault requirement
- **Hardcoded test accounts**: Security risk

---

## 8. Auth0 Free Tier Constraints

### Confirmed Limitations:
- **Users**: 25,000 MAU (monthly active users)
- **RBAC**: No native roles/permissions API
- **MFA**: Limited/no built-in MFA
- **Connections**: Social + database connections supported
- **Actions**: Limited executions (sufficient for login flow)
- **Organizations**: Not available
- **Custom Domains**: Requires credit card verification

### What IS Available on Free Tier:
✅ Database connections with password policies  
✅ Social connections (Google, GitHub, etc.)  
✅ User management (create, update, delete)  
✅ User metadata (app_metadata, user_metadata)  
✅ Actions (limited executions)  
✅ Basic applications and API resource servers  
✅ JWT token signing  

### Implications for Implementation:
- Use `app_metadata` instead of native RBAC
- No MFA requirement (per spec: out of scope)
- Auth0 Actions for adding role claims to tokens
- Password policies via connection settings

---

## 9. Engineering Quality Validation (Constitution VI.1-VI.5)

### How Technology Decisions Support Engineering Quality Principles

#### VI.1 Maintainability
**Decision**: Isolated auth module structure (`src/components/auth/`, `src/contexts/AuthContext.tsx`)
- ✅ **Module isolation**: Auth logic contained in dedicated directory; changes to auth don't affect non-auth components
- ✅ **Self-documenting code**: TypeScript interfaces for User, Session, Role; JSDoc on public API
- ✅ **Single responsibility**: `AuthContext` provides state; `proxy.ts` handles route protection; components display UI
- ✅ **Error handling**: Dedicated error types (`AuthError`, `SessionExpiredError`, `UnauthorizedError`)

#### VI.2 Testability
**Decision**: Mock `@auth0/nextjs-auth0` SDK; inject auth context via React Context API
- ✅ **Pure functions**: Role check logic (`hasRole(user, 'admin')`) is pure, testable without React
- ✅ **Dependency injection**: Auth context injectable via `<AuthProvider>`; tests can provide mock context
- ✅ **Testable interfaces**: Auth0 SDK functions (`getSession`, `withPageAuthRequired`) mockable in Vitest (§5)
- ✅ **No hidden state**: All auth state in React context; no singleton or global variables
- ✅ **Facilities available**: Playwright auth fixtures (§4), Vitest mock setup (§5)

#### VI.3 Extensibility
**Decision**: Config-driven RBAC via `app_metadata`; Action-based token claims
- ✅ **Plugin-like architecture**: New social providers added via Terraform `auth0_connection` resources (no code changes)
- ✅ **Strategy pattern**: Auth providers abstracted behind Auth0 SDK interface (Google, GitHub, Username-Password all use same SDK methods)
- ✅ **Configuration-driven**: Roles stored in `app_metadata` (§2); adding "moderator" role requires Terraform config only
- ✅ **Open-closed principle**: Core auth logic (`AuthContext`) closed; new providers/roles added via config
- ✅ **Extension points documented**: README will explain adding roles (update Action, add Terraform user with new `app_metadata`)

#### VI.4 Modularity
**Decision**: Single entry point (`AuthContext.tsx`); internal SDK usage hidden
- ✅ **Package/module boundaries**: Auth at `src/components/auth/` and `src/contexts/AuthContext.tsx`; non-auth components never import Auth0 SDK directly
- ✅ **Internal vs public API**: Only `AuthProvider`, `useAuth` hook, and auth components exported; SDK calls internal
- ✅ **Import dependency graph**: Auth is leaf module; components → `useAuth` → `AuthContext` → Auth0 SDK (no circular deps)
- ✅ **Single entry point**: `useAuth()` hook is the public API; all consumers use this (never direct SDK imports)
- ✅ **Cross-cutting concerns**: Route protection in `proxy.ts` middleware (not scattered in components)

#### VI.5 Onboarding
**Decision**: README with architecture diagram, setup guide, usage examples (Phase 1 deliverable)
- ✅ **README per module**: `specs/001-auth0-ui-integration/quickstart.md` will serve as module README
- ✅ **Clear examples**: Login component usage, `useAuth` hook examples, role check patterns
- ✅ **Architecture diagrams**: OAuth flow, token claim injection, session management
- ✅ **Walkthrough comments**: OAuth redirect flow, refresh token rotation, role claim extraction
- ✅ **Naming conventions**: `useAuth`, `AuthContext`, `AuthProvider`, `withAuth` (consistent React patterns)

### Summary: Engineering Quality Compliance

| Principle | Key Decision | Validation |
|-----------|--------------|------------|
| Maintainability | Isolated auth module | Changes to auth don't affect non-auth code ✅ |
| Testability | Mock SDK + injectable context | 100% unit testable without Auth0 API ✅ |
| Extensibility | Config-driven roles | Add "moderator" via config, not code ✅ |
| Modularity | Single entry point hook | No circular deps, clear public API ✅ |
| Onboarding | README + diagrams | New devs can understand flow from docs ✅ |

All technology decisions align with Constitution v1.2.0 engineering quality principles (VI.1-VI.5).

---

## Summary of Technology Decisions

| Component | Technology | Reason |
|-----------|-----------|--------|
| Auth SDK | `@auth0/nextjs-auth0` | Official Next.js integration, handles sessions/tokens |
| Middleware | `proxy.ts` (Next.js 16) | New Next.js 16 convention for auth |
| RBAC | `app_metadata` + Actions | Free tier compatible, sufficient for 2 roles |
| IaC | Terraform Auth0 provider | Extends existing module, required by repo |
| E2E Auth | Programmatic tokens + storage state | Fast, reliable, meets perf constraints |
| Unit Tests | Mocked `@auth0/nextjs-auth0` | Isolated, fast, no network calls |
| Social Login | Google + GitHub via Terraform | Meets spec requirements, IaC managed |
| Test Credentials | Azure Key Vault | Repository standard, secure |
| Session Storage | Encrypted cookies (httpOnly) | SDK default, secure by design |
| Token Refresh | Automatic (refresh_token grant) | SDK built-in, transparent to app |

---

## Next Steps: Phase 1 Design

With research complete, Phase 1 will define:
1. **Data Model**: User, Session, Role entities
2. **API Contracts**: Auth0 SDK endpoints (login, logout, profile)
3. **Quickstart Guide**: Developer setup and test account usage

All decisions align with specification requirements (FR-001 through FR-024) and repository constraints (IaC, testing, secrets management).
