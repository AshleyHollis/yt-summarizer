## Remove ROPC Dead Code — injectAuth0Token() in global-setup.ts

**Flagged by:** Dallas (confirmed by DB Investigator)  
**Approved by:** Ashley Hollis  
**Date:** 2026-04-06

### Decision
Remove `injectAuth0Token()` function and associated Auth0 environment variables (`AUTH0_TEST_EMAIL`, `AUTH0_TEST_PASSWORD`) from `apps/web/e2e/global-setup.ts`.

### Reason

1. **ROPC (Resource Owner Password Credentials) is not enabled in preview Auth0 app**
   - Preview app is configured with only `authorization_code` grant
   - All ROPC token requests return 403

2. **Token written to localStorage is never used**
   - Auth0 SDK uses cookies, not localStorage
   - `injectAuth0Token()` writes a token that is ignored by the SDK

3. **No functional effect**
   - Tests are already fixed using standard OAuth flow (web login)
   - Removing this code changes nothing for test behavior

### Impact
- ✅ Cleaner codebase (removes unused function)
- ✅ Removes confusing dead code
- ⚠️ None (no functional changes)

### Files
- `apps/web/e2e/global-setup.ts`
- `.github/workflows/preview-e2e.yml` (remove `AUTH0_TEST_EMAIL`, `AUTH0_TEST_PASSWORD`)

### Status
Ready for implementation (low risk, approved for cleanup).