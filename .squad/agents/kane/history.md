# Kane — History

## Project Context
- **Project**: YT Summarizer — YouTube video knowledge library
- **Stack**: Playwright, pytest, Vitest, GitHub Actions CI
- **User**: Ashley Hollis

## Key Knowledge
- Auth0 test users: admin@test.yt-summarizer.internal, user@test.yt-summarizer.internal
- Passwords stored in Key Vault: auth0-admin-test-password, auth0-user-test-password
- E2E auth setup navigates to API URL directly (not SWA) due to SWA /api/* interception
- Cross-domain cookie issue affects all auth-dependent E2E tests in CI
- Many auth E2E tests have `test.fixme(!!process.env.CI, 'Cross-domain cookie issue...')`
- 5 failing tests in library.spec.ts — all redirecting to Auth0 login when they shouldn't

## Learnings
<!-- Append learnings below -->
