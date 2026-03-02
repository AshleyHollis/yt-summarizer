# Lambert — History

## Project Context
- **Project**: YT Summarizer — YouTube video knowledge library
- **Stack**: Next.js (Azure SWA), React, TypeScript, Playwright, Auth0
- **User**: Ashley Hollis

## Key Knowledge
- SWA intercepts `/api/*` as Azure Functions routes (returns 500). Frontend uses `getClientApiUrl()` to hit AKS directly.
- AuthProvider must wrap all child components in providers.tsx or useAuth() throws, crashing the app.
- E2E tests use maxFailures: 5 and timeout-minutes: 30 to prevent long CI runs.
- Cross-domain cookie issue: auth cookies on API domain, tests from SWA domain — different origins.
- Library page has NO AuthGate but is being redirected to Auth0 login in preview.

## Learnings
<!-- Append learnings below -->
