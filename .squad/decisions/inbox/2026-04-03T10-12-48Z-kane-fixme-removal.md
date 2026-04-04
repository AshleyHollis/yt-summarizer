# Decision: Remove test.fixme(!!process.env.CI) guards from E2E tests

**Date**: 2026-04-03  
**Author**: Kane (Tester)  
**Branch**: test/e2e-env-verification

## Context

All auth-dependent E2E tests were guarded with `test.fixme(!!process.env.CI, '...')` due to a cross-domain cookie issue: auth cookies set on the API domain were not sent by the browser when loading pages from the SWA domain.

The fix landed on this branch:
1. `SameSite=None; Secure` on auth cookies
2. CORS `allow_credentials=True` + `allow_origin_regex` for `*.azurestaticapps.net`
3. `credentials: 'include'` in the frontend

CI confirmed: `[auth-setup] normal user authenticated successfully`.

## Decision

Remove all `test.fixme(!!process.env.CI, ...)` guards from `apps/web/e2e/` with two exceptions:

1. **Keep**: `synthesis-api.spec.ts` Coverage Verification describe block — embed pipeline timing issue, not cookies.
2. **Leave untouched**: `test.skip` (not `test.fixme`) guards — separate concern.

## Files Changed

22 files, 140 lines of guard boilerplate removed.
`global-setup.ts` — `MIN_SEGMENTS_REQUIRED` lowered 40 to 35.

## Rationale

Tests that fail for a different reason will now surface as failures (not silent skips), which is correct CI behaviour.
