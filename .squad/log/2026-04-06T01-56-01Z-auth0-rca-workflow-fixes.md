# Auth0 RCA Session — Workflow Fixes + Admin Role Verification

**Requested by:** Ashley Hollis  
**Date:** 2026-04-06  
**Context:** Challenge to "by design" classification of LIVE_PROCESSING and RBAC skips. Three agents investigated in parallel and found real bugs — not by-design behavior.

## Investigation Summary

Four agents contributed to this session:

### 1. Kane: Auth Setup Hardening & Stale Comment Fix
- **Commit:** `test(e2e): harden auth setup + fix stale LIVE_PROCESSING comment` (`3142afe8`)
- **Changes:**
  - `apps/web/e2e/auth.setup.ts`: Hardened to throw (not warn) when admin role claim is absent from Auth0 session
  - `admin.json` is now only saved when role is confirmed `admin`
  - `catch` block re-throws instead of swallowing errors
  - `playwright.config.ts`: Fixed stale comment — LIVE_PROCESSING IS set in preview workflows, NOT in ci.yml
- **Key Finding:** Silently saving broken `admin.json` causes all RBAC tests to skip with misleading messages

### 2. Parker: Missing Auth0 Environment Variables
- **Commit:** `ci(e2e): add missing Auth0 env vars to preview.yml E2E step` (`3a09dbf5`)
- **Finding:** `preview.yml` was missing `AUTH0_SECRET`, `AUTH0_BASE_URL`, `AUTH0_TEST_EMAIL`, `AUTH0_TEST_PASSWORD` that `preview-e2e.yml` had
- **Failure Chain:** Auth setup fails → 5 quick failures → `maxFailures=5` aborts run → LIVE_PROCESSING tests never execute
- **Confirmation:** LIVE_PROCESSING IS correctly forwarded through shared-infra composite action
- **Follow-up:** MAX_FAILURES raised from 5 to 10 (pending commit)

### 3. Dallas: Auth0 Management API Verification
- **Approach:** No code changes needed — verified Auth0 configuration via Management API
- **Credentials Source:** Terraform client credentials from Key Vault `kv-ytsumm-prd-ci`
- **Findings:**
  - Admin role IS assigned to `admin@test.yt-summarizer.internal` via `app_metadata.role`
  - "Add Role Claims to Tokens" Action is built, deployed, and bound to post-login trigger
  - ROPC warning in CI logs is benign (preview app correctly doesn't have password grant)
- **Result:** Auth0 fully correct — no changes needed

### 4. Parker (2nd Run): MAX_FAILURES Adjustment
- Raised MAX_FAILURES from 5 to 10 in preview E2E workflows
- Rationale: LLM non-determinism causes flakes before LIVE_PROCESSING tests execute

## Key Decisions

- ✅ MAX_FAILURES raised 5 → 10 for preview E2E workflows (Ashley approved)
- ✅ Auth setup must throw, not warn, when role claim is absent
- ✅ No changes needed to Auth0 infrastructure — all correct

## Files Modified

- `apps/web/e2e/auth.setup.ts`
- `playwright.config.ts`
- `preview.yml`
- `.github/workflows/preview-e2e.yml` (pending)

## Learnings for Future Sessions

1. **Auth Setup:** Guard storageState save inside role-confirmation branch. Silently saving broken state cascades failures.
2. **Workflow Env Vars:** Always cross-check both `preview.yml` and `preview-e2e.yml` for env var coverage.
3. **Max Failures:** DEFAULT=5 is too low for LIVE_PROCESSING runs. Baseline should be 10+.
4. **Auth0 Access:** Management API credentials available via Key Vault for advanced debugging.
