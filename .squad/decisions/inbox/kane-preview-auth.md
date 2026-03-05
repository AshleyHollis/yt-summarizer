# Kane — Preview Auth0 Config Issues (PR #177)

**Raised by**: Kane (Tester)  
**Date**: 2026-06-02  
**Scope**: Preview environment for PR #177  
**API**: `https://api-pr-177.yt-summarizer.apps.ashleyhollis.com`  
**SWA**: `https://proud-hill-0940e7300-177.eastasia.6.azurestaticapps.net`

---

## ✅ What's Working

1. **All Auth0 secrets are present** in the API pod (`AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`, `AUTH0_SESSION_SECRET`, `AUTH0_DEFAULT_RETURN_TO`).
2. **Login redirect works**: `GET /api/auth/login` returns 302 to Auth0 (`dev-gvli0bfdrue0h8po.us.auth0.com`) with correct `redirect_uri` pointing back to the preview API callback URL.
3. **Terraform Auth0 wildcards are correct**: Callback, logout, and web origin URLs all include `https://api-pr-*.yt-summarizer.apps.ashleyhollis.com/*` and `https://*.azurestaticapps.net` patterns — Auth0 will accept the preview URLs.
4. **Frontend API URL**: The SWA is configured at deploy time with the correct API URL via `NEXT_PUBLIC_API_URL`.

---

## ⚠️ Issues Found

### ISSUE 1 — CORS mismatch: wrong SWA URL in API pod (BLOCKING)

**Symptom**: Browser-side API calls from the actual SWA (`proud-hill-0940e7300-177`) will be rejected by the API with a CORS error.

**Details**:
- API pod `API__CORS_ORIGINS` = `["https://red-grass-06d413100-177.eastasia.6.azurestaticapps.net","http://localhost:3000"]`
- Actual SWA URL = `https://proud-hill-0940e7300-177.eastasia.6.azurestaticapps.net`
- The `proud-hill` origin is **not in the CORS allowlist**

**Root cause**: `scripts/ci/generate_preview_kustomization.sh` (line 65) falls back to a hardcoded SWA hostname (`red-grass-06d413100-${PR_NUMBER}`) when `--swa-url` is not passed. The `update-k8s-overlay.yml` workflow runs in Phase 2 (before SWA deployment in Phase 7), so it does not yet know the real SWA deployment URL.

**Impact**: Authenticated users will encounter CORS failures when the SWA frontend tries to call the API. Auth login may complete (Auth0 wildcard accepts the request) but subsequent API calls from the browser will fail.

---

### ISSUE 2 — Wrong `AUTH0_DEFAULT_RETURN_TO` post-login redirect (UX)

**Symptom**: After a successful Auth0 login, users are redirected to `https://red-grass-06d413100-177.eastasia.6.azurestaticapps.net` instead of the actual SWA.

**Details**:
- `AUTH0_DEFAULT_RETURN_TO` = `https://red-grass-06d413100-177.eastasia.6.azurestaticapps.net`
- The state JWT `returnTo` field decoded from the login redirect confirms this incorrect URL
- Same root cause as Issue 1 (hardcoded fallback in `generate_preview_kustomization.sh`)

**Impact**: Post-login redirect lands on the wrong (potentially non-existent) SWA URL. Users are dropped after sign-in.

---

## Recommended Fix

**Option A (preferred)**: Add a post-SWA-deploy step to the preview pipeline that patches the API deployment with the actual SWA URL returned by the Azure SWA deploy action.

In `preview.yml`, after `deploy-frontend-preview` succeeds, add a step:
```
kubectl set env deploy/api -n preview-pr-${PR_NUMBER} \
  API__CORS_ORIGINS='["${REAL_SWA_URL}","http://localhost:3000"]' \
  AUTH0_DEFAULT_RETURN_TO="${REAL_SWA_URL}"
```
Where `REAL_SWA_URL` = `deploy-frontend-preview.outputs.static_web_app_url`.

**Option B**: Update `generate_preview_kustomization.sh` to require `--swa-url` (remove the hardcoded fallback) and ensure the `manage-kustomization` action obtains and passes the real SWA URL.

**Option C (partial mitigation)**: If the SWA app name is stable across PRs (the `proud-hill` prefix is always the same per subscription/region), update the hardcoded fallback in the script to match reality. This is fragile and not recommended.

---

## Terraform Auth0 — No Changes Needed

The Auth0 Terraform module (`infra/terraform/environments/prod/variables.tf`) correctly uses wildcards for preview:
- `auth0_allowed_callback_urls`: `https://api-pr-*.yt-summarizer.apps.ashleyhollis.com/api/auth/callback` ✅
- `auth0_allowed_logout_urls`: `https://*.azurestaticapps.net` ✅
- `auth0_allowed_web_origins`: `https://*.azurestaticapps.net` ✅

No Terraform changes needed for Auth0 wildcard coverage.
