# Preview Deployment: HTTPRoute Hostname Mismatch Issue

**Date:** 2026-01-25  
**Status:** Resolved  
**Priority:** Medium  
**Affected Component:** Preview deployment script (`deploy-backend-preview`)

## Problem Summary

Preview deployments were configuring HTTPRoute with the **wrong PR number in the hostname**.

**Example:**
- **Expected:** `api-pr-104.yt-summarizer.apps.ashleyhollis.com`
- **Actual:** `api-pr-103.yt-summarizer.apps.ashleyhollis.com`

This caused preview health checks to fail because they tested the expected URL, but the application was actually deployed at the previous PR's hostname.

## Impact

- ❌ Preview health checks fail (testing wrong URL)
- ❌ PR status checks show failure even though deployment is successful
- ✅ Application is actually healthy and accessible (at wrong URL)
- ✅ All pods, services, and infrastructure working correctly

**Severity:** Medium - Cosmetic failure, doesn't block functionality but hides successful deployments

## Root Cause

The preview deployment script `scripts/ci/generate_preview_kustomization.py` already had logic to substitute `__PREVIEW_HOST__` placeholders in overlay patch files (lines 92-116), but the HTTPRoute patch file was using **hardcoded PR numbers** instead of placeholders.

### Files Updated Correctly ✅
- `k8s/overlays/preview/kustomization.yaml`
  - Namespace: `preview-pr-{number}`
  - Image tags: `pr-{number}-{sha}`
  - Name suffix: `-pr-{number}`
- `k8s/base-preview/api-httproute.yaml`
  - Uses `__PREVIEW_HOST__` placeholder correctly

### File NOT Updated ❌
- `k8s/overlays/preview/patches/httproute-patch.yaml`
  - Had hardcoded hostname: `api-pr-103.yt-summarizer.apps.ashleyhollis.com`
  - Should have used: `__PREVIEW_HOST__` placeholder

## Resolution

**Fix:** Replace hardcoded PR numbers with `__PREVIEW_HOST__` placeholder in `k8s/overlays/preview/patches/httproute-patch.yaml`.

**Changes:**
```yaml
# Before:
metadata:
  annotations:
    external-dns.alpha.kubernetes.io/hostname: api-pr-103.yt-summarizer.apps.ashleyhollis.com
spec:
  hostnames:
  - "api-pr-103.yt-summarizer.apps.ashleyhollis.com"

# After:
metadata:
  annotations:
    external-dns.alpha.kubernetes.io/hostname: __PREVIEW_HOST__
spec:
  hostnames:
  - "__PREVIEW_HOST__"
```

**How it works:**
1. GitHub Actions computes `PREVIEW_HOST` as `api-pr-{PR_NUMBER}.yt-summarizer.apps.ashleyhollis.com` in `.github/actions/compute-preview-urls/compute-preview-urls.sh`
2. The value is passed to `scripts/ci/generate_preview_kustomization.py`
3. The script substitutes all `__PREVIEW_HOST__` placeholders in overlay patches with the computed value
4. Now HTTPRoute gets the correct hostname for each PR deployment

**Domain consistency:**
- Base domain: `yt-summarizer.apps.ashleyhollis.com` (set in `.github/workflows/preview.yml` as `APPS_BASE_DOMAIN`)
- Preview pattern: `api-pr-{PR}.yt-summarizer.apps.ashleyhollis.com`

## Testing

Next deployment will verify:
- HTTPRoute hostname matches PR number
- Health checks pass at correct URL
- External DNS creates correct DNS record

## Related Files

- `k8s/overlays/preview/patches/httproute-patch.yaml` (fixed)
- `k8s/base-preview/api-httproute.yaml` (already correct)
- `scripts/ci/generate_preview_kustomization.py` (substitution logic)
- `.github/actions/compute-preview-urls/compute-preview-urls.sh` (URL computation)
- `.github/workflows/preview.yml` (BASE_DOMAIN definition)

## Notes

- This issue existed because the patch file was manually edited with a specific PR number and never updated to use placeholders
- The deployment script already had the substitution logic in place
- Moving forward, all preview-specific values should use placeholders that the CI/CD pipeline substitutes
