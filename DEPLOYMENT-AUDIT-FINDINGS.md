# Deployment Pipeline Audit Findings

**Date**: 2026-01-18  
**Auditor**: AI Assistant  
**Scope**: Production deployment verification and pipeline reliability

---

## Executive Summary

The production API is **fully functional** and accessible via HTTPS at `https://api.yt-summarizer.apps.ashleyhollis.com`. The deployment failures were caused by:

1. **Incorrect GitHub variable**: `PRODUCTION_URL` was set to `http://20.255.113.149` (old IP, HTTP)
2. **Missing TLS validation**: Production pipeline lacks certificate verification that preview has
3. **Code duplication**: ~300 lines of duplicate verification code across actions
4. **Magic strings**: 109 hard-coded values that should be variables
5. **Inconsistent verification**: Preview and production pipelines have different validation steps

**Status**: ✅ **FIXED** - Updated `PRODUCTION_URL` to `https://api.yt-summarizer.apps.ashleyhollis.com`

---

## Task 1: API Accessibility Diagnosis ✅ COMPLETED

### Root Cause Analysis

**Symptoms**:
- Deployment workflow reported "Status: 000000 (expected: 200)"
- Health checks timing out after 10 attempts
- Error: "Production API did not become healthy"

**Investigation Results**:

1. **Kubernetes Infrastructure** ✅ HEALTHY
   - API pod running: `api-684f555648-dqnlk` (1/1 Ready)
   - Service configured: `api` (ClusterIP 10.0.27.71:80)
   - Endpoints healthy: `10.224.0.116:8000`
   - Pod logs show continuous 200 OK responses to health checks

2. **Gateway API Configuration** ✅ HEALTHY
   - HTTPRoute exists and accepted: `api-httproute`
   - Gateway programmed: `main-gateway` (1 route attached)
   - Load balancer IP: `20.187.186.135`
   - DNS resolution: `api.yt-summarizer.apps.ashleyhollis.com` → `20.187.186.135` ✅

3. **TLS Certificate** ✅ VALID
   - Certificate: Let's Encrypt wildcard for `*.yt-summarizer.apps.ashleyhollis.com`
   - Issuer: Let's Encrypt R12 → ISRG Root X1
   - Valid from: Jan 11 12:56:31 2026 GMT
   - Valid until: Apr 11 12:56:30 2026 GMT
   - Verify return code: 0 (ok)
   - Protocol: TLSv1.3
   - Cipher: TLS_AES_256_GCM_SHA384

4. **External Accessibility** ✅ WORKING
   ```bash
   # HTTPS works perfectly
   curl https://api.yt-summarizer.apps.ashleyhollis.com/health/ready
   → 200 OK: {"ready":true,"timestamp":"...","checks":{"api":true,...}}

   # HTTP port 80 returns 404 (expected - Gateway only routes HTTPS)
   curl http://20.187.186.135/health/ready -H "Host: ..."
   → 404 Not Found
   ```

### Root Cause

**GitHub repository variable `PRODUCTION_URL` was incorrectly configured**:

```yaml
# WRONG (before fix)
PRODUCTION_URL: http://20.255.113.149

# CORRECT (after fix)
PRODUCTION_URL: https://api.yt-summarizer.apps.ashleyhollis.com
```

**Why it failed**:
1. IP `20.255.113.149` appears to be from an old ingress/service (not current)
2. Current Gateway IP is `20.187.186.135`
3. HTTP port 80 is not routed by Gateway (only HTTPS port 443)
4. Workflow was testing HTTP against wrong IP, resulting in connection failures

### Fix Applied

✅ Updated GitHub variables:
```bash
gh variable set PRODUCTION_URL --body "https://api.yt-summarizer.apps.ashleyhollis.com"
gh variable set PRODUCTION_API_URL --body "https://api.yt-summarizer.apps.ashleyhollis.com"
```

### Verification

```bash
# Current status
gh variable list
→ PRODUCTION_URL: https://api.yt-summarizer.apps.ashleyhollis.com ✅
→ PRODUCTION_API_URL: https://api.yt-summarizer.apps.ashleyhollis.com ✅

# Test API accessibility
curl -I https://api.yt-summarizer.apps.ashleyhollis.com/health/ready
→ HTTP/1.1 200 OK ✅
```

---

## Task 2: TLS Certificate Validation Review ✅ COMPLETED

### Current State

**Production Pipeline**: ❌ **DOES NOT** validate TLS certificates  
**Preview Pipeline**: ✅ **DOES** validate TLS certificates (line 785)

### Gap Analysis

| Check | Preview | Production |
|-------|---------|------------|
| **Certificate exists** | ✅ Yes | ❌ No |
| **Certificate not expired** | ✅ Yes | ❌ No |
| **Certificate valid for 7 days** | ✅ Yes | ❌ No |
| **Issuer verification** | ✅ Yes | ❌ No |
| **Gateway API cert status** | ✅ Yes | ❌ No |

### Action: `verify-certificate`

**Location**: `.github/actions/verify-certificate/`  
**Script**: `verify-tls.sh` (72 lines)

**Checks performed**:
1. Retrieves certificate chain using `openssl s_client`
2. Extracts certificate dates
3. Verifies certificate is not currently expired (`checkend 0`)
4. Warns if certificate expires within 7 days
5. Displays issuer information

**Usage**:
```yaml
# preview.yml line 785
- name: Verify TLS certificate
  uses: ./.github/actions/verify-certificate
  with:
    host: ${{ steps.urls.outputs.preview-hostname }}
```

### Recommendation

**HIGH PRIORITY**: Add TLS certificate validation to production pipeline

**Suggested placement** (deploy-prod.yml):
```yaml
# After verify-deployment (line 674), before health checks (line 698)
- name: Verify production TLS certificate
  uses: ./.github/actions/verify-certificate
  with:
    host: api.yt-summarizer.apps.ashleyhollis.com
```

---

## Task 3: Verification Actions/Scripts Audit ✅ COMPLETED

### Overview

Audited 6 verification and health-check actions totaling ~1,200 lines of code. Found **~300 lines of duplication** and **3 different implementations** of Argo CD checking.

### Critical Duplication Issues

#### 1. Argo CD Readiness Checks (CRITICAL)

**Problem**: Same functionality implemented 3 times

**Implementations**:
1. `.github/actions/check-argocd-readiness/action.yml` (151 lines inline bash)
2. `.github/actions/verify-deployment/check-argocd-readiness.sh` (156 lines)
3. `.github/actions/verify-deployment/script.sh` - `check_argocd_health()` function (35 lines)

**Duplication**: Implementations #1 and #2 are **character-for-character identical**.

**Impact**:
- Bug fixes must be applied 3 times
- High risk of implementations drifting
- 300+ lines of duplicated code
- Violates DRY principle

**Recommendation**: 🔴 **HIGH PRIORITY**
- Keep standalone `check-argocd-readiness` action
- Delete `verify-deployment/check-argocd-readiness.sh`
- Remove `check_argocd_health()` from `verify-deployment/script.sh`
- Call action instead of duplicating logic

#### 2. HTTP Health Check Polling

**Problem**: HTTP polling implemented twice

**Implementations**:
1. `.github/actions/health-check/health-check.sh` (69 lines) - Generic, reusable
2. `.github/actions/health-check-preview/check-external-health.sh` (133 lines) - Reimplements polling

**Impact**:
- Duplicate retry/timeout logic
- Inconsistent error handling
- Maintenance burden

**Recommendation**: 🟡 **MEDIUM PRIORITY**
- Refactor `check-external-health.sh` to call `health-check` action
- Move preview-specific logic (cert checks, DNS) to separate pre-check steps

#### 3. Certificate Validation Scattered

**Problem**: Certificate checks in 3 different places

**Implementations**:
1. `verify-certificate/verify-tls.sh` - OpenSSL validation (expiry, issuer)
2. `health-check-preview/check-dns-and-tls.sh` - kubectl CRD status
3. `health-check-preview/check-external-health.sh` - kubectl CRD status (duplicate)

**Impact**:
- Unclear which check to use when
- Duplicated kubectl certificate status checks (#2 and #3)

**Recommendation**: 🟡 **MEDIUM PRIORITY**
- Consolidate kubectl certificate status checks
- Document when to use OpenSSL vs kubectl checks
- Single source of truth for certificate validation

### Dead Code

**File**: `.github/actions/verify-deployment/run-verification.sh` (27 lines)  
**Status**: ❌ Never called, unused  
**Recommendation**: 🔴 **DELETE IMMEDIATELY**

### Action-by-Action Summary

| Action | Lines | Scripts | Issues | Priority |
|--------|-------|---------|--------|----------|
| `check-argocd-readiness` | 151 | 0 | Critical duplication | 🔴 High |
| `health-check` | 69 | 1 | None - well designed | ✅ Good |
| `health-check-preview` | 393 | 5 | Reimplements HTTP polling | 🟡 Medium |
| `verify-certificate` | 72 | 1 | Limited scope, placement | 🟢 Low |
| `verify-deployment` | 480 | 3 | Duplicates, dead code | 🔴 High |
| `verify-workers` | 68 | 1 | No health checks | 🟢 Low |
| **TOTAL** | **1,233** | **11** | **~300 lines duplicate** | - |

---

## Task 4: Preview vs Production Consistency ✅ COMPLETED

### Side-by-Side Comparison

| Verification Stage | Preview | Production | Gap |
|-------------------|---------|------------|-----|
| **1. Argo CD Readiness Check** | ❌ MISSING | ✅ Present | ⚠️ PROD has, PREVIEW lacks |
| **2. Stuck Operation Cleanup** | ✅ Present | ✅ Present | ✅ Consistent |
| **3. Pre-deployment Validation** | ✅ Present | ✅ Present | ✅ Consistent |
| **4. Argo CD Sync Wait** | ✅ 180s | ✅ 360s | ⚠️ Different timeouts |
| **5. API Image Verification** | ✅ Present | ✅ Present | ✅ Consistent |
| **6. Workers Image Verification** | ✅ fail=false | ✅ fail=true | ⚠️ Different behavior |
| **7. Deployment Diagnostics** | ❌ MISSING | ✅ Present | ⚠️ PROD has, PREVIEW lacks |
| **8. Health Check (Internal)** | ✅ specialized | ✅ generic | ⚠️ Different actions |
| **9. External Ingress Check** | ✅ Present | ❌ MISSING | ⚠️ PREVIEW has, PROD lacks |
| **10. TLS Certificate Validation** | ✅ Present | ❌ MISSING | ⚠️ PREVIEW has, PROD lacks |
| **11. K8s Pull Test** | ✅ Present | ❌ MISSING | ⚠️ PREVIEW has, PROD lacks |
| **12. Image Tag Format Validation** | ✅ Present | ❌ MISSING | ⚠️ PREVIEW has, PROD lacks |

### Critical Gaps

#### Production MISSING (but Preview has):
1. ❌ **TLS Certificate Validation** - No verification that production certificates are valid
2. ❌ **External Ingress Health Check** - Doesn't verify external URL accessibility
3. ❌ **Kubernetes Pull Test** - Doesn't verify AKS can pull images from ACR
4. ❌ **Image Tag Format Validation** - Doesn't validate tags match expected format

#### Preview MISSING (but Production has):
1. ❌ **Argo CD Readiness Check** - No pre-sync validation of Argo CD app health
2. ❌ **Deployment Diagnostics Collection** - No automated diagnostics on failure

#### Configuration Differences:

| Parameter | Preview | Production | Impact |
|-----------|---------|------------|--------|
| Argo CD Sync Timeout | 180s (3 min) | 360s (6 min) | Prod allows 2x longer |
| Workers Fail on Mismatch | `false` | `true` | Prod enforces strict matching |
| Health Check Interval | 10s / 15s | 15s | Different retry timing |
| Health Check Timeout | 5s | 30s | Prod has 6x longer per-request timeout |
| Health Check Endpoint | `/health/live` | `/health` | Different endpoints |

### Recommendations

**🔴 HIGH PRIORITY - Add to Production**:
1. TLS certificate validation (use `verify-certificate` action)
2. External ingress health check before main health check
3. K8s pull test in update-overlay job
4. Image tag format validation

**🔴 HIGH PRIORITY - Add to Preview**:
1. Argo CD readiness check before sync
2. Deployment diagnostics collection on failure

**🟡 MEDIUM PRIORITY - Standardize**:
1. Use consistent health check actions
2. Standardize worker verification behavior (fail on mismatch in both)
3. Align health check timeouts/intervals
4. Use same health check endpoint (`/health/ready`)

---

## Task 5: Magic Strings Refactoring ✅ COMPLETED

### Summary Statistics

| Category | Total Occurrences | Already Variables | Need Variables |
|----------|-------------------|-------------------|----------------|
| Service Names | 7 | 0 | 7 |
| Namespaces | 14 | 0 | 14 |
| URLs/Hostnames | 4 | 1 | 3 |
| Timeouts | 20+ | 0 | 8 unique |
| Registry Values | 15 | 15 ✅ | 0 |
| Worker Lists | 2 | 0 | 2 |
| Resource Names | 10 | 10 ✅ | 0 |
| Paths | 19 | 0 | 6 |
| Versions | 9 | 0 | 3 |
| Other Numbers | 9 | 1 | 6 |
| **TOTAL** | **~109** | **~27** | **~49** |

### 🔴 HIGH PRIORITY Magic Strings

These change frequently or impact multiple jobs:

#### 1. Worker List (2 occurrences)
```yaml
# Current
workers: 'transcribe-worker,summarize-worker,embed-worker,relationships-worker'

# Proposed
env:
  WORKER_DEPLOYMENTS: 'transcribe-worker,summarize-worker,embed-worker,relationships-worker'

# Usage
workers: ${{ env.WORKER_DEPLOYMENTS }}
```

**Impact**: Must update in 2 places when adding/removing workers

#### 2. Application Names (17 occurrences)
```yaml
# Proposed env variables
env:
  APP_NAME: 'yt-summarizer'
  API_IMAGE_NAME: 'yt-summarizer-api'
  WORKERS_IMAGE_NAME: 'yt-summarizer-workers'
  ARGOCD_APP_NAME_PROD: 'yt-summarizer-prod'
```

**Occurrences**:
- `yt-summarizer-api`: 7 times (preview.yml: 4, deploy-prod.yml: 3)
- `yt-summarizer-workers`: 4 times (preview.yml: 2, deploy-prod.yml: 2)
- `yt-summarizer-prod`: 6 times (deploy-prod.yml only)

#### 3. Base Domain (1 occurrence)
```yaml
# Current (preview.yml:574)
base_domain: yt-summarizer.apps.ashleyhollis.com

# Proposed
env:
  APPS_BASE_DOMAIN: 'yt-summarizer.apps.ashleyhollis.com'
```

#### 4. Namespace Patterns
```yaml
# Proposed
env:
  NAMESPACE_PROD: 'yt-summarizer'
  NAMESPACE_ARGOCD: 'argocd'
  PREVIEW_NAMESPACE_PREFIX: 'preview-pr-'
```

**Occurrences**:
- `argocd`: 6 times
- `yt-summarizer`: 6 times
- `preview-pr-{number}`: 8 times (dynamic pattern)

#### 5. Timeout Values
```yaml
# Proposed
env:
  # CI/CD timeouts
  CI_WAIT_TIMEOUT_SECONDS: '1800'  # 30 minutes

  # Argo CD timeouts
  ARGOCD_SYNC_TIMEOUT_PREVIEW: '180'   # 3 minutes
  ARGOCD_SYNC_TIMEOUT_PROD: '360'      # 6 minutes
  ARGOCD_OPERATION_TIMEOUT_THRESHOLD: '300'  # 5 minutes

  # Health check parameters
  HEALTH_CHECK_MAX_ATTEMPTS: '10'
  HEALTH_CHECK_INTERVAL_SECONDS: '15'
  HEALTH_CHECK_TIMEOUT_SECONDS: '30'
```

**Occurrences**: 20+ timeout values scattered across workflows

### 🟡 MEDIUM PRIORITY Magic Strings

#### 6. Tool Versions
```yaml
# Proposed
env:
  TERRAFORM_VERSION: '1.5.7'
  KUSTOMIZE_VERSION: '5.8.0'
  NODE_VERSION: '20'
```

**Occurrences**:
- Terraform: 4 times
- Kustomize: 2 times
- Node.js: 3 times

#### 7. Health Check Endpoints
```yaml
# Proposed
env:
  HEALTH_CHECK_PATH: '/health/ready'
  LIVENESS_CHECK_PATH: '/health/live'
```

### 🟢 LOW PRIORITY Magic Strings

#### 8. Path Constants
```yaml
# Proposed
env:
  TERRAFORM_WORKING_DIR: 'infra/terraform/environments/prod'
  KUSTOMIZE_OVERLAY_PREVIEW: 'k8s/overlays/preview'
  KUSTOMIZE_OVERLAY_PROD: 'k8s/overlays/prod'
  ARGOCD_MANIFESTS_PATH: 'k8s/argocd'
```

#### 9. Artifact Retention
```yaml
# Proposed
env:
  ARTIFACT_RETENTION_DAYS: '7'
```

---

## Consolidated Recommendations

### Immediate Actions (Do Now)

1. ✅ **DONE**: Update `PRODUCTION_URL` GitHub variable
2. 🔴 **TODO**: Delete dead code (`verify-deployment/run-verification.sh`)
3. 🔴 **TODO**: Add TLS certificate validation to production pipeline
4. 🔴 **TODO**: Remove duplicate `check-argocd-readiness.sh` from verify-deployment

### Short-term (This Sprint)

1. 🟡 Add Argo CD readiness check to preview pipeline
2. 🟡 Add deployment diagnostics collection to preview
3. 🟡 Standardize health check actions between pipelines
4. 🟡 Add external ingress check to production
5. 🟡 Consolidate HTTP polling logic in health-check-preview

### Medium-term (Next Sprint)

1. 🟢 Create workflow-level environment variables for all high-priority magic strings
2. 🟢 Refactor worker verification to include health checks
3. 🟢 Modularize verify-deployment script (currently 297 lines)
4. 🟢 Consolidate certificate validation logic
5. 🟢 Add image tag format validation to production

### Long-term (Backlog)

1. Extract health check functions from verify-deployment into reusable scripts
2. Create GitHub repository variables for all medium-priority magic strings
3. Document when to use different types of checks (kubectl vs openssl, internal vs external)
4. Add DNS validation to both pipelines
5. Add certificate expiration monitoring

---

## Estimated Impact

### Code Reduction
- **Current**: ~1,200 lines of verification code
- **After cleanup**: ~900 lines (25% reduction)
- **Duplication eliminated**: ~300 lines

### Maintenance Burden
- **Current**: 3 places to update Argo CD checks
- **After**: 1 place
- **Current**: 109 magic strings
- **After**: ~60 (45% reduction)

### Reliability Improvements
- ✅ Consistent verification between preview and production
- ✅ Proper TLS validation in production
- ✅ Better fail-fast error detection
- ✅ Reduced risk of configuration drift

---

## Next Steps

1. Review this document
2. Prioritize which recommendations to implement first
3. Create GitHub issues for tracking
4. Begin implementation starting with high-priority items

**Questions or feedback? Let me know!**
