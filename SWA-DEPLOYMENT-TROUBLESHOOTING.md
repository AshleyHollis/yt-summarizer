# SWA Deployment Troubleshooting Log

**Date**: 2026-01-21  
**Branch**: `fix/swa-backend-integration-baseline`  
**PR**: #69  
**Problem**: SWA deployments failing with "warmup timeout" after integrating Auth0 backend changes

## Context

### Last Successful Deployment
- **Commit**: `129645c` (main branch)
- **Date**: 2026-01-20 10:32 AM
- **Run**: #21168195199
- **Note**: Frontend was SKIPPED in this run (not actually deployed)

### Current State
- **Branch**: `fix/swa-backend-integration-baseline`
- **Latest Commit**: `7e13d21` - "test: revert SWA output_location to .next (Test 1)"
- **SWA Resource**: Freshly recreated (old stuck, new clean)
  - Old: `proud-coast-0bd36cb00.6.azurestaticapps.net`
  - New: `proud-smoke-05b9a9c00.4.azurestaticapps.net`
- **Deployment Token**: Regenerated and updated in GitHub secrets

### Key Finding: Configuration Difference

**Main branch (working)**:
```yaml
output_location: .next
```

**Our branch (failing)**:
```yaml
output_location: ""  # Empty string - correct per MS docs but failing
```

### Code Analysis
- ✅ **NO functional code changes** between `129645c` and current HEAD
- ✅ **Dependencies identical** (package.json unchanged)
- ✅ **Next.js config unchanged** (only formatting)
- ❌ **Workflow config changed**: `output_location` setting

## Tests Performed

### Test 0: Baseline Investigation (COMPLETED)
**Hypothesis**: Code changes broke SWA deployment  
**Method**: Git diff comparison between `129645c` and HEAD  
**Result**: ❌ REJECTED - Only formatting changes, no functional code changes  
**Conclusion**: Problem is NOT in the application code

---

### Test 1: Revert output_location to .next (FAILED)
**Commit**: `7e13d21`  
**Hypothesis**: Empty `output_location` is incompatible with SWA Next.js hybrid deployment  
**Method**: Changed `output_location: ""` → `output_location: .next` in both workflows  
**Run**: #21185010302  
**Result**: ❌ FAILED - Deployment still times out with warmup timeout  
**Duration**: Still timing out after 15+ minutes  
**Conclusion**: `output_location` setting is NOT the root cause

**Analysis**: Successful baseline workflow (Run #21157814189) used `output_location: ""` (empty string) and deployed successfully in 54 seconds. This proves empty string is NOT the problem.

---

### Test 2: Simple Isolated Workflow (IN PROGRESS)
**Commit**: TBD  
**Hypothesis**: Complex workflow orchestration or Auth0 timing is causing the warmup timeout  
**Method**: Created minimal workflow based on successful baseline (Run #21157814189)

**Key simplifications**:
- ✅ No job dependencies (single standalone job)
- ✅ No Auth0 configuration step
- ✅ No backend URL requirement (placeholder API URL)
- ✅ Empty `output_location` (same as successful baseline)
- ✅ Minimal build configuration

**Successful baseline comparison** (test/swa-warmup-baseline):
```yaml
# Successful workflow that deployed in 54 seconds
app_location: apps/web
output_location: ""        # Empty string - worked fine
skip_app_build: true
# No Auth0 config
# No complex dependencies
# Simple placeholder API URL
```

**Current preview workflow** (failing):
```yaml
# Complex workflow with multiple jobs
needs: [get-ingress, build-frontend]  # Job dependencies
# Fetches Auth0 credentials from Key Vault
# Configures Auth0 AFTER deployment completes
# Real backend URL from previous jobs
app_location: apps/web
output_location: .next     # Changed in Test 1 - still fails
skip_app_build: true
```

**Expected outcomes**:
- ✅ **SUCCESS**: Proves complex orchestration/Auth0 is the root cause → Simplify preview workflow
- ❌ **FAILURE**: Indicates deeper Next.js/SWA platform issue → Investigate build artifacts

**Status**: Workflow created (`.github/workflows/swa-simple-test.yml`), ready to commit

---

## Root Cause Analysis

### Working Theory
Azure SWA's Next.js integration may have specific requirements for `output_location`:
1. **Empty string** (`""`) = Tells SWA "no separate output folder, use app root"
2. **`.next`** = Tells SWA "build output is in .next folder"

For Next.js with hybrid rendering:
- Microsoft docs say use empty string
- But main branch uses `.next` and works
- Our branch uses empty string and fails

**Possible explanations**:
1. SWA platform changed behavior recently
2. Empty string triggers different code path that's broken
3. Auth0 app settings + empty output_location = conflict
4. .next folder structure differs from what SWA expects

### Questions to Answer
- [ ] Why does `.next` work when docs say use empty string?
- [ ] What does SWA actually do differently with empty vs `.next`?
- [ ] Is there a recent SWA platform change?
- [ ] Does the build artifact structure matter?

---

## Decision Log

### Decision 1: Abandon output_location Theory
**Date**: 2026-01-21 06:00 UTC  
**Rationale**: Test 1 failed even after reverting to `.next`. Successful baseline used empty string successfully.  
**Action**: Pivot to Test 2 - investigate workflow complexity and Auth0 timing  
**Evidence**: Run #21157814189 (successful) used `output_location: ""` and deployed in 54 seconds

### Decision 2: Test Simple Isolated Workflow
**Date**: 2026-01-21 06:05 UTC  
**Rationale**: Successful baseline had no job dependencies, no Auth0 config, minimal orchestration  
**Action**: Create `.github/workflows/swa-simple-test.yml` based on successful baseline  
**Expected outcome**: Isolate whether deployment mechanism works, identify if orchestration is the issue  
**Risk**: Low - mirrors proven working workflow

---

## References
- [Microsoft Docs: SWA + Next.js](https://learn.microsoft.com/azure/static-web-apps/deploy-nextjs-hybrid)
- [PR #69](https://github.com/AshleyHollis/yt-summarizer/pull/69)
- [Last successful run](https://github.com/AshleyHollis/yt-summarizer/actions/runs/21168195199)
- [Baseline branch commit history](https://github.com/AshleyHollis/yt-summarizer/commits/fix/swa-backend-integration-baseline)

---

## Next Steps
1. ✅ Document current state
2. ⏳ Test 1: Revert output_location
3. ⏳ Monitor deployment
4. ⏳ Document findings
5. ⏳ Implement proper fix with understanding
